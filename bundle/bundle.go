// SPDX-License-Identifier: Apache-2.0

// Package bundle packs one Gemara artifact into an OCI bundle and writes it
// to a registry (or an OCI layout on disk), attaches OCI 1.1 referrers
// (signature, provenance), and — in Publish — runs the whole grc.store
// publish sequence in the one order both client tools must share.
// Extracted from grcli's internal/registry (pack/push) and privateer-sdk's
// internal/oci (referrer attach, explicit registry-token plumbing).
package bundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	gbundle "github.com/gemaraproj/go-gemara/bundle"
	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// ProvenanceArtifactType stamps the signed provenance referrer so hub and
// client verifiers never mistake it for the signature referrer (which is
// mediatype.SigstoreBundle). The blob inside is still a Sigstore v0.3
// bundle whose DSSE statement carries the SLSA predicate.
//
// ponytail: mirror of the ruled mediatype.ProvenanceBundle constant; import
// it from grc-store-protocol once that module tags it.
const ProvenanceArtifactType = "application/vnd.grc-store.provenance.bundle.v0.3+json"

// Registry credential overrides, read when Registry.Token is empty. One
// shared family for every client tool; per-environment, not per-tool.
const (
	RegistryTokenEnv    = "GRC_STORE_REGISTRY_TOKEN"
	RegistryUsernameEnv = "GRC_STORE_REGISTRY_USERNAME"
	RegistryPasswordEnv = "GRC_STORE_REGISTRY_PASSWORD"
)

// Input is the artifact to bundle. Body is the YAML of exactly one
// artifact. License is the canonical SPDX expression, already validated by
// the caller (spdx.Canonicalize); empty means no license annotation.
// Provenance, when non-nil, is embedded unsigned under the bundle
// manifest's metadata.provenance (raw-manifest continuity; the signed
// referrer Publish attaches is the verifiable copy).
type Input struct {
	Filename      string
	ArtifactType  string
	ArtifactID    string
	GemaraVersion string
	Body          []byte
	License       string
	Provenance    any
}

// Result reports what was written.
type Result struct {
	Manifest       ocispec.Descriptor // the bundle manifest; subject for referrers
	ManifestDigest string
	BodyDigest     string
	Tag            string
	Reference      string // <host>/<repository>:<tag>, or oci:<dir>:<tag>
}

// Registry is a dial target. Token is a registry bearer (from
// hub.Client.RegistryToken); when empty the GRC_STORE_REGISTRY_* env
// overrides and then the Docker credential store are consulted.
type Registry struct {
	Host      string
	PlainHTTP bool
	Token     string
}

// openRepository is swapped by tests for an in-memory target.
var openRepository = func(r Registry, repository string) (oras.Target, error) {
	if r.Host == "" {
		return nil, errors.New("registry host is required (hub discovery returned none)")
	}
	if repository == "" {
		return nil, errors.New("repository is required")
	}
	repo, err := remote.NewRepository(r.Host + "/" + repository)
	if err != nil {
		return nil, fmt.Errorf("constructing repository client: %w", err)
	}
	repo.PlainHTTP = r.PlainHTTP
	creds, err := credentialFunc(r.Host, r.Token)
	if err != nil {
		return nil, err
	}
	repo.Client = &auth.Client{
		Client: &http.Client{Transport: retry.NewTransport(&http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		})},
		Cache:      auth.NewCache(),
		Credential: creds,
	}
	return repo, nil
}

// credentialFunc resolves, in order: the explicit token, the env
// username/password pair, the env token, then ~/.docker/config.json and
// its helpers (what `docker login` writes, so CI runners get auth for free).
// The first three are bound to host: a redirect to any other host (a blob
// store behind the registry, say) gets only the Docker chain, never the
// registry token.
func credentialFunc(host, token string) (auth.CredentialFunc, error) {
	store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
	if err != nil {
		return nil, fmt.Errorf("loading docker credentials: %w", err)
	}
	return func(ctx context.Context, registry string) (auth.Credential, error) {
		if registry == host {
			if token != "" {
				return auth.Credential{AccessToken: token}, nil
			}
			if u, p := os.Getenv(RegistryUsernameEnv), os.Getenv(RegistryPasswordEnv); u != "" && p != "" {
				return auth.Credential{Username: u, Password: p}, nil
			}
			if t := os.Getenv(RegistryTokenEnv); t != "" {
				return auth.Credential{AccessToken: t}, nil
			}
		}
		return credentials.Credential(store)(ctx, registry)
	}, nil
}

// Push packs in and pushes it to <Host>/<repository>:<tag>.
func (r Registry) Push(ctx context.Context, repository, tag string, in Input) (*Result, error) {
	target, err := openRepository(r, repository)
	if err != nil {
		return nil, err
	}
	res, err := pack(ctx, target, tag, in)
	if err != nil {
		return nil, err
	}
	res.Reference = fmt.Sprintf("%s/%s:%s", r.Host, repository, tag)
	return res, nil
}

// Attach pushes blob as an OCI 1.1 referrer of subject in repository.
func (r Registry) Attach(ctx context.Context, repository string, subject ocispec.Descriptor, artifactType string, blob []byte) error {
	target, err := openRepository(r, repository)
	if err != nil {
		return err
	}
	return AttachReferrer(ctx, target, subject, artifactType, blob)
}

// PushLocal writes the same bundle to an OCI image layout directory: the
// dry-run path. Identical bundle shape, no network.
func PushLocal(ctx context.Context, dir, tag string, in Input) (*Result, error) {
	if dir == "" {
		return nil, errors.New("output directory is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating output dir: %w", err)
	}
	store, err := oci.New(dir)
	if err != nil {
		return nil, fmt.Errorf("opening OCI layout: %w", err)
	}
	res, err := pack(ctx, store, tag, in)
	if err != nil {
		return nil, err
	}
	res.Reference = fmt.Sprintf("oci:%s:%s", dir, tag)
	return res, nil
}

// AttachReferrer is the target-agnostic referrer push: the blob, then an
// OCI 1.1 manifest of subject carrying it as the single layer, with
// artifactType as both the referrer's artifactType and the layer's media
// type. artifactType must be an RFC 6838 media type — oras rejects
// mediatype.CosignSignReferrer (a URL) before any I/O.
func AttachReferrer(ctx context.Context, target oras.Target, subject ocispec.Descriptor, artifactType string, blob []byte) error {
	if subject.Digest == "" {
		return errors.New("subject descriptor is required")
	}
	if len(blob) == 0 {
		return errors.New("referrer blob is empty")
	}
	desc := ocispec.Descriptor{MediaType: artifactType, Digest: godigest.FromBytes(blob), Size: int64(len(blob))}
	if err := target.Push(ctx, desc, bytes.NewReader(blob)); err != nil {
		return fmt.Errorf("pushing %s blob: %w", artifactType, err)
	}
	if _, err := oras.PackManifest(ctx, target, oras.PackManifestVersion1_1, artifactType, oras.PackManifestOptions{
		Subject: &subject,
		Layers:  []ocispec.Descriptor{desc},
	}); err != nil {
		return fmt.Errorf("pushing %s referrer manifest: %w", artifactType, err)
	}
	return nil
}

// pack builds the in-memory Bundle, calls go-gemara's Pack against target,
// and tags the manifest.
func pack(ctx context.Context, target oras.Target, tag string, in Input) (*Result, error) {
	switch {
	case tag == "":
		return nil, errors.New("tag is required (metadata.version)")
	case len(in.Body) == 0:
		return nil, errors.New("artifact body is empty")
	case in.Filename == "":
		return nil, errors.New("artifact filename is empty")
	}
	manifest := gbundle.Manifest{
		BundleVersion: "1.0",
		GemaraVersion: in.GemaraVersion,
		Metadata:      map[string]any{},
		Artifacts:     []gbundle.Artifact{{Name: in.Filename, Type: in.ArtifactType, ID: in.ArtifactID, Role: "artifact"}},
	}
	if in.Provenance != nil {
		manifest.Metadata["provenance"] = in.Provenance
	}
	b := &gbundle.Bundle{
		Manifest: manifest,
		Source:   gbundle.File{Name: in.Filename, Type: in.ArtifactType, Data: in.Body},
	}
	var opts []gbundle.PackOption
	if in.License != "" {
		opts = append(opts, gbundle.WithAnnotations(map[string]string{ocispec.AnnotationLicenses: in.License}))
	}
	desc, err := gbundle.Pack(ctx, target, b, opts...)
	if err != nil {
		return nil, fmt.Errorf("packing bundle: %w", err)
	}
	if err := target.Tag(ctx, desc, tag); err != nil {
		return nil, fmt.Errorf("tagging %s: %w", tag, err)
	}
	return &Result{
		Manifest:       desc,
		ManifestDigest: desc.Digest.String(),
		BodyDigest:     godigest.FromBytes(in.Body).String(),
		Tag:            tag,
	}, nil
}
