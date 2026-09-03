// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gbundle "github.com/gemaraproj/go-gemara/bundle"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/revanite-io/grc-store-protocol/mediatype"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry"
)

var testInput = Input{
	Filename: "log.yaml", ArtifactType: "EvaluationLog", ArtifactID: "my-log", GemaraVersion: "1.0.0",
	Body: []byte("metadata:\n  id: my-log\n  version: 1.0.0-run1\n"), License: "Apache-2.0",
	Provenance: map[string]string{"buildType": "test"},
}

func TestPushLocal_RoundTripsThroughUnpack(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	res, err := PushLocal(ctx, dir, "1.0.0-run1", testInput)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reference != "oci:"+dir+":1.0.0-run1" || res.ManifestDigest != res.Manifest.Digest.String() || !strings.HasPrefix(res.BodyDigest, "sha256:") {
		t.Errorf("result = %+v", res)
	}
	b, err := unpackLocal(ctx, dir, "1.0.0-run1")
	if err != nil {
		t.Fatal(err)
	}
	if string(b.Source.Data) != string(testInput.Body) || b.Source.Name != "log.yaml" || b.Manifest.GemaraVersion != "1.0.0" {
		t.Errorf("unpacked = %+v", b)
	}
	if b.Manifest.Artifacts[0].Type != "EvaluationLog" || b.Manifest.Artifacts[0].ID != "my-log" || b.Manifest.Metadata["provenance"] == nil {
		t.Errorf("manifest = %+v", b.Manifest)
	}
}

func TestPack_LicenseAnnotationAndValidation(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	res, err := pack(ctx, store, "v1", testInput)
	if err != nil {
		t.Fatal(err)
	}
	var m ocispec.Manifest
	raw, _ := content.FetchAll(ctx, store, res.Manifest)
	_ = json.Unmarshal(raw, &m)
	if m.Annotations[ocispec.AnnotationLicenses] != "Apache-2.0" {
		t.Errorf("license annotation = %q", m.Annotations[ocispec.AnnotationLicenses])
	}
	if d, err := store.Resolve(ctx, "v1"); err != nil || d.Digest != res.Manifest.Digest {
		t.Errorf("tag not resolvable: %v %v", d, err)
	}
	noLicense := testInput
	noLicense.License = ""
	res, _ = pack(ctx, store, "v2", noLicense)
	raw, _ = content.FetchAll(ctx, store, res.Manifest)
	var m2 ocispec.Manifest
	_ = json.Unmarshal(raw, &m2)
	if _, ok := m2.Annotations[ocispec.AnnotationLicenses]; ok {
		t.Error("no license must leave the manifest unannotated")
	}

	for name, in := range map[string]Input{"empty body": {Filename: "x"}, "empty filename": {Body: []byte("x")}} {
		if _, err := pack(ctx, store, "v1", in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := pack(ctx, store, "", testInput); err == nil {
		t.Error("empty tag: expected error")
	}
}

func TestAttachReferrer_StampsArtifactTypeAndRoundTrips(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	res, err := pack(ctx, store, "v1", testInput)
	if err != nil {
		t.Fatal(err)
	}
	sig := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","the":"signature"}`)
	att := []byte(`{"the":"provenance"}`)
	if err := AttachReferrer(ctx, store, res.Manifest, mediatype.SigstoreBundle, sig); err != nil {
		t.Fatal(err)
	}
	if err := AttachReferrer(ctx, store, res.Manifest, ProvenanceArtifactType, att); err != nil {
		t.Fatal(err)
	}
	got := map[string][]byte{}
	refs, _ := registry.Referrers(ctx, store, res.Manifest, "")
	for _, r := range refs {
		raw, _ := content.FetchAll(ctx, store, r)
		var m ocispec.Manifest
		_ = json.Unmarshal(raw, &m)
		if len(m.Layers) != 1 || m.Layers[0].MediaType != r.ArtifactType {
			t.Errorf("referrer %s: layers = %+v", r.ArtifactType, m.Layers)
		}
		got[r.ArtifactType], _ = content.FetchAll(ctx, store, m.Layers[0])
	}
	if string(got[mediatype.SigstoreBundle]) != string(sig) || string(got[ProvenanceArtifactType]) != string(att) {
		t.Errorf("referrers = %v", got)
	}
	// The two referrers must be distinguishable by artifactType alone — a hub
	// filtering on the signature type must never pick up the provenance one.
	if ProvenanceArtifactType == mediatype.SigstoreBundle || ProvenanceArtifactType == mediatype.CosignSignReferrer {
		t.Fatal("provenance artifactType collides with a signature type")
	}
	if err := AttachReferrer(ctx, store, res.Manifest, mediatype.SigstoreBundle, nil); err == nil {
		t.Error("empty blob must fail")
	}
	if err := AttachReferrer(ctx, store, ocispec.Descriptor{}, mediatype.SigstoreBundle, sig); err == nil {
		t.Error("empty subject must fail")
	}
}

// fakeHub serves discovery, /v2/token (with the granted actions it is told
// to grant) and /v1/bundles/sync, recording the order of calls.
func fakeHub(t *testing.T, grant []string) (*httptest.Server, *[]string) {
	t.Helper()
	calls := &[]string{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls = append(*calls, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/.well-known/grc-store-configuration":
			_, _ = fmt.Fprintf(w, `{"registry_url":"http://registry.test","hub_url":%q}`, srv.URL)
		case "/v2/token":
			payload, _ := json.Marshal(map[string]any{"access": []map[string]any{{"type": "repository", "name": "acme/my-log", "actions": grant}}})
			tok := "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
			_, _ = fmt.Fprintf(w, `{"token":%q}`, tok)
		case "/v1/bundles/sync":
			if r.Header.Get("Authorization") != "Bearer hub-bearer" {
				t.Errorf("sync auth = %q", r.Header.Get("Authorization"))
			}
			b, _ := io.ReadAll(r.Body)
			*calls = append(*calls, "sync-body "+string(b))
			_, _ = w.Write([]byte(`{"repository":"acme/my-log","tag":"1.0.0-run1","artifact_count":1,"new_count":1,"types":["EvaluationLog"]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, calls
}

func swapRepository(t *testing.T) (*memory.Store, *[]Registry) {
	t.Helper()
	store := memory.New()
	opened := &[]Registry{}
	orig := openRepository
	openRepository = func(r Registry, repository string) (oras.Target, error) {
		*opened = append(*opened, r)
		if repository != "acme/my-log" {
			t.Errorf("repository = %q", repository)
		}
		return store, nil
	}
	t.Cleanup(func() { openRepository = orig })
	return store, opened
}

func TestPublish_OrderAndSync(t *testing.T) {
	srv, calls := fakeHub(t, []string{"pull", "push"})
	store, opened := swapRepository(t)

	out, err := Publish(context.Background(), testInput, Target{HubURL: srv.URL, Repository: "acme/my-log", Tag: "1.0.0-run1", Bearer: "hub-bearer"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Signed || out.Attested || out.Sync.NewCount != 1 || out.Reference != "registry.test/acme/my-log:1.0.0-run1" {
		t.Errorf("published = %+v", out)
	}
	want := []string{
		"GET /.well-known/grc-store-configuration",
		"GET /v2/token",
		"POST /v1/bundles/sync",
		`sync-body {"repository":"acme/my-log","tag":"1.0.0-run1"}`,
	}
	if strings.Join(*calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("hub calls:\n%s\nwant:\n%s", strings.Join(*calls, "\n"), strings.Join(want, "\n"))
	}
	if len(*opened) != 1 || (*opened)[0].Token == "" || (*opened)[0].Host != "registry.test" || (*opened)[0].PlainHTTP != true {
		t.Errorf("registry opened with %+v; the minted token must reach the repo client directly", *opened)
	}
	if d, err := store.Resolve(context.Background(), "1.0.0-run1"); err != nil || d.Digest != out.Manifest.Digest {
		t.Errorf("bundle not tagged in the registry: %v %v", d, err)
	}
}

func TestPublish_PullOnlyStopsBeforeAnyBytes(t *testing.T) {
	srv, calls := fakeHub(t, []string{"pull"})
	_, opened := swapRepository(t)

	_, err := Publish(context.Background(), testInput, Target{HubURL: srv.URL, Repository: "acme/my-log", Tag: "v", Bearer: "hub-bearer"}, nil)
	if !errors.Is(err, ErrPushDenied) || !strings.Contains(err.Error(), `namespace "acme"`) {
		t.Fatalf("err = %v", err)
	}
	if len(*opened) != 0 {
		t.Error("registry must not be opened when push is denied")
	}
	for _, c := range *calls {
		if strings.Contains(c, "sync") {
			t.Error("sync must not be called after a denied push")
		}
	}
}

func TestPublish_ExplicitRegistryTokenSkipsMint(t *testing.T) {
	srv, calls := fakeHub(t, nil)
	_, opened := swapRepository(t)
	if _, err := Publish(context.Background(), testInput, Target{HubURL: srv.URL, Repository: "acme/my-log", Tag: "v", Bearer: "hub-bearer", RegistryToken: "manual"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range *calls {
		if strings.Contains(c, "/v2/token") {
			t.Error("explicit RegistryToken must skip the mint")
		}
	}
	if (*opened)[0].Token != "manual" {
		t.Errorf("token = %q", (*opened)[0].Token)
	}
}

func unpackLocal(ctx context.Context, dir, tag string) (*gbundle.Bundle, error) {
	store, err := oci.New(dir)
	if err != nil {
		return nil, err
	}
	return gbundle.Unpack(ctx, store, tag)
}
