// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"context"
	"errors"
	"fmt"

	"github.com/revanite-io/grc-store-protocol/mediatype"
	"github.com/revanite-io/grc-store-protocol/syncapi"

	"github.com/gemaraproj/grc-store-clientkit/hub"
	"github.com/gemaraproj/grc-store-clientkit/keyless"
	"github.com/gemaraproj/grc-store-clientkit/provenance"
)

// ErrPushDenied is returned before any bytes move when the hub minted a
// pull-only registry token: the bearer's principal does not own the
// repository's namespace.
var ErrPushDenied = errors.New("registry token does not grant push")

// Target is where Publish sends the bundle. Bearer is the hub bearer the
// caller resolved (auth.Resolve, or hub.CIBearer in CI). Tag must equal the
// artifact's metadata.version — the hub enforces equality at sync — so the
// caller stamps the body before packing. RegistryToken, when set, skips the
// mint (a manual credential override); otherwise Publish mints one.
type Target struct {
	HubURL        string
	Repository    string // <namespace>/<id>
	Tag           string
	Bearer        string
	RegistryToken string
}

// Published is Result plus what the hub indexed.
type Published struct {
	Result
	Sync     *syncapi.Response
	Signed   bool
	Attested bool // signed provenance referrer attached
}

// Publish runs the shared sequence, fail-closed at each preflight:
//
//  1. discover the hub (registry host, plain-HTTP);
//  2. mint a pull+push registry token and stop on ErrPushDenied — before
//     packing, so a non-owner never leaves orphaned bytes;
//  3. pack + push + tag the bundle;
//  4. signer != nil: sign the manifest digest (DSSE in-toto) and attach it as
//     a mediatype.SigstoreBundle referrer;
//  5. signer != nil && in.Provenance != nil: sign the SLSA predicate over the
//     same subject and attach it as a ProvenanceArtifactType referrer;
//  6. POST /v1/bundles/sync.
//
// A nil signer publishes unsigned; the hub rejects that at sync for
// verified types, which is the intended backstop. The signer's identity is
// the Fulcio one (keyless.Identity), never t.Bearer.
func Publish(ctx context.Context, in Input, t Target, signer *keyless.Signer) (*Published, error) {
	disco, err := hub.Discover(ctx, t.HubURL)
	if err != nil {
		return nil, err
	}
	host, plainHTTP, err := hub.Registry(disco)
	if err != nil {
		return nil, err
	}
	client := hub.New(t.HubURL, t.Bearer)

	reg := Registry{Host: host, PlainHTTP: plainHTTP, Token: t.RegistryToken}
	if reg.Token == "" {
		tok, err := client.RegistryToken(ctx, t.Repository, []string{"pull", "push"})
		if err != nil {
			return nil, fmt.Errorf("minting registry token: %w", err)
		}
		if !tok.GrantsPush() {
			return nil, fmt.Errorf("%w to %s: the bearer's principal must own namespace %q", ErrPushDenied, t.Repository, namespaceOf(t.Repository))
		}
		reg.Token = tok.Token
	}

	res, err := reg.Push(ctx, t.Repository, t.Tag, in)
	if err != nil {
		return nil, err
	}
	out := &Published{Result: *res}

	if signer != nil {
		sig, err := signer.Sign(ctx, res.ManifestDigest, "", nil)
		if err != nil {
			return nil, fmt.Errorf("signing %s: %w", res.Reference, err)
		}
		if err := reg.Attach(ctx, t.Repository, res.Manifest, mediatype.SigstoreBundle, sig); err != nil {
			return nil, err
		}
		out.Signed = true
		if in.Provenance != nil {
			att, err := signer.Sign(ctx, res.ManifestDigest, provenance.PredicateType, in.Provenance)
			if err != nil {
				return nil, fmt.Errorf("signing provenance for %s: %w", res.Reference, err)
			}
			if err := reg.Attach(ctx, t.Repository, res.Manifest, ProvenanceArtifactType, att); err != nil {
				return nil, err
			}
			out.Attested = true
		}
	}

	out.Sync, err = client.SyncBundle(ctx, t.Repository, t.Tag)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func namespaceOf(repository string) string {
	for i := 0; i < len(repository); i++ {
		if repository[i] == '/' {
			return repository[:i]
		}
	}
	return repository
}
