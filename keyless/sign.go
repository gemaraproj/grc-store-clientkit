// SPDX-License-Identifier: Apache-2.0

package keyless

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	sgsign "github.com/sigstore/sigstore-go/pkg/sign"
)

const (
	// StatementType is the in-toto Statement v1 type.
	StatementType = "https://in-toto.io/Statement/v1"
	// SignPredicateType is cosign's empty predicate for a plain signature;
	// the default when Sign is called with no predicateType.
	SignPredicateType = "https://sigstore.dev/cosign/sign/v1"
	// PayloadType is the DSSE payloadType sigstore-go's verifier requires on
	// the envelope branch — "DSSE" for grc.store means in-toto DSSE.
	PayloadType = "application/vnd.in-toto+json"

	// FulcioURLEnv / RekorURLEnv override the public-good endpoints for a
	// private Sigstore deployment. Read only when Signer's fields are empty.
	FulcioURLEnv = "GRC_STORE_FULCIO_URL"
	RekorURLEnv  = "GRC_STORE_REKOR_URL"

	defaultFulcioURL = "https://fulcio.sigstore.dev"
	defaultRekorURL  = "https://rekor.sigstore.dev"
)

// Signer holds the resolved identity and the Sigstore endpoints. Empty URLs
// fall back to the GRC_STORE_* env overrides, then the public-good instances.
type Signer struct {
	IDToken   string
	FulcioURL string
	RekorURL  string
}

// Statement builds the DSSE payload: an in-toto Statement v1 whose lone
// subject carries subjectDigest (sha256, with or without the prefix). A nil
// predicate marshals as {} — not null — so a plain signature is byte-shaped
// like cosign's. Exported so a consumer's sign→verify round-trip test can
// prove the exact payload this signer emits verifies.
func Statement(subjectDigest, predicateType string, predicate any) ([]byte, error) {
	hexDigest := strings.TrimPrefix(subjectDigest, "sha256:")
	if raw, err := hex.DecodeString(hexDigest); err != nil || len(raw) != sha256.Size {
		return nil, fmt.Errorf("expected a sha256 digest, got %q", subjectDigest)
	}
	if predicateType == "" {
		predicateType = SignPredicateType
	}
	if predicate == nil {
		predicate = map[string]any{}
	}
	return json.Marshal(map[string]any{
		"_type": StatementType,
		"subject": []map[string]any{{
			"digest":      map[string]string{"sha256": hexDigest},
			"annotations": map[string]any{},
		}},
		"predicateType": predicateType,
		"predicate":     predicate,
	})
}

// Sign produces a Sigstore v0.3 bundle (JSON) over Statement(subjectDigest,
// predicateType, predicate): ephemeral key, Fulcio certificate from the
// IDToken, Rekor entry. No cosign on PATH. A plain signature passes "" and
// nil; the provenance referrer passes the SLSA type and predicate.
func (s Signer) Sign(ctx context.Context, subjectDigest, predicateType string, predicate any) ([]byte, error) {
	if s.IDToken == "" {
		return nil, fmt.Errorf("a signing OIDC ID token is required (Fulcio identity; distinct from the hub bearer)")
	}
	stmt, err := Statement(subjectDigest, predicateType, predicate)
	if err != nil {
		return nil, err
	}
	keypair, err := sgsign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral keypair: %w", err)
	}
	fulcio := firstNonEmpty(s.FulcioURL, os.Getenv(FulcioURLEnv), defaultFulcioURL)
	rekor := firstNonEmpty(s.RekorURL, os.Getenv(RekorURLEnv), defaultRekorURL)
	opts := sgsign.BundleOptions{
		Context:                    ctx,
		CertificateProvider:        sgsign.NewFulcio(&sgsign.FulcioOptions{BaseURL: fulcio, Timeout: 30 * time.Second, Retries: 2}),
		CertificateProviderOptions: &sgsign.CertificateProviderOptions{IDToken: s.IDToken},
		TransparencyLogs:           []sgsign.Transparency{sgsign.NewRekor(&sgsign.RekorOptions{BaseURL: rekor, Timeout: 60 * time.Second, Retries: 2})},
	}
	pb, err := sgsign.Bundle(&sgsign.DSSEData{Data: stmt, PayloadType: PayloadType}, keypair, opts)
	if err != nil {
		return nil, fmt.Errorf("sigstore keyless sign against %s: %w", fulcio, err)
	}
	b, err := sgbundle.NewBundle(pb)
	if err != nil {
		return nil, fmt.Errorf("assembling signature bundle: %w", err)
	}
	out, err := b.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("serializing signature bundle: %w", err)
	}
	return out, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
