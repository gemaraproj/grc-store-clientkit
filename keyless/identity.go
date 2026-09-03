// SPDX-License-Identifier: Apache-2.0

// Package keyless is the shared Sigstore keyless signer: identity
// resolution against a Fulcio-trusted issuer, and a DSSE in-toto signer
// that produces a Sigstore v0.3 bundle over a subject digest. Extracted from
// privateer-sdk's internal/auth (identity, the superset) and grcli's
// internal/sign/keyless.go (the in-toto DSSE shape).
//
// The identity here is NOT the hub bearer. Fulcio trusts public OIDC
// issuers, not the grc.store auth server, so the two tokens come from
// different issuers with different audiences and must never be conflated.
package keyless

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/gemaraproj/grc-store-clientkit/auth"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

const (
	// IDTokenEnv is the explicit-token override: an OIDC token from any
	// Fulcio-trusted issuer (GitLab CI id_tokens, a workload identity).
	IDTokenEnv = "SIGSTORE_ID_TOKEN"
	// PublicGoodAudience is the audience public-good Fulcio requires.
	PublicGoodAudience = "sigstore"

	sigstoreOIDCIssuer = "https://oauth2.sigstore.dev/auth"
	sigstoreClientID   = "sigstore"
)

// Identity resolves the signing OIDC token: SIGSTORE_ID_TOKEN (validated to
// carry audience) > GitHub Actions workflow token minted for audience >
// interactive browser sign-in against the public-good Sigstore issuer.
// Callers pass PublicGoodAudience for public-good Fulcio; the audience is a
// parameter so it can never silently default to the hub's. promptOut, when
// non-nil, receives the interactive-flow instructions. When stdin is not a
// terminal the interactive path fails fast instead of hanging.
func Identity(ctx context.Context, audience string, promptOut io.Writer) (string, error) {
	if audience == "" {
		return "", fmt.Errorf("signing audience is required")
	}
	if raw := strings.TrimSpace(os.Getenv(IDTokenEnv)); raw != "" {
		auds, err := jwtAudiences(raw)
		if err != nil {
			return "", fmt.Errorf("%s is not a valid JWT: %w", IDTokenEnv, err)
		}
		if !slices.Contains(auds, audience) {
			return "", fmt.Errorf("%s has audience %q, but Fulcio requires %q — mint the OIDC token with aud=%q", IDTokenEnv, auds, audience, audience)
		}
		return raw, nil
	}
	if auth.InGitHubActions() {
		return auth.FetchGitHubActionsToken(ctx, audience)
	}
	if !stdinIsTerminal() {
		return "", fmt.Errorf("no Sigstore signing identity available and stdin is not a terminal: set %s to an OIDC token with audience %q (e.g. GitLab CI id_tokens), or run in GitHub Actions where it is detected automatically", IDTokenEnv, audience)
	}
	if promptOut != nil {
		_, _ = io.WriteString(promptOut, "Signing requires a public-good Sigstore identity (separate from your hub login).\nA browser window will open to sign in...\n")
	}
	tok, err := oauthflow.OIDConnect(sigstoreOIDCIssuer, sigstoreClientID, "", "", oauthflow.DefaultIDTokenGetter)
	if err != nil {
		return "", fmt.Errorf("interactive sigstore sign-in: %w", err)
	}
	if tok == nil || tok.RawString == "" {
		return "", fmt.Errorf("sigstore sign-in returned no token")
	}
	return tok.RawString, nil
}

var stdinIsTerminal = func() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// jwtAudiences reads (does not verify) the aud claim. Absent or null aud
// yields nil, which the caller treats as a mismatch.
func jwtAudiences(raw string) ([]string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 dot-separated segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload segment: %w", err)
	}
	var claims struct {
		Aud json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}
	if len(claims.Aud) == 0 || string(claims.Aud) == "null" {
		return nil, nil
	}
	var single string
	if err := json.Unmarshal(claims.Aud, &single); err == nil {
		return []string{single}, nil
	}
	var many []string
	if err := json.Unmarshal(claims.Aud, &many); err == nil {
		return many, nil
	}
	return nil, fmt.Errorf(`"aud" claim is neither a string nor an array of strings`)
}
