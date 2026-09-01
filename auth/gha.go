// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"
)

// ghaTokenTimeout bounds the GitHub Actions token request. It is more generous
// than httpTimeout because the runner's token service is measurably slower than
// an IdP's discovery endpoint, and a spurious timeout here fails a CI publish.
const ghaTokenTimeout = 15 * time.Second

// InGitHubActions reports whether the process is running inside a GitHub Actions
// job with workload OIDC available — the workflow set `permissions: id-token:
// write` and the runtime injected the request URL and token. This is what picks
// the CI publish path (ADR-0032): no stored secret, the workflow's own OIDC
// token IS the credential.
func InGitHubActions() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true" &&
		os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" &&
		os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != ""
}

// FetchGitHubActionsToken requests a workload-OIDC token from the Actions
// runtime for the given audience and returns the raw JWT.
//
// The audience is the caller's argument because the same runner mints tokens for
// two unrelated purposes, and they are not interchangeable:
//
//   - The hub's ci_audience, for trusted publishing. The hub validates the token
//     directly (iss is GitHub's, aud is the hub's) and maps the workflow's
//     repository and ref through its trusted-publisher bindings, so this must
//     match HUB_CI_OIDC_AUDIENCE — the value the hub advertises as ci_audience.
//   - "sigstore", for keyless signing. Public-good Fulcio requires that exact
//     audience and will reject anything else.
//
// A token minted for one is useless for the other, so there is no default here.
func FetchGitHubActionsToken(ctx context.Context, audience string) (string, error) {
	reqURL := strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"))
	reqTok := strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
	if reqURL == "" || reqTok == "" {
		return "", fmt.Errorf("not in GitHub Actions with OIDC available (ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN unset; the workflow needs `permissions: id-token: write`)")
	}
	if audience == "" {
		return "", fmt.Errorf("audience is required for the GitHub Actions OIDC token")
	}
	sep := "?"
	if strings.Contains(reqURL, "?") {
		sep = "&"
	}
	full := reqURL + sep + "audience=" + neturl.QueryEscape(audience)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return "", fmt.Errorf("building GHA OIDC request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+reqTok)
	req.Header.Set("Accept", "application/json; api-version=2.0")

	resp, err := (&http.Client{Timeout: ghaTokenTimeout}).Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching GHA OIDC token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GHA OIDC endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decoding GHA OIDC response: %w", err)
	}
	if out.Value == "" {
		return "", fmt.Errorf("GHA OIDC response had no token value")
	}
	return out.Value, nil
}
