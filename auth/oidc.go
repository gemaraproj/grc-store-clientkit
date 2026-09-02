// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpTimeout caps every outbound call in this file. The device-authorization
// and token endpoints answer well under a second in normal operation; 10s
// absorbs a slow tunnel without letting a wedged IdP hang a CLI session. It is
// per-request, not per-poll-cycle: PollForToken paces itself with the device
// grant's own interval.
const httpTimeout = 10 * time.Second

// maxResponseBytes caps what we will read from an auth-server response. These
// are small JSON documents; anything larger is a misconfiguration or a hostile
// endpoint, and neither deserves unbounded buffering.
const maxResponseBytes = 256 << 10

// User-facing sentinel errors from the device flow. Their text carries no tool
// name — the caller wraps them with App.LoginHint so one package can serve both
// CLIs without telling a pvtr user to run grcli.
var (
	ErrAccessDenied      = errors.New("authorization denied by the user")
	ErrExpiredDeviceCode = errors.New("device code expired before authorization completed")
)

// OIDCMetadata is the subset of the OpenID Connect Discovery 1.0 document the
// device grant consumes, fetched from <issuer>/.well-known/openid-configuration
// — the OIDC standard path, not the hub's separate grc-store-configuration doc.
type OIDCMetadata struct {
	Issuer                      string `json:"issuer"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
}

// FetchOIDCMetadata loads the discovery document for issuerURL and returns the
// endpoints the flow needs. issuerURL is the canonical issuer (e.g.
// https://auth.grc.store/realms/gemara) — the oidc_issuer the hub advertises in
// its discovery doc — and NOT the hub URL. Errors name the URL that was actually
// fetched, so the user can tell whether to blame the hub's discovery doc or the
// auth server behind it.
func FetchOIDCMetadata(ctx context.Context, issuerURL string) (*OIDCMetadata, error) {
	issuerURL = canonicalIssuer(issuerURL)
	if issuerURL == "" {
		return nil, errors.New("OIDC issuer URL is required (the hub discovery doc did not advertise oidc_issuer)")
	}
	discoveryURL := issuerURL + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building OIDC discovery request for %s: %w", discoveryURL, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", discoveryURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery at %s returned %d: %s", discoveryURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	m := &OIDCMetadata{}
	if err := json.Unmarshal(body, m); err != nil {
		return nil, fmt.Errorf("decoding OIDC discovery at %s: %w", discoveryURL, err)
	}
	if m.DeviceAuthorizationEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery at %s did not advertise device_authorization_endpoint; the auth server is not configured for the device grant", discoveryURL)
	}
	if m.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery at %s did not advertise token_endpoint", discoveryURL)
	}
	if m.Issuer == "" {
		// Mirror the URL we used as the canonical store key; some IdPs omit the
		// field. It is already trailing-slash-trimmed.
		m.Issuer = issuerURL
	}
	return m, nil
}

// DeviceAuthorization is RFC 8628 §3.2's device authorization response.
type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// StartDeviceFlow calls the device_authorization_endpoint. The caller displays
// user_code and verification_uri, then hands the result to PollForToken.
func StartDeviceFlow(ctx context.Context, meta *OIDCMetadata, clientID string) (*DeviceAuthorization, error) {
	if clientID == "" {
		return nil, errors.New("an OIDC client_id is required (the hub discovery doc did not advertise oidc_cli_client_id)")
	}
	form := url.Values{}
	form.Set("client_id", clientID)
	// Standard OIDC scopes, explicitly WITHOUT offline_access. Offline tokens
	// need both the client to permit them and the user to hold the
	// offline_access realm role; on a freshly bootstrapped realm the latter is
	// easy to miss, and the device endpoint then refuses the entire flow with
	// "Offline tokens not allowed for the user or client". An interactive CLI
	// does not need them — the SSO-session-bound refresh token issued here
	// covers the realm's idle window, and past that the user logs in again.
	form.Set("scope", "openid profile email")

	resp, body, err := postForm(ctx, meta.DeviceAuthorizationEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("device authorization request: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Decode the standard OIDC error shape so the failures with actionable
		// fixes get named, instead of reflecting a raw body at the user.
		var er struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &er)
		switch er.Error {
		case "invalid_client":
			// Fires when the client_id is unknown, or when it is marked
			// confidential and we (correctly, per the public-client spec for the
			// device grant) sent no secret. Either way the fix is on the auth
			// server; there is no credential the CLI could supply to satisfy it.
			return nil, fmt.Errorf("device authorization rejected: the auth server does not recognize client_id %q as a public device-grant client. The client either does not exist in the realm, is not publicClient=true, or lacks oauth2.device.authorization.grant.enabled=true. Ask whoever runs the auth server to provision it — this is not a credential the CLI can supply", clientID)
		case "unauthorized_client":
			return nil, fmt.Errorf("device authorization rejected: client_id %q exists but is not allowed to use the device grant. Enable oauth2.device.authorization.grant.enabled=true on the client", clientID)
		}
		return nil, fmt.Errorf("device_authorization_endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	d := &DeviceAuthorization{}
	if err := json.Unmarshal(body, d); err != nil {
		return nil, fmt.Errorf("decoding device authorization response: %w (body: %s)", err, strings.TrimSpace(string(body)))
	}
	if d.DeviceCode == "" || d.UserCode == "" || d.VerificationURI == "" {
		return nil, fmt.Errorf("device authorization response missing required fields: %s", strings.TrimSpace(string(body)))
	}
	if d.Interval <= 0 {
		d.Interval = 5 // RFC 8628 §3.2 default
	}
	return d, nil
}

// tokenResponse is the token endpoint's JSON. Success and error share the shape;
// on an error Error is populated and the token fields are zero.
type tokenResponse struct {
	AccessToken      string `json:"access_token,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	IDToken          string `json:"id_token,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// PollForToken blocks polling the token endpoint until the device flow
// terminates, returning the issued Credentials. It honors slow_down (RFC 8628
// §3.5) by widening the interval, and bounds the whole loop by the device
// authorization's own expires_in so a server that answers authorization_pending
// forever cannot pin the CLI in an endless poll.
func PollForToken(ctx context.Context, meta *OIDCMetadata, clientID string, da *DeviceAuthorization) (*Credentials, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", da.DeviceCode)

	expiresIn := da.ExpiresIn
	if expiresIn <= 0 {
		// Servers SHOULD send expires_in; bound the loop regardless.
		expiresIn = 1800
	}
	deadline := time.Now().Add(time.Duration(expiresIn) * time.Second)

	interval := time.Duration(da.Interval) * time.Second
	for {
		if time.Now().After(deadline) {
			return nil, ErrExpiredDeviceCode
		}
		// Wait first: the spec expects the user to have entered the code before
		// the first poll, and many servers answer slow_down if you jump the gun.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		resp, body, err := postForm(ctx, meta.TokenEndpoint, form)
		if err != nil {
			return nil, fmt.Errorf("polling token endpoint: %w", err)
		}
		// 200 carries a token, 400 carries a protocol error (pending, slow_down,
		// denied). Anything else is the server malfunctioning, and decoding its
		// body as a token response would misreport that as a protocol state.
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest {
			return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		tr := tokenResponse{}
		if err := json.Unmarshal(body, &tr); err != nil {
			return nil, fmt.Errorf("decoding token response (HTTP %d): %w (body: %s)", resp.StatusCode, err, strings.TrimSpace(string(body)))
		}
		switch tr.Error {
		case "":
			if tr.AccessToken == "" {
				return nil, fmt.Errorf("token endpoint returned no access_token and no error: %s", strings.TrimSpace(string(body)))
			}
			return credsFromTokenResponse(meta.Issuer, &tr), nil
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "access_denied":
			return nil, ErrAccessDenied
		case "expired_token":
			return nil, ErrExpiredDeviceCode
		default:
			// Surface anything unexpected with the auth server's own description
			// when it provided one; Keycloak does.
			if tr.ErrorDescription != "" {
				return nil, fmt.Errorf("token endpoint error %q: %s", tr.Error, tr.ErrorDescription)
			}
			return nil, fmt.Errorf("token endpoint error %q", tr.Error)
		}
	}
}

// RefreshToken exchanges a refresh_token for a fresh access token. Resolve calls
// it when stored credentials are inside the renewal window.
func RefreshToken(ctx context.Context, meta *OIDCMetadata, clientID, refreshToken string) (*Credentials, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	resp, body, err := postForm(ctx, meta.TokenEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("refresh request: %w", err)
	}
	// Same hazard as PollForToken: 200 carries a token, 400 carries the
	// protocol error (invalid_grant for a revoked or rotated refresh token).
	// Anything else is the server malfunctioning, and its body is not a token
	// response.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	tr := tokenResponse{}
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decoding refresh response (HTTP %d): %w (body: %s)", resp.StatusCode, err, strings.TrimSpace(string(body)))
	}
	if tr.Error != "" {
		if tr.ErrorDescription != "" {
			return nil, fmt.Errorf("refresh failed (%s): %s", tr.Error, tr.ErrorDescription)
		}
		return nil, fmt.Errorf("refresh failed: %s", tr.Error)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("refresh response missing access_token (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return credsFromTokenResponse(meta.Issuer, &tr), nil
}

// postForm posts form to endpoint and returns the response, its (capped) body,
// and any transport error. Every auth-server call in this file has this shape.
func postForm(ctx context.Context, endpoint string, form url.Values) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, fmt.Errorf("building request for %s: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	return resp, body, nil
}

// credsFromTokenResponse converts a token response into a stored record.
//
// The lifetime is floored safely ABOVE RenewalWindow so a token with a missing
// or very short expires_in is not born already-expired — which would make the
// very next Resolve refresh a token just obtained, and fail outright when no
// refresh token came with it. The floor is derived from RenewalWindow so the two
// cannot drift apart: this is exactly the bug that a hardcoded 30s floor sitting
// below a 60s window produced in grcli before the extraction.
func credsFromTokenResponse(issuer string, tr *tokenResponse) *Credentials {
	lifetime := max(time.Duration(tr.ExpiresIn)*time.Second, RenewalWindow+30*time.Second)
	return &Credentials{
		Issuer:       issuer,
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		ExpiresAt:    time.Now().Add(lifetime),
	}
}
