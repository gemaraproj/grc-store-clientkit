// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestDeviceFlow_HappyPath drives a full device-grant cycle against an httptest
// server: discovery, device authorization, two authorization_pending replies,
// then success. The response shapes mirror real Keycloak, so this catches drift
// between the polling logic and what an auth server actually emits.
func TestDeviceFlow_HappyPath(t *testing.T) {
	var tokenCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		issuer := "http://" + r.Host
		fmt.Fprintf(w, `{
		  "issuer": %q,
		  "device_authorization_endpoint": "%s/device-auth",
		  "token_endpoint": "%s/token"
		}`, issuer, issuer, issuer)
	})
	mux.HandleFunc("/device-auth", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{
		  "device_code": "DEV-1",
		  "user_code": "ABCD-EFGH",
		  "verification_uri": "https://auth.example/device",
		  "verification_uri_complete": "https://auth.example/device?user_code=ABCD-EFGH",
		  "expires_in": 300,
		  "interval": 0
		}`)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		switch tokenCalls.Add(1) {
		case 1, 2:
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"authorization_pending","error_description":"keep polling"}`)
		default:
			fmt.Fprint(w, `{
			  "access_token": "real-access",
			  "refresh_token": "real-refresh",
			  "token_type": "Bearer",
			  "expires_in": 900
			}`)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx := context.Background()
	meta, err := FetchOIDCMetadata(ctx, srv.URL)
	if err != nil {
		t.Fatalf("FetchOIDCMetadata: %v", err)
	}
	if meta.DeviceAuthorizationEndpoint != srv.URL+"/device-auth" || meta.TokenEndpoint != srv.URL+"/token" {
		t.Fatalf("endpoints = %+v, want the advertised pair", meta)
	}

	da, err := StartDeviceFlow(ctx, meta, "test-client")
	if err != nil {
		t.Fatalf("StartDeviceFlow: %v", err)
	}
	if da.UserCode != "ABCD-EFGH" {
		t.Errorf("UserCode = %q, want ABCD-EFGH", da.UserCode)
	}
	// interval=0 in the response defaults to RFC 8628's 5s. That is correct and
	// far too slow for a test, so shorten it before polling.
	if da.Interval != 5 {
		t.Errorf("Interval = %d, want the RFC 8628 default of 5 when the server sends 0", da.Interval)
	}
	da.Interval = 1

	creds, err := PollForToken(ctx, meta, "test-client", da)
	if err != nil {
		t.Fatalf("PollForToken: %v", err)
	}
	if creds.AccessToken != "real-access" || creds.RefreshToken != "real-refresh" {
		t.Errorf("credentials = %+v, want the issued pair", creds)
	}
	// The store keys on this, so it must match the metadata issuer exactly.
	if creds.Issuer != srv.URL {
		t.Errorf("Issuer = %q, want %q so the store keys correctly", creds.Issuer, srv.URL)
	}
	if got := tokenCalls.Load(); got < 3 {
		t.Errorf("token endpoint called %d times, want >= 3 (past both pending replies)", got)
	}
}

func TestDeviceFlow_AccessDeniedIsSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"access_denied","error_description":"the user said no"}`)
	}))
	defer srv.Close()

	// Callers branch on the sentinel: "the user declined" is a different
	// recovery from "the auth server is broken".
	_, err := PollForToken(context.Background(),
		&OIDCMetadata{TokenEndpoint: srv.URL},
		"test-client",
		&DeviceAuthorization{DeviceCode: "DEV-1", Interval: 1},
	)
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("PollForToken = %v, want ErrAccessDenied", err)
	}
}

func TestDeviceFlow_ExpiredTokenIsSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"expired_token","error_description":"user waited too long"}`)
	}))
	defer srv.Close()

	_, err := PollForToken(context.Background(),
		&OIDCMetadata{TokenEndpoint: srv.URL},
		"test-client",
		&DeviceAuthorization{DeviceCode: "DEV-1", Interval: 1},
	)
	if !errors.Is(err, ErrExpiredDeviceCode) {
		t.Errorf("PollForToken = %v, want ErrExpiredDeviceCode", err)
	}
}

// A server that answers authorization_pending forever must not pin the CLI in
// an endless poll: the loop is bounded by the device authorization's own
// expires_in. (grcli's copy had no such bound before the extraction.)
func TestPollForToken_BoundedByExpiresIn(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"authorization_pending"}`)
	}))
	defer srv.Close()

	start := time.Now()
	_, err := PollForToken(context.Background(),
		&OIDCMetadata{TokenEndpoint: srv.URL},
		"test-client",
		&DeviceAuthorization{DeviceCode: "DEV-1", Interval: 1, ExpiresIn: 2},
	)
	if !errors.Is(err, ErrExpiredDeviceCode) {
		t.Fatalf("PollForToken = %v, want ErrExpiredDeviceCode once expires_in elapsed", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("poll ran %s past a 2s expires_in; the deadline is not bounding the loop", elapsed)
	}
}

// A malfunctioning server (500, an HTML error page) must not have its body
// decoded as a token response — that would report a transport failure as a
// protocol state and hide the real problem.
func TestPollForToken_UnexpectedStatusIsNotAProtocolState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, "<html>upstream is down</html>")
	}))
	defer srv.Close()

	_, err := PollForToken(context.Background(),
		&OIDCMetadata{TokenEndpoint: srv.URL},
		"test-client",
		&DeviceAuthorization{DeviceCode: "DEV-1", Interval: 1},
	)
	if err == nil {
		t.Fatal("PollForToken = nil error on a 502, want a failure")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error should surface the status, got: %v", err)
	}
}

// Guards the "raw {invalid_client} body" UX failure: when the auth server
// rejects the client, the error must steer the user at the provisioning step,
// not reflect an OIDC error code at them. Otherwise people go hunting for a
// username and password that do not exist for a device-grant public client.
func TestStartDeviceFlow_InvalidClientPointsAtAuthServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_client","error_description":"Invalid client or Invalid client credentials"}`)
	}))
	defer srv.Close()

	_, err := StartDeviceFlow(context.Background(),
		&OIDCMetadata{DeviceAuthorizationEndpoint: srv.URL, TokenEndpoint: srv.URL + "/token"},
		"grcli",
	)
	if err == nil {
		t.Fatal("StartDeviceFlow = nil error on invalid_client, want a failure")
	}
	for _, want := range []string{"grcli", "publicClient=true", "not a credential the CLI can supply"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q, got: %v", want, err)
		}
	}
}

func TestStartDeviceFlow_RequiresClientID(t *testing.T) {
	// Empty means the hub's discovery doc carried no oidc_cli_client_id; say so
	// rather than sending an empty client_id and decoding whatever comes back.
	_, err := StartDeviceFlow(context.Background(), &OIDCMetadata{DeviceAuthorizationEndpoint: "http://unused.example"}, "")
	if err == nil || !strings.Contains(err.Error(), "oidc_cli_client_id") {
		t.Errorf("StartDeviceFlow with no client_id = %v, want an error naming oidc_cli_client_id", err)
	}
}

func TestFetchOIDCMetadata_RejectsMissingEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		// An auth server without the device grant: token endpoint present,
		// device endpoint absent. Refuse here rather than taking a generic 404
		// from the next call.
		fmt.Fprint(w, `{"issuer":"http://x","token_endpoint":"http://x/token"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := FetchOIDCMetadata(context.Background(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "device_authorization_endpoint") {
		t.Errorf("FetchOIDCMetadata = %v, want an error naming device_authorization_endpoint", err)
	}
}

// A freshly issued token must never already sit inside the renewal window.
// Otherwise the next Resolve refreshes a token it just obtained — and fails
// outright when the response carried no refresh token. This is the regression a
// hardcoded 30s floor under a 60s window produced in grcli before the split.
func TestFreshTokenIsNotBornExpired(t *testing.T) {
	for _, expiresIn := range []int{0, 1, 30, 59, 60} {
		creds := credsFromTokenResponse("https://auth.example", &tokenResponse{AccessToken: "at", ExpiresIn: expiresIn})
		if creds.ExpiredAt(time.Now()) {
			t.Errorf("token with expires_in=%d is born expired (ExpiresAt %s)", expiresIn, creds.ExpiresAt)
		}
	}
}

// RefreshToken shares PollForToken's hazard: a malfunctioning server's body
// must not be decoded as a token response. Its pre-extraction copy in
// privateer-sdk had this check; the merge dropped it.
func TestRefreshToken_UnexpectedStatusIsNotAProtocolState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, "<html>upstream is down</html>")
	}))
	defer srv.Close()

	_, err := RefreshToken(context.Background(), &OIDCMetadata{TokenEndpoint: srv.URL}, "test-client", "refresh-1")
	if err == nil {
		t.Fatal("RefreshToken = nil error on a 502, want a failure")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error should surface the status, got: %v", err)
	}
}

func TestRefreshToken_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := r.Form.Get("grant_type"); got != "refresh_token" {
			t.Errorf("grant_type = %q, want refresh_token", got)
		}
		if got := r.Form.Get("refresh_token"); got != "refresh-1" {
			t.Errorf("refresh_token = %q, want refresh-1", got)
		}
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "fresh", RefreshToken: "refresh-2", ExpiresIn: 300})
	}))
	defer srv.Close()

	creds, err := RefreshToken(context.Background(), &OIDCMetadata{Issuer: "https://auth.example/realms/t", TokenEndpoint: srv.URL}, "test-client", "refresh-1")
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessToken != "fresh" || creds.RefreshToken != "refresh-2" || creds.Issuer != "https://auth.example/realms/t" {
		t.Errorf("creds = %+v", creds)
	}
}

// A 200 that fails to decode must not echo the body: it is a token response, so
// the body holds the credential the caller was trying to obtain. The 400 case
// keeps its body, which is where the protocol error lives.
func TestTokenBodyIsRedactedOnlyWhenItCouldHoldACredential(t *testing.T) {
	// expires_in as a JSON string fails json.Unmarshal into an int field, which
	// is how a well-formed-looking 200 reaches the decode-error path at all.
	const leaky = `{"access_token":"super-secret","refresh_token":"also-secret","expires_in":"3600"}`

	t.Run("200 body redacted", func(t *testing.T) {
		srv := tokenEndpoint(t, http.StatusOK, leaky)
		defer srv.Close()
		meta := &OIDCMetadata{Issuer: srv.URL, TokenEndpoint: srv.URL + "/token"}

		_, err := RefreshToken(context.Background(), meta, "cid", "rt")
		if err == nil {
			t.Fatal("expected a decode error")
		}
		if strings.Contains(err.Error(), "super-secret") || strings.Contains(err.Error(), "also-secret") {
			t.Errorf("error leaked credential material: %v", err)
		}
		if !strings.Contains(err.Error(), "redacted") {
			t.Errorf("error should say the body was redacted, got: %v", err)
		}
	})

	t.Run("400 body preserved", func(t *testing.T) {
		srv := tokenEndpoint(t, http.StatusBadRequest, `{"error":]`)
		defer srv.Close()
		meta := &OIDCMetadata{Issuer: srv.URL, TokenEndpoint: srv.URL + "/token"}

		_, err := RefreshToken(context.Background(), meta, "cid", "rt")
		if err == nil {
			t.Fatal("expected a decode error")
		}
		if !strings.Contains(err.Error(), `{"error":]`) {
			t.Errorf("a 400 body carries the protocol error and should be shown, got: %v", err)
		}
	})
}

func tokenEndpoint(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}))
}
