// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInGitHubActions(t *testing.T) {
	cases := []struct {
		name       string
		actions    string
		requestURL string
		requestTok string
		want       bool
	}{
		{"all present", "true", "https://token.example/req", "req-tok", true},
		{"not actions", "false", "https://token.example/req", "req-tok", false},
		{"missing request url", "true", "", "req-tok", false},
		{"missing request token", "true", "https://token.example/req", "", false},
		{"all empty", "", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITHUB_ACTIONS", tc.actions)
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", tc.requestURL)
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", tc.requestTok)
			if got := InGitHubActions(); got != tc.want {
				t.Errorf("InGitHubActions() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFetchGitHubActionsToken(t *testing.T) {
	const wantAud = "https://hub.example"
	const reqTok = "request-secret"

	t.Run("happy path forwards audience and bearer, parses value", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("audience"); got != wantAud {
				t.Errorf("audience query = %q, want %q", got, wantAud)
			}
			if got := r.Header.Get("Authorization"); got != "bearer "+reqTok {
				t.Errorf("Authorization = %q, want bearer %s", got, reqTok)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"value":"the.jwt.token"}`))
		}))
		defer srv.Close()
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", reqTok)

		tok, err := FetchGitHubActionsToken(context.Background(), wantAud)
		if err != nil {
			t.Fatalf("FetchGitHubActionsToken: %v", err)
		}
		if tok != "the.jwt.token" {
			t.Errorf("token = %q, want the.jwt.token", tok)
		}
	})

	t.Run("appends audience with & when request url already has a query", func(t *testing.T) {
		var gotRawQuery string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotRawQuery = r.URL.RawQuery
			_, _ = w.Write([]byte(`{"value":"t"}`))
		}))
		defer srv.Close()
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"/req?foo=bar")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", reqTok)

		if _, err := FetchGitHubActionsToken(context.Background(), wantAud); err != nil {
			t.Fatalf("FetchGitHubActionsToken: %v", err)
		}
		// Both the pre-existing query and the appended audience must survive.
		if !strings.Contains(gotRawQuery, "foo=bar") || !strings.Contains(gotRawQuery, "audience=") {
			t.Errorf("raw query = %q, want it to contain foo=bar and audience=", gotRawQuery)
		}
	})

	t.Run("empty audience errors before any request", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://unused.example")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", reqTok)
		if _, err := FetchGitHubActionsToken(context.Background(), ""); err == nil {
			t.Error("expected error for empty audience")
		}
	})

	t.Run("missing actions env errors", func(t *testing.T) {
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
		if _, err := FetchGitHubActionsToken(context.Background(), wantAud); err == nil {
			t.Error("expected error when not running in GitHub Actions")
		}
	})

	t.Run("non-200 from endpoint errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("nope"))
		}))
		defer srv.Close()
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", reqTok)
		if _, err := FetchGitHubActionsToken(context.Background(), wantAud); err == nil {
			t.Error("expected error on non-200 response")
		}
	})

	t.Run("empty value in response errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"value":""}`))
		}))
		defer srv.Close()
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", reqTok)
		if _, err := FetchGitHubActionsToken(context.Background(), wantAud); err == nil {
			t.Error("expected error when response carries no token value")
		}
	})
}
