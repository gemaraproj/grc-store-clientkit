// SPDX-License-Identifier: Apache-2.0

package hub

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
	"sync/atomic"
	"testing"

	"github.com/revanite-io/grc-store-protocol/discovery"
	"github.com/revanite-io/grc-store-protocol/syncapi"
)

func TestDiscover(t *testing.T) {
	serve := func(t *testing.T, status int, body string, hits *int32) *httptest.Server {
		t.Helper()
		resetDiscoveryCacheForTest()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != WellKnownPath {
				t.Errorf("path = %q, want %s", r.URL.Path, WellKnownPath)
			}
			if hits != nil {
				atomic.AddInt32(hits, 1)
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	t.Run("happy path decodes the shared document", func(t *testing.T) {
		srv := serve(t, 200, `{"registry_url":"https://r","hub_url":"https://h","api_version":"v1","oidc_issuer":"https://i","oidc_cli_client_id":"cli","ci_audience":"https://h/ci"}`, nil)
		d, err := Discover(context.Background(), srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if d.RegistryURL != "https://r" || d.HubURL != "https://h" || d.APIVersion != "v1" || d.OIDCIssuer != "https://i" || d.OIDCCLIClientID != "cli" || d.CIAudience != "https://h/ci" {
			t.Errorf("decoded = %+v", d)
		}
	})
	t.Run("cache serves repeat and trailing-slash calls", func(t *testing.T) {
		var hits int32
		srv := serve(t, 200, `{"registry_url":"https://r"}`, &hits)
		for _, u := range []string{srv.URL, srv.URL, srv.URL + "/"} {
			if _, err := Discover(context.Background(), u); err != nil {
				t.Fatal(err)
			}
		}
		if hits != 1 {
			t.Errorf("HTTP hits = %d, want 1", hits)
		}
	})
	t.Run("missing registry_url fails closed and names the URL", func(t *testing.T) {
		srv := serve(t, 200, `{"hub_url":"https://h"}`, nil)
		_, err := Discover(context.Background(), srv.URL)
		if err == nil || !strings.Contains(err.Error(), "registry_url") || !strings.Contains(err.Error(), srv.URL) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("malformed JSON and non-200 surface the URL and status", func(t *testing.T) {
		srv := serve(t, 200, `not json {{{`, nil)
		if _, err := Discover(context.Background(), srv.URL); err == nil || !strings.Contains(err.Error(), srv.URL) {
			t.Errorf("malformed: err = %v", err)
		}
		srv = serve(t, 500, `{"error":"registry_url_unconfigured"}`, nil)
		if _, err := Discover(context.Background(), srv.URL); err == nil || !strings.Contains(err.Error(), "500") {
			t.Errorf("500: err = %v", err)
		}
	})
	t.Run("empty base URL fails before the network", func(t *testing.T) {
		if _, err := Discover(context.Background(), ""); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestRegistry(t *testing.T) {
	cases := []struct {
		in        string
		host      string
		plainHTTP bool
		wantErr   bool
	}{
		{"https://oci.grc.store", "oci.grc.store", false, false},
		{"http://localhost:5050", "localhost:5050", true, false},
		{"http://localhost:5050/", "localhost:5050", true, false},
		{"https://oci.grc.store:443", "oci.grc.store:443", false, false},
		{"oci.grc.store", "oci.grc.store", false, false},
		{"localhost:5050/", "localhost:5050", false, false},
		{"  http://localhost:5050  ", "localhost:5050", true, false},
		{"", "", false, true},
		{"http://", "", false, true},
	}
	for _, tc := range cases {
		host, plain, err := Registry(&discovery.Document{RegistryURL: tc.in})
		if (err != nil) != tc.wantErr {
			t.Errorf("Registry(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if host != tc.host || plain != tc.plainHTTP {
			t.Errorf("Registry(%q) = (%q, %v), want (%q, %v)", tc.in, host, plain, tc.host, tc.plainHTTP)
		}
	}
}

func ghaEnv(t *testing.T, srvURL string) {
	t.Helper()
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srvURL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")
}

func TestCIBearer(t *testing.T) {
	t.Run("outside GitHub Actions reports ok=false", func(t *testing.T) {
		t.Setenv("GITHUB_ACTIONS", "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
		tok, ok, err := CIBearer(context.Background(), "https://hub", nil)
		if tok != "" || ok || err != nil {
			t.Errorf("got (%q, %v, %v)", tok, ok, err)
		}
	})
	t.Run("uses ci_audience from discovery, falling back to the hub URL", func(t *testing.T) {
		var gotAud string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAud = r.URL.Query().Get("audience")
			_ = json.NewEncoder(w).Encode(map[string]string{"value": "gha-jwt"})
		}))
		defer srv.Close()
		ghaEnv(t, srv.URL)

		tok, ok, err := CIBearer(context.Background(), "https://hub/", &discovery.Document{CIAudience: "https://hub/ci"})
		if err != nil || !ok || tok != "gha-jwt" || gotAud != "https://hub/ci" {
			t.Errorf("with ci_audience: got (%q, %v, %v), aud %q", tok, ok, err, gotAud)
		}
		_, _, _ = CIBearer(context.Background(), "https://hub/", &discovery.Document{})
		if gotAud != "https://hub" {
			t.Errorf("fallback audience = %q, want the trimmed hub URL", gotAud)
		}
	})
	t.Run("token-service failure is an error with ok=true", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
		defer srv.Close()
		ghaEnv(t, srv.URL)
		_, ok, err := CIBearer(context.Background(), "https://hub", nil)
		if !ok || err == nil {
			t.Errorf("got ok=%v err=%v; the caller must be able to tell 'not in CI' from 'CI token failed'", ok, err)
		}
	})
}

func TestVersionExists(t *testing.T) {
	for status, want := range map[int]VersionStatus{200: VersionPresent, 404: VersionAbsent, 410: VersionTombstoned} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/catalogs/ns/id/versions/v1" {
				t.Errorf("path = %q", r.URL.Path)
			}
			w.WriteHeader(status)
		}))
		got, err := New(srv.URL, "").VersionExists(context.Background(), "ns", "id", "v1")
		srv.Close()
		if err != nil || got != want {
			t.Errorf("status %d: got (%v, %v), want %v", status, got, err, want)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte("upstream timeout from zot"))
	}))
	defer srv.Close()
	got, err := New(srv.URL, "").VersionExists(context.Background(), "ns", "id", "v1")
	if err == nil || got != VersionAbsent {
		t.Fatalf("500: got (%v, %v); must not flip to VersionPresent", got, err)
	}
	for _, want := range []string{srv.URL, "500", "upstream timeout from zot"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must contain %q", err, want)
		}
	}
}

func fakeRegistryJWT(t *testing.T, repo string, actions []string) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"access": []map[string]any{{"type": "repository", "name": repo, "actions": actions}}})
	b64 := base64.RawURLEncoding.EncodeToString
	return b64([]byte(`{"alg":"RS256"}`)) + "." + b64(payload) + ".sig"
}

func TestRegistryToken(t *testing.T) {
	var gotScope, gotAuth string
	var actions []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/token" {
			t.Errorf("path = %q", r.URL.Path)
		}
		gotScope, gotAuth = r.URL.Query().Get("scope"), r.Header.Get("Authorization")
		_, _ = fmt.Fprintf(w, `{"token":%q}`, fakeRegistryJWT(t, "acme/hello", actions))
	}))
	defer srv.Close()

	actions = []string{"pull", "push"}
	tok, err := New(srv.URL, "upstream-bearer").RegistryToken(context.Background(), "acme/hello", []string{"pull", "push"})
	if err != nil || !tok.GrantsPush() || tok.Token == "" {
		t.Fatalf("owner: tok=%+v err=%v", tok, err)
	}
	if gotScope != "repository:acme/hello:pull,push" || gotAuth != "Bearer upstream-bearer" {
		t.Errorf("scope=%q auth=%q", gotScope, gotAuth)
	}

	actions = []string{"pull"}
	tok, err = New(srv.URL, "").RegistryToken(context.Background(), "acme/hello", []string{"pull"})
	if err != nil || tok.GrantsPush() {
		t.Errorf("pull-only is not an error and must not grant push: tok=%+v err=%v", tok, err)
	}
	if gotAuth != "" {
		t.Errorf("anonymous mint sent Authorization %q", gotAuth)
	}
	if _, err := New(srv.URL, "").RegistryToken(context.Background(), "", []string{"pull"}); err == nil {
		t.Error("empty repository must fail before the network")
	}

	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) }))
	defer deny.Close()
	_, err = New(deny.URL, "stale").RegistryToken(context.Background(), "acme/hello", []string{"pull"})
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("401 must wrap ErrUnauthorized, got %v", err)
	}
}

func TestSyncBundle(t *testing.T) {
	var gotAuth string
	var gotBody syncapi.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/bundles/sync" {
			t.Errorf("path = %q", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = w.Write([]byte(`{"repository":"a/b","tag":"1.0.0","manifest_etag":"etag","artifact_count":3,"new_count":1,"types":["EvaluationLog"]}`))
	}))
	defer srv.Close()

	resp, err := New(srv.URL, "test-token").SyncBundle(context.Background(), "a/b", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if resp.ArtifactCount != 3 || resp.NewCount != 1 || resp.Types[0] != "EvaluationLog" {
		t.Errorf("resp = %+v", resp)
	}
	if gotAuth != "Bearer test-token" || gotBody.Repository != "a/b" || gotBody.Tag != "1.0.0" {
		t.Errorf("auth=%q body=%+v", gotAuth, gotBody)
	}
	if _, err := New(srv.URL, "").SyncBundle(context.Background(), "a/b", "1.0.0"); !errors.Is(err, ErrNoBearer) {
		t.Errorf("no bearer: err = %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(422)
		_, _ = w.Write([]byte(`{"error":"bundle_unsigned"}`))
	}))
	defer bad.Close()
	_, err = New(bad.URL, "t").SyncBundle(context.Background(), "a/b", "1.0.0")
	for _, want := range []string{bad.URL, "422", "bundle_unsigned"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v must contain %q", err, want)
		}
	}
}

func TestSyncPlugin(t *testing.T) {
	var gotPath string
	var gotBody syncapi.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
	}))
	defer srv.Close()
	if err := New(srv.URL, "b").SyncPlugin(context.Background(), "acme", "hello", "0.1.0"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/plugins/acme/hello/sync" || gotBody.Repository != "acme/plugins/hello" || gotBody.Tag != "0.1.0" {
		t.Errorf("path=%q body=%+v", gotPath, gotBody)
	}
}
