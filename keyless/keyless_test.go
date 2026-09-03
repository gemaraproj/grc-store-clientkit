// SPDX-License-Identifier: Apache-2.0

package keyless

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatement(t *testing.T) {
	hexDigest := strings.Repeat("ab", 32)
	b, err := Statement("sha256:"+hexDigest, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var stmt struct {
		Type    string `json:"_type"`
		Subject []struct {
			Digest      map[string]string `json:"digest"`
			Annotations json.RawMessage   `json:"annotations"`
		} `json:"subject"`
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(b, &stmt); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	if stmt.Type != StatementType || len(stmt.Subject) != 1 || stmt.Subject[0].Digest["sha256"] != hexDigest {
		t.Errorf("statement = %s", b)
	}
	if stmt.PredicateType != SignPredicateType || string(stmt.Predicate) != "{}" || string(stmt.Subject[0].Annotations) != "{}" {
		t.Errorf("plain signature must use cosign's predicateType with {} (not null) objects: %s", b)
	}

	b, _ = Statement(hexDigest, "https://slsa.dev/provenance/v1", map[string]string{"k": "v"})
	if !strings.Contains(string(b), `"predicateType":"https://slsa.dev/provenance/v1"`) || !strings.Contains(string(b), `"predicate":{"k":"v"}`) {
		t.Errorf("custom predicate not carried: %s", b)
	}

	for _, bad := range []string{"", "not-a-digest", "sha256:tooshort", "sha256:" + strings.Repeat("zz", 32), "sha512:" + hexDigest} {
		if _, err := Statement(bad, "", nil); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestSign_RequiresIDToken(t *testing.T) {
	if _, err := (Signer{}).Sign(context.Background(), strings.Repeat("ab", 32), "", nil); err == nil {
		t.Fatal("expected error with no signing ID token")
	}
}

func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	b64 := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return b64(map[string]string{"alg": "none"}) + "." + b64(claims) + ".sig"
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{IDTokenEnv, "GITHUB_ACTIONS", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"} {
		t.Setenv(k, "")
	}
}

func TestIdentity_EnvToken(t *testing.T) {
	clearEnv(t)
	tok := makeJWT(t, map[string]any{"aud": PublicGoodAudience, "iss": "https://gitlab.example"})
	t.Setenv(IDTokenEnv, tok)
	if got, err := Identity(context.Background(), PublicGoodAudience, io.Discard); err != nil || got != tok {
		t.Errorf("got (%q, %v), want the env token verbatim", got, err)
	}

	t.Setenv(IDTokenEnv, makeJWT(t, map[string]any{"aud": []string{"other", PublicGoodAudience}}))
	if _, err := Identity(context.Background(), PublicGoodAudience, io.Discard); err != nil {
		t.Errorf("array audience containing the target must be accepted: %v", err)
	}

	for name, claims := range map[string]map[string]any{
		"wrong audience": {"aud": "some-other"},
		"null audience":  {"aud": nil},
		"no audience":    {"iss": "x"},
	} {
		t.Setenv(IDTokenEnv, makeJWT(t, claims))
		if _, err := Identity(context.Background(), PublicGoodAudience, io.Discard); err == nil || !strings.Contains(err.Error(), "audience") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	t.Setenv(IDTokenEnv, "this-is-not-a-jwt")
	if _, err := Identity(context.Background(), PublicGoodAudience, io.Discard); err == nil || !strings.Contains(err.Error(), "not a valid JWT") {
		t.Errorf("non-JWT: err = %v", err)
	}
}

func TestIdentity_NonInteractiveFailsFast(t *testing.T) {
	clearEnv(t)
	orig := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = orig })
	_, err := Identity(context.Background(), PublicGoodAudience, io.Discard)
	if err == nil || !strings.Contains(err.Error(), IDTokenEnv) || !strings.Contains(err.Error(), "not a terminal") {
		t.Errorf("err = %v", err)
	}
}

func TestIdentity_GitHubActions(t *testing.T) {
	clearEnv(t)
	jwt := makeJWT(t, map[string]any{"aud": PublicGoodAudience})
	var gotAud string
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		gotAud = r.URL.Query().Get("audience")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": jwt})
	}))
	defer srv.Close()
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")

	got, err := Identity(context.Background(), PublicGoodAudience, io.Discard)
	if err != nil || got != jwt || gotAud != PublicGoodAudience {
		t.Errorf("got (%q, %v), aud %q", got, err, gotAud)
	}

	// The explicit env token wins over ambient GHA, and the token service is not called.
	override := makeJWT(t, map[string]any{"aud": PublicGoodAudience, "iss": "https://gitlab.example"})
	t.Setenv(IDTokenEnv, override)
	calls = 0
	if got, err := Identity(context.Background(), PublicGoodAudience, io.Discard); err != nil || got != override || calls != 0 {
		t.Errorf("override: got (%q, %v), token-service calls %d", got, err, calls)
	}
}
