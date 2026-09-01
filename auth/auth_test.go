// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testApp() App { return App{Name: "grcli", TokenEnv: "GRCLI_TEST_TOKEN"} }

func tempStore(t *testing.T) *Store {
	t.Helper()
	return &Store{App: testApp(), Path: filepath.Join(t.TempDir(), "credentials.json")}
}

func TestStoreRoundTripAndPermissions(t *testing.T) {
	s := tempStore(t)

	if _, err := s.Get("https://auth.example/realms/x"); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("Get on empty store = %v, want ErrNoCredentials", err)
	}

	want := &Credentials{
		Issuer:       "https://auth.example/realms/x",
		AccessToken:  "at",
		RefreshToken: "rt",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := s.Put(want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// The file holds a password: it must never be group- or world-readable.
	fi, err := os.Stat(s.Path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("credentials file mode = %o, want 600", mode)
	}

	// A trailing slash must reach the same entry: Keycloak emits the no-slash
	// form in `iss`, but operators and copy-pasted URLs routinely carry one.
	got, err := s.Get("https://auth.example/realms/x/")
	if err != nil {
		t.Fatalf("Get with trailing slash: %v", err)
	}
	if got.AccessToken != "at" || got.RefreshToken != "rt" {
		t.Errorf("round-trip = %+v, want access=at refresh=rt", got)
	}

	if err := s.Delete("https://auth.example/realms/x"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("https://auth.example/realms/x"); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("Get after Delete = %v, want ErrNoCredentials", err)
	}
	// Logging out of an issuer you never logged into is a no-op, not a failure.
	if err := s.Delete("https://auth.example/never-used"); err != nil {
		t.Errorf("Delete of missing entry = %v, want nil", err)
	}
}

// A freshly issued token must never already be inside the renewal window.
// Otherwise the next Resolve refreshes a token it just obtained — and fails
// outright when the response carried no refresh token. This is the regression
// that a hardcoded 30s floor under a 60s window produced before the extraction.
func TestFreshTokenIsNotBornExpired(t *testing.T) {
	for _, expiresIn := range []int{0, 1, 30, 59} {
		creds := credsFromTokenResponse("https://auth.example", &tokenResponse{
			AccessToken: "at",
			ExpiresIn:   expiresIn,
		})
		if creds.ExpiredAt(time.Now()) {
			t.Errorf("token with expires_in=%d is born expired (ExpiresAt %s)", expiresIn, creds.ExpiresAt)
		}
	}
}

func TestResolvePrecedence(t *testing.T) {
	ctx := context.Background()
	app := testApp()

	t.Run("explicit token wins over env", func(t *testing.T) {
		t.Setenv(app.TokenEnv, "from-env")
		got, err := Resolve(ctx, ResolveInput{App: app, ExplicitToken: "from-flag"})
		if err != nil || got != "from-flag" {
			t.Fatalf("Resolve = %q, %v; want from-flag", got, err)
		}
	})

	t.Run("env wins over store", func(t *testing.T) {
		t.Setenv(app.TokenEnv, "from-env")
		s := tempStore(t)
		if err := s.Put(&Credentials{Issuer: "https://auth.example", AccessToken: "from-store", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		got, err := Resolve(ctx, ResolveInput{App: app, Issuer: "https://auth.example", Store: s})
		if err != nil || got != "from-env" {
			t.Fatalf("Resolve = %q, %v; want from-env", got, err)
		}
	})

	t.Run("store used when nothing else is set", func(t *testing.T) {
		s := tempStore(t)
		if err := s.Put(&Credentials{Issuer: "https://auth.example", AccessToken: "from-store", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		got, err := Resolve(ctx, ResolveInput{App: app, Issuer: "https://auth.example", Store: s})
		if err != nil || got != "from-store" {
			t.Fatalf("Resolve = %q, %v; want from-store", got, err)
		}
	})
}

func TestResolveRefreshesInsideRenewalWindow(t *testing.T) {
	s := tempStore(t)
	// Expires in 10s: inside the 60s renewal window, so Resolve must refresh
	// rather than hand back a token that dies mid-push.
	if err := s.Put(&Credentials{
		Issuer:       "https://auth.example",
		AccessToken:  "stale",
		RefreshToken: "rt",
		ExpiresAt:    time.Now().Add(10 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}

	refreshed := false
	got, err := Resolve(context.Background(), ResolveInput{
		App:      testApp(),
		Issuer:   "https://auth.example",
		ClientID: "cli",
		Store:    s,
		MetadataFetcher: func(context.Context, string) (*OIDCMetadata, error) {
			return &OIDCMetadata{Issuer: "https://auth.example", TokenEndpoint: "https://auth.example/token"}, nil
		},
		Refresher: func(context.Context, *OIDCMetadata, string, string) (*Credentials, error) {
			refreshed = true
			return &Credentials{Issuer: "https://auth.example", AccessToken: "fresh", ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !refreshed || got != "fresh" {
		t.Fatalf("Resolve = %q (refreshed=%v); want fresh", got, refreshed)
	}
	// The refreshed token must be persisted, or every command refreshes again.
	stored, err := s.Get("https://auth.example")
	if err != nil || stored.AccessToken != "fresh" {
		t.Errorf("stored token = %+v, %v; want the refreshed one", stored, err)
	}
}

func TestResolveNoTokenErrorsNameTheTool(t *testing.T) {
	app := testApp()

	// No issuer: the store was never consulted, and the fix is to supply a hub
	// URL — a different message from "you are not logged in".
	_, err := Resolve(context.Background(), ResolveInput{App: app})
	var noTok *ErrNoToken
	if !errors.As(err, &noTok) {
		t.Fatalf("Resolve = %v, want *ErrNoToken", err)
	}
	if noTok.CheckedStore {
		t.Error("CheckedStore = true, want false when no issuer was given")
	}
	if !strings.Contains(err.Error(), "grcli login") || !strings.Contains(err.Error(), app.TokenEnv) {
		t.Errorf("error must name the tool and its env var, got: %v", err)
	}

	// Issuer present but nothing stored: the fix IS to log in.
	_, err = Resolve(context.Background(), ResolveInput{App: app, Issuer: "https://auth.example", Store: tempStore(t)})
	if !errors.As(err, &noTok) {
		t.Fatalf("Resolve = %v, want *ErrNoToken", err)
	}
	if !noTok.CheckedStore {
		t.Error("CheckedStore = false, want true when the store was searched")
	}
}
