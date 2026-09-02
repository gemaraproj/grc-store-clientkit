// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const testIssuer = "https://auth.example/realms/r"

func TestResolve_Order(t *testing.T) {
	ctx := context.Background()
	app := testApp()
	store := tempStore(t)

	// Seed a stored token with plenty of life left so the refresh branch never
	// fires and the test is measuring precedence only.
	if err := store.Put(&Credentials{
		Issuer:      testIssuer,
		AccessToken: "from-store",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("explicit token wins over env and store", func(t *testing.T) {
		t.Setenv(app.TokenEnv, "from-env")
		got, err := Resolve(ctx, ResolveInput{App: app, ExplicitToken: "from-flag", Issuer: testIssuer, Store: store})
		if err != nil || got != "from-flag" {
			t.Fatalf("Resolve = %q, %v; want from-flag", got, err)
		}
	})

	t.Run("env wins over store", func(t *testing.T) {
		t.Setenv(app.TokenEnv, "from-env")
		got, err := Resolve(ctx, ResolveInput{App: app, Issuer: testIssuer, Store: store})
		if err != nil || got != "from-env" {
			t.Fatalf("Resolve = %q, %v; want from-env", got, err)
		}
	})

	t.Run("store is consulted when nothing else is set", func(t *testing.T) {
		got, err := Resolve(ctx, ResolveInput{App: app, Issuer: testIssuer, Store: store})
		if err != nil || got != "from-store" {
			t.Fatalf("Resolve = %q, %v; want from-store", got, err)
		}
	})

	t.Run("an App with no TokenEnv ignores the environment entirely", func(t *testing.T) {
		t.Setenv(app.TokenEnv, "from-env")
		got, err := Resolve(ctx, ResolveInput{App: App{Name: "grcli"}, Issuer: testIssuer, Store: store})
		if err != nil || got != "from-store" {
			t.Fatalf("Resolve = %q, %v; want from-store — a tool that declines an env override must not get one", got, err)
		}
	})

	t.Run("no token and no issuer reports the no-discovery shape", func(t *testing.T) {
		_, err := Resolve(ctx, ResolveInput{App: app})
		var noTok *ErrNoToken
		if !errors.As(err, &noTok) {
			t.Fatalf("Resolve = %v, want *ErrNoToken", err)
		}
		if noTok.CheckedStore {
			t.Error("CheckedStore = true, want false when there was no issuer to look up")
		}
		if !strings.Contains(err.Error(), "credential store cannot be consulted") {
			t.Errorf("error should explain why the store was skipped, got: %v", err)
		}
		// Resolve cannot tell a missing hub URL from a hub with no oidc_issuer,
		// so it must not diagnose one.
		if strings.Contains(err.Error(), "hub URL") {
			t.Errorf("error asserts a cause Resolve cannot know, got: %v", err)
		}
		if !strings.Contains(err.Error(), "set "+app.TokenEnv) {
			t.Errorf("error should suggest the env var the tool actually has, got: %v", err)
		}
		// A tool with no TokenEnv must not be told to set one.
		_, err = Resolve(ctx, ResolveInput{App: App{Name: "grcli"}})
		if err == nil || strings.Contains(err.Error(), "set ") {
			t.Errorf("error suggests an env var the tool did not configure, got: %v", err)
		}
	})

	t.Run("no token with an issuer reports the store-checked shape", func(t *testing.T) {
		_, err := Resolve(ctx, ResolveInput{App: app, Issuer: "https://auth.example/realms/other", Store: store})
		var noTok *ErrNoToken
		if !errors.As(err, &noTok) {
			t.Fatalf("Resolve = %v, want *ErrNoToken", err)
		}
		if !noTok.CheckedStore {
			t.Error("CheckedStore = false, want true when the store was searched")
		}
		for _, want := range []string{"grcli login", "https://auth.example/realms/other", app.TokenEnv} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error missing %q, got: %v", want, err)
			}
		}
	})
}

func TestResolve_RefreshesWhenNearExpiry(t *testing.T) {
	store := tempStore(t)
	now := time.Now()
	if err := store.Put(&Credentials{
		Issuer:       testIssuer,
		AccessToken:  "stale",
		RefreshToken: "refresh-1",
		ExpiresAt:    now.Add(10 * time.Second), // inside the 60s renewal window
	}); err != nil {
		t.Fatal(err)
	}

	fetcherCalled, refresherCalled := false, false
	got, err := Resolve(context.Background(), ResolveInput{
		App:      testApp(),
		Issuer:   testIssuer,
		ClientID: "test-client",
		Store:    store,
		Now:      func() time.Time { return now },
		MetadataFetcher: func(_ context.Context, issuer string) (*OIDCMetadata, error) {
			fetcherCalled = true
			if issuer != testIssuer {
				t.Errorf("MetadataFetcher issuer = %q, want %q", issuer, testIssuer)
			}
			return &OIDCMetadata{Issuer: issuer, TokenEndpoint: "https://auth.example/token"}, nil
		},
		Refresher: func(_ context.Context, _ *OIDCMetadata, clientID, refreshToken string) (*Credentials, error) {
			refresherCalled = true
			if clientID != "test-client" || refreshToken != "refresh-1" {
				t.Errorf("Refresher got (%q, %q), want (test-client, refresh-1)", clientID, refreshToken)
			}
			return &Credentials{
				Issuer:       testIssuer,
				AccessToken:  "fresh",
				RefreshToken: "refresh-2",
				ExpiresAt:    now.Add(time.Hour),
			}, nil
		},
	})
	if err != nil || got != "fresh" {
		t.Fatalf("Resolve = %q, %v; want fresh", got, err)
	}
	if !fetcherCalled || !refresherCalled {
		t.Errorf("fetcher=%v refresher=%v; both must run when a refresh is needed", fetcherCalled, refresherCalled)
	}

	// The refreshed pair must be persisted, or every subsequent command
	// refreshes again — and under refresh-token rotation the second attempt
	// fails, since the stored token was already consumed.
	persisted, err := store.Get(testIssuer)
	if err != nil {
		t.Fatalf("Get after refresh: %v", err)
	}
	if persisted.AccessToken != "fresh" || persisted.RefreshToken != "refresh-2" {
		t.Errorf("persisted = %+v, want the refreshed pair", persisted)
	}
}

func TestResolve_RefreshFailureSurfacesLoginHint(t *testing.T) {
	store := tempStore(t)
	now := time.Now()
	if err := store.Put(&Credentials{
		Issuer:       testIssuer,
		AccessToken:  "stale",
		RefreshToken: "refresh-revoked",
		ExpiresAt:    now.Add(-time.Second),
	}); err != nil {
		t.Fatal(err)
	}

	_, err := Resolve(context.Background(), ResolveInput{
		App:      testApp(),
		Issuer:   testIssuer,
		ClientID: "test-client",
		Store:    store,
		Now:      func() time.Time { return now },
		MetadataFetcher: func(_ context.Context, issuer string) (*OIDCMetadata, error) {
			return &OIDCMetadata{Issuer: issuer, TokenEndpoint: "https://auth.example/token"}, nil
		},
		Refresher: func(context.Context, *OIDCMetadata, string, string) (*Credentials, error) {
			return nil, errors.New("invalid_grant: refresh token revoked")
		},
	})
	// Without the hint, users retry the same dead refresh and have no idea what
	// to do next.
	if err == nil || !strings.Contains(err.Error(), "grcli login") {
		t.Errorf("Resolve = %v, want an error pointing at `grcli login`", err)
	}
}

func TestResolve_NoRefreshTokenForcesReLogin(t *testing.T) {
	store := tempStore(t)
	now := time.Now()
	if err := store.Put(&Credentials{
		Issuer:      testIssuer,
		AccessToken: "stale",
		ExpiresAt:   now.Add(-time.Second), // expired, and nothing to refresh with
	}); err != nil {
		t.Fatal(err)
	}

	var warn bytes.Buffer
	_, err := Resolve(context.Background(), ResolveInput{
		App:      testApp(),
		Issuer:   testIssuer,
		ClientID: "test-client",
		Store:    store,
		Now:      func() time.Time { return now },
		Warn:     &warn,
	})
	if err == nil || !strings.Contains(err.Error(), "no refresh token") || !strings.Contains(err.Error(), "grcli login") {
		t.Errorf("Resolve = %v, want an error naming the missing refresh token and the login hint", err)
	}
	// Nothing went wrong that the user can act on beyond the returned error;
	// a warning here would be noise.
	if warn.Len() != 0 {
		t.Errorf("unexpected warning output: %q", warn.String())
	}
}

// The hints must name the tool that is actually running. An error telling a
// pvtr user to run `grcli login` is worse than no error at all.
func TestResolve_HintsNameTheCallingTool(t *testing.T) {
	pvtr := App{Name: "pvtr", TokenEnv: "PVTR_TOKEN"}
	_, err := Resolve(context.Background(), ResolveInput{App: pvtr, Issuer: testIssuer, Store: tempStore(t)})
	if err == nil {
		t.Fatal("Resolve = nil error with an empty store, want *ErrNoToken")
	}
	if !strings.Contains(err.Error(), "pvtr login") || !strings.Contains(err.Error(), "PVTR_TOKEN") {
		t.Errorf("error should name pvtr and PVTR_TOKEN, got: %v", err)
	}
	if strings.Contains(err.Error(), "grcli") {
		t.Errorf("error mentions grcli to a pvtr user: %v", err)
	}
	// pvtr registers no --token flag, so the error must not offer one.
	if strings.Contains(err.Error(), "--token") {
		t.Errorf("error offers a --token flag pvtr does not have: %v", err)
	}

	grcli := App{Name: "grcli", TokenEnv: "GRCLI_TOKEN", TokenFlag: "--token"}
	_, err = Resolve(context.Background(), ResolveInput{App: grcli, Issuer: testIssuer, Store: tempStore(t)})
	if err == nil || !strings.Contains(err.Error(), "--token unset") {
		t.Errorf("error should name the flag grcli registers, got: %v", err)
	}
}

// A store that could not be located must not be reported as a missing issuer:
// the two have different fixes, and an issuer was supplied here.
func TestResolve_StoreErrIsNotReportedAsAMissingIssuer(t *testing.T) {
	app := App{Name: "pvtr", TokenEnv: "PVTR_TOKEN"}
	t.Setenv(app.TokenEnv, "")
	boom := errors.New("resolving home dir for credential store: $HOME is not defined")

	_, err := Resolve(context.Background(), ResolveInput{
		App:      app,
		Issuer:   "https://issuer",
		StoreErr: boom,
	})

	var noTok *ErrNoToken
	if !errors.As(err, &noTok) {
		t.Fatalf("expected *ErrNoToken, got %v", err)
	}
	if !errors.Is(err, boom) {
		t.Error("the store failure should stay matchable through Unwrap")
	}
	msg := err.Error()
	if !strings.Contains(msg, "the credential store could not be located") {
		t.Errorf("message should name the store failure, got: %v", msg)
	}
	if strings.Contains(msg, "no OIDC issuer") || strings.Contains(msg, "advertises oidc_issuer") {
		t.Errorf("an issuer WAS supplied; message must not blame a missing one, got: %v", msg)
	}
}

// With no issuer and no store failure, the issuer is still the thing to name.
func TestResolve_MissingIssuerStillNamesTheIssuer(t *testing.T) {
	app := App{Name: "pvtr", TokenEnv: "PVTR_TOKEN"}
	t.Setenv(app.TokenEnv, "")

	_, err := Resolve(context.Background(), ResolveInput{App: app, Store: &Store{App: app, Path: "/nonexistent/credentials.json"}})

	msg := err.Error()
	if !strings.Contains(msg, "no OIDC issuer") || !strings.Contains(msg, "advertises oidc_issuer") {
		t.Errorf("message should blame the missing issuer, got: %v", msg)
	}
	if strings.Contains(msg, "could not be located") {
		t.Errorf("the store was fine; message must not claim otherwise, got: %v", msg)
	}
}
