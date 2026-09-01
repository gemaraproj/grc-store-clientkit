// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testApp() App { return App{Name: "grcli", TokenEnv: "GRCLI_TEST_TOKEN"} }

func tempStore(t *testing.T) *Store {
	t.Helper()
	return &Store{App: testApp(), Path: filepath.Join(t.TempDir(), "credentials.json")}
}

func TestStore_Roundtrip(t *testing.T) {
	s := tempStore(t)

	// Get on a missing file returns ErrNoCredentials, not a wrapped os error.
	// Callers depend on that to fall back cleanly to an explicit token.
	if _, err := s.Get("https://auth.grc.store/realms/gemara"); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("Get on empty store = %v, want ErrNoCredentials", err)
	}

	creds := &Credentials{
		Issuer:       "https://auth.grc.store/realms/gemara",
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Truncate(time.Second),
	}
	if err := s.Put(creds); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.Get(creds.Issuer)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AccessToken != creds.AccessToken || got.RefreshToken != creds.RefreshToken {
		t.Errorf("round-trip tokens = %q/%q, want %q/%q", got.AccessToken, got.RefreshToken, creds.AccessToken, creds.RefreshToken)
	}
	if !got.ExpiresAt.Equal(creds.ExpiresAt) {
		t.Errorf("ExpiresAt round-trip = %v, want %v", got.ExpiresAt, creds.ExpiresAt)
	}

	if err := s.Delete(creds.Issuer); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(creds.Issuer); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("Get after Delete = %v, want ErrNoCredentials", err)
	}
	// Logging out of an issuer never logged into is a no-op, not a failure.
	if err := s.Delete("https://auth.example/never-used"); err != nil {
		t.Errorf("Delete of missing entry = %v, want nil", err)
	}
}

func TestStore_FilePermsAre0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Mode bits mean something different there, and the XDG layout this
		// targets is POSIX in practice.
		t.Skip("posix-style perms not enforced on windows")
	}
	s := tempStore(t)
	if err := s.Put(&Credentials{
		Issuer:      "https://auth.example/realms/r",
		AccessToken: "x",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	info, err := os.Stat(s.Path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// The file holds long-lived credentials; world-readable here is a real
	// footgun on a shared machine.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("credentials file mode = %o, want 600", perm)
	}
}

func TestStore_MultipleIssuersCoexist(t *testing.T) {
	s := tempStore(t)
	a := &Credentials{Issuer: "https://auth.example/realms/one", AccessToken: "tok-1", ExpiresAt: time.Now().Add(time.Hour)}
	b := &Credentials{Issuer: "https://auth.example/realms/two", AccessToken: "tok-2", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(b); err != nil {
		t.Fatal(err)
	}

	// Deleting one issuer must not touch the other. The "one JSON file holding
	// every login" shape makes a careless rewrite drop the rest.
	if err := s.Delete(a.Issuer); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(a.Issuer); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("deleted issuer still present: %v", err)
	}
	got, err := s.Get(b.Issuer)
	if err != nil || got.AccessToken != "tok-2" {
		t.Errorf("surviving issuer = %+v, %v; want tok-2", got, err)
	}
}

func TestStore_TrailingSlashIsCanonicalized(t *testing.T) {
	s := tempStore(t)
	if err := s.Put(&Credentials{
		Issuer:      "https://auth.example/realms/r/",
		AccessToken: "tok",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	// Keycloak emits the no-slash form in `iss`; copy-pasted URLs carry one.
	// Both must reach the same record.
	for _, key := range []string{"https://auth.example/realms/r/", "https://auth.example/realms/r"} {
		got, err := s.Get(key)
		if err != nil || got.AccessToken != "tok" {
			t.Errorf("lookup with %q = %+v, %v; want tok", key, got, err)
		}
	}
}

func TestStore_CorruptFileReportsActionableError(t *testing.T) {
	s := tempStore(t)
	if err := os.WriteFile(s.Path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Get("https://auth.example/realms/r")
	if err == nil {
		t.Fatal("Get on corrupt store = nil error, want a failure")
	}
	// A bare decoding error leaves the user guessing; name the recovery.
	if !strings.Contains(err.Error(), "delete it to start over") {
		t.Errorf("error should name the recovery, got: %v", err)
	}
}

func TestStore_VersionMismatchRejected(t *testing.T) {
	s := tempStore(t)
	// A future layout must be refused, not silently downgraded.
	if err := os.WriteFile(s.Path, []byte(`{"version":99,"credentials":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Get("https://auth.example/realms/r")
	if err == nil {
		t.Fatal("Get on future-version store = nil error, want a failure")
	}
	if !strings.Contains(err.Error(), "version 99") {
		t.Errorf("error should name the version it found, got: %v", err)
	}
	if !strings.Contains(err.Error(), "grcli") {
		t.Errorf("error should name the tool that cannot read it, got: %v", err)
	}
	// Collapsing this into ErrNoCredentials would shadow the mismatch and send
	// the user into a re-login loop that cannot fix anything.
	if errors.Is(err, ErrNoCredentials) {
		t.Error("version mismatch must not collapse into ErrNoCredentials")
	}
}

func TestStore_DefaultPathIsPerApp(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	grcli, err := NewDefaultStore(App{Name: "grcli"})
	if err != nil {
		t.Fatal(err)
	}
	pvtr, err := NewDefaultStore(App{Name: "pvtr"})
	if err != nil {
		t.Fatal(err)
	}
	// Two tools authenticating against the same issuer must not share one file:
	// one clobbering the other's tokens on logout is a baffling failure.
	if grcli.Path == pvtr.Path {
		t.Errorf("grcli and pvtr share a credential file at %s", grcli.Path)
	}
	if _, err := NewDefaultStore(App{}); err == nil {
		t.Error("NewDefaultStore with no App.Name = nil error, want a failure")
	}
}
