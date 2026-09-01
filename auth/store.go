// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Credentials is one issuer's saved tokens. The Issuer field doubles as the
// storage key so callers don't have to track that separately.
type Credentials struct {
	Issuer       string    `json:"issuer"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// RenewalWindow is how far before ExpiresAt a token is treated as spent, so a
// caller refreshes before a push rather than mid-flight. Keycloak's default
// access-token TTL on the gemara realm is 900s, so 60s refreshes ~6.7% early —
// well clear of any reasonable clock skew between the client and the IdP.
//
// credsFromTokenResponse floors new-token lifetimes ABOVE this value, so a
// freshly issued token can never be born already-expired.
const RenewalWindow = 60 * time.Second

// ExpiredAt reports whether the access token is at or within RenewalWindow of
// expiry as of now. Time is a parameter rather than a call to time.Now so the
// renewal branch is deterministic under test without a package-level clock.
func (c *Credentials) ExpiredAt(now time.Time) bool {
	return !c.ExpiresAt.After(now.Add(RenewalWindow))
}

// Store is the on-disk credential cache: a single JSON file at
// ${XDG_DATA_HOME:-~/.local/share}/<app>/credentials.json, 0600, one entry per
// issuer. The directory is 0700. What is inside is functionally a long-lived
// password.
//
// Why a flat file rather than the OS keyring (Keychain, libsecret): native
// keyring bindings pull in platform-specific cgo that complicates
// cross-compilation, and this is the posture gh, flyctl, and gcloud ship with by
// default. A keyring backend can be added behind this same surface later.
//
// Each App gets its own file. grcli and pvtr authenticate against the same
// issuer but are separate tools, and one clobbering the other's tokens on
// logout would be a genuinely confusing failure.
type Store struct {
	// App names the owning tool: it picks the directory and appears in errors.
	App App
	// Path is the credentials file. NewDefaultStore fills the standard XDG
	// location; set it directly to point somewhere else (tests do).
	Path string
}

// storeFile is the on-disk JSON shape, versioned so a future layout change can
// detect and migrate what it finds.
type storeFile struct {
	Version     int                     `json:"version"`
	Credentials map[string]*Credentials `json:"credentials"`
}

const currentStoreVersion = 1

// ErrNoCredentials is returned by Get when the store holds no entry for the
// issuer. Callers compare with errors.Is to drive their "fall back to an
// explicit token" branches, so this must stay a sentinel and not become a
// formatted error.
var ErrNoCredentials = errors.New("no stored credentials for this issuer")

// NewDefaultStore returns a Store at the standard XDG path for app. The
// directory is created lazily on first write — a Get against a missing file
// simply reports ErrNoCredentials.
func NewDefaultStore(app App) (*Store, error) {
	dir, err := defaultStoreDir(app)
	if err != nil {
		return nil, err
	}
	return &Store{App: app, Path: filepath.Join(dir, "credentials.json")}, nil
}

func defaultStoreDir(app App) (string, error) {
	if app.Name == "" {
		return "", errors.New("App.Name is required to locate the credential store")
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); xdg != "" {
		return filepath.Join(xdg, app.Name), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home dir for credential store: %w", err)
	}
	return filepath.Join(home, ".local", "share", app.Name), nil
}

// Get returns the credentials saved for issuer, or ErrNoCredentials when either
// the file is absent (no logins yet) or it holds no entry for this issuer.
func (s *Store) Get(issuer string) (*Credentials, error) {
	issuer = canonicalIssuer(issuer)
	if issuer == "" {
		return nil, errors.New("issuer is required")
	}
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	c, ok := f.Credentials[issuer]
	if !ok || c == nil {
		return nil, ErrNoCredentials
	}
	// Defensive: a record whose Issuer field disagrees with its key means
	// someone hand-edited the JSON. The key is what we looked up, so the key
	// wins.
	c.Issuer = issuer
	return c, nil
}

// Put writes creds.Issuer -> creds, replacing any existing entry for that
// issuer.
func (s *Store) Put(creds *Credentials) error {
	if creds == nil {
		return errors.New("credentials are required")
	}
	issuer := canonicalIssuer(creds.Issuer)
	if issuer == "" {
		return errors.New("credentials.Issuer is required")
	}
	creds.Issuer = issuer

	f, err := s.load()
	if err != nil {
		return err
	}
	if f.Credentials == nil {
		f.Credentials = map[string]*Credentials{}
	}
	f.Credentials[issuer] = creds
	return s.save(f)
}

// Delete removes the entry for issuer. A missing entry is not an error — a
// logout against an issuer the user never logged into should still succeed.
func (s *Store) Delete(issuer string) error {
	issuer = canonicalIssuer(issuer)
	if issuer == "" {
		return errors.New("issuer is required")
	}
	f, err := s.load()
	if err != nil {
		return err
	}
	delete(f.Credentials, issuer)
	return s.save(f)
}

// load reads the on-disk store. A missing file is not an error — Get, Put and
// Delete all treat that as an empty store. Anything else (corrupt JSON, denied
// permissions, an unknown version) bubbles up.
func (s *Store) load() (*storeFile, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &storeFile{Version: currentStoreVersion, Credentials: map[string]*Credentials{}}, nil
		}
		return nil, fmt.Errorf("reading credential store %s: %w", s.Path, err)
	}
	f := &storeFile{}
	if err := json.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("decoding credential store %s: %w (delete it to start over)", s.Path, err)
	}
	if f.Version != 0 && f.Version != currentStoreVersion {
		return nil, fmt.Errorf("credential store %s is version %d, %s only knows version %d",
			s.Path, f.Version, s.App.name(), currentStoreVersion)
	}
	if f.Credentials == nil {
		f.Credentials = map[string]*Credentials{}
	}
	f.Version = currentStoreVersion
	return f, nil
}

// save writes f atomically: a temp file in the same directory, then a rename, so
// a crash mid-write cannot leave the store half-written.
//
// The 0600 mode is set on the open file handle BEFORE any bytes are written, so
// the secret never exists on disk at a wider mode — not even for the instant
// between create and chmod. That ordering is why this does not use a generic
// write-file-then-rename helper: os.WriteFile applies its mode as a creation
// argument the umask can widen, and the window it opens is small but real.
func (s *Store) save(f *storeFile) error {
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating credential store directory %s: %w", dir, err)
	}
	f.Version = currentStoreVersion
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding credential store: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "credentials-*.json.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if anything below fails before the rename.
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.Path); err != nil {
		return fmt.Errorf("renaming temp file to %s: %w", s.Path, err)
	}
	cleanup = false
	return nil
}

// canonicalIssuer trims trailing slashes and surrounding whitespace so
// "https://auth.grc.store/realms/gemara/" and the same URL without the slash hit
// one entry. Keycloak emits the no-slash form in its iss claim, but operators
// and copy-pasted URLs routinely carry one.
func canonicalIssuer(s string) string {
	return strings.TrimRight(strings.TrimSpace(s), "/")
}
