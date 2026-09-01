// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// ResolveInput is everything Resolve needs to decide which token to use,
// grouped as a struct so callers don't thread a seven-argument signature.
type ResolveInput struct {
	// App names the tool: it supplies the environment variable consulted for an
	// explicit token, and the tool name in every error. Required.
	App App
	// ExplicitToken is a token supplied directly by the user, typically a
	// --token flag. It wins over everything.
	ExplicitToken string
	// Issuer is the OIDC issuer URL naming which stored credentials to look up,
	// typically the oidc_issuer from hub discovery. Empty means "do not consult
	// the store" — the case where the command ran without a hub URL, so no
	// discovery happened and there is no issuer to key on.
	Issuer string
	// ClientID drives a refresh when the stored token is inside the renewal
	// window, typically the oidc_cli_client_id from hub discovery. Empty when a
	// refresh is needed yields an error pointing at a fresh login.
	ClientID string
	// Store holds the on-disk credentials. Nil disables the stored-credential
	// path entirely, leaving only the explicit token and the environment.
	Store *Store
	// MetadataFetcher loads OIDC metadata for the issuer when a refresh is
	// needed. Nil uses FetchOIDCMetadata; tests substitute to stay off the wire.
	MetadataFetcher func(ctx context.Context, issuer string) (*OIDCMetadata, error)
	// Refresher exchanges a refresh token for a fresh access token. Nil uses
	// RefreshToken; tests substitute.
	Refresher func(ctx context.Context, meta *OIDCMetadata, clientID, refreshToken string) (*Credentials, error)
	// Now returns the current time. Nil uses time.Now; tests pin it so the
	// renewal-window branch is deterministic.
	Now func() time.Time
	// Warn receives a one-line message when Resolve hits something non-fatal
	// worth saying out loud (a refreshed token that could not be persisted).
	// Nil discards; os.Stderr is the usual sink.
	Warn io.Writer
}

// ErrNoToken reports that no resolution source produced a token. Its message
// names every source that was tried, so the user knows which one to populate
// rather than guessing at the auth model.
type ErrNoToken struct {
	App App
	// Issuer is the issuer the store was searched for; empty when the store was
	// not consulted at all.
	Issuer string
	// CheckedStore distinguishes "looked in the store and found nothing" from
	// "had no issuer, so never looked" — different user-facing fixes.
	CheckedStore bool
}

func (e *ErrNoToken) Error() string {
	envPart := "no token env var is configured"
	if e.App.TokenEnv != "" {
		envPart = e.App.TokenEnv + " unset"
	}
	if e.CheckedStore {
		return fmt.Sprintf("no token available: --token unset, %s, and no stored credentials for %s — %s to sign in",
			envPart, e.Issuer, e.App.LoginHint())
	}
	return fmt.Sprintf("no token available: --token unset, %s, and no hub URL was given so the credential store cannot be consulted — pass a hub URL, set the token env var, or %s",
		envPart, e.App.LoginHint())
}

// Resolve returns a bearer token authenticating writes to the hub and registry.
// Resolution order, highest first:
//
//  1. ExplicitToken (a --token flag).
//  2. The App.TokenEnv environment variable — the CI escape hatch, where a
//     trusted-publishing OIDC token or a manually minted one is injected.
//  3. Stored credentials for Issuer, refreshed in place when inside the renewal
//     window.
//
// Reaching step 3 with credentials that are spent and unrefreshable returns an
// error pointing at a fresh login. Resolve never re-prompts on its own: a
// function that silently opened a browser from inside a publish would be a
// surprising thing to have called.
//
// The token this returns is NOT a signing identity. Fulcio trusts public OIDC
// issuers, not the grc.store auth server, so keyless signing needs its own token
// from its own issuer — see FetchGitHubActionsToken.
func Resolve(ctx context.Context, in ResolveInput) (string, error) {
	if in.ExplicitToken != "" {
		return in.ExplicitToken, nil
	}
	// Read the environment here rather than taking it as a field: a caller that
	// forgets to wire the fallback gets a CI failure that looks like an auth
	// problem, and there is no case where the tool wants a DIFFERENT value than
	// its own configured variable.
	if in.App.TokenEnv != "" {
		if tok := strings.TrimSpace(os.Getenv(in.App.TokenEnv)); tok != "" {
			return tok, nil
		}
	}
	if in.Store == nil || in.Issuer == "" {
		return "", &ErrNoToken{App: in.App, CheckedStore: false}
	}

	creds, err := in.Store.Get(in.Issuer)
	if err != nil {
		if errors.Is(err, ErrNoCredentials) {
			return "", &ErrNoToken{App: in.App, Issuer: in.Issuer, CheckedStore: true}
		}
		return "", err
	}

	now := time.Now
	if in.Now != nil {
		now = in.Now
	}
	if !creds.ExpiredAt(now()) {
		return creds.AccessToken, nil
	}

	if creds.RefreshToken == "" {
		return "", fmt.Errorf("stored token for %s has expired and carries no refresh token — %s to sign in again", in.Issuer, in.App.LoginHint())
	}
	if in.ClientID == "" {
		return "", fmt.Errorf("stored token for %s needs refreshing but no OIDC client_id is available — pass a hub URL so discovery can supply it, or %s again", in.Issuer, in.App.LoginHint())
	}

	fetcher := in.MetadataFetcher
	if fetcher == nil {
		fetcher = FetchOIDCMetadata
	}
	refresher := in.Refresher
	if refresher == nil {
		refresher = RefreshToken
	}
	meta, err := fetcher(ctx, in.Issuer)
	if err != nil {
		return "", fmt.Errorf("loading OIDC metadata to refresh the stored token: %w", err)
	}
	refreshed, err := refresher(ctx, meta, in.ClientID, creds.RefreshToken)
	if err != nil {
		return "", fmt.Errorf("refreshing the stored token: %w — %s again if this keeps failing", err, in.App.LoginHint())
	}
	if err := in.Store.Put(refreshed); err != nil && in.Warn != nil {
		// The refresh worked and we hold a usable token, so this must not fail
		// the operation — but it must be VISIBLE: under refresh-token rotation
		// the on-disk token has now been consumed, so the next run will demand a
		// fresh login for reasons that would otherwise look arbitrary.
		fmt.Fprintf(in.Warn, "warning: refreshed the token but could not persist it (the next run may require %s): %v\n", in.App.LoginHint(), err)
	}
	return refreshed.AccessToken, nil
}
