// SPDX-License-Identifier: Apache-2.0

// Package auth implements the OIDC device-authorization grant (RFC 8628) and
// credential storage that every grc.store client CLI uses to obtain a bearer
// token for authenticated publishing (ADR-0028).
//
// It was extracted from grcli and privateer-sdk, which had independently grown
// near-identical copies of the same flow — the credential store and the device
// grant were 148 and 187 identical lines respectively at the time of the split.
// Where the two copies had drifted, this package takes the better half of each:
// privateer-sdk's bounded poll loop and its token-lifetime floor (grcli's floor
// sat BELOW the renewal window, so a short-TTL token was born already expired
// and refresh-looped), and grcli's injectable Resolve seams and its more
// actionable device-authorization errors.
//
// Signing identity is deliberately NOT here. The token this package resolves
// authorizes the registry and the hub; the token Fulcio mints a signing
// certificate from is a different token from a different issuer, and conflating
// them is the mistake this boundary exists to prevent. FetchGitHubActionsToken
// serves both only because the audience is the caller's argument.
package auth

// App identifies the consuming CLI. grcli and pvtr share these flows but must
// not share their on-disk credential file or their user-facing hints: two tools
// writing one credentials.json is a support ticket, and an error telling a pvtr
// user to run `grcli login` is worse than no error at all.
type App struct {
	// Name is the tool's binary name ("grcli", "pvtr"). It selects the XDG
	// subdirectory holding the credential store and names the tool in hints.
	Name string
	// TokenEnv is the environment variable carrying an explicit bearer override
	// ("GRCLI_TOKEN", "PVTR_TOKEN") — the CI escape hatch. Empty disables the
	// environment path entirely, so a tool that does not want one cannot get it
	// by accident.
	TokenEnv string
}

// name is the tool name to print, with a fallback so a zero App still produces
// a readable (if vague) error rather than a sentence with a hole in it.
func (a App) name() string {
	if a.Name == "" {
		return "this tool"
	}
	return a.Name
}

// LoginHint is the "run `<tool> login`" phrase used across this package's
// errors, so the wording stays identical everywhere the user is sent to log in.
func (a App) LoginHint() string {
	return "run `" + a.name() + " login`"
}
