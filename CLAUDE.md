# grc-store-clientkit — agent orientation

Apache-2.0 Go module holding the **client-side machinery shared by grc.store publishing tools**
(grcli, privateer-sdk). Module: `github.com/gemaraproj/grc-store-clientkit`. `README.md` is the
fuller overview — point there.

**Key principle: this is the client half, `grc-store-protocol` is the contract half.** Wire types,
constants, and pure functions go in the protocol module (zero-dep, enforced). Code that touches the
network, the disk, or a credential goes here. Something belongs here only when **two or more client
tools must do it identically** and a subtle divergence would be invisible from either side.

## Dev loop
- `go test ./...` · `go vet ./...` · `gofmt -l .` (must print nothing)
- No Makefile, no dependencies. `go mod tidy` should stay a no-op.

## Packages
- `auth` — device-grant OIDC (RFC 8628), credential store, token resolution + refresh, GHA
  workload-OIDC fetch. Parameterized by `App{Name, TokenEnv}`.
- `trustroot` — the pinned public-good Sigstore trusted root, as bytes.

## Gotchas
- **Blast radius is three repos**: grcli, privateer-sdk, and the hub backend (`trustroot` only).
- **`trustroot/trusted_root.json` is trust material.** Rotation is now one edit here — that is the
  entire reason the package exists. Do not let a consumer re-vendor its own copy.
- **Do not add a signing-identity helper to `auth` that defaults its audience.** The hub bearer and
  the Fulcio signing token come from different issuers for different purposes; `FetchGitHubActionsToken`
  takes the audience as an argument precisely so the two can never be silently conflated.
- **Errors must not name a tool.** Sentinels carry no tool name; callers wrap with `App.LoginHint()`.
  An error telling a pvtr user to run `grcli login` is worse than no error.
- **Extraction history matters when reading the code**: where grcli and privateer-sdk had drifted,
  this module took the better half of each (pvtr's bounded poll loop and token-lifetime floor,
  grcli's injectable `Resolve` seams and device-authorization error detail). Don't "restore" a
  consumer's old behaviour without checking which side won and why.
