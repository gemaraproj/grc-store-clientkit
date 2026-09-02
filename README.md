# grc-store-clientkit

Apache-2.0 Go module holding the **client-side machinery shared by grc.store publishing tools** —
today `grcli` and `privateer-sdk` (pvtr), which had independently grown near-identical copies of it.

Module: `github.com/gemaraproj/grc-store-clientkit`

## What belongs here

This is the counterpart to [`grc-store-protocol`][protocol], and the split between them is the point:

| | `grc-store-protocol` | `grc-store-clientkit` (this repo) |
|---|---|---|
| Holds | the **wire contract** — types, constants, pure functions | the **client behaviour** that acts on it |
| Dependencies | zero, enforced in CI | allowed (stdlib only today) |
| Network / disk | never | yes — that is what it is for |

A thing belongs here when **more than one client tool must do it identically**, and getting it
subtly different would produce a bug nobody can see from either side alone: an expired token that
refresh-loops, a credential file at 0644, a trust root that one tool rotated and another didn't.

It does **not** belong here if it is a wire shape (that is `grc-store-protocol`), if only one tool
does it, or if it is user-facing presentation — the CLIs own their own output.

## Packages

- **`auth`** — OIDC device-authorization grant (RFC 8628), the on-disk credential store, token
  resolution with refresh, and the GitHub Actions workload-OIDC fetch. Parameterized by an `App`
  (`{Name, TokenEnv, TokenFlag}`) so each tool keeps its own credential file and its own name in error messages.
- **`trustroot`** — the pinned public-good Sigstore trusted root, as bytes. Previously three
  byte-identical copies across grcli, privateer-sdk, and the hub backend; now one rotation obligation.

## Dev loop

```
go test ./...    # add -count=1 to skip the cache
go vet ./...
gofmt -l .       # must print nothing
```

No Makefile. `go mod tidy` should stay a no-op — this module has no dependencies today, and adding
one is a decision worth making deliberately rather than by accident.

## Gotchas

- **Consumers are grcli, privateer-sdk, and (for `trustroot` only) the hub backend.** A breaking
  change ripples to all three; coordinate releases.
- **`trustroot` is trust material, not configuration.** When the public-good Sigstore root rotates,
  update `trustroot/trusted_root.json` and cut a release. The whole reason it lives here is that
  three separate copies meant three chances to miss that.
- **The bearer token this module resolves is not a signing identity.** Fulcio trusts public OIDC
  issuers, not the grc.store auth server. `auth.Resolve` gets you a token for the hub and registry;
  keyless signing needs a separate token, from a separate issuer, with audience `sigstore`.
- **Credential files are per-tool by design.** grcli and pvtr authenticate against the same issuer,
  but one tool clobbering the other's tokens on logout is a genuinely confusing failure.
- Pre-v1.0.0 (v0.x).

[protocol]: https://github.com/revanite-io/grc-store-protocol
