# grc-store-clientkit

Apache-2.0 Go module holding the **client-side machinery shared by grc.store publishing tools** —
today `grcli` and `privateer-sdk` (pvtr), which had independently grown near-identical copies of it.

Module: `github.com/gemaraproj/grc-store-clientkit`

## What belongs here

This is the counterpart to [`grc-store-protocol`][protocol], and the split between them is the point:

| | `grc-store-protocol` | `grc-store-clientkit` (this repo) |
|---|---|---|
| Holds | the **wire contract** — types, constants, pure functions | the **client behaviour** that acts on it |
| Dependencies | zero, enforced in CI | allowed — oras-go, sigstore-go, go-gemara, the protocol module |
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
- **`hub`** — the hub's publish-side HTTP surface: discovery, the GitHub Actions trusted-publishing
  bearer (`CIBearer`), registry-token mint with a push-grant check, the immutable-version preflight,
  and the bundle + plugin sync routes.
- **`bundle`** — pack one artifact into a Gemara OCI bundle, push it (or write an OCI layout for a
  dry run), attach OCI 1.1 referrers, and `Publish`: the full sequence in the one order both tools
  must share, fail-closed before any bytes move if the caller cannot push.
- **`keyless`** — the Sigstore signing identity (explicit token, GitHub Actions, or browser) and a
  DSSE in-toto signer emitting a Sigstore v0.3 bundle — the shared signed shape.
- **`provenance`** — the SLSA v1 predicate a publish embeds and signs, including the evaluator
  binding that ties an EvaluationLog to the plugin that produced it.
- **`trustroot`** — the pinned public-good Sigstore trusted root, as bytes. Previously three
  byte-identical copies across grcli, privateer-sdk, and the hub backend; now one rotation obligation.

## Dev loop

```
go test -race ./...   # add -count=1 to skip the cache
go vet ./...
gofmt -l .            # must print nothing
golangci-lint run ./...
```

CI runs those on every PR. A second, **advisory** workflow reports an API diff against the last tag
and builds both consumer repos against the PR commit — it never blocks a merge, because on v0.x a
breaking change can be the right call and a consumer's main can be red on its own.

No Makefile. `go mod tidy` should stay a no-op. The protocol module is the zero-dependency one; this
module carries oras-go, sigstore-go, go-gemara, and the protocol module, and adding anything further
is a decision worth making deliberately rather than by accident.

## Gotchas

- **Consumers are grcli, privateer-sdk, and (for `trustroot` only) the hub backend.** A breaking
  change ripples to all three; coordinate releases.
- **`trustroot` is trust material, not configuration.** When the public-good Sigstore root rotates,
  update `trustroot/trusted_root.json` and cut a release. The whole reason it lives here is that
  three separate copies meant three chances to miss that.
- **The bearer token this module resolves is not a signing identity.** Fulcio trusts public OIDC
  issuers, not the grc.store auth server. `auth.Resolve` gets you a token for the hub and registry;
  keyless signing needs a separate token, from a separate issuer, with audience `sigstore` —
  that is `keyless.Identity`, and `bundle.Publish` takes the two separately on purpose.
- **Env overrides are one `GRC_STORE_*` family** (`GRC_STORE_FULCIO_URL`, `GRC_STORE_REKOR_URL`,
  `GRC_STORE_REGISTRY_TOKEN` / `_USERNAME` / `_PASSWORD`), read here so every tool honours them
  identically. Per-tool token env vars (`GRCLI_TOKEN`, `PVTR_TOKEN`) stay per-tool.
- **Credential files are per-tool by design.** grcli and pvtr authenticate against the same issuer,
  but one tool clobbering the other's tokens on logout is a genuinely confusing failure.
- Pre-v1.0.0 (v0.x).

[protocol]: https://github.com/revanite-io/grc-store-protocol
