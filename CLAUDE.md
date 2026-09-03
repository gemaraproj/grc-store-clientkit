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
- No Makefile. `go mod tidy` should stay a no-op. The **protocol** module is the zero-dep one; this
  module carries oras-go, sigstore-go, go-gemara, and the protocol module (since v0.2.0).

## Packages
- `auth` — device-grant OIDC (RFC 8628), credential store, token resolution + refresh, GHA
  workload-OIDC fetch. Parameterized by `App{Name, TokenEnv}`.
- `hub` — hub HTTP client: discovery (cached per URL), `CIBearer` (trusted-publishing bearer in
  GitHub Actions), registry-token mint with `GrantsPush`, `VersionExists` preflight, `SyncBundle`
  and `SyncPlugin`.
- `bundle` — pack one Gemara artifact into an OCI bundle, push (remote or `PushLocal` dry-run),
  `AttachReferrer`, and `Publish`: the one publish sequence both tools share (discover → mint →
  push → sign → provenance → sync).
- `keyless` — Sigstore identity resolution (`SIGSTORE_ID_TOKEN` > GitHub Actions > browser) and the
  DSSE in-toto signer producing a Sigstore v0.3 bundle. Audience is always a parameter.
- `provenance` — SLSA v1 predicate builder, with the `Evaluator` binding for EvaluationLogs.
- `trustroot` — the pinned public-good Sigstore trusted root, as bytes.

## Gotchas
- **Blast radius is three repos**: grcli, privateer-sdk, and the hub backend (`trustroot` only).
- **`trustroot/trusted_root.json` is trust material.** Rotation is now one edit here — that is the
  entire reason the package exists. Do not let a consumer re-vendor its own copy.
- **Do not add a signing-identity helper to `auth` that defaults its audience.** The hub bearer and
  the Fulcio signing token come from different issuers for different purposes; `FetchGitHubActionsToken`
  takes the audience as an argument precisely so the two can never be silently conflated.
- **`bundle.ProvenanceArtifactType` mirrors the ruled `mediatype.ProvenanceBundle`.** Switch to the
  protocol import once that module tags it; the value must never differ.
- **Env overrides are one shared `GRC_STORE_*` family** (`_FULCIO_URL`, `_REKOR_URL`,
  `_REGISTRY_TOKEN` / `_USERNAME` / `_PASSWORD`), read by this module. Per-tool `App.TokenEnv` is
  separate: the hub bearer is a per-tool credential, these are per-environment.
- **Errors must not name a tool.** Sentinels carry no tool name; callers wrap with `App.LoginHint()`.
  An error telling a pvtr user to run `grcli login` is worse than no error.
- **Extraction history matters when reading the code**: where grcli and privateer-sdk had drifted,
  this module took the better half of each (pvtr's bounded poll loop and token-lifetime floor,
  grcli's injectable `Resolve` seams and device-authorization error detail). Don't "restore" a
  consumer's old behaviour without checking which side won and why.
