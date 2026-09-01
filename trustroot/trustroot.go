// SPDX-License-Identifier: Apache-2.0

// Package trustroot carries the pinned public-good Sigstore trusted root
// (Fulcio / Rekor / CTFE) shared by every grc.store component that verifies a
// keyless signature: grcli, privateer-sdk, and the hub backend.
//
// Pinning the root — rather than fetching it live over TUF — makes verification
// offline and deterministic: the binary self-contains its trust material. The
// point of holding it HERE is that the three components previously shipped three
// byte-identical copies, which meant three separate rotation obligations and
// three chances to miss one. A signature one component accepts must be a
// signature the others accept; a divergent root is the one way that can silently
// stop being true.
//
// This package deliberately exposes bytes and nothing else. Each consumer keeps
// its own verifier and its own identity policy — grcli pins the expected SAN +
// issuer, while the hub and privateer-sdk TOFU-pin on first sight (ADR-0034
// decision 7). Only the trust material is shared, not the policy.
//
// OPERATIONAL OBLIGATION: when the public-good root rotates, update
// trusted_root.json here and release a new version. That is now the single edit
// it always should have been.
package trustroot

import _ "embed"

//go:embed trusted_root.json
var pinned []byte

// Bytes returns the pinned public-good Sigstore trusted root as JSON, in the
// form sigstore-go's root.NewTrustedRootFromJSON expects.
//
// The caller gets a copy: the embedded bytes are process-wide trust material and
// handing out an aliased slice would let any consumer mutate what every other
// verifier in the process trusts.
func Bytes() []byte {
	out := make([]byte, len(pinned))
	copy(out, pinned)
	return out
}
