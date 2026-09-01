// SPDX-License-Identifier: Apache-2.0

package trustroot

import (
	"encoding/json"
	"testing"
)

func TestBytesIsParseableTrustedRoot(t *testing.T) {
	var doc struct {
		MediaType string `json:"mediaType"`
	}
	if err := json.Unmarshal(Bytes(), &doc); err != nil {
		t.Fatalf("pinned trusted root is not valid JSON: %v", err)
	}
	if doc.MediaType == "" {
		t.Error("pinned trusted root has no mediaType; sigstore-go will reject it")
	}
}

// The embedded bytes are process-wide trust material. Handing out an aliased
// slice would let any consumer mutate what every verifier in the process trusts.
func TestBytesReturnsACopy(t *testing.T) {
	first := Bytes()
	first[0] = 'X'
	if second := Bytes(); second[0] == 'X' {
		t.Fatal("Bytes() aliases the embedded trust root; a caller can corrupt it for everyone")
	}
}
