package share

// wontfix_spec_test.go — specification test for a finding closed WONT_FIX in
// the adversarial review (VERIFICATION-2026-08.md §8, re-framed for release in
// RELEASE-DECISIONS-v1.md). This pins a DECIDED behaviour, not a bug hunt. If
// it fails, either the behaviour drifted or the decision changed — revisit
// the decision before "fixing" the code to make it pass.

import (
	"strings"
	"testing"
)

// TestSpec_InternalShare0102_DecodeHasNoAuthenticityBinding:
// internal-share-01-02 was closed WONT_FIX because closing it needs a
// key-distribution design (HMAC or signature, and where the trust anchor
// lives) that is a product/security-architecture decision beyond a
// mechanical remediation pass — see RELEASE-DECISIONS-v1.md's Option C.
// Pending that decision, Decode() deliberately checks only that a blob is
// WELL-FORMED (base64 decodes, gzip CRC checks out, size under the cap) —
// never that it actually came from a genuine `dsd health --blob` run on a
// real host. A hand-crafted payload with fabricated content, wrapped in the
// same envelope anyone can reproduce with gzip+base64, must decode
// successfully and identically to a genuine report.
//
// cmd/decode.go's WithDecodeDisclosure (see cmd/decode_test.go's
// TestRunDecode_JSONDisclosesUnverifiedAuthenticity and its text-mode
// sibling) is the mitigation actually shipped for this finding — an INFO
// disclosure at render time, not a change to Decode() itself. This test
// covers the layer that disclosure sits on top of: Decode() has no way to
// tell a forged blob from a genuine one, by design, today.
func TestSpec_InternalShare0102_DecodeHasNoAuthenticityBinding(t *testing.T) {
	t.Parallel()

	genuinePayload := []byte(`{"hostname":"web01.prod","verdict":"CRIT","insights":[{"check":"Disk","level":"CRIT","message":"sda full"}]}`)
	forgedPayload := []byte(`{"hostname":"web01.prod","verdict":"OK","insights":[]}`)

	genuineBlob := Encode(genuinePayload)
	forgedBlob := Encode(forgedPayload) // anyone can produce this — Encode is a pure, keyless function

	genuineOut, err := Decode(genuineBlob)
	if err != nil {
		t.Fatalf("Decode(genuine): %v", err)
	}
	forgedOut, err := Decode(forgedBlob)
	if err != nil {
		t.Fatalf("Decode(forged) returned an error — if Decode now rejects a well-formed-but-fabricated "+
			"payload, internal-share-01-02 has been fixed (a real authenticity check exists); revisit the "+
			"decision doc, don't just relax this test: %v", err)
	}

	if string(genuineOut) != string(genuinePayload) {
		t.Fatalf("genuine round-trip mismatch: got %s want %s", genuineOut, genuinePayload)
	}
	if string(forgedOut) != string(forgedPayload) {
		t.Fatalf("forged round-trip mismatch: got %s want %s", forgedOut, forgedPayload)
	}
	// The point of the finding: a forged blob decodes exactly as cleanly as a
	// genuine one — Decode() has no signal to distinguish them.
	if !strings.Contains(string(forgedOut), `"verdict":"OK"`) {
		t.Fatalf("expected the forged, fabricated verdict to decode verbatim (proving no authenticity check), got: %s", forgedOut)
	}
}
