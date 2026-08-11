package selfupdate

import (
	"strings"
	"testing"
)

// Artifacts produced by the REAL `minisign` tool (v0.11), not our Go re-implementation
// of the signing format. This guards against the verifier's understanding of the
// on-disk format drifting from the tool that actually signs releases in CI — drift
// would make `dsd update` reject a legitimately-signed release (or, worse, mis-accept).
// Regenerate:
//
//	minisign -G -W -p k.pub -s k.sec
//	printf 'abc123  dsd-linux-amd64\ndef456  dsd-linux-arm64\n' > checksums.txt
//	minisign -S -s k.sec -t 'dsd release v9.9.9 checksums' -m checksums.txt
const realMinisignPub = `untrusted comment: minisign public key FBCADA83252B6C2F
RWQvbCslg9rK+03bPSMSUGZb7yOI1k9KiwBdoA+LsyCRSgbgAdvXk5CQ`

const realMinisignSig = `untrusted comment: signature from minisign secret key
RUQvbCslg9rK+1meqVjfXEGLd3x87u/FzrjyQKlvhx7CGXBFdMXLzZEYbE/7APyE5G/z6HknDgNnsTI/lqjakw88gxW6aYT5cgs=
trusted comment: dsd release v9.9.9 checksums
I62X+M97Of82IfiOEvID/iTB4kOdY5wUXJF7WneKlOu8VJ7L09h5bJRBSM89ZdgtVi+MhshrvhAMV82R6DrNBw==
`

var realMinisignFile = []byte("abc123  dsd-linux-amd64\ndef456  dsd-linux-arm64\n")

func TestVerifyMinisignRealTool(t *testing.T) {
	// The genuine signature from the real minisign tool must verify, and the
	// returned trusted comment must be usable for the anti-rollback release
	// binding (trustedCommentNamesRelease) — this fixture's comment names
	// "v9.9.9", matching the real release workflow's `-t "dsd <tag> checksums"`.
	comment, err := verifyMinisign(realMinisignPub, realMinisignFile, []byte(realMinisignSig))
	if err != nil {
		t.Fatalf("real minisign (v0.11) signature REJECTED by verifier — format drift: %v", err)
	}
	if comment != "dsd release v9.9.9 checksums" {
		t.Errorf("returned comment = %q, want the real fixture's trusted comment", comment)
	}
	if !trustedCommentNamesRelease(comment, "v9.9.9") {
		t.Error("trustedCommentNamesRelease should match the real fixture's tag field")
	}
	if trustedCommentNamesRelease(comment, "v10.0.0") {
		t.Error("trustedCommentNamesRelease should not match a tag the real fixture doesn't name")
	}
	// Tampered file → reject.
	if _, err := verifyMinisign(realMinisignPub, []byte("evil  dsd-linux-amd64\n"), []byte(realMinisignSig)); err == nil {
		t.Fatal("verifier accepted a real signature over a tampered file")
	}
	// Forged trusted comment → the global signature must fail.
	forged := strings.Replace(realMinisignSig, "v9.9.9", "v10.0.0", 1)
	if _, err := verifyMinisign(realMinisignPub, realMinisignFile, []byte(forged)); err == nil {
		t.Fatal("verifier accepted a real signature with a forged trusted comment")
	}
}
