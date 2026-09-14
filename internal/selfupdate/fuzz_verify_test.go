package selfupdate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// This file fuzzes verifyMinisign — the ONLY seam in dashdiag that makes a
// trust decision on attacker-controlled bytes (`dsd update` trusts a hash in
// checksums.txt only after this verifies the file was signed by the project
// key). The oracle is a signature-integrity invariant, sound because the
// harness controls the trust root: it holds a freshly generated Ed25519 secret
// key, so no fuzz-mutated input can forge a second valid signature. The
// property under test is not merely "doesn't panic" (though that too) but "a
// signature binds exactly the artifact it was made over, and nothing else."

// fuzzSignMinisign reproduces the minisign SIGNING side (the CI half we do not
// ship in the binary) so a fuzz target can mint a genuine signature to verify
// against. It takes testing.TB (not *testing.T, unlike minisign_test.go's
// signMinisign) so it is callable from *testing.F fuzz setup. Deliberately NOT
// a reimplementation of verifyMinisign (signing != verifying), so the oracle
// built on it is not circular.
func fuzzSignMinisign(tb testing.TB, file []byte, trustedComment string) (pubLine string, sigFile []byte) {
	tb.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("keygen: %v", err)
	}
	var keyID [8]byte
	if _, err := rand.Read(keyID[:]); err != nil {
		tb.Fatalf("keyid: %v", err)
	}
	rawPub := append(append([]byte("Ed"), keyID[:]...), pub...) // 2+8+32 = 42
	pubLine = base64.StdEncoding.EncodeToString(rawPub)

	h := blake2b.Sum512(file)                                   // "ED" prehashed variant
	sig := ed25519.Sign(priv, h[:])                             // 64 bytes
	sigRaw := append(append([]byte("ED"), keyID[:]...), sig...) // 2+8+64 = 74
	bound := append(append([]byte(nil), sig...), []byte(trustedComment)...)
	globalSig := ed25519.Sign(priv, bound)

	lines := []string{
		"untrusted comment: test signature",
		base64.StdEncoding.EncodeToString(sigRaw),
		"trusted comment: " + trustedComment,
		base64.StdEncoding.EncodeToString(globalSig),
	}
	return pubLine, []byte(strings.Join(lines, "\n") + "\n")
}

const fuzzTrustedComment = "dsd v1.2.3 checksums"

func fuzzSignedFile0() []byte {
	return []byte("checksums.txt contents\nabc123  dsd_linux_amd64\n")
}

// FuzzVerifyMinisign_FileBinding asserts a signature binds EXACTLY the file it
// was made over: verifyMinisign accepts a candidate file if and only if that
// file is byte-identical to the one signed. Any altered artifact (a tampered
// dsd binary or checksums.txt) that still verified would be a self-update
// signature bypass. Sound: the harness holds the only secret key, so a
// candidate != file0 cannot carry a valid signature under sigFile0.
func FuzzVerifyMinisign_FileBinding(f *testing.F) {
	file0 := fuzzSignedFile0()
	pubLine, sigFile0 := fuzzSignMinisign(f, file0, fuzzTrustedComment)

	// Positive anchor: the true file must verify and return its comment.
	if got, err := verifyMinisign(pubLine, file0, sigFile0); err != nil || got != fuzzTrustedComment {
		f.Fatalf("valid triple failed to verify: comment=%q err=%v", got, err)
	}

	f.Add(append([]byte(nil), file0...))                                // == file0 (must accept)
	f.Add([]byte("checksums.txt contents\nabc123  dsd_linux_amd64\nX")) // appended byte
	f.Add([]byte("checksums.txt contents\nabc124  dsd_linux_amd64\n"))  // one hex digit flipped
	f.Add([]byte{})
	f.Add([]byte("totally different artifact"))

	f.Fuzz(func(t *testing.T, candidate []byte) {
		_, err := verifyMinisign(pubLine, candidate, sigFile0)
		accepted := err == nil
		shouldAccept := bytes.Equal(candidate, file0)
		if accepted != shouldAccept {
			t.Fatalf("file binding broken: candidate(len=%d) accepted=%v, want %v", len(candidate), accepted, shouldAccept)
		}
	})
}

// FuzzVerifyMinisign_SigRobustness feeds arbitrary bytes as the .minisig
// against a fixed, correctly-signed file. Two properties: (1) it never panics
// on a malformed signature blob, and (2) if it accepts (nil error) it can only
// have returned the one genuine trusted comment — no crafted blob may verify
// file0 while smuggling a DIFFERENT trusted comment past the anti-rollback
// check (trustedCommentNamesRelease). Sound for the same reason: forging a
// second valid (file-sig, global-sig) pair under the harness key is infeasible.
func FuzzVerifyMinisign_SigRobustness(f *testing.F) {
	file0 := fuzzSignedFile0()
	pubLine, sigFile0 := fuzzSignMinisign(f, file0, fuzzTrustedComment)

	f.Add(append([]byte(nil), sigFile0...))
	f.Add([]byte(""))
	f.Add([]byte("untrusted comment: x\n\n\n"))
	f.Add([]byte("a\nnotbase64!!!\ntrusted comment: evil\nalsobad"))
	f.Add([]byte("a\nQQ==\ntrusted comment: evil rollback\nQQ=="))

	f.Fuzz(func(t *testing.T, sig []byte) {
		got, err := verifyMinisign(pubLine, file0, sig)
		if err == nil && got != fuzzTrustedComment {
			t.Fatalf("accepted a signature over file0 but returned comment %q, want %q — trusted-comment smuggling", got, fuzzTrustedComment)
		}
	})
}
