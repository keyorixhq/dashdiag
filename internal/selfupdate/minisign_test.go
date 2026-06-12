package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// signMinisign produces a minisign public-key line and a .minisig over file,
// matching the on-disk format the real `minisign` tool emits, so the verifier is
// tested against real-shaped input. prehashed selects the "ED" (Blake2b) vs "Ed"
// (raw) algorithm.
func signMinisign(t *testing.T, file []byte, trustedComment string, prehashed bool) (pubLine, sig string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var keyID [8]byte
	if _, err := rand.Read(keyID[:]); err != nil {
		t.Fatal(err)
	}

	var algo [2]byte
	var msg []byte
	if prehashed {
		algo = [2]byte{'E', 'D'}
		h := blake2b.Sum512(file)
		msg = h[:]
	} else {
		algo = [2]byte{'E', 'd'}
		msg = file
	}
	fileSig := ed25519.Sign(priv, msg)
	globalSig := ed25519.Sign(priv, append(append([]byte(nil), fileSig...), []byte(trustedComment)...))

	pubRaw := append([]byte{'E', 'd'}, append(keyID[:], pub...)...)
	pubLine = "untrusted comment: test\n" + base64.StdEncoding.EncodeToString(pubRaw) + "\n"

	sigRaw := append(algo[:], append(keyID[:], fileSig...)...)
	sig = strings.Join([]string{
		"untrusted comment: signature",
		base64.StdEncoding.EncodeToString(sigRaw),
		"trusted comment: " + trustedComment,
		base64.StdEncoding.EncodeToString(globalSig),
		"",
	}, "\n")
	return pubLine, sig
}

func TestVerifyMinisign(t *testing.T) {
	file := []byte("abc123  dsd-linux-amd64\ndef456  dsd-linux-arm64\n")

	t.Run("prehashed valid", func(t *testing.T) {
		pub, sig := signMinisign(t, file, "timestamp:1 file:checksums.txt", true)
		if err := verifyMinisign(pub, file, []byte(sig)); err != nil {
			t.Fatalf("valid prehashed signature rejected: %v", err)
		}
	})

	t.Run("legacy raw valid", func(t *testing.T) {
		pub, sig := signMinisign(t, file, "x", false)
		if err := verifyMinisign(pub, file, []byte(sig)); err != nil {
			t.Fatalf("valid legacy signature rejected: %v", err)
		}
	})

	t.Run("tampered file rejected", func(t *testing.T) {
		pub, sig := signMinisign(t, file, "x", true)
		if err := verifyMinisign(pub, []byte("evil  dsd-linux-amd64\n"), []byte(sig)); err == nil {
			t.Fatal("tampered file accepted")
		}
	})

	t.Run("wrong key rejected", func(t *testing.T) {
		_, sig := signMinisign(t, file, "x", true)
		otherPub, _ := signMinisign(t, file, "x", true) // a different keypair's pub line
		if err := verifyMinisign(otherPub, file, []byte(sig)); err == nil {
			t.Fatal("signature from a different key accepted")
		}
	})

	t.Run("tampered trusted comment rejected", func(t *testing.T) {
		pub, sig := signMinisign(t, file, "original", true)
		bad := strings.Replace(sig, "trusted comment: original", "trusted comment: forged", 1)
		if err := verifyMinisign(pub, file, []byte(bad)); err == nil {
			t.Fatal("forged trusted comment accepted")
		}
	})

	t.Run("garbage signature rejected", func(t *testing.T) {
		pub, _ := signMinisign(t, file, "x", true)
		for _, bad := range []string{"", "not base64", "untrusted comment: x\n!!!\ntrusted comment: y\n!!!\n"} {
			if err := verifyMinisign(pub, file, []byte(bad)); err == nil {
				t.Fatalf("garbage signature %q accepted", bad)
			}
		}
	})

	t.Run("empty key is an error (inert guard handled by caller)", func(t *testing.T) {
		_, sig := signMinisign(t, file, "x", true)
		if err := verifyMinisign("", file, []byte(sig)); err == nil {
			t.Fatal("empty public key accepted")
		}
	})
}

// TestVerifyChecksumsSignature covers the updater's release-authenticity gate:
// inert with no key, fail-closed on a missing or bad signature, pass on a valid one.
func TestVerifyChecksumsSignature(t *testing.T) {
	sums := []byte("abc  dsd-linux-amd64\n")
	pub, sig := signMinisign(t, sums, "file:checksums.txt", true)

	mux := http.NewServeMux()
	mux.HandleFunc("/sig", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, sig) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	signedRel := &Release{TagName: "v1", Assets: []Asset{
		{Name: "checksums.txt.minisig", URL: srv.URL + "/sig"},
	}}
	unsignedRel := &Release{TagName: "v1", Assets: []Asset{}}
	ctx := context.Background()

	t.Run("no key configured is inert (nil)", func(t *testing.T) {
		if err := verifyChecksumsSignatureKey(ctx, "", unsignedRel, sums); err != nil {
			t.Fatalf("inert path returned error: %v", err)
		}
	})
	t.Run("key set, valid signature passes", func(t *testing.T) {
		if err := verifyChecksumsSignatureKey(ctx, pub, signedRel, sums); err != nil {
			t.Fatalf("valid signature rejected: %v", err)
		}
	})
	t.Run("key set, missing signature fails closed", func(t *testing.T) {
		if err := verifyChecksumsSignatureKey(ctx, pub, unsignedRel, sums); err == nil {
			t.Fatal("unsigned release accepted despite a configured key")
		}
	})
	t.Run("key set, tampered checksums rejected", func(t *testing.T) {
		if err := verifyChecksumsSignatureKey(ctx, pub, signedRel, []byte("evil  dsd-linux-amd64\n")); err == nil {
			t.Fatal("tampered checksums.txt accepted")
		}
	})
}
