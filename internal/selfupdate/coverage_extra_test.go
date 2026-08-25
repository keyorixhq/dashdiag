package selfupdate

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestVerifyMinisign_MoreErrorPaths exercises the remaining branches of
// verifyMinisign that TestVerifyMinisign doesn't reach: a signature payload of
// the wrong decoded length, an unsupported algorithm tag, and an invalid
// base64 global-signature line.
func TestVerifyMinisign_MoreErrorPaths(t *testing.T) {
	t.Parallel()
	file := []byte("abc123  dsd-linux-amd64\n")

	t.Run("signature decodes but is not 74 bytes", func(t *testing.T) {
		t.Parallel()
		pub, sig := signMinisign(t, file, "x", true)
		// Replace the data line (index 1) with a short-but-valid base64 blob.
		lines := strings.Split(sig, "\n")
		lines[1] = "AAAA" // decodes to 3 bytes, far short of 74
		bad := strings.Join(lines, "\n")
		if _, err := verifyMinisign(pub, file, []byte(bad)); err == nil {
			t.Fatal("expected error for wrong-length signature payload")
		}
	})

	t.Run("unsupported algorithm tag", func(t *testing.T) {
		t.Parallel()
		pub, sig := signMinisign(t, file, "x", true)
		lines := strings.Split(sig, "\n")
		raw, err := base64.StdEncoding.DecodeString(lines[1])
		if err != nil {
			t.Fatalf("decoding fixture signature: %v", err)
		}
		raw[0], raw[1] = 'X', 'X' // corrupt the 2-byte algo tag
		lines[1] = base64.StdEncoding.EncodeToString(raw)
		bad := strings.Join(lines, "\n")
		if _, err := verifyMinisign(pub, file, []byte(bad)); err == nil {
			t.Fatal("expected error for unsupported algorithm tag")
		}
	})

	t.Run("invalid global signature base64", func(t *testing.T) {
		t.Parallel()
		pub, sig := signMinisign(t, file, "x", true)
		lines := strings.Split(sig, "\n")
		lines[3] = "not-base64!!!"
		bad := strings.Join(lines, "\n")
		if _, err := verifyMinisign(pub, file, []byte(bad)); err == nil {
			t.Fatal("expected error for invalid global signature base64")
		}
	})
}

// TestVerifyChecksumsSignatureKey_SignatureFetchFails covers the branch where
// the release is signed (asset present) but downloading the .minisig body
// itself fails.
func TestVerifyChecksumsSignatureKey_SignatureFetchFails(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rel := &Release{TagName: "v1", Assets: []Asset{
		{Name: "checksums.txt.minisig", URL: srv.URL},
	}}
	err := verifyChecksumsSignatureKey(context.Background(), "some-key", rel, []byte("sums"))
	if err == nil {
		t.Fatal("expected error when fetching the signature body fails")
	}
}

// TestDownloadToTemp_CopyError covers the io.Copy error branch in
// downloadToTemp: the server advertises a Content-Length larger than what it
// actually sends, then closes the connection, producing an unexpected-EOF
// error while streaming the body to disk.
func TestDownloadToTemp_CopyError(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Drain the request line/headers minimally, then reply with a
		// Content-Length that promises more bytes than are actually sent,
		// followed by closing the connection early.
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nshort"))
	}()
	defer ln.Close()

	url := "http://" + ln.Addr().String() + "/asset"
	dir := t.TempDir()
	_, _, err = downloadToTemp(context.Background(), url, dir)
	if err == nil {
		t.Fatal("expected an error when the body is shorter than Content-Length promised")
	}
}

// TestFetchBytes_ReadError covers fetchBytes' io.ReadAll error branch, same
// technique as TestDownloadToTemp_CopyError above: a raw listener advertises
// a Content-Length larger than what it actually sends, then closes early.
func TestFetchBytes_ReadError(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nshort"))
	}()
	defer ln.Close()

	url := "http://" + ln.Addr().String() + "/asset"
	_, err = fetchBytes(context.Background(), url)
	if err == nil {
		t.Fatal("expected an error when the body is shorter than Content-Length promised")
	}
}

// TestSaveCache_WriteFileFails covers the os.WriteFile error branch in
// saveCache: MkdirAll succeeds, but the ".tmp" staging path is itself a
// pre-existing directory, so WriteFile fails.
// no t.Parallel(): mutates package-level cachePath, matching the convention
// in TestDownloadToTemp_CloseError below (package-level closeFile).
func TestSaveCache_WriteFileFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "update-check.json")
	// Pre-create the ".tmp" staging path as a directory so WriteFile fails.
	if err := os.MkdirAll(target+".tmp", 0o750); err != nil {
		t.Fatal(err)
	}
	old := cachePath
	cachePath = func() string { return target }
	t.Cleanup(func() { cachePath = old })

	err := saveCache(&checkCache{CheckedAt: time.Now().UTC(), LatestVersion: "v1.0.0"})
	if err == nil {
		t.Fatal("expected saveCache to fail when the .tmp staging path is a directory")
	}
}

// TestDownloadToTemp_CloseError covers the closeFile error branch in
// downloadToTemp: after io.Copy succeeds the overridden closeFile returns an
// error, so downloadToTemp must remove the staged file and propagate the error.
func TestDownloadToTemp_CloseError(t *testing.T) {
	// no t.Parallel(): mutates package-level closeFile, matching the convention
	// in selfupdate_test.go and selfupdate_extra_test.go.

	payload := []byte("file-content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	closeErr := errors.New("close: I/O error")
	oldClose := closeFile
	closeFile = func(f *os.File) error {
		_ = f.Close()
		return closeErr
	}
	t.Cleanup(func() { closeFile = oldClose })

	dir := t.TempDir()
	_, _, err := downloadToTemp(context.Background(), srv.URL, dir)
	if err == nil || !strings.Contains(err.Error(), "close: I/O error") {
		t.Fatalf("expected close error, got %v", err)
	}
}
