package cvedata

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadKEVGzip exercises the .gz branch of LoadKEV: a genuinely
// gzip-compressed catalog decodes exactly like the plain-JSON path.
func TestLoadKEVGzip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_exploited_vulnerabilities.json.gz")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(sampleKEV)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	cat, err := LoadKEV(path)
	if err != nil {
		t.Fatalf("LoadKEV(gzip): %v", err)
	}
	if cat.Count() != 2 {
		t.Errorf("Count() = %d, want 2", cat.Count())
	}
}

// TestLoadKEVGzipUppercaseExtension confirms the .GZ suffix check is
// case-insensitive.
func TestLoadKEVGzipUppercaseExtension(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.JSON.GZ")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(sampleKEV)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	cat, err := LoadKEV(path)
	if err != nil {
		t.Fatalf("LoadKEV(.GZ): %v", err)
	}
	if cat.Count() != 2 {
		t.Errorf("Count() = %d, want 2", cat.Count())
	}
}

// TestLoadKEVBadGzipMagic confirms a .gz-suffixed file that isn't actually
// gzip data surfaces the gzip error, rather than silently falling through to
// the plain-JSON decoder.
func TestLoadKEVBadGzipMagic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.json.gz")
	if err := os.WriteFile(path, []byte("not gzip data"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadKEV(path); err == nil {
		t.Error("expected gzip error for non-gzip .gz file")
	}
}

// TestLoadKEVRejectsGzipBomb covers internal-cvedata-01-02: a KEV catalog
// whose compressed size is tiny but decompresses to more than
// maxDecompressedFeedBytes must be rejected rather than decoded fully into
// memory. Shrinks the cap so the fixture doesn't need to be gigabyte-scale.
func TestLoadKEVRejectsGzipBomb(t *testing.T) {
	withShrunkFeedCap(t, 1024) // 1KiB — small enough to test cheaply

	dir := t.TempDir()
	path := filepath.Join(dir, "bomb.json.gz")

	// Otherwise-valid KEV JSON with a large, highly compressible padding field
	// (json.Decode ignores fields it doesn't recognize) — well past the
	// shrunk cap once decompressed, but the compressed form is tiny.
	payload := `{"catalogVersion":"x","dateReleased":"2026-01-01","vulnerabilities":[],"padding":"` +
		strings.Repeat("a", 10*1024) + `"}`
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadKEV(path); err == nil {
		t.Error("expected LoadKEV to reject a catalog exceeding the decompressed size cap")
	}
}
