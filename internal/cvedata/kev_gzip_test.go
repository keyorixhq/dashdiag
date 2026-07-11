package cvedata

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
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
