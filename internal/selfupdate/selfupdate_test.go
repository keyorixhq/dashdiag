package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v1.2.3", "v1.2.3", 0},
		{"1.2.3", "v1.2.3", 0},
		{"v1.2.3", "v1.2.4", -1},
		{"v1.3.0", "v1.2.9", 1},
		{"v2.0.0", "v1.9.9", 1},
		{"v0.6.1", "v0.10.0", -1},
		{"v1.2.3-rc1", "v1.2.3", 0}, // numeric parts equal; suffix ignored
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestIsNewer(t *testing.T) {
	if !IsNewer("v0.6.1", "v0.7.0") {
		t.Error("0.7.0 should be newer than 0.6.1")
	}
	if IsNewer("v0.7.0", "v0.6.1") {
		t.Error("0.6.1 is not newer than 0.7.0")
	}
	if IsNewer("v0.6.1", "v0.6.1") {
		t.Error("equal is not newer")
	}
	// dev / unparseable current must never be flagged as outdated.
	if IsNewer("dev", "v9.9.9") {
		t.Error("dev build must not nag")
	}
	if IsNewer("v0.6.1-12-gabc123", "v0.7.0") {
		t.Error("git-describe build must not be treated as a release")
	}
}

func TestAssetName(t *testing.T) {
	want := fmt.Sprintf("dsd-%s-%s", runtime.GOOS, runtime.GOARCH)
	if AssetName() != want {
		t.Errorf("AssetName() = %q, want %q", AssetName(), want)
	}
}

// TestApply_EndToEnd serves a fake binary + checksums and verifies Apply
// downloads, checksum-verifies, and atomically replaces a target file.
func TestApply_EndToEnd(t *testing.T) {
	binContent := []byte("#!/bin/sh\necho new-dsd\n")
	sum := sha256.Sum256(binContent)
	sumHex := hex.EncodeToString(sum[:])
	assetName := AssetName()

	mux := http.NewServeMux()
	mux.HandleFunc("/bin", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(binContent) })
	mux.HandleFunc("/sums", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%s  %s\n%s  other-file\n", sumHex, assetName, "deadbeef")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rel := &Release{
		TagName: "v9.9.9",
		Assets: []Asset{
			{Name: assetName, URL: srv.URL + "/bin"},
			{Name: "checksums.txt", URL: srv.URL + "/sums"},
		},
	}

	// Stage a fake "current binary" and point os.Executable at it via a copy in
	// a temp dir (Apply resolves os.Executable, so run the replacement against a
	// file we control by overriding through a symlinked exe is overkill — instead
	// verify the lower-level pieces). Here we exercise the full path by replacing
	// a target we pass in through a tiny shim.
	dir := t.TempDir()
	target := filepath.Join(dir, "dsd")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Apply uses os.Executable(); emulate by overriding via a test hook.
	oldExe := executable
	executable = func() (string, error) { return target, nil }
	defer func() { executable = oldExe }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path, err := Apply(ctx, rel)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Apply resolves symlinks (e.g. macOS /tmp → /private/tmp); compare resolved.
	wantPath, _ := filepath.EvalSymlinks(target)
	if path != wantPath {
		t.Errorf("replaced %q, want %q", path, wantPath)
	}
	got, _ := os.ReadFile(target)
	if string(got) != string(binContent) {
		t.Errorf("target not replaced with new content: %q", got)
	}
}

func TestApply_ChecksumMismatch(t *testing.T) {
	assetName := AssetName()
	mux := http.NewServeMux()
	mux.HandleFunc("/bin", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("tampered")) })
	mux.HandleFunc("/sums", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", "0000000000000000000000000000000000000000000000000000000000000000", assetName)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rel := &Release{TagName: "v9.9.9", Assets: []Asset{
		{Name: assetName, URL: srv.URL + "/bin"},
		{Name: "checksums.txt", URL: srv.URL + "/sums"},
	}}

	dir := t.TempDir()
	target := filepath.Join(dir, "dsd")
	_ = os.WriteFile(target, []byte("old"), 0o755)
	oldExe := executable
	executable = func() (string, error) { return target, nil }
	defer func() { executable = oldExe }()

	_, err := Apply(context.Background(), rel)
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	// The original binary must be untouched.
	got, _ := os.ReadFile(target)
	if string(got) != "old" {
		t.Errorf("binary was replaced despite bad checksum: %q", got)
	}
}

func TestLatestRelease_ParsesAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v1.2.3","html_url":"https://example/r","assets":[{"name":"dsd-linux-amd64","browser_download_url":"https://example/a"}]}`)
	}))
	defer srv.Close()
	oldBase := apiBase
	apiBase = srv.URL
	defer func() { apiBase = oldBase }()

	rel, err := LatestRelease(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rel.TagName != "v1.2.3" || len(rel.Assets) != 1 {
		t.Errorf("parsed release wrong: %+v", rel)
	}
}
