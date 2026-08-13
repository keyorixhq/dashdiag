package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMain widens validateAssetURL to accept the loopback, plain-http
// addresses httptest.NewServer binds to, so the package's many existing
// fixtures (which point Asset.URL at a local httptest server) keep
// exercising the real download path through
// httpGet/fetchBytes/downloadToTemp instead of every individual test needing
// its own workaround. This does not weaken validateAssetURL's production
// behaviour: both relaxations are test-binary-only (requireHTTPSAssetURL,
// the 127.0.0.1 allowlist entry) and the shipped defaults never change.
func TestMain(m *testing.M) {
	assetURLAllowedHosts["127.0.0.1"] = true
	requireHTTPSAssetURL = false
	os.Exit(m.Run())
}

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

	// This test exercises the download/checksum/replace path, not signature
	// verification (that's covered separately by TestVerifyChecksumsSignature) —
	// disable the real embedded key so a fixture release with no
	// checksums.txt.minisig isn't rejected as unsigned.
	oldKey := signingPublicKey
	signingPublicKey = ""
	defer func() { signingPublicKey = oldKey }()

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

	// Isolate this test to the checksum path, not signature verification (see
	// the same override in TestApply_EndToEnd).
	oldKey := signingPublicKey
	signingPublicKey = ""
	defer func() { signingPublicKey = oldKey }()

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
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch error, got: %v", err)
	}
	// The original binary must be untouched.
	got, _ := os.ReadFile(target)
	if string(got) != "old" {
		t.Errorf("binary was replaced despite bad checksum: %q", got)
	}
}

// TestValidateAssetURL_RejectsUntrustedHost is a regression guard for
// internal-selfupdate-01-03: Asset.URL (browser_download_url) comes straight
// from the GitHub API response with no host/scheme validation, so a
// compromised release origin could point an asset at an arbitrary internal
// or attacker-chosen endpoint and dsd would issue a blind outbound GET at it
// during `dsd update`. validateAssetURL must reject anything that isn't an
// https:// GitHub release host, independent of the test-binary relaxations
// TestMain applies for httptest fixtures.
func TestValidateAssetURL_RejectsUntrustedHost(t *testing.T) {
	oldHTTPS, oldHosts := requireHTTPSAssetURL, assetURLAllowedHosts
	requireHTTPSAssetURL = true
	assetURLAllowedHosts = map[string]bool{
		"github.com":                           true,
		"objects.githubusercontent.com":        true,
		"release-assets.githubusercontent.com": true,
	}
	t.Cleanup(func() {
		requireHTTPSAssetURL = oldHTTPS
		assetURLAllowedHosts = oldHosts
	})

	bad := []string{
		"https://evil.example.com/dsd-linux-amd64", // untrusted host
		"http://github.com/keyorixhq/dashdiag/x",   // right host, wrong scheme
		"http://169.254.169.254/latest/meta-data/", // cloud metadata SSRF target
		"https://github.com.evil.example.com/x",    // lookalike host
		"not-a-url\x7f",                            // unparsable
	}
	for _, u := range bad {
		if err := validateAssetURL(u); err == nil {
			t.Errorf("validateAssetURL(%q) = nil, want an error", u)
		}
	}

	good := []string{
		"https://github.com/keyorixhq/dashdiag/releases/download/v1.0.0/dsd-linux-amd64",
		"https://objects.githubusercontent.com/github-production-release-asset/x",
	}
	for _, u := range good {
		if err := validateAssetURL(u); err != nil {
			t.Errorf("validateAssetURL(%q) = %v, want nil", u, err)
		}
	}
}

// TestApply_RejectsAttackerControlledAssetURL is an end-to-end regression
// guard for the same finding: even when checksums.txt is fetched fine from a
// trusted-for-the-test host, Apply must refuse to dial an untrusted bin.URL
// rather than silently attempting the request. The "attacker" server is a
// real, local, listening HTTP server (so a hit is genuinely observable) bound
// to 127.0.0.2 rather than 127.0.0.1 -- a different literal host string from
// the one TestMain allowlists for ordinary fixtures, so the allowlist can
// actually tell "trusted test server" and "attacker server" apart. Both
// addresses are loopback-only; no real network egress is possible even if
// the fix under test were absent.
func TestApply_RejectsAttackerControlledAssetURL(t *testing.T) {
	oldKey := signingPublicKey
	signingPublicKey = ""
	defer func() { signingPublicKey = oldKey }()

	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("127.0.0.2 unavailable in this sandbox: %v", err)
	}
	var attackerHit bool
	attacker := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attackerHit = true
		w.WriteHeader(http.StatusOK)
	}))
	_ = attacker.Listener.Close()
	attacker.Listener = ln
	attacker.Start()
	defer attacker.Close()

	sumsAssetName := AssetName()
	mux := http.NewServeMux()
	mux.HandleFunc("/sums", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "aaaa  %s\n", sumsAssetName)
	})
	srv := httptest.NewServer(mux) // 127.0.0.1 — allowlisted by TestMain
	defer srv.Close()

	rel := &Release{TagName: "v1", Assets: []Asset{
		{Name: sumsAssetName, URL: attacker.URL + "/bin"},
		{Name: "checksums.txt", URL: srv.URL + "/sums"},
	}}

	if _, err := Apply(context.Background(), rel); err == nil {
		t.Fatal("expected Apply to reject the attacker-controlled asset URL")
	}
	if attackerHit {
		t.Error("Apply dialed the attacker-controlled asset URL instead of rejecting it upfront")
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
