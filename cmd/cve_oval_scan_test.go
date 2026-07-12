package cmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// minimalUbuntuOVAL is a syntactically valid but empty Ubuntu-flavoured OVAL
// feed: sniffOVALVendor keys off the "ubuntu.com" marker in the raw content
// (not full USN semantics), so this is enough to route through
// ScanUbuntuOVALPackages — the real success path (real, read-only dpkg-query)
// — with zero definitions, i.e. "no vulnerable packages found".
const minimalUbuntuOVAL = `<?xml version="1.0"?>
<!-- generated for ubuntu.com security -->
<oval_definitions>
  <definitions></definitions>
</oval_definitions>
`

// TestRunOVALScanUbuntuEmptyFeed exercises runOVALScan's success path end to
// end against a real (if content-empty) Ubuntu OVAL feed and the host's real
// dpkg database — the branch TestRunOVALScanExplicitMissingPath/
// TestRunCVEOvalScanNoFile (cve_run_test.go) can't reach since they only
// exercise the load-failure paths.
func TestRunOVALScanUbuntuEmptyFeed(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("OVAL scan requires Linux (dpkg-query / rpm)")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ubuntu.xml")
	if err := os.WriteFile(path, []byte(minimalUbuntuOVAL), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out := captureStdout(t, func() {
		if err := runOVALScan(context.Background(), path, false); err != nil {
			t.Fatalf("runOVALScan on an empty Ubuntu feed: %v", err)
		}
	})
	if !strings.Contains(out, "No vulnerable packages found") {
		t.Errorf("an empty feed should report no vulnerable packages, got:\n%s", out)
	}
}

// TestRunOVALScanUbuntuEmptyFeedJSON exercises the --json branch of the same
// success path.
//
// NOTE (reported, not fixed — see structured output "bugs"): runOVALScan
// unconditionally prints the "🔍 OVAL scan — ..." human banner to stdout
// BEFORE checking jsonOut, so `dsd cve --oval-scan --json` emits non-JSON
// text ahead of the JSON payload — piping into `jq`/similar breaks. This
// test documents current behavior (banner + trailing JSON) rather than
// asserting the (currently false) "stdout is valid JSON" property.
func TestRunOVALScanUbuntuEmptyFeedJSON(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("OVAL scan requires Linux (dpkg-query / rpm)")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ubuntu.xml")
	if err := os.WriteFile(path, []byte(minimalUbuntuOVAL), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	out := captureStdout(t, func() {
		if err := runOVALScan(context.Background(), path, true); err != nil {
			t.Fatalf("runOVALScan --json on an empty Ubuntu feed: %v", err)
		}
	})
	if !strings.Contains(out, "null") && !strings.Contains(out, "[]") {
		t.Errorf("json mode with zero findings should emit an empty/null array, got:\n%s", out)
	}
}

// TestRunCVEInfoWithFixtures exercises runCVEInfo's "found" branches for
// OVAL sidecar discovery, the KEV catalog, and a pre-converted snapshot — all
// via HOME-relative standard paths (no root needed), isolated to a temp HOME.
func TestRunCVEInfoWithFixtures(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// OVAL sidecar (~/.dsd/oval/*.xml — any content, runCVEInfo only lists it).
	ovalDir := filepath.Join(home, ".dsd", "oval")
	if err := os.MkdirAll(ovalDir, 0o750); err != nil {
		t.Fatalf("MkdirAll oval: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ovalDir, "fixture.xml"), []byte(minimalUbuntuOVAL), 0o600); err != nil {
		t.Fatalf("WriteFile oval fixture: %v", err)
	}

	// KEV catalog (~/.dsd/kev/known_exploited_vulnerabilities.json).
	kevDir := filepath.Join(home, ".dsd", "kev")
	if err := os.MkdirAll(kevDir, 0o750); err != nil {
		t.Fatalf("MkdirAll kev: %v", err)
	}
	kevDoc := map[string]any{
		"catalogVersion": "2026.07.01",
		"dateReleased":   "2026-07-01T00:00:00Z",
		"vulnerabilities": []map[string]string{
			{"cveID": "CVE-2024-3094", "vendorProject": "xz", "product": "xz-utils",
				"vulnerabilityName": "XZ Backdoor", "dateAdded": "2024-04-01"},
		},
	}
	kevBytes, err := json.Marshal(kevDoc)
	if err != nil {
		t.Fatalf("marshal KEV fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kevDir, "known_exploited_vulnerabilities.json"), kevBytes, 0o600); err != nil {
		t.Fatalf("WriteFile kev fixture: %v", err)
	}

	// Pre-converted snapshot (~/.dsd/cvedata.json.gz).
	snapPath := filepath.Join(home, ".dsd", "cvedata.json.gz")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	snapDoc := map[string]any{
		"_generated": "2026-07-01T00:00:00Z",
		"_source":    "test-fixture",
		"cves": map[string]any{
			"CVE-2026-0001": map[string]any{"summary": "test cve", "severity": "HIGH"},
		},
	}
	snapBytes, err := json.Marshal(snapDoc)
	if err != nil {
		t.Fatalf("marshal snapshot fixture: %v", err)
	}
	if _, err := gz.Write(snapBytes); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := os.WriteFile(snapPath, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile snapshot fixture: %v", err)
	}

	out := captureStdout(t, func() { runCVEInfo() })
	if !strings.Contains(out, "fixture.xml") {
		t.Errorf("the OVAL sidecar fixture should be listed, got:\n%s", out)
	}
	if !strings.Contains(out, "2026.07.01") {
		t.Errorf("the KEV catalog version should be shown, got:\n%s", out)
	}
	if strings.Contains(out, "none found\n  Generate: make update-cve-data") {
		t.Errorf("a present snapshot must not fall through to the none-found branch, got:\n%s", out)
	}
	if !strings.Contains(out, "1 CVEs") || !strings.Contains(out, "generated 2026-07-01") {
		t.Errorf("a non-empty snapshot should render its CVE count and generation date, got:\n%s", out)
	}
}

// TestRunCVEInfoKEVLoadError covers the KEV-catalog-present-but-unparsable
// branch — distinct from both "no KEV file" and the healthy-load case in
// TestRunCVEInfoWithFixtures above.
func TestRunCVEInfoKEVLoadError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	kevDir := filepath.Join(home, ".dsd", "kev")
	if err := os.MkdirAll(kevDir, 0o750); err != nil {
		t.Fatalf("MkdirAll kev: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kevDir, "known_exploited_vulnerabilities.json"), []byte("not valid json"), 0o600); err != nil {
		t.Fatalf("WriteFile malformed kev fixture: %v", err)
	}

	out := captureStdout(t, func() { runCVEInfo() })
	if !strings.Contains(out, "could not load") {
		t.Errorf("a malformed KEV catalog should say it could not be loaded, got:\n%s", out)
	}
}

// TestRunCVEInfoKEVUnknownVersion covers the CatalogVersion=="" fallback
// ("unknown version") — TestRunCVEInfoWithFixtures always sets a version.
func TestRunCVEInfoKEVUnknownVersion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	kevDir := filepath.Join(home, ".dsd", "kev")
	if err := os.MkdirAll(kevDir, 0o750); err != nil {
		t.Fatalf("MkdirAll kev: %v", err)
	}
	kevDoc := map[string]any{
		"vulnerabilities": []map[string]string{
			{"cveID": "CVE-2024-3094", "vendorProject": "xz", "product": "xz-utils",
				"vulnerabilityName": "XZ Backdoor", "dateAdded": "2024-04-01"},
		},
	}
	kevBytes, err := json.Marshal(kevDoc)
	if err != nil {
		t.Fatalf("marshal KEV fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kevDir, "known_exploited_vulnerabilities.json"), kevBytes, 0o600); err != nil {
		t.Fatalf("WriteFile kev fixture: %v", err)
	}

	out := captureStdout(t, func() { runCVEInfo() })
	if !strings.Contains(out, "unknown version") {
		t.Errorf("a KEV catalog with no version field should say 'unknown version', got:\n%s", out)
	}
}
