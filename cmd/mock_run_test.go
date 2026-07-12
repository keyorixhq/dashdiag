package cmd

// mock_run_test.go covers runMock directly (in-process, not the subprocess
// pattern mock_raw_test.go uses for its end-to-end LVM-replay check) — a
// fixture is written to t.TempDir() and runMock is called with a bare
// cobra.Command, exercising the read-fixture / bad-path / invalid-YAML
// branches that were otherwise only reachable via `go run`.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRunMockValidFixture(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.yaml")
	fixture := "host: mock-web01\n" +
		"os: Ubuntu 22.04 LTS\n" +
		"version: v9.9.9\n" +
		"rows:\n" +
		"  - name: CPU Load\n" +
		"    inline: \"2%\"\n" +
		"  - name: Packages\n" +
		"    level: CRIT\n" +
		"    message: \"14 critical security update(s) available (apt)\"\n" +
		"    hints:\n" +
		"      - \"to fix: apt-get upgrade\"\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &cobra.Command{}
	out := captureStdout(t, func() {
		if err := runMock(c, []string{path}); err != nil {
			t.Fatalf("runMock: %v", err)
		}
	})
	if !strings.Contains(out, "CPU Load") {
		t.Errorf("mock output should include the fixture's row, got:\n%s", out)
	}
	if !strings.Contains(out, "apt-get upgrade") {
		t.Errorf("mock output should include the CRIT insight's fix hint, got:\n%s", out)
	}
}

func TestRunMockDefaultsHostAndOS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "minimal.yaml")
	fixture := "rows:\n  - name: CPU Load\n    inline: \"1%\"\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &cobra.Command{}
	stderr := captureStderr(t, func() {
		if err := runMock(c, []string{path}); err != nil {
			t.Fatalf("runMock: %v", err)
		}
	})
	if !strings.Contains(stderr, "mock-host") {
		t.Errorf("an absent host should default to 'mock-host', got:\n%s", stderr)
	}
}

func TestRunMockMissingFile(t *testing.T) {
	c := &cobra.Command{}
	err := runMock(c, []string{filepath.Join(t.TempDir(), "does-not-exist.yaml")})
	if err == nil {
		t.Fatal("a missing fixture file should error")
	}
	if !strings.Contains(err.Error(), "cannot read fixture") {
		t.Errorf("unexpected error for a missing fixture: %v", err)
	}
}

func TestRunMockInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("host: [this is not valid: yaml"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &cobra.Command{}
	err := runMock(c, []string{path})
	if err == nil {
		t.Fatal("invalid fixture YAML should error")
	}
	if !strings.Contains(err.Error(), "invalid fixture YAML") {
		t.Errorf("unexpected error for invalid YAML: %v", err)
	}
}

// TestRunMockMalformedCVESection covers runMock's error-propagation path when
// the fixture's captured `cve:` section fails to decode as models.CVEAllResult
// — distinct from the top-level fixture-YAML-parse failure above.
func TestRunMockMalformedCVESection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "badcve.yaml")
	fixture := "rows:\n  - name: CPU Load\n    inline: \"1%\"\n" +
		"cve: \"not valid json\"\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &cobra.Command{}
	err := runMock(c, []string{path})
	if err == nil {
		t.Fatal("a malformed captured CVE section should error")
	}
	if !strings.Contains(err.Error(), "decoding captured cve section") {
		t.Errorf("unexpected error for malformed cve section: %v", err)
	}
}

// TestRunMockMalformedTimelineSection covers the same error-propagation path
// for the fixture's captured `timeline:` section.
func TestRunMockMalformedTimelineSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "badtimeline.yaml")
	fixture := "rows:\n  - name: CPU Load\n    inline: \"1%\"\n" +
		"timeline: \"not valid json\"\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &cobra.Command{}
	err := runMock(c, []string{path})
	if err == nil {
		t.Fatal("a malformed captured timeline section should error")
	}
	if !strings.Contains(err.Error(), "decoding captured timeline section") {
		t.Errorf("unexpected error for malformed timeline section: %v", err)
	}
}

// TestRunMockRawDiskData covers runMock's raw-disk-JSON decode path
// (mockRawData returning non-nil), which replaces the text-only stub with the
// real models.DiskInfo — not exercised by the plain inline-text fixtures above.
func TestRunMockRawDiskData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rawdisk.yaml")
	fixture := "rows:\n" +
		"  - name: Disk\n" +
		"    inline: \"OK\"\n" +
		"    raw: '{\"filesystems\":[{\"mount\":\"/\",\"fs_type\":\"ext4\",\"total_gb\":100,\"used_gb\":10,\"used_pct\":10}]}'\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &cobra.Command{}
	out := captureStdout(t, func() {
		if err := runMock(c, []string{path}); err != nil {
			t.Fatalf("runMock: %v", err)
		}
	})
	if out == "" {
		t.Error("runMock with raw disk data produced no output")
	}
}
