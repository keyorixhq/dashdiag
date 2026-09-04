package cmd

// capture_raw_test.go — covers runCaptureRaw and its small helpers. Each test
// performs one real (terse) health collection through source.Recorder — same
// established real-I/O precedent as this package's other cmd-wiring tests
// (see cpu_report_test.go's comment block). No t.Parallel() on the tests that
// swap CWD (report writers write to ".") — os.Chdir is process-global.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// newBareCaptureRawCmd builds a standalone *cobra.Command with the flags
// runCaptureRaw reads via cmd.Flags().Get*.
func newBareCaptureRawCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.StringP("out", "o", "", "")
	f.Bool("sanitize", true, "")
	f.Bool("no-sanitize", false, "")
	f.Bool("identifiers", false, "")
	f.Bool("deep", false, "")
	f.Bool("pkg", false, "")
	f.Bool("cve-scan", false, "")
	return c
}

// TestRunCaptureRaw_DefaultWritesBundle covers GAP-2's default flip
// (docs/product-claim-gaps-2026-09-02.md): the bare command, with no flags
// touched, must now sanitize — the whole point of the flip is that a bundle
// captured under time pressure with the documented command is safe by
// default, not opt-in.
func TestRunCaptureRaw_DefaultWritesBundle(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bundle.tar.gz")
	cmd := newBareCaptureRawCmd()
	_ = cmd.Flags().Set("out", out)
	stderr := captureStderr(t, func() {
		if err := runCaptureRaw(cmd); err != nil {
			t.Fatalf("runCaptureRaw: %v", err)
		}
	})
	if _, err := os.Stat(out); err != nil {
		t.Errorf("expected bundle written at %s, got: %v", out, err)
	}
	if !strings.Contains(stderr, "Raw bundle written") {
		t.Errorf("expected write confirmation on stderr, got: %q", stderr)
	}
	if !strings.Contains(stderr, "Sanitized") {
		t.Errorf("default (no flags touched) should sanitize now, got: %q", stderr)
	}
	if strings.Contains(stderr, "NOTE: unredacted") {
		t.Errorf("default should no longer warn unredacted, got: %q", stderr)
	}
}

// TestRunCaptureRaw_NoSanitizeWritesRawBundle covers the opt-out this same gap
// added: --no-sanitize must still produce the raw, unredacted bundle for the
// case that genuinely needs raw bytes.
func TestRunCaptureRaw_NoSanitizeWritesRawBundle(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bundle.tar.gz")
	cmd := newBareCaptureRawCmd()
	_ = cmd.Flags().Set("out", out)
	_ = cmd.Flags().Set("no-sanitize", "true")
	stderr := captureStderr(t, func() {
		if err := runCaptureRaw(cmd); err != nil {
			t.Fatalf("runCaptureRaw: %v", err)
		}
	})
	if _, err := os.Stat(out); err != nil {
		t.Errorf("expected bundle written at %s, got: %v", out, err)
	}
	if !strings.Contains(stderr, "unredacted") {
		t.Errorf("--no-sanitize should warn it's unredacted, got: %q", stderr)
	}
}

func TestRunCaptureRaw_SanitizeIdentifiers(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bundle.tar.gz")
	cmd := newBareCaptureRawCmd()
	_ = cmd.Flags().Set("out", out)
	_ = cmd.Flags().Set("sanitize", "true")
	_ = cmd.Flags().Set("identifiers", "true")
	stderr := captureStderr(t, func() {
		if err := runCaptureRaw(cmd); err != nil {
			t.Fatalf("runCaptureRaw: %v", err)
		}
	})
	if _, err := os.Stat(out); err != nil {
		t.Errorf("expected bundle written at %s, got: %v", out, err)
	}
	if !strings.Contains(stderr, "Sanitized") {
		t.Errorf("--sanitize should report a sanitize summary, got: %q", stderr)
	}
	if !strings.Contains(stderr, "Identifiers redacted") {
		t.Errorf("--identifiers should mention identifier redaction, got: %q", stderr)
	}
}

// TestRunCaptureRaw_IdentifiersImpliesSanitize covers the branch where
// --identifiers is set without --sanitize: sanitize must still run.
func TestRunCaptureRaw_IdentifiersImpliesSanitize(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bundle.tar.gz")
	cmd := newBareCaptureRawCmd()
	_ = cmd.Flags().Set("out", out)
	_ = cmd.Flags().Set("identifiers", "true")
	stderr := captureStderr(t, func() {
		if err := runCaptureRaw(cmd); err != nil {
			t.Fatalf("runCaptureRaw: %v", err)
		}
	})
	if !strings.Contains(stderr, "Sanitized") {
		t.Errorf("--identifiers alone should imply --sanitize, got: %q", stderr)
	}
}

// TestRunCaptureRaw_DefaultOutPath covers the "" -> generated filename branch.
// Chdir into a temp dir so the generated dsd-raw-*.tar.gz lands there, not in
// the repo working tree.
func TestRunCaptureRaw_DefaultOutPath(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	cmd := newBareCaptureRawCmd()
	captureStderr(t, func() {
		if err := runCaptureRaw(cmd); err != nil {
			t.Fatalf("runCaptureRaw: %v", err)
		}
	})
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "dsd-raw-") && strings.HasSuffix(e.Name(), ".tar.gz") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a default-named dsd-raw-*.tar.gz bundle in %s, got entries: %v", dir, entries)
	}
}

// TestRunCaptureRaw_IdentifiersRedactsDefaultFilename guards
// redaction-primitives-04: fileHost was captured before Sanitize ran and used
// verbatim in the default "dsd-raw-<host>-<timestamp>.tar.gz" filename
// regardless of --identifiers, so the real hostname leaked through the
// bundle's own default filename even when the bundle's CONTENTS correctly
// showed a placeholder — a channel Sanitize was never applied to.
func TestRunCaptureRaw_IdentifiersRedactsDefaultFilename(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	realHost, err := os.Hostname()
	if err != nil || realHost == "" {
		t.Skip("os.Hostname unavailable in this environment")
	}

	cmd := newBareCaptureRawCmd()
	_ = cmd.Flags().Set("identifiers", "true")
	captureStderr(t, func() {
		if err := runCaptureRaw(cmd); err != nil {
			t.Fatalf("runCaptureRaw: %v", err)
		}
	})
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "dsd-raw-") && strings.HasSuffix(e.Name(), ".tar.gz") {
			found = true
			if strings.Contains(e.Name(), realHost) {
				t.Errorf("default bundle filename disclosed the real hostname despite --identifiers: %q", e.Name())
			}
		}
	}
	if !found {
		t.Errorf("expected a default-named dsd-raw-*.tar.gz bundle in %s, got entries: %v", dir, entries)
	}
}

// TestCaptureRawDefaultOutPath_SanitizesTraversal guards cmd-01-06: the
// default --raw bundle filename embeds the OS/container hostname
// unsanitized. The hostname is not always operator-chosen (a container
// orchestrator, cloud-init from a spoofable DHCP option 12, a shared
// multi-tenant host) — a hostname containing '/' or '..' segments must not
// change where the tarball with the full raw capture bundle gets written.
func TestCaptureRawDefaultOutPath_SanitizesTraversal(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := captureRawDefaultOutPath("../../etc/evil", now)
	if strings.ContainsAny(got, "/\\") {
		t.Errorf("captureRawDefaultOutPath(%q) = %q, want no path separators in the result", "../../etc/evil", got)
	}
	if strings.HasPrefix(got, "..") {
		t.Errorf("captureRawDefaultOutPath(%q) = %q, want no leading traversal", "../../etc/evil", got)
	}
}

func TestHostnameOr(t *testing.T) {
	t.Parallel()
	if got := hostnameOr("fallback"); got == "" {
		t.Error("hostnameOr should never return an empty string")
	}
}

// kernelRelease/osPretty/detectGPUPresence read through the currently active
// source (collectors.ActiveSource()); by the time these run no other test in
// this package should have left a Replay source installed (every such test
// defers SetSource(prev)), so these exercise the live/default source — same
// real-I/O precedent as elsewhere in this file.
func TestKernelReleaseOsPrettyDetectGPUPresence(t *testing.T) {
	// These must not panic; on a Linux CI/container box the values will
	// generally be non-empty, but a defensive assertion on emptiness alone
	// would be flaky across sandboxes, so just exercise the call paths.
	_ = kernelRelease()
	_ = osPretty()
	_ = detectGPUPresence()
}

// TestKernelReleaseOsPretty_ReadFailureFallsBack swaps in a Replay over an
// empty bundle (no recorded read for /proc/sys/kernel/osrelease or
// /etc/os-release), forcing the ReadFileViaSource error branch in both
// helpers — the fallback path a live host with those files present never
// exercises.
func TestKernelReleaseOsPretty_ReadFailureFallsBack(t *testing.T) {
	prev := collectors.SetSource(source.NewReplay(source.NewBundle()))
	defer collectors.SetSource(prev)

	if got := kernelRelease(); got != "" {
		t.Errorf("kernelRelease with no recorded read should return empty, got %q", got)
	}
	if got := osPretty(); got == "" {
		t.Error("osPretty with no recorded read should fall back to runtime.GOOS, not empty")
	}
}

// TestOsPretty_ParsesPrettyName covers the success path's PRETTY_NAME line
// parse via a recorded /etc/os-release read.
func TestOsPretty_ParsesPrettyName(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/etc/os-release", []byte("ID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n"))
	prev := collectors.SetSource(source.NewReplay(b))
	defer collectors.SetSource(prev)

	if got := osPretty(); got != "Ubuntu 24.04.1 LTS" {
		t.Errorf("osPretty should parse PRETTY_NAME, got %q", got)
	}
}

// TestOsPretty_NoPrettyNameLineFallsBack covers the loop-exhausted branch:
// /etc/os-release is present and reads successfully but has no PRETTY_NAME
// line, so osPretty falls through to runtime.GOOS — distinct from the
// ReadFileViaSource error branch covered above.
func TestOsPretty_NoPrettyNameLineFallsBack(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/etc/os-release", []byte("ID=mystery\nVERSION_ID=1\n"))
	prev := collectors.SetSource(source.NewReplay(b))
	defer collectors.SetSource(prev)

	if got := osPretty(); got != runtime.GOOS {
		t.Errorf("osPretty with no PRETTY_NAME line should fall back to runtime.GOOS, got %q", got)
	}
}

// TestDetectGPUPresence_CardsFound covers the "found at least one DRM card"
// branch via a recorded glob match.
func TestDetectGPUPresence_CardsFound(t *testing.T) {
	b := source.NewBundle()
	b.PutGlob("/sys/class/drm/card[0-9]", []string{"/sys/class/drm/card0"})
	prev := collectors.SetSource(source.NewReplay(b))
	defer collectors.SetSource(prev)

	if !detectGPUPresence() {
		t.Error("a recorded glob match should report GPU presence")
	}
}

// TestSanitizeDisclosureNote guards sanitize-bundle-03: this is the single
// source of the disclosure text shared between dsd capture --raw's stderr
// warning and the dsd_capture MCP tool's structured Note field — a bug here
// affects both callers identically, so it's worth its own direct table-
// driven coverage independent of either caller's full live-pipeline test.
func TestSanitizeDisclosureNote(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		sanitized   bool
		identifiers bool
		report      source.SanitizeReport
		wantAll     []string
		wantNone    []string
	}{
		{
			name:      "unsanitized",
			sanitized: false,
			wantAll:   []string{"unredacted", "secrets", "--sanitize", "trusted channel"},
			wantNone:  []string{"Sanitized (best-effort)"},
		},
		{
			name:        "sanitized without identifiers",
			sanitized:   true,
			identifiers: false,
			report:      source.SanitizeReport{TotalRedactions: 3, FilesRedacted: 2, CommandsRedacted: 1},
			wantAll:     []string{"Sanitized (best-effort)", "3 redaction(s)", "2 file(s)", "1 command(s)", "REVIEW before sharing", "--identifiers", "trusted channel"},
			wantNone:    []string{"unredacted", "Identifiers redacted"},
		},
		{
			name:        "sanitized with identifiers",
			sanitized:   true,
			identifiers: true,
			report:      source.SanitizeReport{TotalRedactions: 5, FilesRedacted: 4, CommandsRedacted: 1},
			wantAll:     []string{"Sanitized (best-effort)", "Identifiers redacted", "NOT redacted", "trusted channel"},
			wantNone:    []string{"unredacted", "add --identifiers"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sanitizeDisclosureNote(tt.sanitized, tt.identifiers, tt.report)
			for _, want := range tt.wantAll {
				if !strings.Contains(got, want) {
					t.Errorf("sanitizeDisclosureNote(%v, %v) = %q, want substring %q", tt.sanitized, tt.identifiers, got, want)
				}
			}
			for _, notWant := range tt.wantNone {
				if strings.Contains(got, notWant) {
					t.Errorf("sanitizeDisclosureNote(%v, %v) = %q, unexpectedly contains %q", tt.sanitized, tt.identifiers, got, notWant)
				}
			}
		})
	}
}
