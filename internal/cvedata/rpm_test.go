//go:build linux

package cvedata

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestQueryInstalledRPM_NotAvailable exercises the "rpm not in PATH" guard.
// This repo's containers/CI runners are Debian-family and don't ship rpm, so
// this is a deterministic failure here; guarded so a host that DOES have rpm
// installed skips instead of asserting a false expectation.
func TestQueryInstalledRPM_NotAvailable(t *testing.T) {
	t.Parallel()
	rpmUnavailable(t)
	if _, err := QueryInstalledRPM(context.Background()); err == nil {
		t.Error("expected error when rpm binary is not on PATH")
	}
}

// writeFakeRPM drops an executable shell script named "rpm" onto dir, then
// points resolveRPM (P2: platform.ResolveTrustedTool, which deliberately
// ignores $PATH) directly at it for the duration of the test, so
// exec.CommandContext(ctx, resolveRPM("rpm"), "-qa", "--queryformat", ...) in
// QueryInstalledRPM resolves to this fake instead of a real rpm binary. The
// fake ignores its arguments and unconditionally echoes lines in the exact
// "%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE}\n" shape QueryInstalledRPM's
// queryformat produces (rpm.go:18-19), including an "(none)" epoch line so
// the "(none):" -> "0:" normalisation (rpm.go:36) is exercised for real.
//
// Callers MUST NOT also call t.Parallel(): swapping the package-level
// resolveRPM var is only race-free serially, same constraint as t.Setenv.
func writeFakeRPM(t *testing.T, extraLines string) {
	t.Helper()
	writeFakeRPMWithGoVersion(t, "0:1.25.5-160000.1.1", extraLines)
}

// writeFakeRPMWithGoVersion is writeFakeRPM but with a caller-chosen EVR for
// the "go1.25" entry, so callers exercising suseOVAL's "less than
// 0:1.25.5-1.1" state (e.g. CheckCVEFromOVAL) can report either a patched or
// a vulnerable installed version.
func writeFakeRPMWithGoVersion(t *testing.T, goEVR, extraLines string) {
	t.Helper()
	dir := t.TempDir()
	// PATH is replaced wholesale (not prepended) so QueryInstalledRPM
	// resolves only this fake — which means external tools like "cat" are
	// NOT on PATH either. Use sh's builtin echo, not cat/heredoc, so the
	// script needs nothing beyond the shell itself.
	script := "#!/bin/sh\n" +
		"echo 'go1.25 " + goEVR + "'\n" +
		"echo 'xz (none):5.6.1-2'\n" +
		"echo 'xz-libs (none):5.6.1-2'\n" +
		extraLines +
		"echo ''\n" + // blank line: must be skipped, not parsed
		"echo '   '\n" // whitespace-only line: must also be skipped
	path := filepath.Join(dir, "rpm")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake rpm: %v", err)
	}
	orig := resolveRPM
	resolveRPM = func(string) string { return path }
	t.Cleanup(func() { resolveRPM = orig })
}

// TestQueryInstalledRPM_Success exercises the real parsing/success path
// (rpm.go:18-39) via a fake rpm binary on PATH, since this repo's
// containers/CI runners don't ship a real rpm to test against.
func TestQueryInstalledRPM_Success(t *testing.T) {
	// Not t.Parallel(): writeFakeRPM calls t.Setenv.
	writeFakeRPM(t, "")
	pkgs, err := QueryInstalledRPM(context.Background())
	if err != nil {
		t.Fatalf("QueryInstalledRPM: %v", err)
	}
	want := []InstalledPackage{
		{Name: "go1.25", EVR: "0:1.25.5-160000.1.1"},
		{Name: "xz", EVR: "0:5.6.1-2"},
		{Name: "xz-libs", EVR: "0:5.6.1-2"},
	}
	if len(pkgs) != len(want) {
		t.Fatalf("pkgs = %+v, want %d entries", pkgs, len(want))
	}
	for i, w := range want {
		if pkgs[i] != w {
			t.Errorf("pkgs[%d] = %+v, want %+v", i, pkgs[i], w)
		}
	}
}

// TestQueryInstalledRPM_CommandFails exercises the "rpm -qa: %w" wrap
// (rpm.go:20-23) — distinct from TestQueryInstalledRPM_NotAvailable, which
// covers the earlier exec.LookPath guard. Here rpm IS resolved via PATH but
// exits non-zero, so cmd.Output() itself returns the error.
func TestQueryInstalledRPM_CommandFails(t *testing.T) {
	// Not t.Parallel(): t.Setenv is incompatible with parallel subtests.
	dir := t.TempDir()
	path := filepath.Join(dir, "rpm")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("writing fake rpm: %v", err)
	}
	t.Setenv("PATH", dir)
	if _, err := QueryInstalledRPM(context.Background()); err == nil {
		t.Error("expected error when the rpm command exits non-zero")
	}
}

// TestQueryInstalledRPM_SkipsMalformedLine exercises the
// "len(parts) != 2 { continue }" guard (rpm.go:30-32): a line with no space
// (so SplitN never produces a second field) must be dropped rather than
// producing a package with an empty EVR.
func TestQueryInstalledRPM_SkipsMalformedLine(t *testing.T) {
	// Not t.Parallel(): writeFakeRPM calls t.Setenv.
	writeFakeRPM(t, "echo 'no-space-in-this-line'\n")
	pkgs, err := QueryInstalledRPM(context.Background())
	if err != nil {
		t.Fatalf("QueryInstalledRPM: %v", err)
	}
	for _, p := range pkgs {
		if p.Name == "no-space-in-this-line" {
			t.Fatalf("pkgs = %+v, malformed single-field line must be skipped, not parsed", pkgs)
		}
	}
	if len(pkgs) != 3 {
		t.Fatalf("pkgs = %+v, want the 3 well-formed entries only", pkgs)
	}
}
