package cmd

// migrate_run_test.go — covers runMigrateBaseline (delegates to
// runCaptureRaw + a readiness summary) and runMigrateCertify (replay both
// bundles + certifyVerdict + report). Both exercise real (terse) health
// collection through source.Recorder/Replay, same established real-I/O
// precedent as capture_raw_test.go. recordExitCode only mutates the
// package-level pendingExitCode var — it never calls os.Exit — so certify's
// FAIL/WARN paths are safe to exercise directly (see cmd/exitcode.go).

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func newBareMigrateBaselineCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.StringP("out", "o", "", "")
	f.Bool("deep", false, "")
	f.Bool("pkg", false, "")
	f.Bool("cve-scan", false, "")
	f.Bool("sanitize", false, "")
	f.Bool("identifiers", false, "")
	return c
}

func newBareMigrateCertifyCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("json", false, "")
	f.Bool("deep", false, "")
	f.Bool("pkg", false, "")
	f.Bool("force", false, "")
	return c
}

func TestRunMigrateBaseline_WritesBundleAndReadiness(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "baseline.tar.gz")
	cmd := newBareMigrateBaselineCmd()
	_ = cmd.Flags().Set("out", out)

	var stdout string
	captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if err := runMigrateBaseline(cmd, nil); err != nil {
				t.Fatalf("runMigrateBaseline: %v", err)
			}
		})
	})
	if _, err := os.Stat(out); err != nil {
		t.Errorf("expected baseline bundle written at %s, got: %v", out, err)
	}
	if !strings.Contains(stdout, "Migration baseline written") {
		t.Errorf("expected readiness summary on stdout, got: %q", stdout)
	}
	if !strings.Contains(stdout, "dsd migrate certify") {
		t.Errorf("expected next-step guidance, got: %q", stdout)
	}
}

func TestRunMigrateBaseline_DefaultOutPath(t *testing.T) {
	cmd := newBareMigrateBaselineCmd()
	if got, _ := cmd.Flags().GetString("out"); got != "" {
		t.Fatalf("precondition: out should start empty, got %q", got)
	}
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	captureStderr(t, func() {
		captureStdout(t, func() {
			if err := runMigrateBaseline(cmd, nil); err != nil {
				t.Fatalf("runMigrateBaseline: %v", err)
			}
		})
	})
	got, _ := cmd.Flags().GetString("out")
	if got == "" {
		t.Error("runMigrateBaseline should populate --out with a generated default path")
	}
	if _, err := os.Stat(got); err != nil {
		t.Errorf("generated default out path should exist: %v", err)
	}
}

func TestRunMigrateCertify_CleanPass(t *testing.T) {
	dir := t.TempDir()
	src := newReplayTestBundle(t, dir, "src.tar.gz", "src-host")
	dst := newReplayTestBundle(t, dir, "dst.tar.gz", "dst-host")

	pre := pendingExitCode
	t.Cleanup(func() { pendingExitCode = pre })

	cmd := newBareMigrateCertifyCmd()
	out := captureStdout(t, func() {
		if err := runMigrateCertify(cmd, []string{src, dst}); err != nil {
			t.Fatalf("runMigrateCertify: %v", err)
		}
	})
	if !strings.Contains(out, "MIGRATION CERTIFICATION") {
		t.Errorf("expected a certification report, got:\n%s", out)
	}
}

func TestRunMigrateCertify_JSON(t *testing.T) {
	dir := t.TempDir()
	src := newReplayTestBundle(t, dir, "src.tar.gz", "src-host")
	dst := newReplayTestBundle(t, dir, "dst.tar.gz", "dst-host")

	pre := pendingExitCode
	t.Cleanup(func() { pendingExitCode = pre })

	cmd := newBareMigrateCertifyCmd()
	_ = cmd.Flags().Set("json", "true")
	out := captureStdout(t, func() {
		if err := runMigrateCertify(cmd, []string{src, dst}); err != nil {
			t.Fatalf("runMigrateCertify (json): %v", err)
		}
	})
	if !strings.Contains(out, `"verdict"`) {
		t.Errorf("--json should emit the certifyJSON shape, got: %q", out)
	}
}

func TestRunMigrateCertify_MissingSourceErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dst := newReplayTestBundle(t, dir, "dst.tar.gz", "dst-host")
	cmd := newBareMigrateCertifyCmd()
	if err := runMigrateCertify(cmd, []string{"/nonexistent/src.tar.gz", dst}); err == nil {
		t.Fatal("a nonexistent source path should error")
	}
}

func TestRunMigrateCertify_MissingDestinationErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := newReplayTestBundle(t, dir, "src.tar.gz", "src-host")
	cmd := newBareMigrateCertifyCmd()
	if err := runMigrateCertify(cmd, []string{src, "/nonexistent/dst.tar.gz"}); err == nil {
		t.Fatal("a nonexistent destination path should error")
	}
}

// TestPrintCertifyReport_WithRegressions and TestEmitCertifyJSON cover the
// certWarn/certFail branches directly with manufactured verdicts/regressions —
// two consecutive live health runs of the same idle box are very unlikely to
// diff, so driving these branches through a real runMigrateCertify round-trip
// would be nondeterministic. Manufacturing the inputs is deterministic.
func TestPrintCertifyReport_WithRegressions(t *testing.T) {
	src := &source.Bundle{Manifest: source.Manifest{Host: "src-host", OS: "Ubuntu 24.04"}}
	dst := &source.Bundle{Manifest: source.Manifest{Host: "dst-host", OS: "Ubuntu 24.04"}}
	srcSnap := &baseline.Snapshot{Hostname: "src-host", Timestamp: time.Now()}
	dstSnap := &baseline.Snapshot{Hostname: "dst-host", Timestamp: time.Now()}
	regressions := []baseline.DiffEntry{{Name: "Disk", Before: "OK 40%", After: "CRIT unresized"}}

	out := captureStdout(t, func() {
		printCertifyReport(src, dst, certFail, regressions, srcSnap, dstSnap)
	})
	if !strings.Contains(out, "FAIL") {
		t.Errorf("expected the FAIL verdict in the report, got:\n%s", out)
	}
	if !strings.Contains(out, "1 regression(s)") || !strings.Contains(out, "Disk") {
		t.Errorf("expected the regression to be listed, got:\n%s", out)
	}

	clean := captureStdout(t, func() {
		printCertifyReport(src, dst, certPass, nil, srcSnap, dstSnap)
	})
	if !strings.Contains(clean, "No regressions") {
		t.Errorf("no regressions should say so, got:\n%s", clean)
	}
}

func TestEmitCertifyJSON_FailAndWarnRecordExitCode(t *testing.T) {
	src := &source.Bundle{Manifest: source.Manifest{Host: "src-host", Created: "2026-01-01"}}
	dst := &source.Bundle{Manifest: source.Manifest{Host: "dst-host", Created: "2026-01-02"}}
	regressions := []baseline.DiffEntry{{Name: "Network", Before: "OK vmxnet3", After: "WARN emulated"}}

	pre := pendingExitCode
	t.Cleanup(func() { pendingExitCode = pre })

	pendingExitCode = 0
	out := captureStdout(t, func() {
		if err := emitCertifyJSON(src, dst, certFail, regressions); err != nil {
			t.Fatalf("emitCertifyJSON: %v", err)
		}
	})
	if !strings.Contains(out, `"verdict": "FAIL"`) {
		t.Errorf("expected the FAIL verdict in the JSON, got: %s", out)
	}
	if pendingExitCode != 2 {
		t.Errorf("certFail should record exit code 2, got %d", pendingExitCode)
	}

	pendingExitCode = 0
	captureStdout(t, func() {
		if err := emitCertifyJSON(src, dst, certWarn, regressions); err != nil {
			t.Fatalf("emitCertifyJSON: %v", err)
		}
	})
	if pendingExitCode != 1 {
		t.Errorf("certWarn should record exit code 1, got %d", pendingExitCode)
	}
}

func TestManifestHostOS_FallbackDefaults(t *testing.T) {
	t.Parallel()
	empty := &source.Bundle{}
	if manifestHost(empty) != "unknown" {
		t.Errorf("empty host should fall back to 'unknown', got %q", manifestHost(empty))
	}
	if manifestOS(empty) != "" {
		t.Errorf("empty OS with empty GOOS should fall back to GOOS (empty here), got %q", manifestOS(empty))
	}
	withGOOS := &source.Bundle{Manifest: source.Manifest{GOOS: "linux"}}
	if manifestOS(withGOOS) != "linux" {
		t.Errorf("empty OS should fall back to GOOS, got %q", manifestOS(withGOOS))
	}
}

func TestRunMigrateCertify_PlatformMismatchRefused(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := newReplayTestBundle(t, dir, "src.tar.gz", "src-host")

	other := "linux"
	if runtime.GOOS == "linux" {
		other = "darwin"
	}
	mismatched := source.NewBundle()
	mismatched.Manifest = source.Manifest{Format: source.FormatVersion, Host: "dst-host", GOOS: other}
	dst := filepath.Join(dir, "dst-mismatch.tar.gz")
	if err := mismatched.SaveTarball(dst); err != nil {
		t.Fatal(err)
	}

	cmd := newBareMigrateCertifyCmd()
	if err := runMigrateCertify(cmd, []string{src, dst}); err == nil {
		t.Fatal("a platform-mismatched destination should be refused without --force")
	}
}

// TestRunMigrateCertify_SourcePlatformMismatchRefused mirrors the destination
// case above but mismatches the SOURCE bundle instead — runMigrateCertify
// guards src and dst independently (two separate replayPlatformGuard calls),
// and only the dst branch was exercised above.
func TestRunMigrateCertify_SourcePlatformMismatchRefused(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dst := newReplayTestBundle(t, dir, "dst.tar.gz", "dst-host")

	other := "linux"
	if runtime.GOOS == "linux" {
		other = "darwin"
	}
	mismatched := source.NewBundle()
	mismatched.Manifest = source.Manifest{Format: source.FormatVersion, Host: "src-host", GOOS: other}
	src := filepath.Join(dir, "src-mismatch.tar.gz")
	if err := mismatched.SaveTarball(src); err != nil {
		t.Fatal(err)
	}

	cmd := newBareMigrateCertifyCmd()
	if err := runMigrateCertify(cmd, []string{src, dst}); err == nil {
		t.Fatal("a platform-mismatched source should be refused without --force")
	}
}

// TestRunMigrateBaseline_CaptureErrorPropagates covers the branch where the
// underlying runCaptureRaw write fails (line "if err := runCaptureRaw(cmd);
// err != nil { return err }") — an --out path whose parent directory doesn't
// exist makes SaveTarball's final tarGzDir fail deterministically.
func TestRunMigrateBaseline_CaptureErrorPropagates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	out := filepath.Join(dir, "no-such-subdir", "baseline.tar.gz")
	cmd := newBareMigrateBaselineCmd()
	_ = cmd.Flags().Set("out", out)

	captureStderr(t, func() {
		if err := runMigrateBaseline(cmd, nil); err == nil {
			t.Fatal("an unwritable --out path should propagate the capture error")
		}
	})
}
