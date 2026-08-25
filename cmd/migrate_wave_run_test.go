package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// captureStdoutErr runs f with both os.Stdout and os.Stderr redirected,
// returning what each captured. runMigrateWave always writes a progress
// line to stderr ("Certifying N pair(s)…") even in --json mode, so tests
// that don't want that noise mixed into stdout use this helper.
func captureStdoutErr(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()
	stderr = captureStderr(t, func() {
		stdout = captureStdout(t, f)
	})
	return stdout, stderr
}

// newBareWaveCmd returns a cobra.Command with the flags that runMigrateWave reads.
// applyBrand reads "brand" and "logo"; the rest are the wave-specific flags.
func newBareWaveCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.String("pairs-file", "", "")
	f.String("brand", "", "")
	f.String("logo", "", "")
	f.String("name", "", "")
	f.Bool("force", false, "")
	f.Bool("deep", false, "")
	f.Bool("pkg", false, "")
	f.Bool("json", false, "")
	f.Bool("report-html", false, "")
	return c
}

// TestRunMigrateWave_NoPairs covers the "no pairs given" early return in
// runMigrateWave. On any host with no args and no --pairs-file the function
// returns after the pairs check without touching the network or filesystem.
func TestRunMigrateWave_NoPairs(t *testing.T) {
	t.Parallel()
	cmd := newBareWaveCmd()
	err := runMigrateWave(cmd, nil)
	if err == nil {
		t.Fatal("expected error from runMigrateWave with no pairs, got nil")
	}
	if !strings.Contains(err.Error(), "no pairs given") {
		t.Errorf("expected 'no pairs given' error, got %q", err.Error())
	}
}

// TestRunMigrateWave_BadPairsFile covers the resolvePairs file-open error path:
// --pairs-file set to a path that does not exist causes resolvePairs to return
// a "reading --pairs-file: …" error, which runMigrateWave propagates.
func TestRunMigrateWave_BadPairsFile(t *testing.T) {
	t.Parallel()
	cmd := newBareWaveCmd()
	dir := t.TempDir()
	missing := filepath.Join(dir, "does_not_exist.txt")
	if err := cmd.Flags().Set("pairs-file", missing); err != nil {
		t.Fatal(err)
	}
	err := runMigrateWave(cmd, nil)
	if err == nil {
		t.Fatal("expected error from runMigrateWave with non-existent --pairs-file")
	}
	if !strings.Contains(err.Error(), "reading --pairs-file") {
		t.Errorf("expected 'reading --pairs-file' error, got %q", err.Error())
	}
}

// TestRunMigrateWave_BadArgFormat covers the resolvePairs positional-arg parse
// error path: a positional arg without a colon returns an error from resolvePairs
// before runMigrateWave reaches the len(pairs)==0 guard.
func TestRunMigrateWave_BadArgFormat(t *testing.T) {
	t.Parallel()
	cmd := newBareWaveCmd()
	// "noseparator" has no colon → resolvePairs returns an error.
	err := runMigrateWave(cmd, []string{"noseparator"})
	if err == nil {
		t.Fatal("expected error from runMigrateWave with malformed pair arg")
	}
	if !strings.Contains(err.Error(), "expected src:dst") {
		t.Errorf("expected 'expected src:dst' error, got %q", err.Error())
	}
}

// TestRunMigrateWave_PairsFileWithBadLine covers the pairs-file parse error
// path: a file with a line that has too many fields causes resolvePairs to
// return an error before any bundle files are touched.
func TestRunMigrateWave_PairsFileWithBadLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pf := filepath.Join(dir, "pairs.txt")
	// Three fields on one line → "expected two fields" error.
	if err := os.WriteFile(pf, []byte("a.tar.gz b.tar.gz extra\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newBareWaveCmd()
	if err := cmd.Flags().Set("pairs-file", pf); err != nil {
		t.Fatal(err)
	}
	err := runMigrateWave(cmd, nil)
	if err == nil {
		t.Fatal("expected error from runMigrateWave with a bad pairs-file line")
	}
	if !strings.Contains(err.Error(), "expected two fields") {
		t.Errorf("expected 'expected two fields' error, got %q", err.Error())
	}
}

// TestRunMigrateWave_Success_PlainTable covers runMigrateWave's success
// path in plain mode: certifyWave runs for real against a minimal but
// valid bundle pair (same source.NewBundle() precedent as
// replay_run_test.go), and printWaveTable renders the pair count summary.
func TestRunMigrateWave_Success_PlainTable(t *testing.T) {
	dir := t.TempDir()
	src := newReplayTestBundle(t, dir, "src.tar.gz", "src-host")
	dst := newReplayTestBundle(t, dir, "dst.tar.gz", "dst-host")

	pre := pendingExitCode
	t.Cleanup(func() { pendingExitCode = pre })

	cmd := newBareWaveCmd()
	stdout, _ := captureStdoutErr(t, func() {
		if err := runMigrateWave(cmd, []string{src + ":" + dst}); err != nil {
			t.Fatalf("runMigrateWave: %v", err)
		}
	})
	if !strings.Contains(stdout, "1 pair(s)") {
		t.Errorf("expected the wave table summary in stdout, got:\n%s", stdout)
	}
}

// TestRunMigrateWave_Success_JSON covers runMigrateWave's --json branch,
// which returns via emitWaveJSON instead of printWaveTable.
func TestRunMigrateWave_Success_JSON(t *testing.T) {
	dir := t.TempDir()
	src := newReplayTestBundle(t, dir, "src.tar.gz", "src-host")
	dst := newReplayTestBundle(t, dir, "dst.tar.gz", "dst-host")

	pre := pendingExitCode
	t.Cleanup(func() { pendingExitCode = pre })

	cmd := newBareWaveCmd()
	_ = cmd.Flags().Set("json", "true")
	stdout, _ := captureStdoutErr(t, func() {
		if err := runMigrateWave(cmd, []string{src + ":" + dst}); err != nil {
			t.Fatalf("runMigrateWave (json): %v", err)
		}
	})
	if !strings.Contains(stdout, `"verdict"`) {
		t.Errorf("--json should emit the waveJSON shape, got: %q", stdout)
	}
}

// TestRunMigrateWave_ReportHTML covers runMigrateWave's --report-html
// branch: GenerateWaveHTMLReport writes dsd-migration-wave-<ts>.html to the
// CWD (no injectable output dir), so this Chdir's into a t.TempDir() for
// the duration of the call — same precedent as
// TestRunMigrateBaseline_DefaultOutPath in migrate_run_test.go.
func TestRunMigrateWave_ReportHTML(t *testing.T) {
	dir := t.TempDir()
	src := newReplayTestBundle(t, dir, "src.tar.gz", "src-host")
	dst := newReplayTestBundle(t, dir, "dst.tar.gz", "dst-host")

	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	pre := pendingExitCode
	t.Cleanup(func() { pendingExitCode = pre })

	cmd := newBareWaveCmd()
	_ = cmd.Flags().Set("report-html", "true")
	_, stderr := captureStdoutErr(t, func() {
		if err := runMigrateWave(cmd, []string{src + ":" + dst}); err != nil {
			t.Fatalf("runMigrateWave (report-html): %v", err)
		}
	})
	if !strings.Contains(stderr, "Wave HTML report saved") {
		t.Errorf("expected the report-saved confirmation on stderr, got:\n%s", stderr)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "dsd-migration-wave-*.html"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Errorf("expected exactly one generated wave report file in %s, got %v", dir, matches)
	}
}
