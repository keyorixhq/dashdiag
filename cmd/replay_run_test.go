package cmd

// replay_run_test.go — covers replayBundle, runReplay, runReplayDiff, and
// renderCaptureDiff against minimal in-memory bundles (source.NewBundle(),
// same "empty bundle over source.NewReplay is safe" precedent already used by
// internal/collectors/collector_test.go's TestActiveSource). No live hardware
// or network is touched — every collector reads from the (empty) recorded
// bundle and degrades to "unavailable/absent", same as a real replay of a
// sparse capture.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// newReplayTestBundle writes a minimal bundle tarball whose Manifest matches
// this machine's OS family, so replayPlatformGuard passes without --force.
func newReplayTestBundle(t *testing.T, dir, name, host string) string {
	t.Helper()
	b := source.NewBundle()
	b.Manifest = source.Manifest{
		Format: source.FormatVersion,
		Host:   host,
		OS:     "Test OS",
		GOOS:   runtime.GOOS,
	}
	path := filepath.Join(dir, name)
	if err := b.SaveTarball(path); err != nil {
		t.Fatalf("SaveTarball: %v", err)
	}
	return path
}

func newBareReplayCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("json", false, "")
	f.Bool("gpu", false, "")
	f.Bool("pkg", false, "")
	f.Bool("cve", false, "")
	f.Bool("deep", false, "")
	f.Bool("layered", false, "")
	f.Bool("report", false, "")
	f.Bool("report-html", false, "")
	f.Bool("force", false, "")
	f.String("diff", "", "")
	f.String("brand", "", "")
	f.String("logo", "", "")
	return c
}

func TestReplayBundle_EmptyBundleNoPanic(t *testing.T) {
	b := source.NewBundle()
	b.Manifest = source.Manifest{GOOS: runtime.GOOS}
	results, insights, snap := replayBundle(b, false, false, false, false)
	if results == nil {
		t.Error("replayBundle should return a (possibly all-erroring) results slice, not nil")
	}
	_ = insights
	if snap == nil {
		t.Error("replayBundle should return a non-nil snapshot")
	}
}

func TestRunReplay_HumanOutput(t *testing.T) {
	dir := t.TempDir()
	bundle := newReplayTestBundle(t, dir, "b.tar.gz", "captured-host")
	cmd := newBareReplayCmd()
	out := captureStdout(t, func() {
		if err := runReplay(cmd, []string{bundle}); err != nil {
			t.Fatalf("runReplay: %v", err)
		}
	})
	_ = out // human render goes through the real renderer; just confirm no error
}

func TestRunReplay_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	bundle := newReplayTestBundle(t, dir, "b.tar.gz", "captured-host")
	cmd := newBareReplayCmd()
	_ = cmd.Flags().Set("json", "true")
	out := captureStdout(t, func() {
		if err := runReplay(cmd, []string{bundle}); err != nil {
			t.Fatalf("runReplay (json): %v", err)
		}
	})
	if !strings.Contains(out, `"hostname"`) {
		t.Errorf("json mode should emit the JSONOutput shape, got: %q", out)
	}
}

func TestRunReplay_LayeredHuman(t *testing.T) {
	dir := t.TempDir()
	bundle := newReplayTestBundle(t, dir, "b.tar.gz", "captured-host")
	cmd := newBareReplayCmd()
	_ = cmd.Flags().Set("layered", "true")
	captureStdout(t, func() {
		if err := runReplay(cmd, []string{bundle}); err != nil {
			t.Fatalf("runReplay (layered): %v", err)
		}
	})
}

func TestRunReplay_ReportAndReportHTML(t *testing.T) {
	dir := t.TempDir()
	bundle := newReplayTestBundle(t, dir, "b.tar.gz", "captured-host")
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	cmd := newBareReplayCmd()
	_ = cmd.Flags().Set("report", "true")
	_ = cmd.Flags().Set("report-html", "true")
	errOut := captureStderr(t, func() {
		if err := runReplay(cmd, []string{bundle}); err != nil {
			t.Fatalf("runReplay (report): %v", err)
		}
	})
	if !strings.Contains(errOut, "Report saved") {
		t.Errorf("--report should confirm the markdown report path, got: %q", errOut)
	}
	if !strings.Contains(errOut, "HTML report saved") {
		t.Errorf("--report-html should confirm the HTML report path, got: %q", errOut)
	}
}

func TestRunReplay_LoadBundleErrors(t *testing.T) {
	t.Parallel()
	cmd := newBareReplayCmd()
	if err := runReplay(cmd, []string{"/nonexistent/bundle.tar.gz"}); err == nil {
		t.Fatal("a nonexistent bundle path should error")
	}
}

func TestRunReplay_PlatformMismatchRefused(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	other := "linux"
	if runtime.GOOS == "linux" {
		other = "darwin"
	}
	b := source.NewBundle()
	b.Manifest = source.Manifest{Format: source.FormatVersion, Host: "h", GOOS: other}
	path := filepath.Join(dir, "mismatch.tar.gz")
	if err := b.SaveTarball(path); err != nil {
		t.Fatal(err)
	}
	cmd := newBareReplayCmd()
	if err := runReplay(cmd, []string{path}); err == nil {
		t.Fatal("a platform-mismatched bundle should be refused without --force")
	}
}

func TestRunReplay_WithDiff(t *testing.T) {
	dir := t.TempDir()
	base := newReplayTestBundle(t, dir, "base.tar.gz", "host-a")
	current := newReplayTestBundle(t, dir, "current.tar.gz", "host-b")
	cmd := newBareReplayCmd()
	_ = cmd.Flags().Set("diff", base)
	out := captureStdout(t, func() {
		if err := runReplay(cmd, []string{current}); err != nil {
			t.Fatalf("runReplay --diff: %v", err)
		}
	})
	_ = out
}

func TestRunReplayDiff_BaselineLoadErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	current := newReplayTestBundle(t, dir, "current.tar.gz", "host-b")
	b, err := loadBundle(current)
	if err != nil {
		t.Fatal(err)
	}
	err = runReplayDiff(b, "/nonexistent/baseline.tar.gz", false, false, false, false, false, false)
	if err == nil {
		t.Fatal("a nonexistent baseline path should error")
	}
}

func TestRenderCaptureDiff_JSONAndHuman(t *testing.T) {
	dir := t.TempDir()
	baseP := newReplayTestBundle(t, dir, "base.tar.gz", "host-a")
	curP := newReplayTestBundle(t, dir, "current.tar.gz", "host-b")
	base, err := loadBundle(baseP)
	if err != nil {
		t.Fatal(err)
	}
	current, err := loadBundle(curP)
	if err != nil {
		t.Fatal(err)
	}

	humanOut := captureStdout(t, func() {
		if err := renderCaptureDiff(base, current, false, false, false, false, false, false); err != nil {
			t.Fatalf("renderCaptureDiff (human): %v", err)
		}
	})
	_ = humanOut

	jsonOut := captureStdout(t, func() {
		if err := renderCaptureDiff(base, current, false, false, false, false, true, false); err != nil {
			t.Fatalf("renderCaptureDiff (json): %v", err)
		}
	})
	_ = jsonOut
}

func TestRenderCaptureDiff_PlatformMismatchRefused(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	other := "linux"
	if runtime.GOOS == "linux" {
		other = "darwin"
	}
	mismatched := source.NewBundle()
	mismatched.Manifest = source.Manifest{Format: source.FormatVersion, Host: "h", GOOS: other}
	mismatchedPath := filepath.Join(dir, "mismatch.tar.gz")
	if err := mismatched.SaveTarball(mismatchedPath); err != nil {
		t.Fatal(err)
	}
	current := newReplayTestBundle(t, dir, "current.tar.gz", "host-b")

	mismatchedBundle, err := loadBundle(mismatchedPath)
	if err != nil {
		t.Fatal(err)
	}
	currentBundle, err := loadBundle(current)
	if err != nil {
		t.Fatal(err)
	}
	if err := renderCaptureDiff(mismatchedBundle, currentBundle, false, false, false, false, false, false); err == nil {
		t.Fatal("mismatched baseline platform should be refused")
	}
	if err := renderCaptureDiff(currentBundle, mismatchedBundle, false, false, false, false, false, false); err == nil {
		t.Fatal("mismatched current platform should be refused")
	}
}
