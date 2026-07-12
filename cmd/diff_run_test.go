package cmd

// diff_run_test.go — covers runDiff, the top-level `dsd diff` alias for
// `dsd replay <current> --diff <baseline>`. Reuses newReplayTestBundle
// (replay_run_test.go) for minimal in-memory bundles.

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func newBareDiffCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("json", false, "")
	f.Bool("gpu", false, "")
	f.Bool("pkg", false, "")
	f.Bool("deep", false, "")
	f.Bool("cve", false, "")
	f.Bool("force", false, "")
	return c
}

func TestRunDiff_HumanAndJSON(t *testing.T) {
	dir := t.TempDir()
	base := newReplayTestBundle(t, dir, "base.tar.gz", "host-a")
	current := newReplayTestBundle(t, dir, "current.tar.gz", "host-b")

	cmd := newBareDiffCmd()
	captureStdout(t, func() {
		if err := runDiff(cmd, []string{base, current}); err != nil {
			t.Fatalf("runDiff: %v", err)
		}
	})

	jsonCmd := newBareDiffCmd()
	_ = jsonCmd.Flags().Set("json", "true")
	out := captureStdout(t, func() {
		if err := runDiff(jsonCmd, []string{base, current}); err != nil {
			t.Fatalf("runDiff (json): %v", err)
		}
	})
	if !strings.Contains(out, "{") {
		t.Errorf("--json should emit machine-readable output, got: %q", out)
	}
}

func TestRunDiff_MissingBaselineErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	current := newReplayTestBundle(t, dir, "current.tar.gz", "host-b")
	cmd := newBareDiffCmd()
	if err := runDiff(cmd, []string{"/nonexistent/base.tar.gz", current}); err == nil {
		t.Fatal("a nonexistent baseline path should error")
	}
}

func TestRunDiff_MissingCurrentErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := newReplayTestBundle(t, dir, "base.tar.gz", "host-a")
	cmd := newBareDiffCmd()
	if err := runDiff(cmd, []string{base, "/nonexistent/current.tar.gz"}); err == nil {
		t.Fatal("a nonexistent current path should error")
	}
}
