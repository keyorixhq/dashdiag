package cmd

// mcp_symlink_repro_test.go — reproducer for NET1-F1: safeBundlePath's CWD
// constraint is lexical, so an MCP path argument whose DIRECTORY component is
// a symlink to outside CWD passes the check, and toolCapture's write
// (source.tarGzDir, O_NOFOLLOW on the final component only) lands outside CWD.
//
// Gated behind DSD_NET1_REPRO=1 because it fails on the current tree by
// design: it is the red half of a red/green proof, not a regression test. The
// green half (TestReproSafeBundlePathDirSymlinkEscape_ProposedFixGreen)
// always runs: the same oracle applied to the proposed fix passes.
//
// Oracle: the real (symlink-resolved) parent directory of every path
// safeBundlePath accepts lies under the real CWD.
//
// What this does NOT verify: the read side end to end (dsd_replay/dsd_diff/
// dsd_share from_path go through the same check, only the write is driven
// here); TOCTOU between the check and the open (a symlink swapped in after
// the check); hard links.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// realParentUnderRealCWD is the oracle.
func realParentUnderRealCWD(t *testing.T, accepted string) error {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	realCWD, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return err
	}
	abs := accepted
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(cwd, abs)
	}
	realDir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil // parent does not exist: the write fails, nothing escapes
	}
	if realDir != realCWD && !strings.HasPrefix(realDir, realCWD+string(filepath.Separator)) {
		return errors.New("accepted path " + accepted + " really resolves to " + realDir + ", outside " + realCWD)
	}
	return nil
}

// symlinkEscapeFixture builds cwd/link -> outside and chdirs into cwd.
func symlinkEscapeFixture(t *testing.T) (outside string) {
	t.Helper()
	outside = t.TempDir()
	cwd := t.TempDir()
	t.Chdir(cwd)
	if err := os.Symlink(outside, "link"); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	return outside
}

func TestReproSafeBundlePathDirSymlinkEscape(t *testing.T) {
	if os.Getenv("DSD_NET1_REPRO") != "1" {
		t.Skip("red half of the NET1-F1 red/green proof; set DSD_NET1_REPRO=1 to run (fails on the current tree)")
	}
	mcpAllowAbsolutePaths = false
	outside := symlinkEscapeFixture(t)

	accepted, err := safeBundlePath("link/out.tar.gz")
	if err != nil {
		t.Fatalf("premise: expected safeBundlePath to accept link/out.tar.gz, got %v", err)
	}
	if err := realParentUnderRealCWD(t, accepted); err != nil {
		t.Errorf("oracle fired: %v", err)
	}

	// End to end through the live MCP handler: the capture bundle is written
	// into the directory outside CWD.
	prev := runHealthOnceFn
	t.Cleanup(func() { runHealthOnceFn = prev })
	runHealthOnceFn = func(_ context.Context, _ platform.ContainerContext, _ platform.CloudEnvironment,
		_ platform.Profile, _ output.OutputMode, _ healthRunOpts, _ *analysis.PolicyFile,
	) ([]runner.Result, []models.Insight, *baseline.Snapshot, time.Duration) {
		return nil, nil, nil, 0
	}
	_, out, err := toolCapture(t.Context(), nil, mcpCaptureInput{OutPath: "link/out.tar.gz"})
	if err != nil {
		t.Fatalf("toolCapture: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "out.tar.gz")); statErr == nil {
		t.Errorf("toolCapture wrote %s (%d bytes) outside CWD, into %s", out.BundlePath, out.Bytes, outside)
	}
}

// safeBundlePathProposedFix models the issue-ready fix: run the existing
// lexical check, then additionally resolve symlinks in the parent directory
// and re-apply the containment check to the real path. Harness-only; the
// production function is unchanged.
func safeBundlePathProposedFix(raw string) (string, error) {
	cleaned, err := safeBundlePath(raw)
	if err != nil || mcpAllowAbsolutePaths {
		return cleaned, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	realCWD, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", err
	}
	abs := cleaned
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(cwd, abs)
	}
	realDir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	if realDir != realCWD && !strings.HasPrefix(realDir, realCWD+string(filepath.Separator)) {
		return "", errors.New("path resolves outside the current working directory via a symlink")
	}
	return cleaned, nil
}

func TestReproSafeBundlePathDirSymlinkEscape_ProposedFixGreen(t *testing.T) {
	mcpAllowAbsolutePaths = false
	symlinkEscapeFixture(t)
	if err := os.Mkdir("real", 0o700); err != nil {
		t.Fatal(err)
	}
	// The escape is refused...
	if got, err := safeBundlePathProposedFix("link/out.tar.gz"); err == nil {
		if oerr := realParentUnderRealCWD(t, got); oerr != nil {
			t.Fatalf("proposed fix still lets the oracle fire: %v", oerr)
		}
	}
	// ...and legitimate paths still pass the oracle and the fix.
	for _, p := range []string{"out.tar.gz", "real/out.tar.gz"} {
		got, err := safeBundlePathProposedFix(p)
		if err != nil {
			t.Fatalf("proposed fix over-rejects %q: %v", p, err)
		}
		if oerr := realParentUnderRealCWD(t, got); oerr != nil {
			t.Fatalf("oracle false positive on %q: %v", p, oerr)
		}
	}
}
