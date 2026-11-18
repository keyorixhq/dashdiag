package cmd

// MC4 target 5 — companion to FuzzMC4ToolCaptureNoHostWrite. This runs the
// GENUINELY UNSEAMED toolCapture: the real runHealthOnce (a full live collector
// sweep) through the real Recorder/SaveTarball write path, over a real
// mcp.Server, a BOUNDED number of times, under the same filesystem-fingerprint
// oracle. It closes the one dimension the fuzz loop seams away — "the collectors
// themselves never write to the host" — end to end at the MCP layer, without
// making the shared thermally-constrained host run a sweep hundreds of times in
// a fuzz loop (see FuzzMC4ToolCaptureNoHostWrite's header for that split).
//
// Network stays OFF (default), so the sweep does no outbound dials. If the live
// sweep errors on this host, toolCapture still writes its (possibly tiny) bundle
// under cwd — the no-host-write claim is independent of sweep success, and that
// is exactly what C2/C3 assert here.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

func TestMC4RealCollectorNoHostWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("real collector sweep is slow; skipped under -short")
	}

	// A handful of real captures with in-cwd and escape-attempt paths. The
	// collector sweep is the real one (no seam on runHealthOnceFn here).
	cases := []struct {
		name    string
		outPath string
	}{
		{"in-cwd", "bundle.tar.gz"},
		{"in-cwd-subdir", "sub/bundle.tar.gz"},
		{"traversal-escape", "../sentinel/escape.tar.gz"},
		{"absolute-escape", "/tmp/dsd-mc4-evil.tar.gz"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			cwd := filepath.Join(parent, "work")
			if err := os.MkdirAll(cwd, 0o755); err != nil {
				t.Fatalf("mkdir cwd: %v", err)
			}
			sentinel := plantSentinel(t, parent)
			t.Chdir(cwd)

			before := resource.Fingerprint(t, sentinel)
			known := map[string]bool{}
			_ = filepath.Walk(parent, func(path string, fi os.FileInfo, err error) error {
				if err == nil && !fi.IsDir() {
					known[path] = true
				}
				return nil
			})

			// Real, unseamed handler + real collector sweep.
			driveRealCapture(captureCallFrame(tc.outPath, false, false))

			resource.AssertUnchanged(t, sentinel, before)
			if escaped := newFilesOutsideCwd(t, parent, cwd, known); len(escaped) > 0 {
				t.Fatalf("real-collector no-host-write violated: out_path=%q wrote outside cwd %s:\n  %s",
					tc.outPath, cwd, join(escaped))
			}
		})
	}
}

// TestMC4FingerprintCatchesEscapedWrite is the RED/GREEN proof that C2/C3 is a
// real guard, not a vacuous one. With the secure default (containment on) no
// out_path can write outside cwd, so C2/C3 pass trivially — a guard that can
// never fail. This test deliberately DISABLES containment
// (--allow-absolute-paths, mcpAllowAbsolutePaths=true — the explicit operator
// opt-out documented on safeBundlePath), captures to an ABSOLUTE path INSIDE the
// sentinel, and asserts the fingerprint oracle DOES observe the escaped write.
// That proves the fuzz target's C2/C3 would catch a real containment breach, and
// doubles as the characterisation of what --allow-absolute-paths gives up (it is
// exactly the arbitrary-file-write primitive safeBundlePath otherwise bounds).
func TestMC4FingerprintCatchesEscapedWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("real collector sweep is slow; skipped under -short")
	}
	oldAllow := mcpAllowAbsolutePaths
	mcpAllowAbsolutePaths = true
	defer func() { mcpAllowAbsolutePaths = oldAllow }()

	parent := t.TempDir()
	cwd := filepath.Join(parent, "work")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatalf("mkdir cwd: %v", err)
	}
	sentinel := plantSentinel(t, parent)
	t.Chdir(cwd)

	before := resource.Fingerprint(t, sentinel)
	known := map[string]bool{}
	_ = filepath.Walk(parent, func(path string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			known[path] = true
		}
		return nil
	})

	// Absolute path INTO the sentinel — only reachable because containment is off.
	escapeTarget := filepath.Join(sentinel, "written.tar.gz")
	driveRealCapture(captureCallFrame(escapeTarget, false, false))

	// RED proof: the oracle MUST see the escape (fingerprint changed AND a new
	// file appeared outside cwd). If either stayed clean, the capture silently
	// failed to write and the oracle would be unprovable.
	after := resource.Fingerprint(t, sentinel)
	if after == before {
		t.Fatalf("red/green proof failed: capture to %s did not change the sentinel fingerprint — the escaped write did not land, so C2 is unproven", escapeTarget)
	}
	escaped := newFilesOutsideCwd(t, parent, cwd, known)
	if len(escaped) == 0 {
		t.Fatalf("red/green proof failed: capture to %s produced no new file outside cwd — C3 is unproven", escapeTarget)
	}
	t.Logf("red/green OK: --allow-absolute-paths capture escaped cwd and the C2/C3 oracle observed it: %s", join(escaped))
}

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += "\n  "
		}
		out += s
	}
	return out
}
