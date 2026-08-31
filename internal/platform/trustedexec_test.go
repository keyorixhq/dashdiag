package platform

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveTrustedTool_NotFoundNeverFallsBackToPATH is a regression guard for
// the PATH-hijack gap this function exists to close. A name absent from every
// trustedToolDirs entry used to be returned UNCHANGED (bare), which looks safe
// in isolation but is not: Go's exec.Command/CommandContext performs its OWN
// PATH search whenever the given command has no path separator
// (filepath.Base(name) == name) — so a caller that execs the "unresolved"
// bare name (as collectors/k8s.go's k8sDetectBin PATH fallback does for k3s/
// k0s/microk8s/kubectl) silently regains the exact untrusted-$PATH search
// this file's comment claims is removed. The fix anchors an unresolved name
// under a directory that can never exist, so it always contains a "/" and Go
// never falls back to its own PATH search.
func TestResolveTrustedTool_NotFoundNeverFallsBackToPATH(t *testing.T) {
	t.Parallel()
	got := ResolveTrustedTool("definitely-not-a-real-dsd-tool")
	if !strings.Contains(got, "/") {
		t.Fatalf("ResolveTrustedTool(unresolvable) = %q, must contain a path separator so exec.Command never performs its own PATH search", got)
	}
	if filepath.Base(got) != "definitely-not-a-real-dsd-tool" {
		t.Errorf("ResolveTrustedTool(unresolvable) = %q, base name changed unexpectedly", got)
	}
}

// TestResolveTrustedTool_UnresolvedNameNeverExecutesFromPATH is the end-to-end
// version of the guard above: it actually plants a malicious "tool" on $PATH
// (simulating a writable directory prepended ahead of the real system dirs —
// sudo -E, a permissive secure_path, a container image with a writable early
// PATH entry) and proves that exec'ing ResolveTrustedTool's result never runs
// it, regardless of what the process's inherited PATH contains.
func TestResolveTrustedTool_UnresolvedNameNeverExecutesFromPATH(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sentinel")
	script := "#!/bin/sh\ntouch '" + sentinel + "'\n"
	toolPath := filepath.Join(dir, "dsd-test-hijack-tool")
	if err := os.WriteFile(toolPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake tool: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	resolved := ResolveTrustedTool("dsd-test-hijack-tool")
	cmd := exec.CommandContext(context.Background(), resolved) //nolint:gosec // test constructs the exact path under test
	_ = cmd.Run()                                              // expected to fail — the point is that it must NOT run the planted script

	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("planted PATH tool was executed — ResolveTrustedTool's unresolved fallback still honors the inherited $PATH")
	}
}

// TestHardenedEnv asserts the exact contract HardenedEnv's doc comment
// promises: the inherited environment, plus LC_ALL=C and LANG=C appended so
// external command output stays locale-stable (see the doc comment's dmesg
// -T / es_ES example). Every hardened exec site in the codebase depends on
// this shape.
func TestHardenedEnv(t *testing.T) {
	t.Setenv("DSD_TEST_HARDENED_ENV_MARKER", "present")
	env := HardenedEnv()

	foundMarker, foundLCAll, foundLang := false, false, false
	for _, kv := range env {
		switch kv {
		case "DSD_TEST_HARDENED_ENV_MARKER=present":
			foundMarker = true
		case "LC_ALL=C":
			foundLCAll = true
		case "LANG=C":
			foundLang = true
		}
	}
	if !foundMarker {
		t.Error("HardenedEnv() dropped an inherited environment variable — it must extend os.Environ(), not replace it")
	}
	if !foundLCAll {
		t.Error(`HardenedEnv() missing "LC_ALL=C"`)
	}
	if !foundLang {
		t.Error(`HardenedEnv() missing "LANG=C"`)
	}
}

// TestDirIsRootSafe is the pure decision table for dirOwnedAndLockedByRoot,
// exercised with synthetic uid/mode values so it needs neither real root
// privilege nor a real filesystem to test every branch.
func TestDirIsRootSafe(t *testing.T) {
	cases := []struct {
		name string
		uid  uint32
		mode os.FileMode
		want bool
	}{
		{"root-owned, locked down (0755)", 0, 0o755, true},
		{"root-owned, locked down (0700)", 0, 0o700, true},
		{"root-owned but group-writable", 0, 0o775, false},
		{"root-owned but world-writable", 0, 0o757, false},
		{"non-root owner, otherwise locked down — Homebrew's actual shape on macOS", 501, 0o755, false},
		{"non-root owner and world-writable — the worst case", 501, 0o777, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dirIsRootSafe(tc.uid, tc.mode); got != tc.want {
				t.Errorf("dirIsRootSafe(uid=%d, mode=%o) = %v, want %v", tc.uid, tc.mode, got, tc.want)
			}
		})
	}
}

// TestResolveTrustedTool_SkipsUnsafeDirWhenRoot is the integration proof: as
// root, a trusted-list directory that exists, contains the named executable,
// but is NOT root-owned must be skipped — the tool must resolve as "not
// found" (the safe, already-handled degrade path), never to a binary sitting
// in a directory a local unprivileged user could have planted it in.
//
// The test directory here is created by the test process itself, so on any
// normal (non-root) test run it is genuinely NOT uid-0-owned — exactly the
// Homebrew-on-macOS shape this guards against. If the test process itself
// happens to run as real root (uid 0), the created directory would
// legitimately BE root-owned, defeating the test's premise entirely, so that
// case is skipped rather than silently passing for the wrong reason.
func TestResolveTrustedTool_SkipsUnsafeDirWhenRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test process itself runs as root — a created temp dir would be genuinely root-owned, defeating this test's premise")
	}

	dir := t.TempDir() // owned by the test process's own (non-root) uid
	toolPath := filepath.Join(dir, "dsd-test-tool")
	if err := os.WriteFile(toolPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write fake tool: %v", err)
	}

	origDirs, origGeteuid := trustedToolDirs, geteuid
	trustedToolDirs = []string{dir}
	geteuid = func() int { return 0 }
	t.Cleanup(func() { trustedToolDirs, geteuid = origDirs, origGeteuid })

	got := ResolveTrustedTool("dsd-test-tool")
	if got == toolPath {
		t.Fatalf("ResolveTrustedTool resolved to %q, a non-root-owned directory, while simulating a root dsd process — the tool should have been skipped as untrusted", got)
	}
}

// TestResolveTrustedTool_NonRootProcessDoesNotCheckDirOwnership confirms the
// new check is scoped to root: a non-root dsd process trusting a
// user-writable directory grants a local attacker nothing they didn't
// already have, so the SAME non-root-owned directory that gets skipped above
// must still resolve normally when dsd itself is not root.
func TestResolveTrustedTool_NonRootProcessDoesNotCheckDirOwnership(t *testing.T) {
	dir := t.TempDir()
	toolPath := filepath.Join(dir, "dsd-test-tool")
	if err := os.WriteFile(toolPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write fake tool: %v", err)
	}

	origDirs, origGeteuid := trustedToolDirs, geteuid
	trustedToolDirs = []string{dir}
	geteuid = func() int { return 501 } // non-root
	t.Cleanup(func() { trustedToolDirs, geteuid = origDirs, origGeteuid })

	got := ResolveTrustedTool("dsd-test-tool")
	if got != toolPath {
		t.Errorf("ResolveTrustedTool(non-root process) = %q, want %q — directory-ownership check must not apply when dsd itself is not root", got, toolPath)
	}
}
