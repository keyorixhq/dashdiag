package source

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
