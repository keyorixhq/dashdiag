package installscript

// install_script_test.go — specification test for a finding closed WONT_FIX
// in the adversarial review (VERIFICATION-2026-08.md §8; BUGS.md's BUG-100
// entry). Pins a DECIDED behaviour, not a bug hunt. If it fails, either the
// behaviour drifted or the decision changed — revisit the decision before
// "fixing" the script.
//
// This is the one WONT_FIX finding whose decided behaviour lives in a shell
// script, not Go. There is no shell-test harness elsewhere in this repo to
// build on (that gap is itself part of why a full end-to-end install.sh test
// — mocking curl against a fake GitHub release, controlling PATH — was judged
// disproportionate). Instead of that, or a weaker "grep the script for
// strings" check, this test exercises the real functions install.sh defines
// (verify_signature's signature_unenforced) hermetically: sourcing the
// script's function/variable definitions (everything except its trailing
// `main "$@"` invocation, which needs real network access and a real
// platform to run) into a throwaway shell and calling the exact function the
// decision is about. No network, no mocked curl, no fixture platform needed.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// installShLibrary reads install.sh from the repo root (this test file's own
// directory — it lives at the repo root by construction) and returns its
// content with the trailing `main "$@"` line removed, so sourcing it defines
// every function and variable without actually running the installer (which
// needs network access and touches the filesystem). Fails loudly if that
// exact line isn't found, rather than silently sourcing (and running) the
// whole installer — a rewrite of main's invocation must not make this test
// pass by accident.
func installShLibrary(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed to resolve this test file's path")
	}
	repoRoot := filepath.Dir(thisFile)
	raw, err := os.ReadFile(filepath.Join(repoRoot, "install.sh"))
	if err != nil {
		t.Fatalf("reading install.sh: %v", err)
	}
	content := string(raw)
	const mainInvocation = "\nmain \"$@\"\n"
	idx := strings.LastIndex(content, mainInvocation)
	if idx == -1 || idx+len(mainInvocation) != len(content) {
		t.Fatalf(`install.sh does not end with %q as its last line — this test strips exactly that `+
			`line so sourcing the rest defines functions/vars without running the installer; if the `+
			`script's structure changed, update this test's assumption, don't just drop the check`, mainInvocation)
	}
	return content[:idx] + "\n"
}

// runInstallShFunc sources the stripped install.sh library into a POSIX sh
// subshell and then runs body (e.g. a function call). Returns combined
// stdout+stderr and the process's exit status via err (nil on exit 0).
func runInstallShFunc(t *testing.T, body string) (output string, err error) {
	t.Helper()
	dir := t.TempDir()
	libPath := filepath.Join(dir, "lib.sh")
	if writeErr := os.WriteFile(libPath, []byte(installShLibrary(t)), 0o600); writeErr != nil {
		t.Fatalf("writing stripped install.sh library: %v", writeErr)
	}
	script := ". \"$1\"\n" + body
	cmd := exec.Command("sh", "-c", script, "--", libPath) // #nosec G204 -- script is this test's own fixed literal, libPath is a t.TempDir() path
	out, runErr := cmd.CombinedOutput()
	return string(out), runErr
}

// TestSpec_InstallScript06_DefaultWarnsAndProceedsWithoutSignature:
// install-script-06 was closed WONT_FIX because it's a deliberate, already-
// documented tradeoff (BUGS.md BUG-100): minisign ships on essentially no
// distro out of the box, so requiring it by default would break the common
// `curl | sh` install for most users. signature_unenforced's default branch
// warns and falls back to checksum-only rather than failing closed. This
// test asserts that decided default. If it starts failing closed with no
// flag, the tradeoff was reversed — revisit BUG-100's "permanent by design"
// framing before "fixing" this test.
func TestSpec_InstallScript06_DefaultWarnsAndProceedsWithoutSignature(t *testing.T) {
	out, err := runInstallShFunc(t, `signature_unenforced "release signature present but 'minisign' is not installed"
echo REACHED_AFTER_CALL
`)
	if err != nil {
		t.Fatalf("signature_unenforced with no --require-signature must NOT abort the script, got error: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "REACHED_AFTER_CALL") {
		t.Errorf("script did not continue past signature_unenforced — expected it to warn and fall through, output:\n%s", out)
	}
	if !strings.Contains(out, "verified checksum only") {
		t.Errorf("expected the checksum-only fallback warning, output:\n%s", out)
	}
}

// TestSpec_InstallScript06_RequireSignatureFlagFailsClosed is the flip side
// of the same decision: --require-signature (REQUIRE_SIGNATURE=1, as main's
// flag parsing sets it) exists precisely so CI / high-trust deployments can
// opt into the same fail-closed standard `dsd update` already enforces. This
// must keep aborting install — if this starts passing (script exits 0) with
// REQUIRE_SIGNATURE=1 set, the fail-closed opt-out broke, which is worse than
// a docs bug: it silently removes the one enforced path this finding's
// WONT_FIX reasoning depends on.
func TestSpec_InstallScript06_RequireSignatureFlagFailsClosed(t *testing.T) {
	out, err := runInstallShFunc(t, `REQUIRE_SIGNATURE=1
signature_unenforced "release signature present but 'minisign' is not installed"
echo REACHED_AFTER_CALL
`)
	if err == nil {
		t.Fatalf("signature_unenforced with REQUIRE_SIGNATURE=1 must abort the script (die), got exit 0\noutput:\n%s", out)
	}
	if strings.Contains(out, "REACHED_AFTER_CALL") {
		t.Errorf("script continued past signature_unenforced despite REQUIRE_SIGNATURE=1 — die should have exited first, output:\n%s", out)
	}
	if !strings.Contains(out, "--require-signature") {
		t.Errorf("expected the fail-closed message to reference --require-signature, output:\n%s", out)
	}
}
