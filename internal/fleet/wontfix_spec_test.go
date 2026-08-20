package fleet

// wontfix_spec_test.go — specification test for a finding closed WONT_FIX in
// the adversarial review (VERIFICATION-2026-08.md §8). Pins a DECIDED
// behaviour, not a bug hunt. If it fails, either the behaviour drifted or the
// decision changed — revisit the decision before "fixing" the code.
//
// The WaitDelay half of this finding (force-kill after context cancel) is
// already covered by this package's own tests exercising real sshRun/scp
// calls. What's untested is the DELIBERATE non-application of
// source.HardenedEnv/source.ResolveTrustedTool — a scoping decision, not an
// oversight (see sshRun's own "internal-init-01-04" cross-reference comment
// in fleet.go, which is the sibling this finding was scoped narrower than).

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSpec_SubprocessWrappers08_SSHRunDoesNotForceLocale:
// subprocess-wrappers-08 was closed WONT_FIX because it's already correctly
// scoped per an explicit earlier decision in this engagement: apply
// source.ExecWaitDelay to fleet's ssh/scp (a wedged remote session must still
// die with the context), but deliberately do NOT apply
// source.HardenedEnv/source.ResolveTrustedTool the way collectors/baseline/
// drilldown do — ssh/scp need the OPERATOR's own $PATH, SSH agent, and
// ProxyCommand setup to work at all (corporate wrapper scripts, non-standard
// install prefixes), and sshRun's stdout is the remote dsd's own JSON output,
// not text this process parses for locale-sensitive words/numbers, so
// there's nothing to force C locale for. This test asserts that: the
// operator's own LC_ALL reaches the ssh subprocess unchanged. If it starts
// seeing "C" instead, sshRun started overriding the environment and this
// decision needs revisiting, not silently overridden.
func TestSpec_SubprocessWrappers08_SSHRunDoesNotForceLocale(t *testing.T) {
	dir := t.TempDir()
	writeFakeBin(t, dir, "ssh", `echo "LC_ALL=$LC_ALL"
`)
	t.Setenv("PATH", dir)
	t.Setenv("LC_ALL", "en_US.UTF-8") // the operator's own locale — not "C"

	out, err := sshRun(context.Background(), Options{ConnectTimeout: 5 * time.Second}, "h1", "dsd health --json")
	if err != nil {
		t.Fatalf("sshRun error = %v", err)
	}
	if got := string(out); got != "LC_ALL=en_US.UTF-8\n" {
		t.Errorf("sshRun's subprocess saw LC_ALL=%q, want the operator's own \"en_US.UTF-8\" to pass "+
			"through unchanged — if sshRun now forces C locale (source.HardenedEnv), "+
			"subprocess-wrappers-08 may have been widened beyond its scoped decision; revisit the "+
			"decision doc rather than just updating this expectation", got)
	}
}

// TestSpec_SubprocessWrappers08_SCPDoesNotForceLocale mirrors the sshRun
// assertion above for scp — same deliberately-narrow scoping, same reasoning
// (a corporate SSH wrapper's ProxyCommand or agent forwarding depends on the
// operator's real environment, and scp parses no locale-sensitive output at
// all). scp returns no captured stdout of its own, so the fake binary writes
// its environment to a file instead.
func TestSpec_SubprocessWrappers08_SCPDoesNotForceLocale(t *testing.T) {
	dir := t.TempDir()
	captureFile := filepath.Join(t.TempDir(), "env.txt")
	writeFakeBin(t, dir, "scp", `echo "LC_ALL=$LC_ALL" > "`+captureFile+`"
exit 0
`)
	t.Setenv("PATH", dir)
	t.Setenv("LC_ALL", "en_US.UTF-8")

	local := filepath.Join(t.TempDir(), "dsd")
	if err := os.WriteFile(local, []byte("binary"), 0o755); err != nil {
		t.Fatalf("writing local bin: %v", err)
	}

	if err := scp(context.Background(), Options{ConnectTimeout: 5 * time.Second}, local, "h1", "/tmp/dsd-fleet"); err != nil {
		t.Fatalf("scp error = %v, want nil", err)
	}
	captured, err := os.ReadFile(captureFile)
	if err != nil {
		t.Fatalf("reading captured env: %v", err)
	}
	if got := string(captured); got != "LC_ALL=en_US.UTF-8\n" {
		t.Errorf("scp's subprocess saw LC_ALL=%q, want the operator's own \"en_US.UTF-8\" to pass "+
			"through unchanged (subprocess-wrappers-08's scoped decision)", got)
	}
}
