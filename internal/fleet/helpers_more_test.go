package fleet

import (
	"strings"
	"testing"
	"time"
)

// sshBaseArgs builds the common SSH options used by both sshRun and scp. A drift
// here (e.g. dropping BatchMode) would make fleet hang on a password prompt
// instead of failing fast — worth pinning.
func TestSSHBaseArgs(t *testing.T) {
	args := sshBaseArgs(Options{ConnectTimeout: 12 * time.Second})
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"BatchMode=yes",     // never prompt — fail fast
		"ConnectTimeout=12", // derived from opts via seconds()
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("sshBaseArgs missing %q; got %v", want, args)
		}
	}
}

// TestSSHBaseArgs_DefaultDoesNotOverrideHostKeyChecking is the regression test
// for internal-fleet-01-02: the package doc comment promises fleet "inherits
// the user's ~/.ssh/config" for host-key policy, but a hardcoded
// StrictHostKeyChecking=accept-new used to be appended unconditionally — ssh
// -o flags take precedence over ssh_config, so that silently downgraded any
// stricter policy an operator had configured for a host, with no way to opt
// out. By default (AcceptNewHostKeys unset), sshBaseArgs must not mention
// StrictHostKeyChecking at all, leaving ssh_config in full control.
func TestSSHBaseArgs_DefaultDoesNotOverrideHostKeyChecking(t *testing.T) {
	args := sshBaseArgs(Options{ConnectTimeout: 5 * time.Second})
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "StrictHostKeyChecking") {
		t.Errorf("sshBaseArgs must not set StrictHostKeyChecking by default (overrides the user's ssh_config); got %v", args)
	}
}

// TestSSHBaseArgs_AcceptNewHostKeysOptIn confirms the explicit opt-in still
// works: an operator who wants TOFU convenience can ask for it.
func TestSSHBaseArgs_AcceptNewHostKeysOptIn(t *testing.T) {
	args := sshBaseArgs(Options{ConnectTimeout: 5 * time.Second, AcceptNewHostKeys: true})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "StrictHostKeyChecking=accept-new") {
		t.Errorf("sshBaseArgs with AcceptNewHostKeys=true missing StrictHostKeyChecking=accept-new; got %v", args)
	}
}

func TestResultFinalize(t *testing.T) {
	r := &Result{}
	start := time.Now().Add(-25 * time.Millisecond)
	r.finalize(start)

	if r.Elapsed <= 0 {
		t.Errorf("Elapsed = %v, want > 0", r.Elapsed)
	}
	// ElapsedMs must be the millisecond view of Elapsed.
	if r.ElapsedMs != r.Elapsed.Milliseconds() {
		t.Errorf("ElapsedMs = %d, want %d", r.ElapsedMs, r.Elapsed.Milliseconds())
	}
}
