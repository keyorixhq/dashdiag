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
		"BatchMode=yes",                    // never prompt — fail fast
		"ConnectTimeout=12",                // derived from opts via seconds()
		"StrictHostKeyChecking=accept-new", // first-contact hosts allowed, MITM after rejected
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("sshBaseArgs missing %q; got %v", want, args)
		}
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
