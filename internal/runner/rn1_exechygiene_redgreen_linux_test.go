//go:build linux

package runner

// Red/green proof for RN1 target 2 (rn1_exechygiene_fuzz_linux_test.go). Each
// hygiene oracle must FIRE against a deliberately-defective exec path and stay
// SILENT against the production one — "a guard nobody has watched fail is not a
// guard." Production source is never touched: the defect lives in a local leaky
// runFn, exactly as RO1's plantedCollector does.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// rn1LeakedFiles pins leaked *os.File references so the Go runtime's
// finalizer does NOT auto-close them — a real fd leak is one something still
// holds a reference to; a reference nothing holds is just GC pressure, which the
// runtime closes for you and which is NOT what H1 must catch.
var rn1LeakedFiles []*os.File

// leakyRunFn reproduces three real defects at once, each tripping a different
// oracle: (a) it opens an fd and never closes it (H1), (b) it starts a child
// WITHOUT Wait()ing (H2), and (c) it leaves a file under the pinned TMPDIR (H3).
func leakyRunFn(pinDir string) func(ctx context.Context) (any, error) {
	return func(ctx context.Context) (any, error) {
		// (a)+(c): a temp file under pinDir, left open (fd leak) and on disk.
		for i := 0; i < 3; i++ { // 3 fds > the +1 churn tolerance → unambiguous
			f, err := os.CreateTemp(pinDir, "rn1-leak-")
			if err != nil {
				return nil, err
			}
			rn1LeakedFiles = append(rn1LeakedFiles, f) // pin so the finalizer can't close it
		}

		// (b): start a child but never Wait → leftover/zombie.
		cmd := exec.CommandContext(ctx, os.Args[0],
			"-test.run=^TestRN1ExecHelper$", "-test.v=false",
			rn1HelperMarker, "sleep", strconv.Itoa(200))
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		// intentionally no cmd.Wait()
		return 0, nil
	}
}

func TestRN1ExecHygieneRedGreen(t *testing.T) {
	execHygieneMu.Lock()
	defer execHygieneMu.Unlock()

	// GREEN — production path: no fd leak, no leftover child, no temp file,
	// bounded output and wall time.
	t.Run("green_production", func(t *testing.T) {
		pinDir := t.TempDir()
		baseFP := resource.Fingerprint(t, pinDir)
		settleCollectors(200)
		baseFD := fdCount(t)
		obs := execOnce(t, 80*time.Millisecond, prodRunFn("fast", 0), pinDir, baseFP)
		if obs.afterFD > baseFD+1 {
			t.Errorf("GREEN H1: unexpected fd growth %d → %d", baseFD, obs.afterFD)
		}
		if len(obs.leftover) != 0 {
			t.Errorf("GREEN H2: unexpected leftover children %v", obs.leftover)
		}
		if obs.tempChange {
			t.Errorf("GREEN H3: unexpected temp-tree change")
		}
	})

	// RED — leaky path must trip every one of H1/H2/H3.
	t.Run("red_leaky", func(t *testing.T) {
		t.Cleanup(reapAllChildren)
		pinDir := t.TempDir()
		baseFP := resource.Fingerprint(t, pinDir)
		settleCollectors(200)
		baseFD := fdCount(t)
		obs := execOnce(t, 80*time.Millisecond, leakyRunFn(pinDir), pinDir, baseFP)

		if obs.afterFD <= baseFD+1 {
			t.Errorf("RED H1: fd leak NOT caught (%d → %d)", baseFD, obs.afterFD)
		} else {
			t.Logf("RED H1 caught: fd %d → %d", baseFD, obs.afterFD)
		}
		if len(obs.leftover) == 0 {
			t.Errorf("RED H2: leftover child NOT caught")
		} else {
			t.Logf("RED H2 caught: %d leftover child(ren) %v", len(obs.leftover), obs.leftover)
		}
		if !obs.tempChange {
			t.Errorf("RED H3: temp file NOT caught")
		} else {
			t.Logf("RED H3 caught: temp-tree change detected")
		}
	})
}

// capBytes is satisfied by both *source.CapWriter and *bytes.Buffer.
type capBytes interface {
	Write(p []byte) (int, error)
	Bytes() []byte
}

// execFloodCapture execs the flood child (floodKB KiB to stdout) through the
// real hardened exec path, capturing stdout into w, and returns how many bytes w
// kept. (Uses platform.RunHardened directly so the test can inject a small cap.)
func execFloodCapture(t *testing.T, w capBytes, floodKB int) int {
	t.Helper()
	cmd, err := platform.RunHardened(context.Background(), os.Args[0],
		"-test.run=^TestRN1ExecHelper$", "-test.v=false",
		rn1HelperMarker, "flood", strconv.Itoa(floodKB))
	if err != nil {
		t.Fatalf("RunHardened: %v", err)
	}
	cmd.Stdout = w
	if err := cmd.Run(); err != nil {
		t.Fatalf("flood child run: %v", err)
	}
	return len(w.Bytes())
}

// TestRN1OutputBoundRedGreen proves H4: the CapWriter the production exec path
// uses bounds captured output, while an uncapped buffer (the defect) does not.
func TestRN1OutputBoundRedGreen(t *testing.T) {
	execHygieneMu.Lock()
	defer execHygieneMu.Unlock()
	const floodKB = 255
	const cap = 4096

	// GREEN: the capped writer the production path uses stays within its limit.
	capped := execFloodCapture(t, source.NewCapWriter(cap), floodKB)
	if capped > cap {
		t.Errorf("GREEN H4: capped writer kept %d B, over limit %d", capped, cap)
	}
	// RED: an uncapped buffer (what the exec path would do WITHOUT CapWriter)
	// keeps the entire flood — unbounded memory, the defect H4 guards against.
	raw := execFloodCapture(t, &bytes.Buffer{}, floodKB)
	if raw <= cap {
		t.Errorf("RED H4: uncapped writer kept only %d B — flood not reproduced", raw)
	}
	t.Logf("H4: capped=%d B, uncapped=%d B (flood=%d KiB)", capped, raw, floodKB)
}

// reapAllChildren best-effort reaps any child the leaky fixture left, so it
// cannot contaminate a later test in the same binary.
func reapAllChildren() {
	for i := 0; i < 60; i++ {
		var ws syscall.WaitStatus
		pid, _ := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if pid <= 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
}
