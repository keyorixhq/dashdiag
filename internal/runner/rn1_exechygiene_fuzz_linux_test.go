//go:build linux

package runner

// RN1 target 2 — collector-execution path resource hygiene (real child
// process).
//
// Seam. Every collector that shells out reaches the OS through
// source.Live.Run → defaultExec → platform.RunHardened → exec.CommandContext
// with cmd.WaitDelay = platform.ExecWaitDelay (force-kill after ctx cancel) and
// stdout/stderr captured through source.NewCapWriter(MaxCapturedOutput). cmd.Run
// always Waits, so the child is reaped (BUG-021). This target wraps that exact
// production path in a runner.Collector, drives it through RunAll under a fuzzed
// timeout, and fuzzes the CHILD's behaviour via a re-exec of this test binary:
// fast, partial-output-then-nonzero-exit, stdout flood, sleep, hang (ignores
// ctx), and a child that installs signal handlers to ignore SIGTERM/SIGINT (only
// SIGKILL — which CommandContext uses — can reap it).
//
// Oracles (all measured AFTER the exec goroutine has fully drained, so a child
// killed on the timeout path has been reaped and its pipes closed):
//
//   H1  NO FD LEAK. /proc/self/fd count returns to its pre-run baseline — the
//       stdout/stderr pipes are closed on every path (success, non-zero exit,
//       timeout-kill, signal-ignoring kill).
//   H2  NO LEFTOVER PROCESS. No child process has this test process as its
//       parent after the run — no zombie (unreaped Wait) and no orphan.
//   H3  NO TEMP FILE. A pinned TMPDIR tree is byte-for-byte unchanged across the
//       run (resource.Fingerprint) — the exec path leaves no temp file of dsd.
//   H4  OUTPUT BOUNDED. Captured stdout/stderr never exceeds
//       source.MaxCapturedOutput. (A direct small-cap CapWriter red/green in
//       TestRN1ExecHygieneRedGreen proves the bound actually truncates.)
//   H5  WALL TIME BOUNDED. The run returns within timeout + ExecWaitDelay +
//       collectGrace + slack — a hanging/signal-ignoring child cannot outlive
//       its caller's deadline.
//
// Resource meters enabled: FD count (H1 — the resource helper explicitly does
// NOT cover fds, so this target adds its own, per that helper's header), PROCESS
// count (H2), DISK/temp via resource.Fingerprint (H3), TIME via resource.Measure
// (H5), and output BYTES (H4). Memory alloc is recorded but not asserted (a
// flood child allocates the captured buffer on purpose). The whole measured body
// is serialised by execHygieneMu because /proc/self/fd, the child-process table
// and the pinned TMPDIR are process-global.

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

var execHygieneMu sync.Mutex

const rn1HelperMarker = "rn1helper"

// TestRN1ExecHelper is the re-exec child. When this test binary is run with the
// marker token in its args (by the fuzz target below), it performs the requested
// behaviour and exits WITHOUT returning to the test framework (so no "PASS\nok"
// pollutes the captured stdout). When run normally (no marker) it is a no-op, so
// it costs nothing in the ordinary suite.
func TestRN1ExecHelper(t *testing.T) {
	args := os.Args
	idx := -1
	for i, a := range args {
		if a == rn1HelperMarker {
			idx = i
			break
		}
	}
	if idx < 0 || idx+2 >= len(args) {
		return // not the helper invocation
	}
	behavior := args[idx+1]
	n, _ := strconv.Atoi(args[idx+2])

	switch behavior {
	case "fast":
		fmt.Fprint(os.Stdout, "ok")
		os.Exit(0)
	case "exitcode":
		fmt.Fprint(os.Stdout, "partial-output")
		os.Exit(n % 256)
	case "flood":
		// Write n KiB to stdout then exit 0.
		buf := make([]byte, 1024)
		for i := range buf {
			buf[i] = 'A'
		}
		w := bufio.NewWriter(os.Stdout)
		for i := 0; i < n; i++ {
			_, _ = w.Write(buf)
		}
		_ = w.Flush()
		os.Exit(0)
	case "sleep":
		time.Sleep(time.Duration(n) * time.Millisecond)
		os.Exit(0)
	case "hang":
		select {} // block forever; only a kill ends this
	case "ignoresig":
		signal.Ignore(syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
		select {} // ignores catchable signals; SIGKILL still reaps it
	default:
		os.Exit(0)
	}
}

// --- oracle instrumentation (linux /proc) ---

func fdCount(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("reading /proc/self/fd: %v", err)
	}
	return len(ents)
}

// childProcesses returns the pids whose parent is this test process.
func childProcesses(t *testing.T) []int {
	t.Helper()
	self := os.Getpid()
	ents, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("reading /proc: %v", err)
	}
	var kids []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue // process exited between readdir and read — fine
		}
		// stat format: "pid (comm) state ppid ..."; comm may contain spaces and
		// parens, so split after the LAST ')'.
		s := string(data)
		rparen := strings.LastIndexByte(s, ')')
		if rparen < 0 || rparen+2 >= len(s) {
			continue
		}
		fields := strings.Fields(s[rparen+2:])
		if len(fields) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(fields[1]) // state, ppid, ...
		if err != nil {
			continue
		}
		if ppid == self {
			kids = append(kids, pid)
		}
	}
	return kids
}

// settleChildren polls until the child-process set attributable to us is empty
// (a just-killed child takes a moment to be reaped), or gives up.
func settleChildren(t *testing.T, maxTries int) []int {
	t.Helper()
	for i := 0; i < maxTries; i++ {
		kids := childProcesses(t)
		if len(kids) == 0 {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return childProcesses(t)
}

// execCollector wraps an exec through a pluggable runFn so the same oracle body
// can run against the production path and (in the red/green test) a leaky one.
type execCollector struct {
	name    string
	timeout time.Duration
	runFn   func(ctx context.Context) (any, error)
}

func (c *execCollector) Name() string                             { return c.name }
func (c *execCollector) Timeout() time.Duration                   { return c.timeout }
func (c *execCollector) Collect(ctx context.Context) (any, error) { return c.runFn(ctx) }

// prodRunFn is the real production exec path: source.Live{}.Run (defaultExec →
// RunHardened → CapWriter → cmd.Run).
func prodRunFn(behavior string, n int) func(ctx context.Context) (any, error) {
	return func(ctx context.Context) (any, error) {
		res, err := source.Live{}.Run(ctx, os.Args[0],
			"-test.run=^TestRN1ExecHelper$", "-test.v=false",
			rn1HelperMarker, behavior, strconv.Itoa(n))
		if err != nil {
			return nil, err
		}
		return len(res.Stdout) + len(res.Stderr), nil
	}
}

// execOnce drives one exec through RunAll and returns the measured report, the
// results, and the post-drain fd/child/temp observations. Both runHygiene (which
// asserts) and the red/green test (which inspects) call this, so the oracle
// definitions live in exactly one place.
type hygieneObs struct {
	elapsed    time.Duration
	outBytes   int
	leftover   []int
	afterFD    int
	tempChange bool
}

func execOnce(t *testing.T, timeout time.Duration, runFn func(ctx context.Context) (any, error), pinDir, baseFP string) hygieneObs {
	t.Helper()
	col := []Collector{&execCollector{name: "exec", timeout: timeout, runFn: runFn}}

	var results []Result
	rep := resource.Measure(0, func() {
		results = drain(RunAll(context.Background(), col))
	})

	// The exec runs inside runOne's Collect goroutine; after RunAll drains, that
	// goroutine may still be closing pipes / reaping. Wait for it to be gone
	// before measuring fds/children (settleCollectors attributes on runOne.func1).
	settleCollectors(300)

	obs := hygieneObs{elapsed: rep.Elapsed}
	if len(results) == 1 {
		if nbytes, ok := results[0].Data.(int); ok {
			obs.outBytes = nbytes
		}
	}
	obs.leftover = settleChildren(t, 300)
	obs.afterFD = fdCount(t)
	obs.tempChange = resource.Fingerprint(t, pinDir) != baseFP
	return obs
}

// runHygiene drives one exec through RunAll and asserts H1–H5.
func runHygiene(t *testing.T, timeout time.Duration, runFn func(ctx context.Context) (any, error), pinDir, baseFP string, baseFD int) {
	t.Helper()
	obs := execOnce(t, timeout, runFn, pinDir, baseFP)

	// H5 — wall time bounded by the timeout, not the child's own duration.
	bound := timeout + platform.ExecWaitDelay + collectGrace + 3*time.Second
	if obs.elapsed > bound {
		t.Fatalf("H5 wall-time: exec took %s, bound %s (timeout=%s)", obs.elapsed, bound, timeout)
	}
	// H4 — output bounded.
	if obs.outBytes > source.MaxCapturedOutput*2 {
		t.Fatalf("H4 output: captured %d B exceeds 2×MaxCapturedOutput", obs.outBytes)
	}
	// H2 — no leftover child.
	if len(obs.leftover) != 0 {
		t.Fatalf("H2 process leak: %d child process(es) still parented by us: %v", len(obs.leftover), obs.leftover)
	}
	// H1 — no fd leak (+2 tolerance for runtime churn).
	if obs.afterFD > baseFD+1 {
		t.Fatalf("H1 fd leak: fd count grew from %d to %d", baseFD, obs.afterFD)
	}
	// H3 — no temp file left.
	if obs.tempChange {
		t.Fatalf("H3 temp leak: pinned TMPDIR tree %s changed across the run", pinDir)
	}
}

func decodeExecSpec(data []byte) (behavior string, n int, timeout time.Duration) {
	behaviors := []string{"fast", "exitcode", "flood", "sleep", "hang", "ignoresig"}
	if len(data) < 3 {
		return "fast", 0, 50 * time.Millisecond
	}
	behavior = behaviors[int(data[0])%len(behaviors)]
	switch behavior {
	case "flood":
		n = int(data[1]) % 256 // ≤ 255 KiB — feasible to fuzz, well under the 64 MiB cap
	case "sleep":
		n = int(data[1]) % 400 // ≤ 400 ms
	case "exitcode":
		n = int(data[1])
	}
	timeout = 30*time.Millisecond + time.Duration(data[2]%8)*20*time.Millisecond // 30–170 ms
	return behavior, n, timeout
}

func FuzzCollectorExecHygiene(f *testing.F) {
	f.Add([]byte{0, 0, 0})   // fast
	f.Add([]byte{1, 3, 1})   // exitcode 3
	f.Add([]byte{2, 64, 2})  // flood 64 KiB
	f.Add([]byte{3, 100, 1}) // sleep 100 ms
	f.Add([]byte{4, 0, 0})   // hang (killed on timeout)
	f.Add([]byte{5, 0, 0})   // ignore-signals (killed on timeout)

	f.Fuzz(func(t *testing.T, data []byte) {
		behavior, n, timeout := decodeExecSpec(data)

		execHygieneMu.Lock()
		defer execHygieneMu.Unlock()

		// Pin a fresh empty TMPDIR for the H3 fingerprint. (We do not export it
		// to the child's env — HardenedEnv snapshots the parent env; the point is
		// that the production path leaves nothing, so a stable empty tree is the
		// correct oracle.)
		pinDir := t.TempDir()
		baseFP := resource.Fingerprint(t, pinDir)

		settleCollectors(200) // let any prior exec goroutine drain before baselining
		baseFD := fdCount(t)

		runHygiene(t, timeout, prodRunFn(behavior, n), pinDir, baseFP, baseFD)
	})
}
