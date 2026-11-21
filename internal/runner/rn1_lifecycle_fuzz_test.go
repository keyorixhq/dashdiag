package runner

// RN1 target 1 — runner lifecycle and resource hygiene.
//
// Seam. runner.RunAll fans a slice of collectors out across goroutines, bounds
// each with its own timeout, recovers panics, and ABANDONS a collector that
// ignores its context and misses its deadline (runOne: the Collect goroutine is
// left parked on the buffered `done` channel, synthesizing a timeout Result so
// the run stays bounded). RO1 reported these abandoned goroutines accumulating
// under a deny-all harness. This target drives RunAll with fuzz-generated
// synthetic collectors — fast, slow-but-ctx-respecting, ctx-IGNORING hangers,
// panickers, error-returners and big-output producers — in every mix, and
// asserts the lifecycle guarantees per input.
//
// Oracles (each independent of the runner's own bookkeeping):
//
//   O1  GOROUTINE ACCOUNTING. After the run drains, the only goroutines above
//       the pre-run baseline are the ctx-ignoring hangers the input planted —
//       exactly one parked goroutine per hanger, nothing else leaks. When the
//       hangers are then released, NumGoroutine settles back to baseline: an
//       abandoned goroutine is a BOUNDED, DRAINABLE parkel, never a permanent
//       leak. (This is the RO1 quantification: abandoned == #ctx-ignoring
//       collectors, and they all exit once their blocking call returns.)
//   O2  WALL-TIME BOUND. The channel closes within maxTimeout + collectGrace +
//       slack — bounded by the single longest declared timeout plus the grace,
//       NOT by the number of collectors (concurrency, not serialization).
//   O3  OUTPUT BOUNDED. Aggregate Result.Data bytes equal exactly what the
//       collectors declared — the runner neither drops nor amplifies output,
//       and total output is bounded by the per-input cap.
//   O4  TIMED-OUT ⇒ NEVER OK. A collector past its deadline (hanger or
//       ctx-respecting-but-slow) yields Err set to DeadlineExceeded/Canceled
//       and Data == nil — never a silent success. Fast/error/panic collectors
//       map to their own deterministic outcomes.
//   O5  DETERMINISM. The same input, run twice, yields the same canonical
//       report (results sorted by name; err-class + data length per result),
//       regardless of the nondeterministic completion ORDER.
//
// Resource meters enabled: TIME (O2, plus resource.Measure records elapsed) and
// GOROUTINES (O1, the central meter — resource.Measure's GoroutineDiff plus a
// hand-rolled settle/attribution). Memory alloc is RECORDED via resource.Measure
// (peak amplification lead) but NOT asserted: big-output collectors allocate on
// purpose, so a fixed alloc budget would be a calibrated false positive here.
// CPU/disk/network meters are N/A — this target is pure in-process, spawns no
// child process, opens no fd and touches no disk (the fd/process/temp-file
// hygiene of the REAL exec path is RN1 target 2,
// rn1_exechygiene_fuzz_linux_test.go).
//
// Concurrency note: NumGoroutine is process-global and the Go fuzzer runs
// workers in one process, so the whole measured body is serialized by
// lifecycleMu. With the lock held, the only other worker is parked on the lock
// (a single, stable goroutine the baseline absorbs), so the accounting is sound
// even under -parallel 2.

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// lifecycleMu serializes the goroutine-sensitive body (see header).
var lifecycleMu sync.Mutex

// collectGraceLocal mirrors the unexported runner.collectGrace. Kept as a local
// const (not a reach into runner internals) so this test states the coupling
// explicitly; a divergence would show up as an O2 wall-time failure, which is
// the intended tripwire.
const collectGraceLocal = collectGrace

// errRN1Sentinel is the deterministic error an ERROR-kind collector returns.
var errRN1Sentinel = errors.New("rn1 sentinel error")

type rn1Kind uint8

const (
	kindFast        rn1Kind = iota // respects ctx, returns quickly with small data
	kindBigOutput                  // respects ctx, returns a declared-size []byte
	kindSlowRespect                // respects ctx, delay >> timeout → returns ctx.Err() promptly
	kindHangIgnore                 // IGNORES ctx, blocks on release → abandoned by runner
	kindPanic                      // panics immediately → recovered into Result.Err
	kindError                      // returns errRN1Sentinel immediately
	rn1KindCount
)

type rn1Spec struct {
	kind    rn1Kind
	timeout time.Duration
	outLen  int // only meaningful for kindBigOutput
}

const (
	rn1MaxCollectors = 8
	rn1MaxOutLen     = 64 << 10 // 64 KiB per big-output collector (bounds total output)
	rn1MinTimeout    = 10 * time.Millisecond
	rn1WalltimeSlack = 2500 * time.Millisecond
)

// decodeSpecs turns fuzz bytes into up to rn1MaxCollectors collector specs. The
// timeouts are kept small (10–60 ms) and well-separated from the behaviours so
// outcomes are deterministic (no delay≈timeout boundary that could flip a run):
// a fast collector always completes, a hanger/slow-respect always exceeds its
// timeout. That separation is what makes O5 (determinism) a sound assertion.
func decodeSpecs(data []byte) []rn1Spec {
	var specs []rn1Spec
	for i := 0; i+2 < len(data) && len(specs) < rn1MaxCollectors; i += 3 {
		kind := rn1Kind(data[i] % uint8(rn1KindCount))
		timeout := rn1MinTimeout + time.Duration(data[i+1]%6)*10*time.Millisecond
		outLen := (int(data[i+2]) * rn1MaxOutLen) / 255
		specs = append(specs, rn1Spec{kind: kind, timeout: timeout, outLen: outLen})
	}
	return specs
}

type rn1Collector struct {
	name    string
	spec    rn1Spec
	release <-chan struct{}
}

func (c *rn1Collector) Name() string           { return c.name }
func (c *rn1Collector) Timeout() time.Duration { return c.spec.timeout }

func (c *rn1Collector) Collect(ctx context.Context) (any, error) {
	switch c.spec.kind {
	case kindFast:
		return []byte("ok"), nil
	case kindBigOutput:
		return make([]byte, c.spec.outLen), nil
	case kindSlowRespect:
		// Respects ctx: a delay far beyond the timeout, but cancellable, so it
		// returns ctx.Err() promptly when the deadline fires (no grace wait).
		select {
		case <-time.After(10 * time.Second):
			return []byte("late"), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	case kindHangIgnore:
		// Ignores ctx entirely — a wedged syscall analogue. The runner must
		// synthesize a timeout and abandon this goroutine; it exits only when
		// the test releases it.
		<-c.release
		return []byte("released"), nil
	case kindPanic:
		panic("rn1 induced panic")
	case kindError:
		return nil, errRN1Sentinel
	default:
		return nil, nil
	}
}

func buildCollectors(specs []rn1Spec, release <-chan struct{}) []Collector {
	cs := make([]Collector, len(specs))
	for i, s := range specs {
		cs[i] = &rn1Collector{name: fmt.Sprintf("c%d", i), spec: s, release: release}
	}
	return cs
}

func drain(ch <-chan Result) []Result {
	var out []Result
	for r := range ch {
		out = append(out, r)
	}
	return out
}

// collectFrameMarker is the stack-frame substring that identifies a goroutine
// the runner spawned to run one collector. Goroutine accounting is done by
// ATTRIBUTION (goleak-style) rather than by a raw NumGoroutine delta: the Go
// fuzzer reuses one process across inputs, so inter-input goroutine churn makes
// a bare count flaky, but a goroutine in runOne's Collect-runner closure is
// unambiguously a not-yet-reaped collector no matter what else the process does.
//
// We attribute on the RUNNER's own wrapper goroutine (runOne.func1), not on the
// collector's Collect frame, on purpose: a collector that has returned but whose
// wrapper is stuck trying to deliver its late Result (e.g. a regression that
// unbuffers the `done` channel) is still an un-reaped, leaked goroutine — it is
// parked in runOne.func1 at the send, no longer inside Collect. Counting the
// wrapper catches both the "still running Collect" and the "stuck delivering"
// leak classes; counting only Collect would miss the second (found during RN1
// red-proofing — the unbuffered-done plant leaked here invisibly).
const collectFrameMarker = "runner.runOne.func1"

// goroutineStacks returns a full stack dump of every goroutine, growing the
// buffer until it fits.
func goroutineStacks() string {
	size := 1 << 16
	for {
		buf := make([]byte, size)
		n := runtime.Stack(buf, true)
		if n < size {
			return string(buf[:n])
		}
		size *= 2
	}
}

// collectorGoroutines counts goroutines currently executing inside a
// rn1Collector.Collect frame — i.e. collectors the runner has NOT yet reaped.
func collectorGoroutines() int {
	return strings.Count(goroutineStacks(), collectFrameMarker)
}

// settleStableReads is how many consecutive equal reads (10ms apart) count as
// settled. Two reads proved too few: a sibling test's collector goroutine that
// drains ~20ms later inflated the baseline (surplus -1 on slow macOS runners).
const settleStableReads = 6

// settleCollectors polls collectorGoroutines until it is stable across
// settleStableReads consecutive reads (short-lived non-hanger Collect goroutines
// have exited), or gives up after maxTries. Returns the stable count.
func settleCollectors(maxTries int) int {
	prev := collectorGoroutines()
	stable := 1
	for i := 0; i < maxTries; i++ {
		time.Sleep(10 * time.Millisecond)
		cur := collectorGoroutines()
		if cur != prev {
			prev, stable = cur, 1
			continue
		}
		if stable++; stable >= settleStableReads {
			return cur
		}
	}
	return prev
}

// numGoroutineSettle reads NumGoroutine until stable across two reads, used only
// as a LOOSE secondary guard (with tolerance) against gross leaks of the
// runner's own fan-out/waiter goroutines, which attribution does not cover.
func numGoroutineSettle(maxTries int) int {
	prev := runtime.NumGoroutine()
	for i := 0; i < maxTries; i++ {
		time.Sleep(10 * time.Millisecond)
		cur := runtime.NumGoroutine()
		if cur == prev {
			return cur
		}
		prev = cur
	}
	return prev
}

// errClass canonicalizes a Result for the determinism oracle.
func errClass(r Result) string {
	switch {
	case r.Err == nil:
		return "ok"
	case errors.Is(r.Err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(r.Err, context.Canceled):
		return "canceled"
	case errors.Is(r.Err, errRN1Sentinel):
		return "sentinel"
	case strings.Contains(r.Err.Error(), "panicked"):
		return "panic"
	default:
		return "other"
	}
}

func canonical(results []Result) string {
	lines := make([]string, len(results))
	for i, r := range results {
		dataLen := 0
		if b, ok := r.Data.([]byte); ok {
			dataLen = len(b)
		}
		lines[i] = fmt.Sprintf("%s|%s|%d", r.Name, errClass(r), dataLen)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func totalDataBytes(results []Result) int {
	n := 0
	for _, r := range results {
		if b, ok := r.Data.([]byte); ok {
			n += len(b)
		}
	}
	return n
}

func FuzzRunnerLifecycle(f *testing.F) {
	// Seeds: one per kind, plus mixes and the all-hangers accumulation case.
	f.Add([]byte{byte(kindFast), 0, 0})
	f.Add([]byte{byte(kindBigOutput), 0, 255})
	f.Add([]byte{byte(kindSlowRespect), 0, 0})
	f.Add([]byte{byte(kindHangIgnore), 0, 0})
	f.Add([]byte{byte(kindPanic), 0, 0})
	f.Add([]byte{byte(kindError), 0, 0})
	// Mix: fast + hanger + big-output + panic.
	f.Add([]byte{
		byte(kindFast), 1, 0,
		byte(kindHangIgnore), 2, 0,
		byte(kindBigOutput), 0, 128,
		byte(kindPanic), 1, 0,
	})
	// Accumulation worst case: all hangers (max abandoned goroutines).
	f.Add([]byte{
		byte(kindHangIgnore), 0, 0, byte(kindHangIgnore), 1, 0,
		byte(kindHangIgnore), 2, 0, byte(kindHangIgnore), 3, 0,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		specs := decodeSpecs(data)
		if len(specs) == 0 {
			return
		}

		lifecycleMu.Lock()
		defer lifecycleMu.Unlock()

		// Count the ctx-ignoring hangers (the only kind the runner abandons).
		hangers := 0
		maxTimeout := rn1MinTimeout
		expectedData := 0
		for _, s := range specs {
			if s.kind == kindHangIgnore {
				hangers++
			}
			if s.timeout > maxTimeout {
				maxTimeout = s.timeout
			}
			switch s.kind {
			case kindFast:
				expectedData += len("ok")
			case kindBigOutput:
				expectedData += s.outLen
			}
		}

		// Baseline the collector-goroutine count: it is a DELTA oracle, not an
		// absolute-zero one, because sibling tests in this package run their own
		// mock collectors through the very same runOne.func1 frame the marker
		// counts, and under a plain `go test ./internal/runner` their goroutines
		// may still be draining when a fuzz seed runs. settleCollectors waits for
		// a stable reading; that stable value is our base, and every assertion
		// below is measured relative to it. (Under the real fuzz invocation
		// `-run=NONE -fuzz=...` no sibling runs, so base is 0.)
		base := settleCollectors(200)
		baseline := numGoroutineSettle(50)

		// ---- Run 1 (measured) ----
		release1 := make(chan struct{})
		c1 := buildCollectors(specs, release1)
		var res1 []Result
		rep := resource.Measure(len(data), func() {
			res1 = drain(RunAll(context.Background(), c1))
		})

		// O2 — wall-time bounded by the single longest timeout + grace, not by
		// collector count.
		bound := maxTimeout + collectGraceLocal + rn1WalltimeSlack
		if rep.Elapsed > bound {
			close(release1)
			t.Fatalf("O2 wall-time bound: run took %s, bound %s (maxTimeout=%s grace=%s slack=%s, %d collectors)",
				rep.Elapsed, bound, maxTimeout, collectGraceLocal, rn1WalltimeSlack, len(specs))
		}

		if len(res1) != len(specs) {
			close(release1)
			t.Fatalf("expected %d results, got %d", len(specs), len(res1))
		}

		// O1a — abandoned-goroutine accounting BEFORE releasing the hangers.
		// Every non-hanger collector goroutine has returned; only the
		// ctx-ignoring hangers remain parked in Collect. By stack attribution,
		// the number of parked collectors must equal exactly the number of
		// hangers the input planted — nothing more leaks.
		abandoned := settleCollectors(200) - base
		if abandoned != hangers {
			dump := goroutineDump()
			close(release1)
			t.Fatalf("O1 goroutine accounting: expected exactly %d abandoned collector goroutine(s) (one per ctx-ignoring hanger), saw surplus %d over base %d\n%s",
				hangers, abandoned, base, dump)
		}

		// O4 — a collector past its deadline is never a silent OK; each kind
		// maps to its deterministic outcome.
		byName := map[string]Result{}
		for _, r := range res1 {
			byName[r.Name] = r
		}
		for i, s := range specs {
			r := byName[fmt.Sprintf("c%d", i)]
			switch s.kind {
			case kindHangIgnore, kindSlowRespect:
				if r.Err == nil {
					close(release1)
					t.Fatalf("O4: collector %s (kind %d) exceeded its timeout but returned nil error (silent OK)", r.Name, s.kind)
				}
				if !errors.Is(r.Err, context.DeadlineExceeded) && !errors.Is(r.Err, context.Canceled) {
					close(release1)
					t.Fatalf("O4: collector %s timed out but Err is not Deadline/Canceled: %v", r.Name, r.Err)
				}
				if r.Data != nil {
					close(release1)
					t.Fatalf("O4: collector %s timed out but carries non-nil Data: %v", r.Name, r.Data)
				}
			case kindFast, kindBigOutput:
				if r.Err != nil {
					close(release1)
					t.Fatalf("O4: fast/big collector %s unexpectedly errored: %v", r.Name, r.Err)
				}
				if _, ok := r.Data.([]byte); !ok {
					close(release1)
					t.Fatalf("O4: fast/big collector %s missing []byte data", r.Name)
				}
			case kindError:
				if !errors.Is(r.Err, errRN1Sentinel) {
					close(release1)
					t.Fatalf("O4: error collector %s lost its sentinel: %v", r.Name, r.Err)
				}
			case kindPanic:
				if r.Err == nil || !strings.Contains(r.Err.Error(), "panicked") {
					close(release1)
					t.Fatalf("O4: panic collector %s not surfaced as a panic error: %v", r.Name, r.Err)
				}
			}
		}

		// O3 — output exactly what was declared (no runner drop/amplification),
		// and bounded by the per-input cap.
		got := totalDataBytes(res1)
		if got != expectedData {
			close(release1)
			t.Fatalf("O3: aggregate output %d B != declared %d B", got, expectedData)
		}
		if cap := rn1MaxCollectors * rn1MaxOutLen; got > cap {
			close(release1)
			t.Fatalf("O3: aggregate output %d B exceeds hard cap %d B", got, cap)
		}

		// O1b — release the hangers; every abandoned collector goroutine must
		// now drain. An abandoned goroutine is BOUNDED and DRAINABLE, never a
		// permanent leak: once its blocking call returns it exits (its buffered
		// `done` send never blocks). Attribution must fall to zero.
		close(release1)
		if remaining := settleCollectors(300) - base; remaining > 0 {
			dump := goroutineDump()
			t.Fatalf("O1 drain: %d collector goroutine(s) still parked (over base %d) after releasing %d hanger(s) — a permanent leak\n%s",
				remaining, base, hangers, dump)
		}
		// Loose secondary guard: the runner's own fan-out/waiter goroutines must
		// not accumulate either. Generous tolerance absorbs fuzzer/runtime churn
		// — the strong per-collector guarantee is O1a/O1b above.
		if after := numGoroutineSettle(100); after > baseline+4 {
			t.Fatalf("O1 gross leak: NumGoroutine grew from baseline %d to %d after a fully-drained run", baseline, after)
		}

		// ---- Run 2 (determinism) ----
		release2 := make(chan struct{})
		c2 := buildCollectors(specs, release2)
		res2 := drain(RunAll(context.Background(), c2))
		close(release2)
		settleCollectors(300)

		// O5 — identical canonical report regardless of completion order.
		if a, b := canonical(res1), canonical(res2); a != b {
			t.Fatalf("O5 determinism: two runs of the same input produced different reports:\n--- run1 ---\n%s\n--- run2 ---\n%s", a, b)
		}
	})
}

// goroutineDump returns a trimmed stack dump for attributing a leak in an O1
// failure message.
func goroutineDump() string {
	buf := make([]byte, 1<<16)
	n := runtime.Stack(buf, true)
	s := string(buf[:n])
	if len(s) > 8000 {
		s = s[:8000] + "\n...(truncated)"
	}
	return s
}
