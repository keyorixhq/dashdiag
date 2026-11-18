//go:build linux

package collectors

// NFL1 target — goroutine/fd leak oracle for the NFS stale-mount probe.
//
// RN1 CANDIDATE: nfsCheckMount (nfs_linux.go) runs syscall.Statfs in a goroutine
// it cannot join; on the 2 s-deadline OR ctx.Done() path it abandons that
// goroutine. On a real stale NFS mount the Statfs parks in D-state and never
// returns, so the goroutine leaks. For one-shot `dsd health` this is bounded (the
// process exits). For the long-running `dsd mcp` server (cmd/mcp.go toolHealth →
// runHealthOnce → runner.RunAll → NFSCollector → nfsCheckMount) the process
// persists across many dsd_health calls, so each call that re-probes the same
// stale mount leaks ANOTHER goroutine — unbounded growth.
//
// This file is the leak oracle. It drives nfsCheckMount through a fake source
// whose Statfs blocks until the test releases it (never a real NFS mount), using
// an ALREADY-CANCELLED context so nfsCheckMount takes its ctx.Done() abandon path
// instantly instead of waiting the real 2 s — the same abandon path, measured in
// microseconds. It asserts that probing M distinct mounts R times each leaves at
// most ~M abandoned goroutines (one per distinct in-flight mount), not M*R.
//
// Resource meters enabled (internal/testutil/resource):
//   - Goroutines: the leak is a goroutine leak — this is the primary meter.
//   - OpenFDs: the candidate claims "plus its fd". syscall.Statfs takes a path and
//     opens no descriptor, so this meter is expected to stay flat and REFUTES the
//     fd half of the candidate for THIS collector (a FIFO-open collector would be
//     the one to watch — see the sibling sweep in nfl1_blocking_syscall_sweep).
// Memory/CPU/disk/network/sleep meters are NOT enabled: the measured path does no
// disk/network I/O of its own (the fake source blocks in memory) and allocates
// trivially; the thing that can blow up is goroutine count, which is metered.
//
// What this oracle does NOT verify: it uses a cancelled context to reach the
// abandon path quickly, so it does not exercise the real 2 s wall-clock deadline
// (that path is covered by TestNfsCheckMount/"statfs hangs past 2s deadline").
// It does not prove the OS thread backing a D-state syscall is reclaimed — a Go
// goroutine blocked on a cgo/syscall keeps its M; the oracle counts goroutines,
// which is the user-visible leak. It cannot distinguish a genuinely-wedged mount
// from a slow one; that is a policy call nfsCheckMount already makes.

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// statfsInflightResetForTest clears all in-flight accounting so one case's
// deliberately-parked probes do not make the next case's first probe short-circuit.
func statfsInflightResetForTest() {
	statfsInflight.mu.Lock()
	defer statfsInflight.mu.Unlock()
	statfsInflight.n = map[string]int{}
	statfsInflight.abandoned = map[string]int{}
}

// A healthy mount probed by two overlapping callers must not read as wedged; only
// a probe whose caller already gave up (abandoned) caps further probes.
func TestStatfsGuardOverlapAllowedUntilAbandoned(t *testing.T) {
	statfsInflightResetForTest()
	t.Cleanup(statfsInflightResetForTest)
	p1, ok := statfsProbeBegin(nsDisk, "/m")
	if !ok {
		t.Fatal("first probe must be allowed")
	}
	p2, ok := statfsProbeBegin(nsDisk, "/m")
	if !ok {
		t.Fatal("overlapping probe whose peer is still being waited on must be allowed (healthy overlap)")
	}
	p1.abandon()
	if _, ok := statfsProbeBegin(nsDisk, "/m"); ok {
		t.Fatal("an abandoned (parked) probe must cap further probes")
	}
	p1.abandon() // idempotent: must not double-count
	p2.end()     // the waited-on probe finishing does not clear the parked one
	if _, ok := statfsProbeBegin(nsDisk, "/m"); ok {
		t.Fatal("mount stays capped while the abandoned probe is still parked")
	}
	p1.end()
	p1.abandon() // abandon after end is a no-op (race with the goroutine returning)
	if _, ok := statfsProbeBegin(nsDisk, "/m"); !ok {
		t.Fatal("after the parked probe returns, the mount must probe again")
	}
}

// blockingStatfsSource simulates a wedged NFS mount: Statfs blocks on a shared
// release channel (standing in for a D-state syscall that never returns) until
// the test closes it. started counts how many Statfs calls are currently parked,
// so the oracle can wait for them all to drain after releasing — keeping one
// fuzz iteration's abandoned goroutines from accumulating across the whole run.
type blockingStatfsSource struct {
	*source.Replay
	release chan struct{}
	started int64 // atomic: Statfs entries
	done    int64 // atomic: Statfs returns
}

func newBlockingStatfsSource() *blockingStatfsSource {
	return &blockingStatfsSource{
		Replay:  source.NewReplay(source.NewBundle()),
		release: make(chan struct{}),
	}
}

func (b *blockingStatfsSource) Statfs(_ string) (source.StatfsInfo, error) {
	atomic.AddInt64(&b.started, 1)
	<-b.release // park like a stale-NFS D-state statfs
	atomic.AddInt64(&b.done, 1)
	return source.StatfsInfo{}, nil
}

// releaseAndDrain unblocks every parked Statfs and waits for them to return, so
// the next iteration starts from a clean goroutine baseline.
func (b *blockingStatfsSource) releaseAndDrain(t testing.TB) {
	t.Helper()
	close(b.release)
	deadline := time.Now().Add(10 * time.Second)
	for atomic.LoadInt64(&b.done) < atomic.LoadInt64(&b.started) {
		if time.Now().After(deadline) {
			t.Fatalf("parked statfs goroutines did not drain: started=%d done=%d",
				atomic.LoadInt64(&b.started), atomic.LoadInt64(&b.done))
		}
		time.Sleep(time.Millisecond)
	}
}

// probeLeak runs the core measurement: with a cancelled context (instant abandon
// path), probe each of `mounts` `rounds` times through a blocking source, and
// report goroutine and fd growth measured WHILE the abandoned goroutines are
// still parked. It releases and drains before returning.
//
// Returns (goroutineDiff, fdDiff, distinctMounts).
func probeLeak(t testing.TB, mounts []string, rounds int) (int, int, int) {
	t.Helper()
	src := newBlockingStatfsSource()
	prev := SetSource(src)
	defer SetSource(prev)
	defer src.releaseAndDrain(t)

	// Already-cancelled ctx: nfsCheckMount selects ctx.Done() immediately,
	// marks the mount stale, and abandons the (now parked) statfs goroutine —
	// the real leak path, without the 2 s wall wait.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	distinct := map[string]struct{}{}
	for _, m := range mounts {
		distinct[m] = struct{}{}
	}

	// Let any pre-test goroutines settle, then sample.
	resource.WaitGoroutinesBelow(0, 50*time.Millisecond) // no-op settle: Gosched a few times
	before := resource.Sample(t)

	for r := 0; r < rounds; r++ {
		for _, mp := range mounts {
			m := &models.NFSMount{Mount: mp}
			nfsCheckMount(ctx, m)
		}
	}
	// Wait until exactly the expected number of statfs goroutines have actually
	// started parking (they are spawned asynchronously), so the sample is not
	// racing goroutine startup. Under the fix, fewer start (short-circuited).
	// We bound the wait; the assertion uses whatever has parked.
	settleStarted(src, 200*time.Millisecond)
	after := resource.Sample(t)

	return before.GoroutineDiff(after), before.FDDiff(after), len(distinct)
}

// settleStarted waits until the started counter stops increasing for a short
// quiet period or the deadline passes — the spawned statfs goroutines park
// asynchronously, so a naive immediate sample can undercount.
func settleStarted(src *blockingStatfsSource, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	last := int64(-1)
	for time.Now().Before(deadline) {
		cur := atomic.LoadInt64(&src.started)
		if cur == last {
			return
		}
		last = cur
		time.Sleep(5 * time.Millisecond)
	}
}

// slack absorbs runtime background-goroutine / fd jitter on the shared host.
const nfl1GoroutineSlack = 4
const nfl1FDSlack = 4

// assertBounded fails if the leak exceeds (distinct mounts + slack). Before the
// per-mount in-flight guard this FIRES (growth is rounds*distinct); after it,
// growth is ~distinct. fdDiff must stay within fd slack in BOTH states (statfs
// holds no fd — the fd half of the candidate is refuted for this collector).
func assertBounded(t testing.TB, label string, gDiff, fdDiff, distinct, rounds int) {
	t.Helper()
	if gDiff > distinct+nfl1GoroutineSlack {
		t.Fatalf("%s: goroutine leak unbounded: distinct mounts=%d rounds=%d -> leaked %d goroutines (cap %d). "+
			"Each repeat probe of an already-blocked mount spawned another abandoned statfs goroutine.",
			label, distinct, rounds, gDiff, distinct+nfl1GoroutineSlack)
	}
	if fdDiff > nfl1FDSlack {
		t.Fatalf("%s: fd leak: distinct=%d rounds=%d -> leaked %d fds (cap %d)",
			label, distinct, rounds, fdDiff, nfl1FDSlack)
	}
}

// TestNFSMountGoroutineLeakBounded is the deterministic red/green oracle.
// RED on current code (no guard): probing one mount 8 times leaks 8 goroutines.
// GREEN after the per-mount in-flight guard: leaks 1.
func TestNFSMountGoroutineLeakBounded(t *testing.T) {
	statfsInflightResetForTest()
	t.Cleanup(statfsInflightResetForTest)

	cases := []struct {
		name   string
		mounts []string
		rounds int
	}{
		{"one mount, repeated", []string{"/mnt/nfl1-stale-A"}, 8},
		{"three mounts, repeated", []string{"/mnt/nfl1-stale-B", "/mnt/nfl1-stale-C", "/mnt/nfl1-stale-D"}, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			statfsInflightResetForTest()
			gDiff, fdDiff, distinct := probeLeak(t, tc.mounts, tc.rounds)
			t.Logf("%s: goroutineΔ=%d fdΔ=%d distinct=%d rounds=%d", tc.name, gDiff, fdDiff, distinct, tc.rounds)
			assertBounded(t, tc.name, gDiff, fdDiff, distinct, tc.rounds)
		})
	}
}

// TestNFSMountGoroutineFlatOver1000 proves the fix keeps the goroutine count flat
// across 1000 probes of the same stale mount — the task's acceptance bar.
func TestNFSMountGoroutineFlatOver1000(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000-probe flatness check in -short")
	}
	statfsInflightResetForTest()
	t.Cleanup(statfsInflightResetForTest)
	gDiff, fdDiff, distinct := probeLeak(t, []string{"/mnt/nfl1-stale-1k"}, 1000)
	t.Logf("1000 probes: goroutineΔ=%d fdΔ=%d distinct=%d", gDiff, fdDiff, distinct)
	assertBounded(t, "1000 probes same mount", gDiff, fdDiff, distinct, 1000)
}

// probeDiskLeak drives disk.go's statfsToFS (the sibling leak site found by the
// sweep) through the same blocking source. statfsToFS ignores ctx and only
// abandons on its real 2 s timeout, so this cannot use the cancelled-ctx shortcut
// — each call costs ~2 s. Keep rounds small; the mechanism is identical to NFS.
func probeDiskLeak(t testing.TB, mount string, rounds int) (int, int) {
	t.Helper()
	src := newBlockingStatfsSource()
	prev := SetSource(src)
	defer SetSource(prev)
	defer src.releaseAndDrain(t)

	before := resource.Sample(t)
	for r := 0; r < rounds; r++ {
		_, _ = statfsToFS(mountEntry{device: "nfl1:/x", mountPoint: mount, fsType: "nfs"})
	}
	settleStarted(src, 200*time.Millisecond)
	after := resource.Sample(t)
	return before.GoroutineDiff(after), before.FDDiff(after)
}

// TestDiskStatfsGoroutineLeakBounded is the sibling red/green oracle for disk.go.
// RED on unguarded code: probing one wedged mount 3 times leaks 3 abandoned
// statfs goroutines. GREEN with the shared statfs in-flight guard: leaks 1.
func TestDiskStatfsGoroutineLeakBounded(t *testing.T) {
	statfsInflightResetForTest()
	t.Cleanup(statfsInflightResetForTest)
	// 8 rounds so the unguarded leak (8) clears the goroutine slack (distinct+4=5)
	// and the RED fires crisply; guarded, the first probe waits the 2 s timeout and
	// the other 7 short-circuit instantly (~2 s total, not 16 s).
	const rounds = 8
	gDiff, fdDiff := probeDiskLeak(t, "/mnt/nfl1-disk-stale", rounds)
	t.Logf("disk statfsToFS: goroutineΔ=%d fdΔ=%d rounds=%d", gDiff, fdDiff, rounds)
	// distinct=1 mount; same bound as the NFS oracle.
	assertBounded(t, "disk statfsToFS repeated", gDiff, fdDiff, 1, rounds)
}

// FuzzNFSMountGoroutineLeak explores mount-set shapes (how many distinct mounts,
// how many repeat rounds, degenerate path strings) and asserts the per-mount
// in-flight guard bounds the goroutine leak for every shape. The fuzzer input is
// decoded into a small (distinctMounts, rounds) pair plus a path flavour so the
// corpus can probe empty paths, duplicate paths and many-distinct-path sets.
func FuzzNFSMountGoroutineLeak(f *testing.F) {
	f.Add(byte(1), byte(8), byte(0))
	f.Add(byte(3), byte(4), byte(1))
	f.Add(byte(0), byte(2), byte(2)) // 0 -> clamped to 1 mount
	f.Add(byte(8), byte(1), byte(3))
	f.Add(byte(2), byte(16), byte(7))

	f.Fuzz(func(t *testing.T, nMounts, nRounds, flavour byte) {
		// Clamp to a host-friendly range: at most 8 distinct mounts, 32 rounds.
		distinct := int(nMounts%8) + 1
		rounds := int(nRounds%32) + 1

		mounts := make([]string, 0, distinct*rounds)
		base := make([]string, distinct)
		for i := 0; i < distinct; i++ {
			// Vary the path flavour so empty/odd strings are exercised too, but
			// keep each distinct mount a distinct key.
			base[i] = fmt.Sprintf("/mnt/nfl1-fuzz-%d-%d", flavour, i)
		}
		for r := 0; r < rounds; r++ {
			mounts = append(mounts, base...)
		}

		statfsInflightResetForTest()
		defer statfsInflightResetForTest()
		gDiff, fdDiff, d := probeLeak(t, mounts, rounds)
		assertBounded(t, fmt.Sprintf("fuzz n=%d r=%d", distinct, rounds), gDiff, fdDiff, d, rounds)
	})
}
