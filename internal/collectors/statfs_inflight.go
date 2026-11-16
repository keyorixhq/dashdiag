package collectors

import "sync"

// ── statfs in-flight guard (NFL1) ─────────────────────────────────────────────
//
// Two collectors probe a mount with syscall.Statfs in a goroutine they CANNOT
// join, because a stale NFS/CIFS/FUSE mount parks Statfs in uninterruptible
// D-state forever:
//
//   - nfsCheckMount   (nfs_linux.go)  — per NFS mount
//   - statfsToFS      (disk.go)       — per mount in the whole mount table
//
// Both abandon that goroutine when their 2 s deadline (or, for NFS, ctx) fires.
// For one-shot `dsd health` that leaks one goroutine per wedged mount until the
// process exits — bounded. For the long-running `dsd mcp` server the process
// persists across many dsd_health calls (cmd/mcp.go toolHealth → runHealthOnce →
// runner.RunAll → both collectors), so WITHOUT this guard every re-probe of the
// same still-wedged mount abandons ANOTHER goroutine + OS thread — unbounded
// growth, one per health run per wedged mount.
//
// The guard caps outstanding statfs probes at ONE per mount path, process-wide
// and shared across collectors (a path wedged for Disk is the same wedge NFS
// would hit). While a path's probe is still parked, a new probe does not spawn a
// second goroutine. An entry exists only while a Statfs is genuinely still
// blocked — the spawning goroutine clears it via statfsProbeEnd the instant
// Statfs returns — so "in flight" means "this path is unresponsive right now",
// and the caller reports that honestly instead of spawning a duplicate. The map
// is keyed by mount path and bounded by the number of distinct LIVE wedged mounts
// (a system fact from /proc/mounts, never attacker input), so it cannot grow
// without limit. A mount that recovers lets its parked Statfs return, clears the
// entry, and the next probe runs for real again — the guard self-heals.
const statfsMaxInflightPerMount = 1

var statfsInflight = struct {
	mu sync.Mutex
	n  map[string]int // mount path -> currently-parked statfs probes
}{n: map[string]int{}}

// statfsProbeBegin records intent to spawn a Statfs probe for mount. It returns
// true (incrementing the in-flight count) when the caller MAY spawn; it returns
// false when a probe for this mount is already parked at the cap, in which case
// the caller must NOT spawn and should report the mount unresponsive.
func statfsProbeBegin(mount string) bool {
	statfsInflight.mu.Lock()
	defer statfsInflight.mu.Unlock()
	if statfsInflight.n[mount] >= statfsMaxInflightPerMount {
		return false
	}
	statfsInflight.n[mount]++
	return true
}

// statfsProbeEnd clears one in-flight probe for mount, called by the spawned
// goroutine when (if ever) its Statfs returns. A wedged D-state probe never calls
// this, so the mount stays capped — exactly the bounded steady state we want.
func statfsProbeEnd(mount string) {
	statfsInflight.mu.Lock()
	defer statfsInflight.mu.Unlock()
	if statfsInflight.n[mount] > 0 {
		statfsInflight.n[mount]--
		if statfsInflight.n[mount] == 0 {
			delete(statfsInflight.n, mount) // keep the map bounded by LIVE wedged mounts
		}
	}
}

// statfsInflightResetForTest clears all in-flight accounting. Test-only: the leak
// oracles reset between cases so one case's deliberately-parked probes do not make
// the next case's first probe short-circuit.
func statfsInflightResetForTest() {
	statfsInflight.mu.Lock()
	defer statfsInflight.mu.Unlock()
	statfsInflight.n = map[string]int{}
}
