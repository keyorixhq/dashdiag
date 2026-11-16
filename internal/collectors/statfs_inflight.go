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
// The guard caps outstanding statfs probes at ONE per (collector, mount path).
// While a (collector, path) probe is still parked, a new probe of the same pair
// does not spawn a second goroutine. An entry exists only while a Statfs is
// genuinely still blocked — the spawning goroutine clears it via statfsProbeEnd
// the instant Statfs returns — so "in flight" means "this path is unresponsive
// right now", and the caller reports that honestly instead of spawning a
// duplicate. The map is keyed by (collector, mount path) and bounded by the
// number of distinct LIVE wedged mounts (a system fact from /proc/mounts, never
// attacker input) times the small fixed number of statfs-probing collectors, so
// it cannot grow without limit. A mount that recovers lets its parked Statfs
// return, clears the entry, and the next probe runs for real again — self-healing.
//
// Why the key is (collector, path) and NOT just path: the leak this guard bounds
// is accumulation ACROSS health runs, which is per-collector anyway (each run
// invokes each collector once). The NFS and Disk collectors run CONCURRENTLY in
// one run (runner.RunAll) and both probe NFS mount paths. A path-only key would
// let one collector's in-flight probe make the OTHER collector short-circuit —
// and for a HEALTHY mount (statfs returns in microseconds) that overlap is a
// race window in which a live mount would be falsely reported unresponsive. The
// collector namespace removes that cross-collector coupling; each collector still
// gets its own one-probe-per-mount cap, which is all the leak bound needs.
const statfsMaxInflightPerMount = 1

// statfs-probe namespaces, so the two concurrently-running call sites never
// contend on each other's in-flight slot (see the file header).
const (
	nsNFS  = "nfs\x00"
	nsDisk = "disk\x00"
)

var statfsInflight = struct {
	mu sync.Mutex
	n  map[string]int // "<ns>\x00<mount path>" -> currently-parked statfs probes
}{n: map[string]int{}}

// statfsProbeBegin records intent to spawn a Statfs probe for (ns, mount). It
// returns true (incrementing the in-flight count) when the caller MAY spawn; it
// returns false when a probe for this (ns, mount) is already parked at the cap,
// in which case the caller must NOT spawn and should report the mount
// unresponsive.
func statfsProbeBegin(ns, mount string) bool {
	key := ns + mount
	statfsInflight.mu.Lock()
	defer statfsInflight.mu.Unlock()
	if statfsInflight.n[key] >= statfsMaxInflightPerMount {
		return false
	}
	statfsInflight.n[key]++
	return true
}

// statfsProbeEnd clears one in-flight probe for (ns, mount), called by the
// spawned goroutine when (if ever) its Statfs returns. A wedged D-state probe
// never calls this, so the mount stays capped — the bounded steady state we want.
func statfsProbeEnd(ns, mount string) {
	key := ns + mount
	statfsInflight.mu.Lock()
	defer statfsInflight.mu.Unlock()
	if statfsInflight.n[key] > 0 {
		statfsInflight.n[key]--
		if statfsInflight.n[key] == 0 {
			delete(statfsInflight.n, key) // keep the map bounded by LIVE wedged mounts
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
