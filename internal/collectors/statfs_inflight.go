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

// statfsProbe is one spawned Statfs probe. The caller marks it abandoned when it
// stops waiting (timeout or ctx cancel); the spawned goroutine ends it if/when
// Statfs returns.
type statfsProbe struct {
	key       string
	abandoned bool
	done      bool
}

var statfsInflight = struct {
	mu        sync.Mutex
	n         map[string]int // "<ns><mount path>" -> outstanding probes (waited-on or parked)
	abandoned map[string]int // "<ns><mount path>" -> probes whose caller gave up (parked in D-state)
}{n: map[string]int{}, abandoned: map[string]int{}}

// statfsProbeBegin registers a Statfs probe for (ns, mount). It returns the probe
// handle and true when the caller MAY spawn; it returns false only when an
// ABANDONED probe for this (ns, mount) is still parked — the mount is wedged, so
// the caller must NOT spawn another goroutine and should report it unresponsive.
// A probe whose caller is still waiting is not wedged evidence: a healthy statfs
// returns in microseconds, so two overlapping callers (parallel collectors,
// overlapping dsd_health calls on the long-running MCP server) must both be
// allowed to probe rather than the second reading a healthy mount as unresponsive.
func statfsProbeBegin(ns, mount string) (*statfsProbe, bool) {
	key := ns + mount
	statfsInflight.mu.Lock()
	defer statfsInflight.mu.Unlock()
	if statfsInflight.abandoned[key] >= statfsMaxInflightPerMount {
		return nil, false
	}
	statfsInflight.n[key]++
	return &statfsProbe{key: key}, true
}

// abandon records that the caller stopped waiting on this probe (deadline or ctx).
// From now until the probe ends, the mount counts as wedged. No-op if the probe
// already ended.
func (p *statfsProbe) abandon() {
	statfsInflight.mu.Lock()
	defer statfsInflight.mu.Unlock()
	if p.done || p.abandoned {
		return
	}
	p.abandoned = true
	statfsInflight.abandoned[p.key]++
}

// end clears this probe, called by the spawned goroutine when (if ever) its
// Statfs returns. A wedged D-state probe never calls this, so the mount stays
// capped — the bounded steady state we want.
func (p *statfsProbe) end() {
	statfsInflight.mu.Lock()
	defer statfsInflight.mu.Unlock()
	if p.done {
		return
	}
	p.done = true
	if statfsInflight.n[p.key] > 0 {
		statfsInflight.n[p.key]--
		if statfsInflight.n[p.key] == 0 {
			delete(statfsInflight.n, p.key) // keep the map bounded by LIVE wedged mounts
		}
	}
	if p.abandoned {
		statfsInflight.abandoned[p.key]--
		if statfsInflight.abandoned[p.key] <= 0 {
			delete(statfsInflight.abandoned, p.key)
		}
	}
}
