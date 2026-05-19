# DashDiag — Build Kickoff Summary
**Last updated: May 2026 | Sessions 1–5 complete**
**Research: COMPLETE (~80 sources, saturated)**

This document is your single-page reference before each Claude Code session.
Keep it open alongside DashDiag_Gap_Specs.md when building.

> Claude Code reads `CLAUDE.md` and `.cursorrules` automatically.
> Architecture rules in `.cursorrules` are NON-NEGOTIABLE.

---

## The Ironclad Rule

> **Never build deep before fast is in production use.**

Fast = runs in < 3s, ships first, gets real-world feedback.
Deep = opt-in with `--deep`, ships after fast is validated on real hardware.

---

## What Ships (commit a248bd0, Session 5)

| Command | File | Status |
|---|---|---|
| `dsd health` | cmd/health.go | ✅ fast+deep, k8s+docker wired |
| `dsd health deep` | collector | ✅ cgroup v2, smaps, top procs |
| `dsd net` | cmd/net.go | ✅ fast+deep+dns |
| `dsd net dns` | cmd/net.go | ✅ resolv.conf audit, live test |
| `dsd logs` | cmd/logs.go | ✅ shipped |
| `dsd services` | cmd/services.go | ✅ fast+deep |
| `dsd docker` | cmd/docker.go | ✅ crash-loop fixed, MTU, netavark |
| `dsd k8s` | cmd/k8s.go | ✅ JSON API, events, OS-layer deep |
| `dsd proc` | cmd/proc.go | ✅ smaps_rollup, FD map, D-state |
| `dsd cron` | cmd/cron.go | ✅ daemon, quality, anacron |
| `dsd gpu` | cmd/gpu.go | ✅ AMD sysfs + NVIDIA nouveau |
| `dsd security` | cmd/security.go | ✅ sshd-T, AVC, user audit |
| 20+ collectors | internal/collectors/ | ✅ shipped |

---

## Session 6 Build Plan

**What to build next (priority order):**

### 1. `dsd logs` improvements (~1.5d)
- Severity-ranked summary (CRITICAL/ERROR/WARN counts) at top
- Crash file detection: `/var/crash/`, `/var/lib/systemd/coredump/`, `/sys/fs/pstore/`
- `/var/log/*` scan on systems where syslog + journald coexist
- Journal corruption resilience fallback

**Spec:** DashDiag_Gap_Specs.md § Spec 3
**Files:** `internal/collectors/logs.go` (extend), `internal/models/logs.go` (extend)

### 2. `dsd disk` standalone (~2d)
- All mounted filesystems: used%, free, inode%, WARN/CRIT thresholds
- Physical disk type from `/sys/block/*/queue/rotational`
- SMART summary per disk
- ZFS pool health gate: `zpool binary + /proc/mounts has zfs entry`
- Deep: I/O rate via `/proc/diskstats` delta, top I/O processes, fuser busy check

**Spec:** DashDiag_Gap_Specs.md § Spec 4 + 4a + 4b
**Files:** `cmd/disk.go` (new), `internal/collectors/disk_linux.go` (new),
          `internal/collectors/disk_notlinux.go` (new), `internal/models/disk.go` (new)

---

## Session 7 Build Plan (needs Proxmox hardware)

### 3. `dsd pve` — Proxmox VE (~4d)
Gate: `/usr/share/pve-manager` exists.
All data via `pvesh` REST API (10s timeout per call).
**Spec:** DashDiag_Gap_Specs.md § Spec 24

### 4. `dsd kvm` — KVM/libvirt (~3d)
Gate: `virsh version` exit 0.
**Spec:** DashDiag_Gap_Specs.md § Spec 15

---

## Session 8 Build Plan

### 5. `dsd net deep` — NFS mount health (~1.5d)
Non-blocking stale mount detection (goroutine + 2s Statfs() timeout).
**Spec:** DashDiag_Gap_Specs.md § Spec 11

### 6. `dsd net deep` — BIND/named health (~1d)
Gate: named/bind9 process running.
**Spec:** DashDiag_Gap_Specs.md § Spec 16

---

## Key Patterns

### New collector template
```go
//go:build linux

package collectors

import (
    "context"
    "time"
    "github.com/keyorixhq/dashdiag/internal/models"
)

type FooCollector struct{}

func NewFooCollector() *FooCollector           { return &FooCollector{} }
func (c *FooCollector) Name() string           { return "Foo" }
func (c *FooCollector) Timeout() time.Duration { return 8 * time.Second }
func (c *FooCollector) Collect(ctx context.Context) (interface{}, error) {
    // ... read /proc or /sys, no external commands where possible
    return &models.FooInfo{}, nil
}
```

### Deploy to Legion
```bash
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.HXDa4Xy7fZ/Listeners make deploy
```

### k3s kubectl under sudo
```go
// WRONG: exec.LookPath("k3s") — sudo strips /usr/local/bin from PATH
// RIGHT: os.Stat("/usr/local/bin/k3s") — absolute path check
```

### funlen limit
90 statements per function max. Split at logical boundaries.
Renderers: split into Identity/State/Resources/Files/Connections sections.
Heuristics: split into sub-checks (checkK8sNodes, checkK8sPodHealth, etc).

---

## Gap Spec Locations

```
DashDiag_Gap_Specs.md    ← 51 specs, ~58d total, RESEARCH COMPLETE
BACKLOG.md               ← Sprint backlog, ✅ for done items
CLAUDE.md                ← Per-session Claude Code context
```
