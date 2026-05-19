# DashDiag — Build Kickoff Summary
**Last updated: May 2026 | Sessions 1–6 complete**
**Research: COMPLETE (~80 sources, saturated)**

This document is your single-page reference before each Claude Code session.
Keep it open alongside DashDiag_Gap_Specs.md when building.

> Claude Code reads `CLAUDE.md` and `.cursorrules` automatically.
> Architecture rules in `.cursorrules` are NON-NEGOTIABLE.

---

## The Ironclad Rule

> **Never build deep before fast is in production use.**

---

## What Ships (commits through f1a8296, Session 6)

| Command | Status | Notes |
|---|---|---|
| `dsd health` | ✅ fast+deep | k8s+docker+sessions wired in |
| `dsd health deep` | ✅ | cgroup v2, smaps, top procs |
| `dsd net` | ✅ fast+deep+dns | |
| `dsd logs` | ✅ | severity summary, crash files, log source |
| `dsd services` | ✅ fast+deep | failed units, boot offenders |
| `dsd docker` | ✅ | crash-loop fixed, MTU, netavark |
| `dsd k8s` | ✅ + deep | JSON API, events, OS-layer checks |
| `dsd proc` | ✅ | smaps_rollup, FD map, D-state |
| `dsd cron` | ✅ | daemon, quality, anacron |
| `dsd gpu` | ✅ | AMD sysfs + NVIDIA nouveau |
| `dsd security` | ✅ | sshd-T, AVC, user audit |
| `dsd disk` | ✅ + deep | SMART Linux+macOS, ZFS, I/O rate |
| 20+ collectors | ✅ | all shipped |

---

## Session 7 Build Plan (needs Proxmox hardware)

### 1. `dsd pve` — Proxmox VE (~4d)
Gate: `/usr/share/pve-manager` exists.
All data via `pvesh` REST API (10s timeout per call).
**Spec:** DashDiag_Gap_Specs.md § Spec 24
**Files:**
```
cmd/pve.go
internal/collectors/pve_linux.go
internal/models/pve.go
```

**Key checks:**
- Node status: CPU, RAM, load, uptime via `pvesh get /nodes/localhost/status`
- VM/CT list: state, CPU/RAM allocation via `pvesh get /nodes/localhost/qemu` + `/lxc`
- Storage pools: used%, state via `pvesh get /nodes/localhost/storage`
- Recent task errors: `pvesh get /nodes/localhost/tasks --errors 1`
- Cluster quorum: `pvesh get /cluster/status` (if cluster)

### 2. `dsd kvm` — KVM/libvirt (~3d)
Gate: `virsh version` exits 0.
**Spec:** DashDiag_Gap_Specs.md § Spec 15
**Files:**
```
cmd/kvm.go
internal/collectors/kvm_linux.go
internal/models/kvm.go
```

---

## Session 8 Build Plan

### 3. `dsd net deep` — NFS mount health (~1.5d)
Non-blocking stale mount detection (goroutine + 2s `Statfs()` timeout).
**Spec:** DashDiag_Gap_Specs.md § Spec 11

### 4. `dsd net deep` — BIND/named health (~1d)
Gate: named/bind9 process running. `named-checkconf`, `rndc status`.
**Spec:** DashDiag_Gap_Specs.md § Spec 16

---

## Session 9 Build Plan

### 5. Package dependency integrity (~0.5d)
`dpkg --audit` (Debian) + `dnf check` / `rpm --verify` (RHEL, deep-only 10s cap).
**Spec:** DashDiag_Gap_Specs.md § Spec 12

---

## Key Patterns

### New collector — Linux+macOS template
```
internal/collectors/foo_linux.go      //go:build linux
internal/collectors/foo_darwin.go     //go:build darwin   (if macOS variant)
internal/collectors/foo_darwin_stub.go //go:build darwin  (no-op Linux methods)
internal/collectors/foo_notlinux.go   //go:build !linux && !darwin
```

### Deploy to Legion
```bash
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.HXDa4Xy7fZ/Listeners make deploy
```

### SMART parser — NVMe field format
```go
// smartctl -A output: "Percentage Used:  0%"
colonIdx := strings.Index(line, ":")
val := strings.TrimSpace(line[colonIdx+1:])
valFields := strings.Fields(val)
if len(valFields) == 0 { continue }
val = strings.TrimSuffix(valFields[0], "%")
```

### macOS SMART — diskutil (no smartctl)
```go
// diskutil info /dev/disk0 → "SMART Status: Verified"
// No external tool needed — diskutil ships with every macOS
```

### ZFS gate — zero overhead
```go
// Only runs when: zpool binary exists AND /proc/mounts has zfs entry
// parseZFSSize() lives in collectors/zfs.go — never redeclare
```

### k3s sudo PATH fix
```go
// WRONG: exec.LookPath("k3s") — sudo strips /usr/local/bin
// RIGHT: os.Stat("/usr/local/bin/k3s")
```

### funlen = 90 statements
Split renderers into: Identity / State / Resources / Files / Connections sections.
Split heuristics into: checkXxxNodes, checkXxxPodHealth, checkXxxExtras etc.

---

## Gap Spec Locations

```
DashDiag_Gap_Specs.md    ← 51 specs, ~58d total, RESEARCH COMPLETE
BACKLOG.md               ← Sprint backlog, ✅ for done items
CLAUDE.md                ← Per-session Claude Code context
```
