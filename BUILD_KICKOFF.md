# DashDiag — Build Kickoff Summary
**Last updated: May 2026 | Sessions 1–8 complete**
**Research: COMPLETE (~80 sources, saturated)**

This document is your single-page reference before each Claude Code session.
Keep it open alongside DashDiag_Gap_Specs.md when building.

> Claude Code reads `CLAUDE.md` and `.cursorrules` automatically.
> Architecture rules in `.cursorrules` are NON-NEGOTIABLE.

---

## The Ironclad Rule

> **Never build deep before fast is in production use.**

---

## What Ships (commits through d8351a9, Session 8)

| Command | Status | Notes |
|---|---|---|
| `dsd health` | ✅ fast+deep | k8s+docker+kvm+sessions wired in |
| `dsd health deep` | ✅ | cgroup v2, smaps, pkg integrity |
| `dsd net` | ✅ fast+deep+dns | |
| `dsd net deep` | ✅ | + NFS health + BIND/named health |
| `dsd logs` | ✅ | severity summary, crash files, log source |
| `dsd services` | ✅ fast+deep | failed units, boot offenders |
| `dsd docker` | ✅ | crash-loop fixed, MTU, netavark |
| `dsd k8s` | ✅ + deep | JSON API, events, OS-layer checks |
| `dsd proc` | ✅ | smaps_rollup, FD map, D-state |
| `dsd cron` | ✅ | daemon, quality, anacron |
| `dsd gpu` | ✅ | AMD sysfs + NVIDIA nouveau |
| `dsd security` | ✅ | sshd-T, AVC, user audit |
| `dsd disk` | ✅ + deep | SMART Linux+macOS, ZFS, I/O rate |
| `dsd kvm` | ✅ | VM/network/pool, libvirt/QEMU |
| 20+ collectors | ✅ | all shipped |

---

## Session 9 Build Plan

### Option A — Proxmox (BLOCKED, needs hardware)

#### 1. `dsd pve` — Proxmox VE (~4d)
Gate: `/usr/share/pve-manager` exists.
All data via `pvesh` REST API (10s timeout per call).
**Spec:** DashDiag_Gap_Specs.md § Spec 24
**Files:**
```
cmd/pve.go
internal/collectors/pve_linux.go
internal/models/pve.go
```

### Option B — Unblocked alternatives

#### 2. `dsd ssh` — SSH connection doctor (~1.5d)
Tests SSH connectivity, key auth, banner, latency per host.
**Spec:** DashDiag_Gap_Specs.md § Spec 13
**Files:** `cmd/ssh.go`, `internal/collectors/ssh_linux.go`, `internal/models/ssh_doctor.go`

#### 3. `dsd timeline` — unified incident timeline (~3d)
Merges journalctl, dmesg, sar, load avg into single timeline.
The "20:00 overnight cluster" canonical scenario target.
**Spec:** DashDiag_Gap_Specs.md § Spec 22

#### 4. CVE exposure check (~1 week)
OVAL feed integration, WARN CVSS ≥ 7.0, CRIT CVSS ≥ 9.0.

---

## Key Patterns

### New section in dsd net deep (NFS/BIND pattern)
```go
// 1. collector returns nil when gate fails (service not present)
func (c *BINDCollector) Collect(ctx context.Context) (interface{}, error) {
    if !bindDetect() { return nil, nil }
    // ... collect ...
}

// 2. cmd/net.go adds to cols slice
if deepFlag { cols = append(cols, collectors.NewBINDCollector()) }

// 3. type-switch on result
case *models.BINDInfo: bindInfo = v

// 4. render after network section
if bindInfo != nil && bindInfo.Detected { printBINDReport(bindInfo) }
```

### NFS non-blocking stale detection
```go
go func() { err := syscall.Statfs(mount, &st); ch <- err }()
select {
case <-ch:        // healthy — got response within timeout
case <-time.After(2 * time.Second): // STALE — never blocks caller
}
```

### Deploy to Legion
```bash
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.HXDa4Xy7fZ/Listeners make deploy
```

### Build both platforms (cross-compile check)
```bash
go build ./...                                         # macOS
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ...    # Linux
```

---

## Gap Spec Locations

```
DashDiag_Gap_Specs.md    ← 51 specs, ~58d total, RESEARCH COMPLETE
BACKLOG.md               ← Sprint backlog, ✅ for done items
CLAUDE.md                ← Per-session Claude Code context
```
