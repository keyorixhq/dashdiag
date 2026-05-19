# DashDiag — Build Kickoff Summary
**Last updated: May 2026 | Sessions 1–10 complete**
**Research: COMPLETE (~80 sources, saturated)**

This document is your single-page reference before each Claude Code session.
Keep it open alongside DashDiag_Gap_Specs.md when building.

> Claude Code reads `CLAUDE.md` and `.cursorrules` automatically.
> Architecture rules in `.cursorrules` are NON-NEGOTIABLE.

---

## The Ironclad Rule

> **Never build deep before fast is in production use.**

---

## What Ships (commits through 67ff3a7, Session 10)

| Command | Status | Notes |
|---|---|---|
| `dsd health` | ✅ fast+deep | k8s+docker+kvm+sessions wired in |
| `dsd health deep` | ✅ | cgroup v2, smaps, pkg integrity, **cgroup scope labels** |
| `dsd net` | ✅ fast+deep+dns | |
| `dsd net deep` | ✅ | + NFS health + BIND/named health |
| `dsd logs` | ✅ | severity summary, crash files, log source |
| `dsd services` | ✅ fast+deep | failed units, boot offenders |
| `dsd docker` | ✅ + deep | exit codes, events, secrets, root, socket, daemon, log driver, IP fwd, firewalld |
| `dsd k8s` | ✅ + deep | JSON API, events, OS-layer checks |
| `dsd proc` | ✅ | smaps_rollup, FD map, D-state |
| `dsd cron` | ✅ | daemon, quality, anacron |
| `dsd gpu` | ✅ | AMD sysfs + NVIDIA nouveau |
| `dsd security` | ✅ | sshd-T, AVC+booleans+AppArmor, user audit, PAM |
| `dsd disk` | ✅ + deep | SMART Linux+macOS, ZFS, I/O, **LVM RAID/mirror** |
| `dsd kvm` | ✅ | VM/network/pool, libvirt/QEMU |
| `dsd timeline` | ✅ | journal+dmesg+load, dedup ×N |
| 20+ collectors | ✅ | all shipped |

---

## Session 11 Build Plan

### Option A — Proxmox (BLOCKED, needs hardware)
**`dsd pve`** — Proxmox VE node diagnostics (Spec 24, ~4d)
Gate: `/usr/share/pve-manager` exists. All data via `pvesh` REST API.
Files: `cmd/pve.go`, `internal/collectors/pve_linux.go`, `internal/models/pve.go`

### Option B — Unblocked (do these)

**1. Correlation engine v1** (~1d)
Wire the "20:00 overnight cluster" memory-pressure cascade:
- Input: `dsd health deep` OOM kills + `dsd docker` container exits + `dsd timeline` events
- Rule: OOM kill within 5 min of container exit → "memory pressure cascade" CRIT
- Files: `internal/analysis/correlations.go` (extend existing Correlate function)

**2. CVE exposure check** (~1 week)
OVAL feed: WARN CVSS ≥7.0, CRIT CVSS ≥9.0. Offline mode (no network during check).
Files: `cmd/cve.go` exists but only uses dnf/apt — add OVAL feed enrichment.

**3. Hetzner Debian validation** (~0.5d)
Set up Hetzner Debian server, run full smoke test. Key new surfaces:
- AppArmor denials (not SELinux)
- apt/dpkg package manager path
- No firewalld (ufw or nftables directly)

**4. Remaining docker addendums** (~0.5d total)
- 7g: DNS trap (container DNS → host 127.0.0.53 loop)
- 7h: Docker socket file permissions (should be 660, not 666)
- 7i: Architecture mismatch (ARM image on x86)

---

## Key Patterns (all sessions)

### New Linux-only command
```go
// 1. cmd/foo.go + internal/collectors/foo_linux.go + internal/models/foo.go
// 2. foo_notlinux.go stub (//go:build !linux)
// 3. Register in cmd/root.go init()
// 4. Wire into dsd health via FooAvailable() gate
```

### New section in dsd net deep
```go
// cmd/net.go: type-switch on *models.FooInfo after RunAll
// Collector returns nil = section absent
if deepFlag { cols = append(cols, collectors.NewFooCollector()) }
```

### NFS non-blocking stale (mandatory for any mount check)
```go
go func() { err := syscall.Statfs(mount, &st); ch <- err }()
select { case <-ch: /* healthy */; case <-time.After(2s): /* STALE */ }
```

### Deploy to Legion
```bash
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.HXDa4Xy7fZ/Listeners make deploy
```

### Build both platforms (always verify cross-compile)
```bash
go build ./...                                         # macOS
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ...   # Linux
```

---

## Gap Spec Locations

```
DashDiag_Gap_Specs.md    ← 51 specs, ~58d total, RESEARCH COMPLETE
BACKLOG.md               ← Sprint backlog, ✅ for done items
CLAUDE.md                ← Per-session Claude Code context
```
