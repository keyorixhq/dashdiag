# DashDiag — Build Kickoff Summary
**Last updated: May 2026 | Sessions 1–11 complete**
**Research: COMPLETE (~80 sources, saturated)**

This document is your single-page reference before each Claude Code session.
Keep it open alongside DashDiag_Gap_Specs.md when building.

> Claude Code reads `CLAUDE.md` and `.cursorrules` automatically.
> Architecture rules in `.cursorrules` are NON-NEGOTIABLE.

---

## The Ironclad Rule

> **Never build deep before fast is in production use.**

---

## What Ships (commits through 0c42bb6, Session 11)

| Command | Status | Notes |
|---|---|---|
| `dsd health` | ✅ fast+deep | k8s+docker+kvm+sessions wired in |
| `dsd health deep` | ✅ | cgroup v2, smaps, pkg integrity, cgroup scope labels |
| `dsd net` | ✅ fast+deep+dns | |
| `dsd net deep` | ✅ | + NFS health + BIND/named health |
| `dsd logs` | ✅ | severity summary, crash files, log source |
| `dsd services` | ✅ fast+deep | failed units, boot offenders |
| `dsd docker` | ✅ + deep | exit codes, events, secrets, root, socket, daemon, log driver, IP fwd, firewalld, **DNS trap, arch mismatch** |
| `dsd k8s` | ✅ + deep | JSON API, events, OS-layer checks |
| `dsd proc` | ✅ | smaps_rollup, FD map, D-state |
| `dsd cron` | ✅ | daemon, quality, anacron |
| `dsd gpu` | ✅ | AMD sysfs + NVIDIA nouveau |
| `dsd security` | ✅ | sshd-T, AVC+booleans+AppArmor, user audit, PAM |
| `dsd disk` | ✅ + deep | SMART Linux+macOS, ZFS, I/O, LVM RAID/mirror |
| `dsd kvm` | ✅ | VM/network/pool, libvirt/QEMU |
| `dsd timeline` | ✅ | journal+dmesg+load, dedup ×N, **18-pattern hint system** |
| `dsd cve` | ✅ | dnf/apt/zypper + **OVAL scan** + **CVSS scores** + **subscription detection** |
| Correlation engine | ✅ | 9 rules: memory cascade, OOM, IO, network, GPU, CPU steal, DBus, **Container OOM Cascade** |
| 20+ collectors | ✅ | all shipped |

---

## Session 11 — Completed (RHEL 10.1 live hardware, Legion)

| Commit | What | Validated |
|---|---|---|
| `eaec50a` | Podman OOM: `die+exitCode=137` counts as OOMEvents | RHEL 10.1 live |
| `57754c2` | Docker 7g/7h/7i: DNS trap, socket perm, arch mismatch | arm64/amd64 live |
| `8f04e08` | CVE dnf severity parser: all-Low→1 Critical/101 Important | RHEL 10.1 live |
| `65dd20c` | Timeline hint system: 18 patterns, explain/inspect/fix/persist | veth/ENOBUFS live |
| `247f6e5` | `dsd cve --oval-scan`: CVSS-scored OVAL package scan (1,772 findings) | RHEL 10.1 live |
| `2638fda` | CVE enrichment: RHSA→CVE IDs from subscribed RHEL dnf | RHEL 10.1 live |
| `0c42bb6` | Subscription detection: not-root / not-registered / expired hints | RHEL 10.1 live |

**Bugs found and fixed on live hardware:**
- Podman emits `die+exitCode=137` not a separate `oom` event (OOMEvents always 0 before)
- `dnf updateinfo list` format is `RHSA Critical/Sec. pkg` not `RHSA security critical pkg`
- `/usr/local/bin` not in root's PATH on RHEL 10 — deploy now hits both locations
- `ScanAllCVEs` 60s timeout too short for list + CVE enrichment passes (now 120s)

---

## Session 12 Build Plan

### BLOCKED (needs Proxmox hardware)
**`dsd pve`** — Proxmox VE node diagnostics (Spec 24, ~4d)
Gate: `/usr/share/pve-manager` exists. All data via `pvesh` REST API.
Files: `cmd/pve.go`, `internal/collectors/pve_linux.go`, `internal/models/pve.go`

### Unblocked — do in order

**1. Hetzner Debian validation** (~0.5d)
Set up Hetzner Debian server, run full smoke test. Key new surfaces:
- AppArmor denials (not SELinux) — Session 10 security work not yet live-validated
- apt/dpkg package manager path
- No firewalld (ufw or nftables directly)
- Docker (not Podman) — validate 7g/7h/7i on Docker runtime

**2. v2 direction: correlation engine enrichment** (~1-2d)
The "synthesis gap" is the product's deepest strategic opportunity.
Next rule to encode: the 20:00 overnight cluster scenario as a multi-step
cascade (memory → swap → IO → network → OOM kills, all within a 15-min window).
File: `internal/analysis/correlate.go` — add `CorrelateDeep` time-window rules.

**3. `dsd cve` OVAL for Debian/Ubuntu** (~1d)
OVAL parser works for RHEL. Debian/Ubuntu OVAL uses a different schema.
Source: https://security-metadata.canonical.com/oval/
Files: `internal/cvedata/oval_rhel.go` pattern → `oval_debian.go`

**4. First paying customer prep**
- Landing page copy from MARKETING.md stories
- `dsd trial start` command (14-day team trial, no card)
- Pricing page: Free / Pro / Enterprise

---

## Key Patterns (all sessions)

### New Linux-only command
```go
// 1. cmd/foo.go + internal/collectors/foo_linux.go + internal/models/foo.go
// 2. foo_notlinux.go stub (//go:build !linux)
// 3. Register in cmd/root.go init()
// 4. Wire into dsd health via FooAvailable() gate
```

### Deploy to Legion (installs to both /usr/bin and /usr/local/bin)
```bash
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.HXDa4Xy7fZ/Listeners make deploy
```

### Run as root on Legion
```bash
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.HXDa4Xy7fZ/Listeners make run-root ARGS="health deep --plain"
```

### Capture broken state BEFORE cleaning up (mandatory)
```bash
# On the broken machine — run this BEFORE fixing or cleaning up:
sudo dsd health --json | dsd capture > fixtures/HOSTNAME-SCENARIO-DATE.yaml

# Verify it replays:
dsd mock fixtures/HOSTNAME-SCENARIO-DATE.yaml

# Also save raw disk/LVM state:
sudo dsd disk --json > marketing-assets/HOSTNAME-data/disk-SCENARIO.json
```
The fixture is replayable forever, on any machine, no hardware needed.

---

## Gap Spec Locations

```
DashDiag_Gap_Specs.md    ← 51 specs, ~58d total, RESEARCH COMPLETE
BACKLOG.md               ← Sprint backlog, ✅ for done items
CLAUDE.md                ← Per-session Claude Code context
MARKETING.md             ← All stories and positioning copy
```
