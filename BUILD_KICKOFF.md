# DashDiag — Build Kickoff Summary
**Last updated: May 2026 | Sessions 1–12 complete**
**Research: COMPLETE (~80 sources, saturated)**

This document is your single-page reference before each Claude Code session.
Keep it open alongside DashDiag_Gap_Specs.md when building.

> Claude Code reads `CLAUDE.md` and `.cursorrules` automatically.
> Architecture rules in `.cursorrules` are NON-NEGOTIABLE.

---

## The Ironclad Rule

> **Never build deep before fast is in production use.**

---

## What Ships (commits through e31329f, Session 12)

| Command | Status | Notes |
|---|---|---|
| `dsd health` | ✅ fast+deep | k8s+docker+kvm+sessions wired in |
| `dsd health deep` | ✅ | cgroup v2, smaps, pkg integrity, cgroup scope labels |
| `dsd net` | ✅ fast+deep+dns | |
| `dsd net deep` | ✅ | + NFS health + BIND/named health |
| `dsd logs` | ✅ | severity summary, crash files, log source |
| `dsd services` | ✅ fast+deep | failed units, boot offenders |
| `dsd docker` | ✅ + deep | exit codes, events, secrets, root, socket, daemon, log driver, IP fwd, firewalld, DNS trap, arch mismatch |
| `dsd k8s` | ✅ + deep | JSON API, events, OS-layer checks |
| `dsd proc` | ✅ | smaps_rollup, FD map, D-state |
| `dsd cron` | ✅ | daemon, quality, anacron |
| `dsd gpu` | ✅ | AMD sysfs + NVIDIA (nvidia-smi) + nouveau fallback |
| `dsd security` | ✅ | sshd-T, AVC+booleans+AppArmor, user audit, PAM |
| `dsd disk` | ✅ + deep | SMART Linux+macOS, ZFS, I/O, LVM RAID/mirror, **btrfs device health** |
| `dsd kvm` | ✅ | VM/network/pool, libvirt/QEMU |
| `dsd timeline` | ✅ | journal+dmesg+load, dedup ×N, 18-pattern hint system |
| `dsd cve` | ✅ | dnf/apt/zypper + OVAL scan (RHEL/Ubuntu/SUSE) + CVSS scores + subscription detection |
| Correlation engine | ✅ | 9 rules incl. Container OOM Cascade |
| 20+ collectors | ✅ | all shipped |

---

## Session 12 — Completed (Debian 13 + openSUSE Leap 16.0)

### Bugs found and fixed on live hardware

| Bug | Distro | Commit |
|---|---|---|
| LVM `debian-vg` → `debian--vg` in dm path — VG not detected as active | Debian 13 | `1c7b64d` |
| `Launchd ✅` showing on every Linux distro — macOS-only row leaking | Both | `10dd73f` |
| rsyslog install hint missing `zypper install rsyslog` | openSUSE | `79e0361` |
| NVIDIA hint showed `dnf` first — should be `apt` for Debian/Ubuntu | Debian 13 | `d83281c` |
| btrfs RAID1 missing device — NOT detected (fixed with new btrfs collector) | openSUSE | `0f16b76` |
| SUSE OVAL `Leap-release` in every result — platform marker, not a package | openSUSE | `ce85170` |

### New capabilities

| Feature | Commit |
|---|---|
| Ubuntu/Debian OVAL parser (`oval_debian.go`) — dpkg + priority strings | `1c8688e` |
| SUSE/openSUSE OVAL parser (`oval.go`) — patch class + RPM + title severity | `ce85170` |
| btrfs device health (`btrfs_linux.go`) — missing devices + I/O errors | `0f16b76` |
| OVAL router: auto-detect RHEL/Ubuntu/SUSE by filename | `1c8688e` |

### Validated distros (Session 12)
- Debian 13 (Trixie), kernel 6.12.88+deb13-amd64
- openSUSE Leap 16.0, kernel 6.12.0-160000.5-default
- Ubuntu 26.04 LTS (Resolute Raccoon), kernel 7.0.0-15-generic

---

## Session 13 Build Plan

### Distro validation (in progress)
**Ubuntu 26.04 LTS** ✅ COMPLETE — microk8s detected, LVM confirmed, OVAL 98 findings

**Rocky Linux 9** — next hardware target
- Validates RHEL 9 OVAL on real hardware (had RHEL 10 before, no subscription)
- Most common enterprise RHEL replacement — high customer relevance
- Confirms dnf path, SELinux, SMART all working on RHEL-compatible distro
- ~30 min smoke test

**Fedora 42** — after Rocky
- DNF5 (different from DNF4 on RHEL/Rocky) — separate code path
- Cutting-edge kernel, fast validation
- ~20 min

### Unblocked — next code work

**1. First paying customer prep** (highest priority after validation)
- Landing page copy from MARKETING.md stories
- `dsd trial start` command (14-day team trial, no card)
- Pricing page: Free / Pro / Enterprise

**2. Correlation engine v2** (~1-2d)
The synthesis gap is the product's deepest strategic opportunity.
Next rule: 20:00 overnight memory cascade (memory → swap → IO → network → OOM).
File: `internal/analysis/correlate.go`

**3. `dsd capture` extension** (~0.5d)
Accept `dsd disk --json` as input (not just health).
Needed before first public demo.

**4. `dsd pve`** — BLOCKED on Proxmox hardware

---

## Key Patterns (all sessions)

### New Linux-only command
```go
// 1. cmd/foo.go + internal/collectors/foo_linux.go + internal/models/foo.go
// 2. foo_notlinux.go stub (//go:build !linux)
// 3. Register in cmd/root.go init()
// 4. Wire into dsd health via FooAvailable() gate
```

### Deploy (installs to both /usr/bin and /usr/local/bin)
```bash
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.HXDa4Xy7fZ/Listeners make deploy
```

### Capture broken state BEFORE cleaning up (mandatory)
```bash
sudo dsd health --json | dsd capture > fixtures/HOSTNAME-SCENARIO-DATE.yaml
dsd mock fixtures/HOSTNAME-SCENARIO-DATE.yaml   # verify
sudo dsd disk --json > marketing-assets/HOSTNAME-data/disk-SCENARIO.json
```

### OVAL parser routing (by filename)
```
ubuntu*/debian*/canonical* → oval_debian.go (dpkg + priority strings)
suse*/opensuse*/sles*       → oval.go ScanSUSEOVALPackages (RPM + title severity)
everything else             → oval_rhel.go (RPM + CVSS3 attribute)
```

---

## Gap Spec Locations

```
DashDiag_Gap_Specs.md    ← 51 specs, ~58d total, RESEARCH COMPLETE
BACKLOG.md               ← Sprint backlog, ✅ for done items
CLAUDE.md                ← Per-session Claude Code context
MARKETING.md             ← All stories and positioning copy
fixtures/                ← Replayable dsd mock fixtures (12 distros)
```
