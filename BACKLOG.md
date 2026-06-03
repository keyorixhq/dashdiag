# DashDiag Backlog

This file tracks all planned features not yet implemented.
Items in cmd/*.go files are also tagged `TODO(backlog)` inline.
Build order rule: **never build deep before fast is in production use.**

**Last updated: 2026-06-03 — Sessions 1–12 complete + June 3 sessions 1-3 (Sprint 1+2+3 + PVE deep + bugs)**

---

## ✅ Recently Completed (Sessions 1–12, May 2026)

| Item | Session | Commit |
|---|---|---|
| `dsd services deep` — failed units, boot offenders, journal health | S1 | e192915 |
| `dsd health` active sessions (Spec H1) — `w -h`, root SSH CRIT, idle WARN | S1 | e192915 |
| SSH hardening via `sshd -T` — effective config, weak cipher/MAC/KEX | S2 | e192915 |
| User account audit — `/etc/shadow` empty passwords, password expiry, sticky bit | S2 | e192915 |
| `dsd cron` — daemon, failure scan, crontab quality, anacron staleness | S2 | e192915 |
| `dsd net dns` — resolv.conf audit, NM/resolved detection, live resolution test | S2 | e192915 |
| `dsd gpu` — AMD amdgpu sysfs + NVIDIA nouveau detection, `NoDriver` field | S3 | e192915 |
| `dsd health deep` cgroup v2 — slice CPU throttle, mem limits, OOM kills | S3 | e192915 |
| Journal persistence — `Storage=persistent`, `SyncIntervalSec=30s` on Legion | S3 | e192915 |
| LVM thin snapshot fix — `attr[9]='k'`, `findLVOrigin()` for blank data% | S3 | e192915 |
| Docker/Podman crash-loop fix — `RestartCount` at top level, not in `State` | S4 | 0b53299 |
| Docker wired into `dsd health` — gated on `DetectContainerSocket()` | S4 | 0b53299 |
| Container network backend detection (netavark vs CNI) + MTU mismatch check | S4 | 0b53299 |
| SELinux AVC grouping — `parseAVCGroups()`, boolean-first fix suggestion | S4 | 0b53299 |
| `dsd k8s` — JSON API, events, PVCs, workloads, OS-layer deep (Spec 23) | S5 | a248bd0 |
| `dsd proc <PID>` — smaps_rollup, FD map, socket conns, D-state (Spec 10) | S5 | a248bd0 |
| k3s v1.35.4 installed on Legion, wired into `dsd health` | S5 | infra |
| `dsd logs` — severity summary, crash file detection, log source (Spec 3) | S6 | 9822a57 |
| `dsd disk` — SMART (Linux+macOS), ZFS pools, I/O rate, physical drives model | S6 | 9822a57 |
| macOS SMART via `diskutil` — no external tools, `disk_darwin.go` | S6 | f1a8296 |
| `dsd kvm` — VM/network/pool/disk error diagnostics (Spec 15) | S7 | 2e05b0e |
| Package integrity in `dsd health deep` — `NewPackagesDeepCollector` wired (Spec 12) | S7 | aa14092 |
| NFS mount health in `dsd net deep` — non-blocking stale detection (Spec 11) | S7 | 3bef93a |
| BIND/named health in `dsd net deep` — config/zone/query/rndc checks (Spec 16) | S8 | d8351a9 |
| `dsd docker` exit code labels (7a), events (7e), plaintext secrets (7o) | S9 | b6bc7e0 |
| `dsd docker` root user detection (7m), socket mount detection (7n) | S9 | e39382f |
| `dsd docker` daemon health — version, storage driver, journal errors (7c) | S9 | 01401f0 |
| `dsd docker --deep` log driver + json-file size check (7b) | S9 | d8b99d7 |
| `dsd docker` IP forwarding check (7f), firewalld nftables backend (7k) | S9 | 6a5109f |
| `dsd health deep` cgroup scope labels — `system:k3s`, `container:<id>`, `k8s` (Spec 5) | S10 | 4ed11b8 |
| `dsd security` permission disambiguation — booleans, AppArmor groups, autorelabel, PAM (Spec 6) | S10 | 1e99158 |
| `dsd disk` LVM RAID/mirror health — degraded CRIT, resyncing INFO (Spec 21) | S10 | fbb170d |
| `dsd timeline` — unified incident timeline, dedup, journal+dmesg+load | S10 | 67ff3a7 |
| Correlation engine: Container OOM Cascade — kernel OOM + Podman die+137, 5-min window | S11 | eaec50a |
| Docker 7g: DNS trap — host resolv.conf loopback breaks container DNS | S11 | 57754c2 |
| Docker 7h: socket permission diagnosis (group membership, session refresh) | S11 | 57754c2 |
| Docker 7i: image architecture mismatch — arm64 image on amd64 host | S11 | 57754c2 |
| CVE: fix dnf severity parser — `Critical/Sec.` format, Important bucket bug | S11 | 8f04e08 |
| `dsd timeline` hint system — 18 kernel/systemd patterns, explain/inspect/fix/persist | S11 | 65dd20c |
| `dsd cve --oval-scan` — CVSS-scored OVAL package scan (RHEL 9 OVAL, 1,772 findings) | S11 | 247f6e5 |
| CVE: RHSA→CVE ID enrichment from subscribed RHEL `dnf updateinfo info` | S11 | 2638fda |
| CVE: subscription detection — not-root / not-registered / expired hints | S11 | 0c42bb6 |
| Fix: LVM `debian-vg` → `debian--vg` dm path — VG falsely inactive on Debian/Ubuntu | S12 | 1c7b64d |
| Fix: `Launchd ✅` row showing on all Linux — macOS-only, return nil on non-Darwin | S12 | 10dd73f |
| Fix: rsyslog hint now includes `zypper install rsyslog` for openSUSE | S12 | 79e0361 |
| Fix: NVIDIA install hint — Debian/Ubuntu first, RHEL/Fedora second | S12 | d83281c |
| Ubuntu/Debian OVAL parser — `oval_debian.go`, dpkg, priority→CVSS mapping | S12 | 1c8688e |
| SUSE/openSUSE OVAL parser — patch class, RPM, title severity, platform marker filter | S12 | ce85170 |
| btrfs device health — `btrfs_linux.go`, missing devices + I/O errors, DEGRADED CRIT | S12 | 0f16b76 |
| microk8s detection — `/snap/bin/microk8s kubectl` added to k8sDetectBin() | S12 | 7bd0a63 |
| btrfs DEGRADED now surfaces in `dsd health` heuristics (not just `dsd disk`) | S12 | a580f34 |
| Ubuntu 26.04 LTS (Resolute Raccoon) validation — all paths clean, 0 bugs | S12 | 2e6278a |
| Ubuntu LVM break test — `ubuntu-vg` dash-name fix confirmed, RAID1 DEGRADED detected | S12 | 7bd0a63 |

## ✅ Recently Completed (June 3, 2026 — Bug fixes + GTM unblocking)

| Item | Commit |
|---|---|
| Fix: journald `SyncIntervalSec` fix hint NixOS-aware → `services.journald.extraConfig` | 04fea7b |
| Fix: SMART false positive on virtual disks (QEMU/virtio/VMware) — gate via `isVirtualDisk()` | 04fea7b |
| NixOS 25.05 marketing assets re-captured clean at v0.6.0-38 | bb872b2 |
| Landing page built — `landing/index.html`, "DashDiag by Keyorix", animated terminal proof | 48e5826 |
| Landing page updated — real `install.sh` one-liner, removed "Coming soon" stubs | d2356fe |

## ✅ Recently Completed (June 3, 2026 — Session 2: CI green + repo public + PVE hardware validation)

| Item | Commit |
|---|---|
| fix(ci): `TestSELinuxAbsent` skip on Linux — CI green after 2 days red | — |
| All 7 Dependabot PRs merged (actions/checkout v6, actions/setup-go v6, action-gh-release v3, gopsutil 3.24.5, viper 1.21.0, cobra 1.10.2, go-ping 1.2.0) | — |
| Repo made public (`github.com/keyorixhq/dashdiag`) | — |
| v0.6.1 released — 4 binaries + `checksums.txt`, install one-liner verified working | — |
| `landing/` moved to separate repo `keyorixhq/dashdiag-landing` (Netlify deploy pending) | — |
| Branch protection ruleset deleted (solo founder, no contributors yet) | — |
| BUG-015–019 fixed and verified on live PVE hardware | 4f5e668 |

## ✅ Recently Completed (June 3, 2026 — Session 3: Sprint 1+2+3 + PVE deep)

| Item | Commit |
|---|---|
| BUG-020: SMART suppressed inside LXC containers — `NewDiskCollector(ctrCtx)` gate | d89324f |
| Ubuntu 24.04 LXC validation — clean run, 0 bugs, marketing assets captured | d89324f |
| AlmaLinux 9 LXC (CT 213, 192.168.10.8) added to test matrix — replaces Legion | 9724e23 |
| Spec 2: DNS resolver audit block for `dsd net deep` — resolved/NM/stub/DNSSEC/VPN | 9724e23 |
| Spec 2 verified: Ubuntu 24.04 (resolved path) + AlmaLinux 9 (NM fallback path) | 9724e23 |
| Spec 3: `dsd logs` — `--json` flag, `TopCritical` with source+age, `/var/log` fallback | 9a25127 |
| Fix: RFC3339 timestamp parse in `TopCritical` (`age_min` was always -1) | 9a25127 |
| Fix: `/var/log` fallback now sets `LogSource` even on clean system (observability) | 9a25127 |
| Fix: `--since` flag now reaches journalctl error/warning calls (`lookbackToSince`) | 2cf65f4 |
| Spec 24: `dsd pve` complete — node overview, task errors, per-VM backup audit, bridges, `--json` | ae9c4c4 |
| Spec 24 verified live on pve01: all 5 new sections, fast + deep + json | ae9c4c4 |
| CLAUDE.md updated — Legion retired, AlmaLinux LXC test matrix, v0.6.1 ref | cfdcb9d |

## 🚨 GTM Blockers (revenue-blocking, do these first)

| Item | Status | Notes |
|---|---|---|
| Register `dashdiag.sh` | **PENDING** | ~$35/yr, confirmed available at Namecheap. Card ready. |
| Make repo public | **✅ DONE** | Public at `github.com/keyorixhq/dashdiag` (June 3) |
| Create GitHub release | **✅ DONE** | v0.6.1 published — 4 binaries + `checksums.txt`, install one-liner verified |
| Wire Formspree/Tally email capture | **PENDING** | Search `STUB` in `landing/index.html` — one-line swap |
| Deploy landing page | **PENDING** | Static single file, no build step. Cloudflare Pages or GitHub Pages. DNS swap after domain. |

---

## Container Runtimes

### [CONTAINER-CRIO] Add CRI-O socket detection to dsd docker collector

**Current state:** `dsd docker` auto-detects Docker and Podman sockets. CRI-O is not detected.
CRI-O is the default runtime on OpenShift and RHEL-based Kubernetes clusters.

**What to add:** One line in `collectors/docker.go` socket candidate list:
```go
{"/var/run/crio/crio.sock", "crio"},
```

**Priority:** Low-medium. Quick win (~1h). Do before first OpenShift/RHEL k8s customer.

---

### [CONTAINER-PODMAN-SYSTEMD] Detect systemd-managed Podman containers (quadlets)

**Current state:** Podman socket detection works. But RHEL admins increasingly use Podman
via systemd unit files (`podman generate systemd`, quadlets in `/etc/containers/systemd/`).
These containers are not visible via the Podman socket — they're managed as systemd services.

**What to add:**
- Scan `/etc/containers/systemd/` and `~/.config/containers/systemd/` for `.container` / `.pod` files
- Cross-reference with `systemctl list-units --type=service` for units named `podman-*`
- Surface stopped/failed quadlet containers as WARN in `dsd docker` output

**Priority:** Medium. Relevant on RHEL 9/10, Rocky, AlmaLinux. ~4h.

---

### [CONTAINER-CONTAINERD] Standalone containerd health check

**Current state:** `dsd k8s` OS layer checks `containerd.service` status when kubelet is
present. But containerd running standalone (k3s, Rancher, non-k8s) is not checked.

**What to add:**
- Socket detection: `/run/containerd/containerd.sock`
- Query `ctr namespaces list` + `ctr -n k8s.io containers list` for running containers
- Surface containerd service failures in `dsd health`

**Priority:** Low. k3s users already get coverage via `dsd k8s`. Only needed when
containerd is used without any k8s layer. ~1d.

**Skip for now:** Low-level runtimes (runc, crun, gVisor, Kata) — not admin-facing,
zero diagnostic value for DashDiag's target audience.

---

## Tooling

### [CAPTURE] dsd capture — extend to support dsd disk, dsd cve, dsd timeline

**Current state:** `dsd capture` only reads `dsd health --json`. The detailed LVM state
(thin pool %, RAID health, missing PV) lives in `dsd disk --json` and is not captured.

**Priority:** Medium. Do before first public demo.

---

### [BTRFS-HEALTH] Wire btrfs volume health into dsd health

**Current state:** `dsd disk` shows btrfs DEGRADED via `BtrfsVolumes`. But `dsd health`
Disk check only uses filesystem usage — btrfs missing devices don't surface in health.

**What to add:** In `heuristics.go` checkDisk(), walk `info.BtrfsVolumes` and emit
CRIT insight for degraded/missing devices, WARN for device errors.

**Priority:** High — silent failure mode, same severity as degraded RAID in LVM.

**Estimated:** ~1h

---

**Gap found:** During the Session 11 LVM break test (4 simultaneous failures), we cleaned
up before running `dsd capture`. The health fixture is now hand-crafted. The `dsd disk`
detail was never captured.

**What to build:**
- `dsd capture --disk` — reads `dsd disk --json` from stdin, appends disk insights into the fixture
- OR: `dsd capture --all` — runs all collectors internally, writes a multi-section fixture
- The fixture format already handles arbitrary checks — just need ingestion paths for other commands

**Priority:** Medium. Do before first public demo so every session produces a replayable artifact.

**Estimated:** ~0.5d

---

## Commands

### ~~[GAP-SPEC] dsd services deep~~ ✅ DONE (Session 1)
Failed units + last journal lines, boot offenders, daemon-reload detection, masked units.
Collector: `internal/collectors/services_deep_linux.go`. Commit: e192915.

---

### ~~[GAP-SPEC] dsd health — Active Session List (Spec H1)~~ ✅ DONE (Session 1)
`w -h` parser, root SSH CRIT, idle >8h WARN, concurrent session count, remote IP INFO.
Commit: e192915.

---

### ~~[GAP-SPEC] dsd net deep — DNS Resolver Audit~~ ✅ DONE (Session 2)
resolv.conf audit, NM/resolved/static detection, live resolution test.
Commit: e192915.

---

### ~~[GAP-SPEC] dsd cron~~ ✅ DONE (Session 2)
crond/anacron daemon detection, 24h failure scan, crontab quality, anacron staleness.
Commit: e192915.

---

### ~~[GAP-SPEC] dsd security — SSH hardening + user account audit~~ ✅ DONE (Session 2)
`sshd -T` effective config, weak cipher/MAC/KEX, empty passwords, expiry, sticky bit.
Commit: e192915.

---

### ~~[GAP-SPEC] dsd gpu~~ ✅ DONE (Session 3)
AMD amdgpu sysfs metrics + NVIDIA nouveau detection with per-distro install hints.
Commit: e192915.

---

### ~~[GAP-SPEC] dsd health deep — cgroup v2~~ ✅ DONE (Session 3)
Slice CPU throttle %, memory current/limit/%, OOM kills. Commit: e192915.

---

### ~~[GAP-SPEC] dsd security — SELinux AVC grouping~~ ✅ DONE (Session 4)
`parseAVCGroups()` with boolean-first fix order. Commit: 0b53299.

---

### ~~dsd docker — crash-loop fix + health wiring~~ ✅ DONE (Session 4)
`RestartCount` fixed, netavark/CNI detection, MTU mismatch WARN. Commit: 0b53299.

---

### ~~[GAP-SPEC] dsd k8s — Kubernetes Cluster + OS-Layer Diagnosis~~ ✅ DONE (Session 5)
Full JSON API rewrite covering Spec 23 + addendums 23a–23g.
- Node conditions, Warning events with flannel subnet.env detection
- PVC health, Deployments/StatefulSets, stuck Terminating pods
- OS-layer deep: kubelet, CNI bins, IP forwarding, KUBE-FORWARD, cert expiry
- Wired into `dsd health` via `K8sAvailable()`; absolute path for sudo
- Live: `FailedCreatePodSandBox×3` + flannel subnet.env CRIT with fix hint
Commit: a248bd0.

---

### ~~[GAP-SPEC] dsd proc \<PID\>~~ ✅ DONE (Session 5)
`/proc`-only inspector: smaps_rollup, FD map, socket connections, D-state guide.
Live: k3s — 322 FDs, 518 MB Private_Dirty, 244 sockets. Commit: a248bd0.

---

### ~~[GAP-SPEC] dsd logs — Cross-Source Triage Improvements~~ ✅ DONE (Session 6)
**Spec 3. Commits: 9822a57.**
- Severity summary: ERROR + WARNING counts from `journalctl` in last hour
- Top 5 deduplicated error messages (`×count` format)
- Crash file detection: `/var/crash/`, `/var/lib/systemd/coredump/`, `/sys/fs/pstore/`
  — files from last 30 days with size + age
- Log source detection: `journald` / `journald+syslog` / `syslog`
- Heuristics: crash dumps WARN; ErrorCount >50 WARN; >10 INFO
- `checkJournalHealthInsights` split: `checkJournalConfig` + `checkJournalActivity`
- Renderer split into 6 sub-functions (all ≤90 stmts)
- Live RHEL 10.1: 38k errors (SELinux/Podman BPF flood), `journald+syslog` detected

---

### ~~[GAP-SPEC] dsd disk — Standalone Disk + I/O Diagnostics~~ ✅ DONE (Session 6)
**Spec 4 + 4a + 4b. Commits: 9822a57 + f1a8296.**

**Linux (`disk_linux.go`):**
- Physical drive enumeration from `/proc/partitions` → `collectPhysicalDrives()`
- SMART via `smartctl -H -A`: health, wear%, spare%, temp, media errors
  NVMe parser: handles `"Percentage Used: 0%"` / `"Temperature: 51 Celsius"` format
- ZFS gate: zero overhead (`zpool` binary + `/proc/mounts` zfs entry)
  `collectZFSPools`: list with size/cap/frag/health; per-pool vdev errors + scrub age
- I/O rate (`--deep` only): `/proc/diskstats` delta 1s sample

**macOS (`disk_darwin.go`):**
- Physical drive enumeration via `diskutil list` (ships with every macOS)
- Per-drive: model, size, type (Apple Fabric→NVMe, SATA→SSD, rotational→HDD)
- SMART health from `diskutil info` → `SMART Status: Verified` — **no smartctl needed**
- APFS container label instead of "not mounted" for Apple internal disks
- Live: `disk0  500GB  NVMe  APFS container  [APPLE SSD AP0512R]  ✅ SMART: PASSED`

**Model:** `DriveType`, `SMARTInfo`, `PhysicalDrive`, `DiskIOStat`; `ZFSPool` from `models/zfs.go`
**Heuristics:** `checkDiskExtras` — SMART FAIL CRIT, wear ≥90% WARN, ZFS DEGRADED CRIT,
  vdev errors WARN, scrub age INFO
**Renderer split:** `printDiskDrives`, `printDiskZFS`, `printDiskFilesystems`, `printDiskIO`

---

### ~~[GAP-SPEC] dsd net deep — NFS Mount Health~~ ✅ DONE (Session 7)
**Spec 11. Commit: 3bef93a.**
Non-blocking stale detection: `syscall.Statfs` in goroutine + 2s timeout — no D-state hang.
Server reachability via TCP probe (port 111/2049, no ICMP required).
Mount option audit: soft-without-timeo, nolock, vers=2/3, `_netdev` missing from fstab.
rpcbind status + `/proc/net/rpc/nfs` stats.
`nfs_linux.go` + `nfs_notlinux.go` stub. `models/nfs.go`: `NFSMount` + `NFSInfo`.
Live: `STALE (timeout after 2s)` fires in 2.36s — no hang validated.

---

### ~~[GAP-SPEC] dsd net deep — BIND/named server health~~ ✅ DONE (Session 8)
**Spec 16. Commit: d8351a9.**
Gate: `pgrep named` or `systemctl is-active named` — section absent when BIND not running.
Config file auto-detected: `/etc/named.conf` (RHEL) or `/etc/bind/named.conf` (Debian).
`named-checkconf` validation. `include` directives followed (depth-limited to 5).
Zone file parsing: skips `hint`/`forward`/`stub` types, resolves relative paths.
`named-checkzone` per primary zone (3s timeout each, cap 20 zones).
Port 53 check: TCP + UDP separately via `ss -tulpn`.
Live DNS query test: `dig @127.0.0.1 localhost A +time=2 +tries=1`.
`rndc status`: version, uptime, query count (graceful if not configured).
Heuristics: service inactive CRIT, port 53 WARN, config error CRIT, zone failures CRIT.
Live BIND 9.18.33: 5 zones pass, hint zone excluded, includes followed.

---

### ~~[GAP-SPEC] dsd pve — Proxmox VE Node Diagnostics~~ ⏳ BLOCKED (needs Proxmox hardware)
**Sprint 9. Full spec in DashDiag_Gap_Specs.md § Spec 24.**
Fast: node overview, VM/CT status, storage pool health, recent task errors, cluster quorum.
Deep: PVEPerf benchmark, VM resource over-commitment, backup audit, network bridge health.
Estimated scope: ~4d.

---

### ~~[GAP-SPEC] dsd kvm — KVM/libvirt diagnostics~~ ✅ DONE (Session 7)
**Spec 15. Commit: 2e05b0e.**
Gate: `virsh version --daemon` (libvirtd reachable). `KVMAvailable()` exported for `dsd health`.
VM status: running/paused/shut-off/crashed via `virsh dominfo`. `domblkerror` for disk I/O errors.
`/var/log/libvirt/qemu/<name>.log` scanned for last error line.
Network: `virsh net-list --all` + virbr* bridge link state via `ip link show`.
Storage pools: `virsh pool-info` capacity/available → `UsedPct`.
Heuristics: crashed CRIT, paused WARN, down+autostart WARN, I/O errors CRIT,
  inactive networks WARN, pools >85% WARN.
Wired into `dsd health` via `KVMAvailable()`. `KVMVMState` typed constants.
`domblkerror` false positive fix: `"No errors found"` correctly excluded.
Live: libvirt 11.10.0 / QEMU 10.1.0, test-vm running, virbr0 up.

---

### ~~[GAP-SPEC] Package dependency integrity~~ ✅ DONE (Session 7)
**Spec 12. Commit: aa14092.**
`NewPackagesDeepCollector` was built but never wired — now included automatically in
`dsd health deep` (no `--packages` flag needed). Fast path unchanged.
Covers: `dnf check`, `dpkg --audit`, missing `.so` lib detection on canary binaries.
Live RHEL 10.1: shows 7 critical security updates, clean integrity (no broken deps).

---

## Collectors (dsd health additions)

### CVE exposure check
Cross-reference installed packages against local OVAL advisory feed.
WARN CVSS ≥ 7.0, CRIT CVSS ≥ 9.0 or known exploited.
Estimated scope: ~1 week.

---

## Strategic Discussions Required

### [DISCUSS] Team mode — how should it work?
Before building any paid tier, answer sharing model, team workspace, fleet view,
identity/auth, monetisation boundary, privacy/trust questions.

### [DISCUSS] Pricing strategy
Anchor price, per-host fee, open source core + paid cloud model.

### --share flag
Upload to dashdiag.sh and return shareable URL. Requires dashdiag.sh backend.

### --badge flag
shields.io-compatible badge endpoint. Requires dashdiag.sh backend.

### Team workspace MVP (paid tier)
Shared snapshot history across a team.
Requires dashdiag.sh backend, auth, billing. Estimated scope: ~10d.

### ~~dsd policy (CI gate)~~ ✅ DONE

---

## Polish

### [LOW] External bug reports — upstream kernel / distro issues
**ELAN touchpad dead on Lenovo Legion 5 15ACH6H — kernel i2c_designware**
File: `bug-reports/elan-touchpad-i2c-lenovo-legion.md`
Root cause: ACPI DSDT 400kHz vs driver 100kHz mismatch.

### CIS/STIG compliance checks
Enterprise-only. After core health stable + paying customers.
Estimated scope: ~2 weeks.

### [TESTBED] openSUSE Leap 16 + SLES validation
zypper, btrfs, YaST, AppArmor enforcing.

---

## [STRATEGIC] V2 Diagnostic Engine

Do NOT start before first paying customer is acquired.

### [V2-CORRELATION] Symptom correlation engine
**v0 SHIPPED (commit dc729d4)** — 4 hardcoded rules + GPU context rule live.
Next rules backlogged:
- Multiple OOM kills + same service → memory leak in specific service
- Entropy low + TLS signals → crypto bootstrapping failure
- IO CRIT on one device + other OK → single drive degradation
- Sysctl drift + recent reboot → parameter not persisted

### [V2-COLLECTOR] Kernel instability extensions
Soft/hard lockups, kernel panic history, watchdog resets.

### [V2-COLLECTOR] Network deep diagnostics
TCP retransmissions, SYN backlog, connection tracking table.

### [V2-COLLECTOR] CPU scheduling pathology
Run queue saturation, context switch spikes, iowait vs steal.

### [V2-COLLECTOR] Storage performance diagnostics
Write amplification, queue depth, fsync latency (eBPF — v3).

### [V2-COLLECTOR] TLS / certificate health
`dsd tls`: expired cert detection, remote endpoint expiry, system trust store drift.

### [V2-COLLECTOR] Security drift detection
SSH config drift, sudoers changes, new SUID binaries, cron injection.

### [V2-COLLECTOR] Process-to-network anomaly mapping
Unknown processes on ports, reverse shell heuristics.
CAUTION: drifts toward EDR territory — strategic decision required.

### [V2-COLLECTOR] macOS additions
Lower priority. Defer until macOS user demand exists.

---

## [TESTBEDS] Hardware Validation

### RHEL 10 Laptop (192.168.1.145) — active Linux testbed
**Sessions 1–10 validated:**
- `dsd services deep` ✅ | `dsd health` sessions ✅ | SSH hardening ✅
- User account audit ✅ | `dsd cron` ✅ | `dsd net dns` ✅
- `dsd gpu` AMD + NVIDIA nouveau ✅ | cgroup v2 ✅ | LVM thin snapshots ✅
- Docker/Podman crash-loop ✅ | SELinux AVC grouping ✅
- k3s `dsd k8s` — flannel CRIT, workloads degraded ✅
- `dsd proc <k3s>` — 518 MB Private_Dirty, 244 sockets ✅
- `dsd logs` — 38k errors (SELinux/Podman), journald+syslog ✅
- `dsd disk` — SK Hynix NVMe SMART PASSED, wear:0%, spare:100%, temp:51°C ✅
- `dsd disk --deep` — nvme0n1 1.5 MB/s write I/O rate ✅
- `dsd kvm` — libvirt 11.10.0 / QEMU 10.1.0, test-vm healthy ✅
- `dsd health deep` package integrity — 7 critical security updates surfaced ✅
- `dsd net deep` NFS — healthy mount (1ms) + stale detection (2.36s, no hang) ✅
- `dsd net deep` BIND — BIND 9.18.33, 5 zones OK, includes followed ✅
- `dsd docker` — exit:137 (OOM kill), socket mount ❌, root user ⚠️, secrets ⚠️ ✅
- `dsd docker` daemon — version: 5.6.0 (API 1.41) ✅ Storage: overlay ✅
- `dsd docker` firewalld nftables WARN fires in `dsd health` ✅
- `dsd health deep` cgroup scopes — `system:k3s.service`, `k8s`, `user:1000` ✅
- `dsd security` SELinux booleans, AVC groups (init_t → container_runtime_t) ✅
- `dsd disk` LVM — 2 VGs, thin pool, snapshot, RAID API tested ✅
- `dsd timeline` — veth0 failure ×402 deduplicated, load avg shown ✅

**Still to test on Legion:**
- Suspend/resume cycle | Battery vs AC transitions | GPU power state transitions

### MacBook (arm64 macOS) — active macOS testbed
**Sessions 1–6 validated:**
- `dsd disk` — disk0 500GB NVMe [APPLE SSD AP0512R] SMART: PASSED ✅
- APFS container label (no false "not mounted") ✅

### Test Coverage Matrix

| Scenario | RHEL Laptop | Proxmox Host | Hetzner Debian | macOS arm64 |
|---|---|---|---|---|
| 20+ collectors | ✅ | TODO | TODO | ✅ |
| NVMe SMART (Linux) | ✅ | TODO (aged) | N/A | N/A |
| NVMe SMART (macOS diskutil) | N/A | N/A | N/A | ✅ |
| HDD detection | N/A | TODO | N/A | N/A |
| ZFS pool health | N/A | TODO | TODO | N/A |
| Disk I/O rate (deep) | ✅ | TODO | TODO | N/A |
| LVM thin pool + snapshots | ✅ | TODO | TODO | N/A |
| AMD GPU (amdgpu) | ✅ | depends | N/A | N/A |
| NVIDIA (nouveau) | ✅ | depends | depends | N/A |
| k3s / k8s | ✅ | depends | TODO | N/A |
| KVM / libvirt | ✅ | ✅ likely | TODO | N/A |
| NFS stale detection | ✅ | TODO | TODO | N/A |
| BIND/named health | ✅ | TODO | TODO | N/A |
| Package integrity (deep) | ✅ | TODO | TODO | N/A |
| dsd proc smaps_rollup | ✅ | ✅ likely | ✅ | N/A |
| Docker/Podman | ✅ | depends | TODO | TODO |
| cgroup v2 | ✅ | ✅ likely | ✅ | N/A |
| SELinux enforcing | ✅ | depends | N/A | N/A |
| Battery | ✅ | N/A | N/A | ✅ |
| Journal persistent | ✅ | ✅ likely | ✅ | N/A |
| Log severity summary | ✅ | TODO | TODO | N/A |
| Crash file detection | ✅ | TODO | TODO | N/A |
| Suspend/resume | TODO | N/A | N/A | TODO |
| Multi-socket / NUMA | N/A | depends | N/A | N/A |
| apt vs dnf | dnf only | apt likely | apt | brew |

---

BUG: dsd spawns unreapped zombie subprocess during health run - parent 48436 child 48451 - investigate runCmd callers in collectors
