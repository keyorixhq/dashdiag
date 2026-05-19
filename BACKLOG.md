# DashDiag Backlog

This file tracks all planned features not yet implemented.
Items in cmd/*.go files are also tagged `TODO(backlog)` inline.
Build order rule: **never build deep before fast is in production use.**

**Last updated: 2026-05-19 — Sessions 1–5 complete on Lenovo Legion (RHEL 10.1)**

---

## ✅ Recently Completed (Sessions 1–5, May 2026)

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
| Podman 5.6.0 installed on Legion (`/run/podman/podman.sock`) | S4 | infra |
| `dsd k8s` — JSON API, events, PVCs, workloads, OS-layer deep (Spec 23) | S5 | a248bd0 |
| `dsd proc <PID>` — smaps_rollup, FD map, socket conns, D-state (Spec 10) | S5 | a248bd0 |
| k3s v1.35.4 installed on Legion, wired into `dsd health` | S5 | infra |

---

## Commands

### ~~[GAP-SPEC] dsd services deep~~ ✅ DONE (Session 1)
Failed units + last journal lines, boot offenders (`.device`/`.socket` filtered),
daemon-reload detection, masked units, journal integrity, user systemd units.
Collector: `internal/collectors/services_deep_linux.go`. Commit: e192915.

---

### ~~[GAP-SPEC] dsd health — Active Session List (Spec H1)~~ ✅ DONE (Session 1)
`w -h` parser, root SSH CRIT, idle >8h WARN, concurrent session count, remote IP INFO.
Collector: `internal/collectors/sessions.go` (cross-platform). Commit: e192915.

---

### ~~[GAP-SPEC] dsd net deep — DNS Resolver Audit~~ ✅ DONE (Session 2)
`dsd net dns` command: resolv.conf audit, NM/resolved/static detection, live resolution
test, libc truncation/loopback/ndots/IPv6-only/duplicate checks.
Collector: `internal/collectors/dns_linux.go`. Commit: e192915.

---

### ~~[GAP-SPEC] dsd cron — Cron Health + Job Failure Triage~~ ✅ DONE (Session 2)
crond/anacron daemon detection, 24h failure scan (journal + syslog), crontab quality
(missing PATH, missing binary, MAILTO), anacron staleness via `/var/spool/anacron/`.
Collector: `internal/collectors/cron_linux.go`. Commit: e192915.

---

### ~~[GAP-SPEC] dsd security — SSH hardening audit (sshd -T)~~ ✅ DONE (Session 2)
`sshd -T` effective config with file fallback. Weak cipher/MAC/KEX detection.
`without-password` alias fix. `SSHAuditSource` field added to `SecurityInfo`.
Commit: e192915.

---

### ~~[GAP-SPEC] dsd security — User account hardening audit~~ ✅ DONE (Session 2)
`/etc/shadow` empty passwords CRIT, password expiry WARN (UID≥1000 with 99999 max days),
world-writable `/tmp`/`/var/tmp`/`/dev/shm` missing sticky bit CRIT.
Commit: e192915.

---

### ~~[GAP-SPEC] dsd gpu~~ ✅ DONE (Session 3)
AMD amdgpu: full sysfs metrics (temp, util, VRAM, power). NVIDIA: `detectNvidiaWithoutSMI()`
detects nouveau-bound cards with per-distro install hints. `NoDriver []GPUDetected` field.
Live: Legion shows AMD full metrics + NVIDIA RTX 3070 (24DD) [nouveau].
Commit: e192915.

---

### ~~[GAP-SPEC] dsd health deep — cgroup v2~~ ✅ DONE (Session 3)
Slice-level CPU throttle %, memory current/limit/%, cumulative I/O. OOM kill counter.
CRIT >20% throttle, WARN >5%; CRIT >90% mem of limit, WARN >75%.
Panic fix: io.stat lines with no stats caused `slice bounds out of range [1:0]`.
Commit: e192915.

---

### ~~[GAP-SPEC] dsd security — SELinux AVC grouping~~ ✅ DONE (Session 4)
`parseAVCGroups()` groups by `(stype, ttype, tclass)` with counts. Boolean-first fix
order (getsebool), semanage fcontext/port fallback, audit2allow as last resort.
`SELinuxAVCGroup` type + `SELinuxAVCGroups []SELinuxAVCGroup` in `SecurityInfo`.
Live: `init_t → container_runtime_t [bpf] ×1981` from crash-looping Podman container.
Commit: 0b53299.

---

### ~~dsd docker — crash-loop fix + health wiring~~ ✅ DONE (Session 4)
`RestartCount` bug: was read from `State.RestartCount` (always 0 in Podman), now
correctly read from top-level field. `DetectContainerSocket()` exported.
`dsd health` now includes Docker/Podman when socket is reachable.
Network: backend detection (netavark vs CNI), MTU mismatch WARN.
Commit: 0b53299.

---

### ~~[GAP-SPEC] dsd k8s — Kubernetes Cluster + OS-Layer Diagnosis~~ ✅ DONE (Session 5)
Full rewrite using JSON API (`-o json`) — single call for all pod data.
- Node conditions: MemoryPressure, DiskPressure, PIDPressure from JSON
- Warning events: reason×count, flannel subnet.env detection + fix hint
- PVC health: Bound/Pending/Lost counts via `K8sPVCInfo`
- Deployments + StatefulSets: `WorkloadsDown` via `K8sWorkloadInfo`
- Pod enrichment: termination msg (23c), init errors (23b), previous logs (23g)
- Stuck Terminating pods detection (23a)
- OS-layer deep: kubelet journal, IP forwarding, CNI bins, flannel subnet.env,
  KUBE-FORWARD chain (iptables/nft), firewalld masquerade, cert expiry
- Wired into `dsd health` via `K8sAvailable()` — absolute path detection for sudo
- Heuristics: `checkK8sNodes`, `checkK8sPodHealth`, `checkK8sWorkloadsAndEvents`,
  `checkK8sOSLayer` (each ≤90 statements)
- Live on Legion k3s v1.35.4: `FailedCreatePodSandBox×3, Unhealthy×1` with
  flannel subnet.env CRIT + `sudo systemctl restart k3s` fix hint
Commit: a248bd0.

---

### ~~[GAP-SPEC] dsd proc \<PID\> — /proc-based Process Inspector~~ ✅ DONE (Session 5)
Zero-impact: reads `/proc` only, no ptrace/strace.
- Identity: PID, PPID, user (from `/etc/passwd`), cgroup scope, cmdline, uptime
- State + wchan: D-state detection with blocking kernel function + D-state guide
- Resources: CPU time (jiffies), RSS, swap, threads, FD count vs limit
- smaps_rollup: `Private_Dirty` (true unique footprint), `Shared_Clean` (libraries)
  Fallback to `/proc/<PID>/smaps` sum on kernel < 4.14
- Open files: socket/file/pipe counts, deleted `.so` detection (post-update restart hint)
- Socket inode → `/proc/net/tcp[6]` connection resolution with state decoding
- Top-list mode (no PID): 15 processes by RSS with MEM%
- Renderer split into 6 helper functions (≤80 statements each)
- Live: k3s PID — 322 FDs, 518 MB `Private_Dirty`, 244 sockets, all API ports
Commit: a248bd0.

---

### [GAP-SPEC] dsd logs — Cross-Source Triage Improvements
**Sprint 2 carry-over. Full spec in DashDiag_Gap_Specs.md § Spec 3.**

- Severity-ranked summary (CRITICAL/ERROR/WARN counts) at top
- `/var/log/*` scan on systems with journald + syslog coexisting
- Crash file detection: `/var/crash/`, `/var/lib/systemd/coredump/`, `/sys/fs/pstore/`
- Journal corruption resilience: fallback to `--file` or `/var/log/syslog`
- JSON additions: severity counts, crash_files_found, log_source_used

Journal is now persistent on Legion — enables full log triage testing.
Estimated scope: ~1.5d.

---

### [GAP-SPEC] dsd disk — Standalone Disk + I/O Diagnostics
**Sprint 2 carry-over. Full spec in DashDiag_Gap_Specs.md § Spec 4 + 4a + 4b.**

Fast: all mounts, read-only detection, disk type, SMART summary, ZFS pool health.
Deep: I/O rate via `/proc/diskstats`, top I/O processes, large dir finder, fuser busy check.
LVM: VG space, snapshot overflow inline when LVM detected.
Estimated scope: ~2d.

---

### [GAP-SPEC] dsd net deep — NFS Mount Health
**Sprint 3. Full spec in DashDiag_Gap_Specs.md § Spec 11.**

Non-blocking stale mount detection (goroutine + 2s `Statfs()` timeout).
Server reachability, rpcbind, NFS retransmission stats, mount option audit.
Estimated scope: ~1.5d.

---

### [GAP-SPEC] dsd net deep — BIND/named server health
**Sprint 3. Full spec in DashDiag_Gap_Specs.md § Spec 16.**
Only shown when `named`/`bind9` process is running.
`named-checkconf`, `named-checkzone`, live dig test, `rndc status`.
Estimated scope: ~1d.

---

### [GAP-SPEC] dsd pve — Proxmox VE Node Diagnostics
**Sprint 4. Full spec in DashDiag_Gap_Specs.md § Spec 24.**
Fast: node overview, VM/CT status, storage pool health, recent task errors, cluster quorum.
Deep: PVEPerf benchmark, VM resource over-commitment, backup audit, network bridge health.
Estimated scope: ~4d.

---

### [GAP-SPEC] dsd kvm — KVM/libvirt diagnostics
**Sprint 4. Full spec in DashDiag_Gap_Specs.md § Spec 15.**
VM status, log errors, network health, storage pool capacity, disk I/O errors.
Estimated scope: ~3d.

---

### [GAP-SPEC] Package dependency integrity
**Sprint 2. Full spec in DashDiag_Gap_Specs.md § Spec 12.**
`dpkg --audit` + `apt-get check` (Debian, fast).
`dnf check` + `rpm --verify --all` (RHEL, deep-only, 10s cap).
Estimated scope: ~0.5d.

---

## Collectors (dsd health additions)

### CVE exposure check
Cross-reference installed packages against local OVAL advisory feed.
WARN CVSS ≥ 7.0, CRIT CVSS ≥ 9.0 or known exploited.
Estimated scope: ~1 week.

---

## Session 5 Build Plan

**Setup first (2 commands):**
```bash
# Install k3s on Legion
SSH_AUTH_SOCK=... ssh andrei@192.168.1.145 'curl -sfL https://get.k3s.io | sudo sh -'

# Verify
SSH_AUTH_SOCK=... ssh andrei@192.168.1.145 'sudo k3s kubectl get nodes'
```

**Build order:**
1. `dsd k8s` fast additions (single JSON call, events, PVC, Deployments) — ~2d
2. `dsd k8s` deep OS-layer (kubelet, CNI, iptables/nft, cert expiry) — ~3d
3. `dsd proc <PID>` — ~2.5d
4. `dsd logs` improvements — ~1.5d

---

## Strategic Discussions Required

### [DISCUSS] Team mode — how should it work?
Before building any paid tier, answer sharing model, team workspace, fleet view,
identity/auth, monetisation boundary, privacy/trust questions.

### [DISCUSS] Pricing strategy
Anchor price, per-host fee, open source core + paid cloud model.

### --share flag
Upload to dashdiag.sh and return shareable URL.
Requires dashdiag.sh backend.

### --badge flag
shields.io-compatible badge endpoint.
Requires dashdiag.sh backend.

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

### RHEL 10 Laptop (192.168.1.145) — active testbed
**Session 1–5 validated:**
- `dsd services deep` — systemd on RHEL 10.1 ✅
- `dsd health` active sessions ✅
- SSH hardening via `sshd -T` — hmac-sha1 correctly flagged ✅
- User account audit — andrei has 99999 max days, correctly WARN ✅
- `dsd cron` — crond active, anacron healthy, 1 quality finding ✅
- `dsd net dns` — NM-managed, 5 nameservers, libc truncation WARN ✅
- `dsd gpu` — AMD amdgpu full metrics + NVIDIA RTX 3070 [nouveau] ✅
- cgroup v2 slice summary — cpuset cpu io memory hugetlb pids ✅
- Journal persistence — `Storage=persistent`, 30s sync ✅
- LVM thin snapshot — `dsd_test` VG with thin pool + `snap_thin` (Vwi---tz-k) ✅
- Docker/Podman — crash-loop container (`test-crashloop`, 2514 restarts) ✅
- SELinux AVC — `init_t → container_runtime_t [bpf] ×1981` ✅
- k3s v1.35.4 — `dsd k8s` detects flannel subnet.env CRIT, workloads degraded ✅
- `dsd proc 1` (systemd) — 30 MB RSS, 301 FDs, ep_poll wchan ✅
- `dsd proc <k3s>` — 518 MB Private_Dirty, 244 sockets, all API ports ✅

**Still to test on Legion:**
- Suspend/resume cycle (laptop-only behavior)
- Battery vs AC power transitions
- GPU power state transitions (gpu_burn → idle → burn)

### Test Coverage Matrix

| Scenario | RHEL Laptop | Proxmox Host | Hetzner Debian | macOS arm64 |
|---|---|---|---|---|
| 18 collectors | ✅ | TODO | TODO | ✅ |
| NVMe SMART | ✅ | TODO (aged) | N/A | ✅ |
| HDD detection | N/A | TODO | N/A | N/A |
| ZFS | N/A | TODO | TODO | N/A |
| LVM thin pool + snapshots | ✅ | TODO | TODO | N/A |
| AMD GPU (amdgpu) | ✅ | depends | N/A | N/A |
| NVIDIA (nouveau) | ✅ | depends | depends | N/A |
| k3s / k8s | ✅ | depends | TODO | N/A |
| dsd proc smaps_rollup | ✅ | ✅ likely | ✅ | N/A |
| Docker/Podman | ✅ | depends | TODO | TODO |
| cgroup v2 | ✅ | ✅ likely | ✅ | N/A |
| SELinux enforcing | ✅ | depends | N/A | N/A |
| Battery | ✅ | N/A | N/A | ✅ |
| Journal persistent | ✅ | ✅ likely | ✅ | N/A |
| Suspend/resume | TODO | N/A | N/A | TODO |
| Multi-socket / NUMA | N/A | depends | N/A | N/A |
| apt vs dnf | dnf only | apt likely | apt | brew |
