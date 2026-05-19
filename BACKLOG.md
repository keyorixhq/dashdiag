# DashDiag Backlog

This file tracks all planned features not yet implemented.
Items in cmd/*.go files are also tagged `TODO(backlog)` inline.
Build order rule: **never build deep before fast is in production use.**

---

## Commands

### [GAP-SPEC] dsd services deep — Systemd Failure Diagnosis
**Sprint 1. Full spec in DashDiag_Gap_Specs.md § Spec 1.**

The existing `dsd services` checks port connectivity (SSH :22, HTTP :80, etc).
This is a separate deep variant that diagnoses WHY systemd services are failing.

Key checks:
- Failed units with last journal line and exit code
- systemd-analyze blame filtered to real services only (no .device/.socket noise)
- NeedsDaemonReload detection (modified unit files not yet reloaded)
- Masked unit detection (silent trap — masking looks like disabled)
- Journal health/corruption detection
- AppArmor/SELinux denial correlation per failed unit
- User service (--user) inclusion when running

Collector: `internal/collectors/services_deep_linux.go`
Build tag: linux only (systemd). On macOS: launchctl equivalent or skip.
Estimated scope: ~2 days.

---

### [GAP-SPEC] dsd health — Active Session List (Spec H1)
**Sprint 1. New sub-check in existing dsd health (fast). Full spec in DashDiag_Gap_Specs.md § Spec H1.**
**Source: nixCraft tool #3 — `w` command; shows who is logged in and what they're running.**

New `[Active sessions]` section in `dsd health` fast output.
Collapsed to one INFO line when only current user is logged in.

Key checks:
- `w -h` for TTY, from IP, idle time, current command per session
- CRIT: root logged in via SSH (cross-reference with Spec 13 SSH audit)
- WARN: any session idle > 8 hours (unattended terminal)
- WARN: > 5 concurrent sessions (unusual for most servers)
- INFO: unique remote IPs for security awareness
- Cross-reference: if a logged-in user's process is in top CPU consumers, show link

macOS: `w -h` works identically.
Collector: reads /var/run/utmp via `who` or `w -h` shell-out.
Estimated scope: ~0.5 days.

---

### [GAP-SPEC] dsd net deep — DNS Resolver Audit Block
**Sprint 1. Full spec in DashDiag_Gap_Specs.md § Spec 2.**

Additive enhancement to existing `dsd net deep`. Inserts `[DNS Resolver]` section.

Key checks:
- systemd-resolved active/inactive + feature set (DNSSEC, DoT status)
- /etc/resolv.conf mode: stub vs uplink vs custom/unmanaged
- DNSSEC degradation detection (configured yes but active no)
- DNSSEC validation test (sigok.verteiltesysteme.net)
- VPN DNS integration check (tun0/wg0/nordlynx — DNS routed through VPN?)
- RHEL fallback: NetworkManager DNS config when resolved is disabled

Estimated scope: ~1 day.

---

### [GAP-SPEC] dsd logs — Cross-Source Triage Improvements
**Sprint 2. Full spec in DashDiag_Gap_Specs.md § Spec 3.**

Enhancement to existing `dsd logs` command. Does NOT replace or break current behaviour.

Key additions:
- Severity-ranked summary (CRITICAL/ERROR/WARN counts) at top of output
- /var/log/* scan (syslog, auth.log, kern.log, nginx/apache error logs) on systems
  where these coexist with journald — deduplicates if journald already has the content
- Crash file detection: /var/crash/, /var/lib/systemd/coredump/, /sys/fs/pstore/
- Journal corruption resilience: fallback to --file or /var/log/syslog on corruption
- JSON additions: severity counts, crash_files_found, log_source_used

Estimated scope: ~1.5 days.

---

### [GAP-SPEC] dsd disk — Standalone Disk + I/O Diagnostics
**Sprint 2. Full spec in DashDiag_Gap_Specs.md § Spec 4 + addendums 4a, 4b.**

New standalone command. Disk checks exist inside `dsd health` but there is no
dedicated disk command with I/O attribution and deep SMART analysis.

Fast checks (< 3s):
- All mounted filesystems: used%, free, inode usage, WARN/CRIT thresholds
- Read-only mount detection
- Physical disk type (NVMe/SSD/HDD) from /sys/block/*/queue/rotational
- SMART summary per disk
- **ZFS pool health (Spec 4b):** `zpool status -x` gate (zero overhead on non-ZFS);
  DEGRADED/FAULTED/OFFLINE states, per-vdev error counts, resilver progress,
  scrub age > 30 days. CRIT on DEGRADED/FAULTED, WARN on checksum errors.

Deep checks (< 15s):
- I/O rate per device: /proc/diskstats sampled 1s apart
- Top I/O processes: /proc/*/io ranked by total bytes
- Large directory finder: du -xm on WARN/CRIT filesystems
- SMART extended: wear level, media errors, reallocated sectors
- Filesystem error log: dmesg scan for I/O errors, EXT4/XFS corruption
- fuser busy check (Spec 4a): show processes with open files on WARN/CRIT mounts
- LVM layer health (Spec 21): VG space, snapshot overflow, RAID degraded

ZFS support: `zfs list` for capacity (statvfs gives wrong results on thin pools);
`zpool status` for health (Spec 4b — gate: zpool binary + zfs mount detected).
LVM support: parse /dev/mapper/* devices, trace back to physical via /sys/block/dm-N/slaves/

---

### [GAP-SPEC] dsd health deep — Cgroup Tree + Process Hierarchy
**Sprint 3. Extends the existing dsd health deep item already in this backlog.**
**Full spec in DashDiag_Gap_Specs.md § Spec 5.**

Additions to the existing dsd health deep scope:
- Top process list enriched with cgroup scope label (docker/<name>, system/<svc>, user/uid)
- Per-cgroup CPU + memory summary for Docker containers and systemd service slices
- CPU throttling detection via cpu.stat → throttled_time field
- iowait culprit attribution: names device AND top I/O process when iowait > 5%

Collector: `internal/collectors/cgroup_linux.go` (new)
cgroup v2 only in Sprint 3. cgroup v1 (legacy) support deferred to Sprint 4.
macOS: section not shown (cgroup not applicable).

---

### [GAP-SPEC] dsd security — SSH hardening audit (sshd -T)
**Sprint 2. Additive to existing dsd security. Full spec in DashDiag_Gap_Specs.md § Spec 13.**

Uses `sshd -T` (extended test mode) — dumps full effective config, zero side effects.
Production-safe SSH audit that respects sshd_config.d/*.conf drop-ins.

Key checks:
- PermitRootLogin (CRIT if yes)
- PasswordAuthentication (WARN if yes)
- PermitEmptyPasswords (CRIT if yes)
- Weak ciphers: CBC-mode (aes*-cbc, 3des-cbc), arcfour
- Weak MACs: hmac-md5, hmac-sha1
- Weak KEX: diffie-hellman-group1/14-sha1
- ClientAliveInterval: WARN if 0 (no idle timeout)
- X11Forwarding: WARN if yes (attack surface)
- Optional: ssh-audit binary integration when present

Falls back to /etc/ssh/sshd_config parsing if sshd -T not accessible (older RHEL 7).
Estimated scope: ~1 day.

---

### [GAP-SPEC] dsd security — User account hardening audit
**Sprint 2. Additive to existing dsd security. Full spec in DashDiag_Gap_Specs.md § Spec 14.**

Key checks:
- Empty password accounts: awk check on /etc/shadow (CRIT)
- Non-root UID=0 accounts: awk check on /etc/passwd (CRIT)
- Password aging: flag human accounts (UID≥1000) with Maximum_days=99999
- SUID/SGID binary audit: find /usr /bin /sbin -perm /6000
  Compare against expected list — flag unexpected binaries as WARN
- World-writable /tmp, /var/tmp, /dev/shm without sticky bit

SUID scan capped at 10s with -maxdepth 5. Expected SUID list overridable via dsd policy.
Graceful degradation if /etc/shadow not readable (show INFO, not error).
Estimated scope: ~1 day.

---

### [GAP-SPEC] dsd kvm — KVM/libvirt diagnostics
**Sprint 4. Full spec in DashDiag_Gap_Specs.md § Spec 15.**

New command. Completes the virtualisation trio: dsd docker + dsd pve + dsd kvm.
Triggered only when libvirtd is running (virsh version exit 0).

Fast checks:
- VM status: virsh list --all grouped by state (running/paused/crashed/shut-off+autostart)
- VM log errors: last 20 lines of /var/log/libvirt/qemu/<name>.log for non-running VMs
- Network health: virsh net-list, virbr0 bridge UP check
- Storage pool capacity: virsh pool-list, flag > 85% full
- Disk I/O errors: virsh domblkerror per running VM

Deep variant adds: virsh dumpxml for non-running VMs (missing paths, invalid devices),
NUMA topology check, kvm_stat if debugfs mounted.

Uses virsh shell-out for cross-distro reliability.
Estimated scope: ~3 days.

---

### [GAP-SPEC] dsd pve — Proxmox VE Node Diagnostics
**Sprint 4. Full spec in DashDiag_Gap_Specs.md § Spec 24.**

New standalone command. Completes the virtualisation trio: dsd docker + dsd pve + dsd kvm.
Gate: `/usr/share/pve-manager` exists. All data via `pvesh` REST API (10s timeout per call).

Fast checks (< 5s):
- Node overview: PVE version, kernel, CPU%, memory, uptime
- VM/CT status: running/stopped/paused counts; autostart VMs not running (WARN);
  paused VMs (WARN — hung migration); error state (CRIT)
- Storage pool health: active/inactive, used%; inactive = CRIT; >85% WARN; >95% CRIT
- Recent task errors (last 24h): backup/migration/resize failures with message
- Cluster quorum (if corosync.conf present): quorate=false CRIT; node offline WARN
- Subscription: INFO only (no-subscription is valid free tier, never WARN/CRIT)
- ZFS pool health inline (Spec 4b): shown when ZFS storage detected on PVE node

Deep checks (< 30s):
- **PVEPerf storage benchmark** (`pveperf /var/lib/vz`, ~5–10s, deep-only):
  Parse FSYNCS/SEC, HDPARM MB/s, DD MB/s, FIO randwrite IOPS against baselines
  CRIT: FSYNCS/SEC < 100; WARN: < 500. Cross-ref ZFS resilver as likely cause.
- VM resource over-commitment: vCPU ratio WARN >4:1 / CRIT >8:1;
  memory WARN >100% RAM / CRIT >150%
- Backup audit: last successful vzdump per VM; WARN >7 days; CRIT >30 days or never;
  templates excluded
- Network bridge health: vmbr uplink check, bond member status;
  CRIT: bridge DOWN; WARN: no physical uplink attached

Estimated scope: ~4 days.

---

### [GAP-SPEC] dsd net deep — BIND/named server health block
**Sprint 3. Additive to existing dsd net deep. Full spec in DashDiag_Gap_Specs.md § Spec 16.**

[DNS server (BIND)] section — only shown when named/bind9 process is running.
Completely distinct from Spec 2 (client-side resolver audit).

Key checks:
- named service status
- Port 53 TCP+UDP listening via ss
- named-checkconf (syntax validation)
- named-checkzone per configured zone (parse named.conf for zone paths)
- Live DNS query test: dig @127.0.0.1 localhost +time=2
- rndc status if accessible (uptime, query count)

Auto-detects RHEL (/etc/named.conf) vs Debian (/etc/bind/named.conf) config path.
named-checkzone capped at 20 zones in fast variant.
Estimated scope: ~1 day.

---

### [GAP-SPEC] dsd security — Permission Root-Cause Disambiguation
**Sprint 3. Extends the existing dsd security command.**
**Full spec in DashDiag_Gap_Specs.md § Spec 6 + Spec 6 Addendum (SELinux Primer).**

Adds a `[Permission diagnosis]` section triggered by recent AVC/AppArmor/PAM events.

Key additions from original spec:
- AVC denial grouping by source → target → action with fix hints (semanage/restorecon)
- AppArmor denial parsing and profile-level grouping with aa-logprof hints
- PAM module failure detection (separate from brute-force SSH failures)
- pam_faillock / pam_tally2 account lockout detection
- Distinguishes enforcing (real block) vs permissive (logged only)

Addendum additions from Red Hat SELinux Primer:
- **Boolean-first order**: `getsebool -a | grep <service>` runs BEFORE AVC grouping
  (Red Hat explicitly: "Check Booleans First in Troubleshooting!")
  Shows OFF booleans that may explain each denial, with setsebool fix
- **Port context check**: services on unlabeled ports → `semanage port -a` fix hint
  Also scans all listening ports from ss against `semanage port -l`
- **chcon vs semanage fcontext detection**: `matchpathcon` vs `ls -Z` comparison
  Warns if context was set temporarily (chcon, no semanage rule — lost on relabel)
- **Autorelabel detection**: `/.autorelabel` existence → WARN with timing (~15 min)

Estimated scope: ~2 days (including addendum).

---

### [GAP-SPEC] Platform normalization layer — platform.Profile
**Sprint 4. Internal/architectural. Full spec in DashDiag_Gap_Specs.md § Spec 8.**

Formalize distro detection into a `platform.Profile` struct returned by `platform.Detect()`.
Replaces ad-hoc inline distro checks scattered across collectors.

Fields: OS, Distro, DistroVersion, InitSystem, NetworkStack, HasNetplan, HasResolved,
SELinuxMode, AppArmorActive, PackageManager, InContainer, ContainerRuntime,
SyslogPath, AuthLogPath, AuditLogPath.

Apply to: LogsCollector, SecurityCollector, NetworkCollector, ServicesDeepCollector,
DiskCollector (standalone), DockerCollector.
Add `--debug` output: detected profile printed at startup.
Estimated scope: ~2 days refactor.

---

### [GAP-SPEC] dsd cron — Cron Health + Job Failure Triage
**Sprint 2. Full spec in DashDiag_Gap_Specs.md § Spec 9.**

New standalone command. Cron jobs fail silently — different PATH, no TTY, no MAILTO.
No existing DashDiag command surfaces cron health.

Key checks:
- Cron daemon active (cron/crond/anacron variant detection)
- Recent job failures from syslog/cron log (last 24h, grouped by job)
- Crontab quality: no PATH, no MAILTO, relative paths, missing commands
- Anacron stale job detection (machine was off during scheduled window)
- Systemd timer INFO if no cron installed but timers exist

Collector: `internal/collectors/cron_linux.go`
Estimated scope: ~1.5 days.

---

### [GAP-SPEC] dsd proc <PID> — /proc-based Process Inspector
**Sprint 3. Full spec in DashDiag_Gap_Specs.md § Spec 10 + Spec 10a addendum.**

New targeted command. Replaces strace (too slow for production) and lsof (requires
install + root). Everything read from /proc — zero performance impact on target.

Key checks from original spec:
- Identity: name, cmdline, user, parent, uptime, cgroup scope
- State + wchan: if D-state (hung), shows which kernel function it's stuck in
- Resources: CPU time, RSS/swap, thread count, FD count vs limit
- Open files: categorized, socket inode-to-connection resolution
- Network: listening, established, CLOSE_WAIT count
- Deleted libraries: detects updated package but process still using old .so

Spec 10a addendum (nixCraft pmap section):
- pmap private vs shared memory breakdown via /proc/<PID>/smaps_rollup
  Shows: RSS total, Private_Dirty (true unique footprint), Private_Clean,
  Shared_Clean (mapped libraries), Shared_Dirty (rare), Swap
  WARN if Private_Dirty > 80% of system free RAM
  Fallback to /proc/<PID>/smaps sum if smaps_rollup not available (kernel < 4.14)

`dsd proc` without PID shows top CPU list.
macOS fallback: lsof -p (lsof pre-installed on macOS).
Estimated scope: ~2 days (original) + ~0.5 days (pmap addendum) = ~2.5 days.

---

### [GAP-SPEC] dsd net deep — NFS Mount Health Block
**Sprint 3. Additive to existing dsd net deep. Full spec in DashDiag_Gap_Specs.md § Spec 11.**

[NFS mounts] section — only shown when NFS mounts detected.

CRITICAL: stale mount detection uses goroutine + 2s Statfs() timeout.
Never do blocking I/O on NFS paths directly — causes caller to hang in D-state.

Key checks:
- Non-blocking stale mount detection per NFS mount
- Server reachability (ping + TCP :2049)
- rpcbind/portmapper status
- NFS retransmission stats from /proc/net/rpc/nfs
- Mount option audit (soft, nolock, vers=3, _netdev)

Estimated scope: ~1.5 days.

---

### [GAP-SPEC] Package dependency integrity (dsd health deep addition)
**Sprint 2. Small addition. Full spec in DashDiag_Gap_Specs.md § Spec 12.**

Debian: dpkg --audit + apt-get check (fast — also suitable for dsd health fast)
RHEL: dnf check + rpm --verify --all (slow — deep only, 10s timeout hard cap)
Shared library check: ldconfig -p + ldd on canary binaries

Estimated scope: ~0.5 days.

---

### [GAP-SPEC] dsd security — SSH hardening audit (sshd -T)
**Sprint 2. Additive to existing dsd security. Full spec in DashDiag_Gap_Specs.md § Spec 13.**

Uses `sshd -T` (extended test mode, zero side effects) — reads effective merged config
including sshd_config.d/*.conf drop-ins. Does NOT parse files directly.

Key checks:
- PermitRootLogin (CRIT if yes, WARN if without-password/prohibit-password)
- PasswordAuthentication (WARN if yes — prefer key-only)
- PermitEmptyPasswords (CRIT if yes)
- Weak ciphers: any CBC-mode (aes*-cbc, 3des-cbc) or arcfour
- Weak MACs: hmac-md5, hmac-sha1, hmac-ripemd160, umac-64
- Weak KEX: diffie-hellman-group1-sha1, diffie-hellman-group14-sha1
- ClientAliveInterval=0 (WARN — no idle session timeout)
- X11Forwarding=yes (WARN — unneeded attack surface on servers)
- AllowUsers/AllowGroups not set (INFO — any user can SSH)
- Optional: ssh-audit binary integration when present (not a requirement)

Falls back to /etc/ssh/sshd_config file parse on older RHEL 7 where sshd -T
may require root (but note: drop-in files may be missed in that fallback).
Estimated scope: ~1 day.

---

### [GAP-SPEC] dsd security — User account hardening audit
**Sprint 2. Additive to existing dsd security. Full spec in DashDiag_Gap_Specs.md § Spec 14.**

Key checks (all standard sysadmin hygiene checks, none currently automated by dsd):
- Empty password accounts: awk -F: '($2 == "") {print $1}' /etc/shadow (CRIT)
- Non-root UID=0 accounts: awk -F: '($3 == "0") {print $1}' /etc/passwd (CRIT)
- Password aging: human accounts (UID≥1000) with Maximum_days=99999 (WARN)
- Unexpected SUID/SGID binaries: find /usr /bin /sbin -perm /6000 vs expected list (WARN)
- World-writable /tmp, /var/tmp, /dev/shm without sticky bit (WARN)

SUID scan capped at 10s with -maxdepth 5.
Expected SUID list overridable via dsd policy file (future feature hook).
Graceful degradation if /etc/shadow not readable (INFO, not error).
Estimated scope: ~1 day.

---

### [GAP-SPEC] dsd net deep — BIND/named server health block
**Sprint 3. Additive to existing dsd net deep. Full spec in DashDiag_Gap_Specs.md § Spec 16.**

[DNS server (BIND)] section — only shown when named/bind9 process is detected running.
DISTINCT from Spec 2 (client-side resolver audit). This is for servers *running* BIND.

Key checks:
- named/bind9 service active
- Port 53 TCP+UDP listening via ss (flag WARN if process running but not listening)
- named-checkconf syntax validation (path auto-detected: RHEL vs Debian layout)
- named-checkzone per zone (paths parsed from named.conf, capped at 20 in fast)
- Live DNS query: dig @127.0.0.1 localhost +time=2 +tries=1
- rndc status uptime + query count (graceful skip if no RNDC key)

Estimated scope: ~1 day.

---

### [GAP-SPEC] dsd kvm — KVM/libvirt VM diagnostics
**Sprint 4. Full spec in DashDiag_Gap_Specs.md § Spec 15.**

New standalone command. Completes the virtualisation trio: dsd docker + dsd pve + dsd kvm.
Only activates when libvirtd is running (virsh version exit 0). Graceful INFO if not.

Fast checks (< 5s, 5 VMs):
- VM status via virsh list --all: running/paused/crashed/shut-off+autostart
- VM log errors: last 20 lines of /var/log/libvirt/qemu/<name>.log for non-running VMs
- Network health: virsh net-list, virbr0 bridge UP check
- Storage pool capacity: virsh pool-list + pool-info, flag > 85%
- Disk I/O errors: virsh domblkerror per running VM (CRIT if non-empty)

Deep variant adds: virsh dumpxml missing-path analysis, NUMA topology check,
kvm_stat if debugfs mounted.

Uses virsh shell-out for cross-distro reliability (RHEL/Debian/Ubuntu).
Estimated scope: ~3 days.

---

### [GAP-SPEC] dsd steamos — SteamOS RAUC/Gamescope/Partition Health
**Sprint 3. Full spec in DashDiag_Gap_Specs.md § Spec 17.**
**Only activates on SteamOS (ID=steamos in /etc/os-release). Graceful INFO on standard Linux.**

New command. SteamOS has fundamentally different architecture vs standard Linux:
- Immutable BTRFS root (5GB A/B slots, RAUC atomic updates)
- /var is only 256MB — fills up causing update and logging failures
- Gamescope compositor session replaces standard desktop WM in Game Mode
- steamos-atomupd-client + RAUC for OTA updates (NOT apt/dnf)

Fast checks:
- OS version + update channel (from /etc/steamos-atomupd/client.conf)
  Flag WARN if config file missing (breaks updater — GitHub issue #1132)
- RAUC slot health (`rauc status`): A/B boot status
  CRIT if booted slot boot status = "bad"
  WARN if inactive slot = "bad" (no rollback possible if update needed)
  Fix: `sudo rauc status mark-active booted`
- steamos-readonly: CRIT if rootfs is writable (next update overwrites changes)
- gamescope-session.service + steam-launcher.service active check
- /var usage: WARN at 70%, CRIT at 85% (256MB total)
- /home usage: WARN at 85%, CRIT at 95%
- Wi-Fi backend: iwd (default) vs wpa_supplicant (3.7.x workaround dev mode toggle)
- Steam update server DNS: `steamdeck-atomupd.steamos.cloud` reachability

Deep adds: gamescope journal errors, RAUC history, Proton prefix + shader cache sizes,
flatpak health, BIOS version advisory.

Collector: `internal/collectors/steamos_collector.go`
Estimated scope: ~4 days.

---

### [GAP-SPEC] dsd gpu — GPU/APU Temperature, TDP, VRAM, Clocks
**Sprint 3. Full spec in DashDiag_Gap_Specs.md § Spec 18.**

New standalone command. No existing DashDiag command covers GPU diagnostics.
Critical for SteamOS (GPU temps to 93°C causing crashes, TDP throttling
documented in GitHub issue #2029). Useful for all Linux gaming/compute.

All AMD data from sysfs (no external tools required):
- Temperature: edge + junction + memory from hwmon/amdgpu
  WARN at 90°C junction, CRIT at 100°C
- Clocks: current vs max from pp_dpm_sclk
- TDP: power1_cap (limit) vs power1_input (actual draw)
  WARN if draw ≥ 95% of cap (TDP throttling)
- VRAM: used/total from mem_info_vram_* (shared memory on APU)
- GPU utilization: gpu_busy_percent (1-second sample)
- Driver + Mesa version

NVIDIA: nvidia-smi fallback. Intel: partial hwmon. macOS: system_profiler fallback.
Build tag: linux (with macOS fallback)
Estimated scope: ~2 days.

---

### [GAP-SPEC] dsd disk — SteamOS partition layout block
**Sprint 3. Additive to existing dsd disk (SteamOS-only section).**
**Full spec in DashDiag_Gap_Specs.md § Spec 19.**

BTRFS root health via `btrfs device stats /` (live, read-only, safe).
Shader cache size audit (~/.steam/steam/shadercache/): WARN >10GB, CRIT >30GB.
Bind mount integrity check (/opt, /root → /home/.steamos/offload/).
Section absent on non-SteamOS systems.
Estimated scope: ~1 day.

---

### [GAP-SPEC] dsd disk — fuser filesystem busy check (Spec 4a)
**Sprint 2. Additive to existing dsd disk. Full spec in DashDiag_Gap_Specs.md § Spec 4a.**
**Source: nixCraft comment — "fuser command is missing from this list"**

When a filesystem is at WARN/CRIT usage, show which processes have it open.
Inverts the dsd proc direction: given a path, show who has it open.
Critical for "target is busy" unmount errors.

Checks:
- `fuser -m <mountpoint>` for any WARN/CRIT filesystem
- Show PID, process name, user, open mode (read/write)
- Graceful fallback to /proc/*/fd scan if fuser not installed
- Only runs for WARN/CRIT mounts (not all mounts — avoid slowness)

Estimated scope: ~0.5 days (small addition to existing DiskCollector).

---

### [GAP-SPEC] dsd net — SteamOS Wi-Fi regression checks
**Sprint 3. Additive to existing dsd net (SteamOS-only section).**
**Full spec in DashDiag_Gap_Specs.md § Spec 20.**

iwd vs wpa_supplicant backend detection.
SSID band conflict check (2.4GHz + 5GHz same name — known OLED issue).
Steam CDN DNS latency check: WARN if > 500ms.
Section absent on non-SteamOS systems.
Estimated scope: ~0.5 days.

---

### [GAP-SPEC] dsd k8s — Kubernetes Cluster + OS-Layer Diagnosis
**Sprint 3 (fast) / Sprint 4 (deep). Full spec in DashDiag_Gap_Specs.md § Spec 23.**

Fast/deep split. The moat: not a viewer like kubectl/Lens/k9s — a diagnostician that
correlates pod failures with OS-level signals no kubectl viewer exposes.
Estimated scope: ~5d fast (extending existing code) + ~5d deep (OS-layer moat) = ~10d total.

Collector code already built and tested against a running k3s cluster.

**What already exists (code):**
- `internal/collectors/k8s.go` — node/pod detection, CrashLooping/Pending/HighRestarts counts
- `internal/models/k8s.go` — K8sInfo, K8sNodeInfo, K8sPodInfo structs
- `cmd/k8s.go` — nodes table, pods table, problem pods highlighted, summary line

**Fast additions (Spec 23 — extending existing code):**
- Node conditions: MemoryPressure, DiskPressure, PIDPressure, NetworkUnavailable
- Recent Warning events: `kubectl get events -A --field-selector type=Warning`
  OOMKilling, BackOff, FailedScheduling, FailedMount, Unhealthy — top 10
- PVC health: `kubectl get pvc -A` — Bound/Pending/Lost status
- Deployment/StatefulSet status: ready < desired ratio per controller
- Resource usage: `kubectl top nodes/pods` (graceful skip if no metrics-server)
- Services without endpoints: empty subsets = connection refused
- ImagePullBackOff detail: surface image name for failing pods
- Cluster info: server version, node count, namespace count in output header

**Deep — OS-layer moat (Spec 23 — Linux only, must run on a k8s node):**
- kubelet health: `systemctl status kubelet` + `journalctl -u kubelet -n 30`
- containerd/CRI health: socket check + service status + crictl info
- CNI readiness: `/etc/cni/net.d/` config, `/opt/cni/bin/` binaries, `/run/flannel/subnet.env`
- IP forwarding: `/proc/sys/net/ipv4/ip_forward` — CRIT if 0
- iptables FORWARD chain: KUBE-FORWARD rule check (nft fallback)
- firewalld masquerade: Flannel requires masquerade; nftables backend WARN (RHEL)
- SELinux AVC denials: containerd/kubelet/flannel process filter
- Certificate expiry: `/etc/kubernetes/pki/*.crt` or `kubeadm certs check-expiration`
- etcd health: pod status check + optional exec health query (control plane only)
- HPA status: at-ceiling detection, targets unknown detection

**Addendum fast checks (23a–23g — additional pod scanner enrichments):**
- Pods stuck in Terminating > 5min: finalizer + webhook configuration check (23a)
- Init container status: Init:Error, Init:CrashLoopBackOff, failing container name (23b)
- Termination message: `lastState.terminated.message` for crashed pods (23c)
- Unknown pod status: StatefulSet network partition scenario (23f)
- Previous container logs: `kubectl logs --previous --tail=10` for CrashLoopBackOff pods,
  up to 5 pods, restarts >= 3, concurrent with 5s timeout (23g)

**Addendum deep checks (23d, 23e):**
- kube-proxy pod health in kube-system: explicit crash check + log scan (23d)
- KUBE-SERVICES chain: iptables nat table service routing check; IPVS fallback (23e)

**Implementation note (23a–23c, 23f):** All these addendums share a single
`kubectl get pods -A -o json` call that replaces the existing `--no-headers` call.
The JSON response contains deletionTimestamp, finalizers, initContainerStatuses,
lastState.terminated.message, ownerReferences, and nodeName in one round-trip.

**k3s vs kubeadm:** service name and cert path auto-detected.
**OS-layer gate:** skipped with INFO if not on a k8s node (no kubelet/CNI detected).

**Validation note:** k3s on Rocky/RHEL 10 has nftables masquerade issues (kernel 6.12).
Deep checks 5+6 directly address this. Use RHEL laptop (k3s available) as primary testbed.
Also: Ubuntu 22.04 VM or `kind` for kubeadm path.

### dsd docker
**Sprint 3. Full spec in DashDiag_Gap_Specs.md § Spec 7 + addendums 7a–7o.**

Container health — running/stopped/unhealthy containers, resource pressure, volumes,
network bridge checks, security posture.
Estimated scope: ~6.2d (4d core + 2.2d addendum).

**Core fast checks (Spec 7):**
- Container status: running/unhealthy/restarting/stopped with exit code interpretation
- Resource pressure: CPU%, memory vs limit (WARN >80%); no-limit flag (INFO)
- Volume health: dangling volumes, total size, backing filesystem capacity
- Network bridge: docker0 subnet overlap with VPN/corporate routes
- Disk usage summary: docker system df

**Addendum fast checks (7a–7n, 7o):**
- Exit code interpretation: 137=OOM, 139=segfault, 127=cmd not found (7a)
- Daemon health: API ping, version, storage driver, journal errors (7c)
- Compose v1 vs v2 detection (7d)
- docker events recent history: OOM kills, unexpected stops in last 1h (7e)
- IP forwarding sysctl check: /proc/sys/net/ipv4/ip_forward (7f)
- Container DNS trap: resolv.conf → 127.0.0.53 loopback (7g)
- Socket permission diagnosis: group membership check on connect failure (7h)
- Image architecture mismatch: amd64 image on arm64 host (7i)
- Swarm mode detection: INFO when LocalNodeState=active (7j)
- firewalld nftables backend: iptables rules silently dropped (RHEL family) (7k)
- MTU mismatch: VPN overlay reduces effective MTU (7l)
- Container running as root: Config.User check (7m)
- Docker socket mounted in container: HostConfig.Binds check (7n)
- Plaintext secrets in env vars: name-pattern scan, value never shown (7o)

**Addendum deep check (7b):**
- Log driver config: json-file without max-size; per-container log file size

**Collector:** `internal/collectors/docker_collector.go`
Socket API only (no docker CLI dependency). Podman socket supported.
RHEL: /run/podman/podman.sock. Ubuntu/Debian: /var/run/docker.sock.

**Test scenarios to set up:**
- Spin up deliberately broken containers (OOM, crash loops, unhealthy)
- Validate dsd catches stopped + restart-looping containers
- Test container detection when DashDiag itself runs inside Docker
- Validate cgroup v1 vs v2 (Debian 12 = cgroup v2, Ubuntu 20.04 = mixed)
- Validate Podman socket detection on RHEL 9/10

**Layer 1 note — `dsd health` from INSIDE a container (validated RHEL 10.1 + Docker 29.4.3, 2026-05-12):**
- cgroup memory limit correctly read (tested with `--memory=512m`, showed 512MB not 15GB)
- `dsd` binary footprint inside container: 20.5MB RSS
- Systemd and KernelSec correctly report INFO (not CRIT) when not present in container
- Known false alarm: Memory/Slab WARN fires inside containers with tight cgroup limits.
  Fix: suppress slab check when `ctrCtx.InContainer == true`.

### ~~dsd logs~~ ✅ DONE
OOM kills, segfaults, crash loops, journal size. Reads journald directly.

### ~~dsd security~~ ✅ DONE
SSH config, failed logins, listening ports, sudo NOPASSWD, SELinux/AppArmor denials.

### ~~dsd compare (multi-server)~~ ✅ DONE
Status matrix, outlier detection, stdin/file/process substitution input.
Validated RHEL+Debian+macOS 3-host fleet. Commit: 8f1b5cf

### dsd pve (Proxmox)
Proxmox VE health — VM/LXC status, storage pool usage, cluster quorum.
Phase 4. Specialist audience. After dsd docker is validated.
Estimated scope: ~3 days.

### ~~dsd net deep~~ ✅ DONE
dsd net --deep: jitter, TCP SYN retrans, TIME_WAIT, listen overflows, conntrack.
parseTCPCounters from /proc/net/netstat + /proc/net/sockstat. Commit: b2d6d98

---

## Collectors (dsd health additions)

### ~~Entropy collector~~ ✅ DONE
Implemented in internal/collectors/entropy_linux.go.
Reads /proc/sys/kernel/random/entropy_avail. WARN < 256, CRIT < 64.

### ~~Package security advisory~~ ✅ DONE
Shipped 2026-05-12. apt (Debian/Ubuntu) + dnf (RHEL) paths implemented.
Severity classification by package name. Missing security repo detection.
Commit: 924512e + 3ee96cd

### ~~Sysctl advisor / kernel tuning~~ ✅ DONE
6 workload profiles: k8s, webserver, database, elasticsearch, container, default.
Persist hints, dirty_background_ratio field added. Commit: 6f6c4b6

### CVE exposure check
Cross-reference installed packages against local OVAL advisory feed.
WARN CVSS >= 7.0, CRIT CVSS >= 9.0 or known exploited.
Advisory data downloaded and cached locally (~weekly). No cloud registration.
Estimated scope: ~1 week.

### ~~Configuration drift detection~~ ✅ DONE
dsd baseline save/diff/list. Sysctl value drift + status changes. Exit 1 on drift.
Validated on Debian 13. Commit: 52b64f1

---

## Strategic Discussions Required

These items need a design/strategy session before implementation begins.
Do not start building until the discussion is complete and decisions are recorded.

### [DISCUSS] Team mode — how should it work?
Before building any paid tier, answer these questions:

**Sharing model:**
- How does a user share a snapshot? URL? File? Email?
- Is sharing pull (recipient requests) or push (sender uploads)?
- Does a shared snapshot expire? How long?
- Can a recipient re-run the check or only view the saved state?
- What happens when the shared system is behind a firewall?

**Team workspace:**
- What does a "team" own? Snapshots? Alerts? Policies?
- Is the team model org-based (like GitHub orgs) or invite-based?
- How does a solo user graduate to a team account?
- What is the free tier limit? (e.g. 1 host, 7 days history, no sharing)

**Fleet view:**
- How do multiple hosts register to a team workspace?
- Push model (host uploads on cron) vs pull model (server SSHes in)?
- What does the fleet overview screen look like — table? map? timeline?
- How does dsd compare fit into the fleet view?

**Identity and auth:**
- SSO only? Email/password? CLI token?
- How does the CLI authenticate to dashdiag.sh? API key in ~/.dsd.yaml?
- How do we handle key rotation and revocation?

**Monetisation boundary:**
- What is free forever vs paid?
- Is the paid gate per-host, per-user, or per-team?
- What is the pricing model — seat-based, usage-based, or flat?
- What triggers an upgrade prompt inside the CLI?

**Privacy and trust:**
- What data leaves the machine on --share?
- Can users redact hostnames or IPs from shared snapshots?
- Where is data stored and for how long?
- GDPR implications for EU users (Andrei is in Spain)?

Suggested session format: 1-2 hour whiteboard session.
Output: decisions recorded in SPEC.md §30 before any backend work begins.

### [DISCUSS] Viral growth mechanics — how do we get word-of-mouth?
- --share URL: what does the landing page look like for a non-dsd user?
- --badge: where exactly does the badge embed and what does it show?
- Is there a "powered by DashDiag" attribution in shared snapshots?
- What is the install command we want spreading? (curl | bash vs brew vs apt)
- Should dsd health output include a one-liner install hint for new users?

### [DISCUSS] Pricing strategy
- What is the anchor price for team workspace?
- Is there a per-host fee or unlimited hosts per team?
- Open source core + paid cloud, or freemium CLI?
- Competitor reference: Datadog charges ~$15/host/month. What is DashDiag's angle?


### --share flag
Upload snapshot to dashdiag.sh and return a shareable URL.
Viral feature — every shared link is a product impression.
Requires dashdiag.sh backend. Build after landing page is live.
Estimated scope: ~1 day (CLI side) + backend.

### --badge flag
shields.io-compatible badge endpoint showing system health status.
Embeds in GitHub README. Viral — visible to every repo visitor.
Requires dashdiag.sh backend.
Estimated scope: ~2 hours (CLI side) + backend.

### Team workspace MVP (paid tier)
Shared snapshot history across a team. First paid product.
Requires dashdiag.sh backend, auth, and billing.
Estimated scope: ~10 days.

### ~~dsd policy (CI gate)~~ ✅ DONE
Shipped 2026-05-12. YAML policy file overrides thresholds, controls CI exit behaviour.
dsd policy init, dsd policy check, dsd health --policy PATH.
Commit: 5d8e644 + e34c630

### dsd trial start
Onboarding command for paid tier trial.
Requires backend. Build after team workspace MVP.
Estimated scope: ~1 day.

---

## Polish

### [LOW] External bug reports — upstream kernel / distro issues found during DashDiag validation

During testbed validation we found bugs in the Linux kernel and distros
that affect the hardware DashDiag runs on. Low priority, do when time
permits. All data collected and stored in `bug-reports/`.

**ELAN touchpad dead on Lenovo Legion 5 15ACH6H — kernel i2c_designware**
- File: `bug-reports/elan-touchpad-i2c-lenovo-legion.md`
- Root cause: ACPI DSDT specifies 400kHz I2C, driver forces 100kHz as
  "Firmware Bug" workaround. ELAN06FA needs 400kHz for data transfer.
  Touch events never reach kernel. Physical click also silent.
- Reproduced on: Debian 13.4 (kernel 6.12.73) + RHEL 10.1 (kernel 6.12.0)
- Hardware: Lenovo Legion 5 15ACH6H (82JU), AMDI0010:01 + ELAN06FA:00
- Report to: kernel.org Bugzilla (I2C/SMBus), Red Hat Bugzilla, Debian BTS
- Before filing: search lkml.org + Arch/Gentoo trackers — may already exist
- Try first: kernel param `i2c_designware.timings=0,400000` to confirm theory


### dsd health deep
Per-core CPU breakdown, per-process memory detail, extended sysctl analysis.
Build rule: implement only after dsd health fast is in production use.
Estimated scope: ~3 days.

### CIS/STIG compliance checks
Compare system config against CIS Benchmark or STIG profiles.
Enterprise-only. Implement after core health checks are stable and paying customers exist.
Estimated scope: ~2 weeks.

### [TESTBED] openSUSE Leap 16 + SLES validation
openSUSE Leap 16 (free, based on SLES 16) — download and install on p17 (58GB).
SLES requires registration — use openSUSE Leap as proxy for SLES validation.

Key things to validate vs other distros:
- zypper package manager — packages collector has zero zypper support yet
- btrfs default filesystem — disk collector behavior on btrfs
- YaST — different network/system config layer
- AppArmor enforcing (same as Ubuntu)
- Different sysctl defaults

Download (net installer, ~300MB):
https://download.opensuse.org/distribution/leap/16.0/iso/openSUSE-Leap-16.0-NET-x86_64-Current.iso

Partition: p17 (58GB, 686-744GB on nvme0n1) + p18 (2GB swap)
EFI: reuse p6 (existing ESP, do not format)

### ~~dsd init cloud detection improvements~~ ✅ DONE
DMI file reads: sys_vendor, board_vendor, chassis_vendor added.
Hetzner, Oracle Cloud, Vultr detection added. String() and IsCloud() methods.
Commit: 5919214

### ~~--dry-run on file-writing operations~~ ✅ DONE
Implemented in `dsd hook --dry-run`. Shows what would be written without writing.
Trust building for dsd hook. Already shipped.

### [DISCUSS] Multi-socket / NUMA testing
Rent Hetzner AX162-S or similar (2x AMD EPYC) for a few hours to validate:
- NUMA topology collector (/sys/devices/system/node/)
- Per-socket load imbalance detection (/proc/stat per-CPU)
- IRQ affinity analysis (/proc/interrupts)
- Cross-node memory traffic
- CPU pinning drift detection

Hetzner dedicated auction servers: ~€0.50-2/hour.
Also: ask friends with multi-socket hardware.
Build after core product is stable and first paying customer exists.

---

## [STRATEGIC] V2 Diagnostic Engine — From Collector to Doctor

These ideas were captured during a strategic review session. The core insight:
DashDiag v1 is a high-quality collector platform. V2's moat is interpretation —
becoming "OBD that reads codes" not just "OBD that shows sensor values".

Do NOT start any of these items before first paying customer is acquired
(target: 6 weeks from initial sprint per project guide).

### [V2-CORRELATION] Symptom correlation engine
**v0 SHIPPED (2026-05-12, commit dc729d4)** — 4 hardcoded rules live:
- Memory Pressure Cascade: RAM WARN/CRIT + Swap CRIT + Processes CRIT or Logs OOM
- Hard OOM Event: Memory CRIT + Logs OOM + Swap not CRIT
- IO Stall Under Memory Pressure: IO CRIT + Memory WARN/CRIT + Swap CRIT
- Network Degraded Under System Load: Network CRIT + CPU/Swap/Memory loaded

All 4 rules validated live on RHEL 10.1. 20 tests in correlate_test.go.
Output: DIAGNOSIS block between per-collector results and summary.

**Next rules to add (evidence from RHEL validation):**

~~GPU Sustained Compute Load context rule~~ ✅ DONE
Shipped in correlate.go. Fires when GPU INFO/WARN + Thermal or Memory elevated.
INFO level, shows which secondary signals are GPU-driven. 4 tests in correlate_test.go.

Other rules backlogged:
- Multiple OOM kills + same service → memory leak in that specific service
- Entropy low + TLS/crypto collector signals → crypto bootstrapping failure
- IO CRIT on one device + other devices OK → single drive degradation (not load)
- Sysctl drift + recent reboot → kernel parameter not persisted across reboot

Implementation phases remaining:
2. Confidence scoring per rule match
3. (V3) graph-based DAG of symptom → cause → fix

### ~~[V2-COLLECTOR] Filesystem & inode pressure~~ ✅ ALREADY DONE
InodesUsedPct collected via statfs in DiskCollector, checked in checkDisk
against DiskWarnPct/DiskCritPct thresholds. WARN at 80%, CRIT at 90%.
Hint: df -i + find to identify inode hog. No new work needed.

### [V2-COLLECTOR] Kernel instability extensions
Extend LogsCollector:
- soft lockups (kernel: BUG: soft lockup)
- hard lockups (NMI watchdog)
- kernel panic history (/sys/fs/pstore, /var/crash)
- watchdog resets
Signals: journalctl -k, /sys/fs/pstore, dmesg patterns
Estimated scope: ~2 days.

### [V2-COLLECTOR] Network deep diagnostics
Extend NetworkCollector:
- TCP retransmissions rate (/proc/net/netstat)
- SYN backlog saturation
- TIME_WAIT explosion (already partial in TCP states)
- connection tracking table usage (/proc/sys/net/netfilter/nf_conntrack_count)
Signals: /proc/net/netstat, /proc/net/sockstat, conntrack
Estimated scope: ~2 days. Belongs in `dsd net deep`.

### [V2-COLLECTOR] CPU scheduling pathology
- run queue saturation (load vs cores)
- context switch spike detection
- iowait vs steal time separation (VM-host vs host-host)
- CPU throttling due to cgroups (/sys/fs/cgroup/cpu.stat)
Signals: /proc/stat, /proc/schedstat, cgroup files
Estimated scope: ~2 days. Belongs in `dsd health deep`.

### [V2-COLLECTOR] Storage performance diagnostics
- write amplification estimate (SSD wear prediction from SMART)
- queue depth saturation (/sys/block/*/queue/nr_requests vs in_flight)
- fsync latency spikes (eBPF — significant complexity)
- disk scheduler latency distribution
Signals: iostat -x equivalent, /sys/block/*/queue/, /proc/diskstats
Estimated scope: ~3 days. fsync latency would need eBPF — defer to v3.

### [V2-COLLECTOR] TLS / certificate health (high-value cross-platform)
New `dsd tls` standalone command:
- expired cert detection (local cert paths)
- remote endpoint cert expiry (configurable list)
- TLS handshake failures from logs
- system trust store drift (compare to known baseline)
Signals: /etc/ssl/certs/*, openssl s_client, /etc/pki/ca-trust/
Estimated scope: ~3 days. High leverage for DevOps audience.

### [V2-COLLECTOR] Security drift detection (extends Hardening)
- SSH config drift vs baseline
- sudoers unexpected changes (audit /etc/sudoers timestamp + diff)
- new SUID binaries (find / -perm -4000, compare to baseline snapshot)
- cron job injection detection (/etc/cron*, /var/spool/cron/)
- writable PATH binaries
- new users with UID 0
Signals: file system scans, baseline comparison
Estimated scope: ~3 days.

### [V2-COLLECTOR] Process-to-network anomaly mapping
- unknown process listening on port
- port-process mismatch (e.g. nginx listening on :22)
- reverse shell heuristics (tty-less shell + network connection)
Signals: /proc/*/cmdline cross-referenced with /proc/net/tcp
Estimated scope: ~2 days.

CAUTION: This drifts toward EDR territory (CrowdStrike, SentinelOne).
EDR is a regulated, compliance-heavy market. Do not position DashDiag as
EDR-class without explicit strategic decision.

### [V2-COLLECTOR] macOS additions
Lower priority — DashDiag audience is primarily Linux servers.
- top CPU processes by app bundle
- memory pressure breakdown (swap vs compressed memory)
- LaunchAgents / LaunchDaemons inspection (~/Library/LaunchAgents)
- Spotlight indexing health (mdutil -s /)
Estimated scope: ~3 days combined. Defer until macOS user demand exists.

---

## [STRATEGIC] V2 Framing Decision Required

The original analysis claimed: "Collectors are commoditized. Interpretation is not."

Counter-position: DashDiag's collectors are NOT commoditized — most tools shell out
to top/vmstat/ss with shallow parsing. DashDiag reads /proc and /sys directly with
mount detection, build tags, and platform-aware logic. THAT is the moat for v1.

For v2, the framing shifts toward interpretation. The correlation engine becomes
the unique value, not the collectors.

**DECISION RECORDED (initial review):** Lean toward "system doctor" — correlation
engine over collector expansion. Rationale:
- Anyone can add another collector; correlation rules encode actual SRE knowledge
- The cascade output format ("Memory pressure with cascade") differentiates strongly
- v1 already has solid collector coverage (18 collectors validated on RHEL + macOS)
- Overnight stress cron data is a natural validation dataset for correlation rules

Open questions still requiring decision:
- Are we a "comprehensive observability CLI" or a "system doctor"?
- Confirm: lean hard into correlation, accept fewer collectors in v2?
- This decision affects messaging, pricing tier structure, engineering priorities.
- Re-confirm after first paying customer is acquired and gives input.

---

## [TESTBEDS] Hardware Validation — Use Real Hardware Before It Goes Away

DashDiag is validated against /proc, /sys, and kernel interfaces. Different hardware
and OS combinations expose different code paths. This section tracks which scenarios
need testing on which physical hardware, before access expires.

### RHEL 10 Laptop (192.168.1.145) — ~2 weeks remaining

Hardware that cloud VMs can't replicate:
- 2x SK Hynix 1TB NVMe (one Windows, one RHEL — dual boot)
- RTX 3070 Laptop GPU 8GB (validated under gpu_burn)
- AMD Ryzen 7 5800H (8c/16t)
- Wi-Fi (wlp4s0) + ethernet (eno1)
- k3s on bare metal (containerd runtime)
- Real battery + thermal + power transitions

Scenarios still worth testing (ranked by uniqueness):

**[HIGH] Suspend/resume cycle**
Laptop-only behavior. Does `dsd health` cope when clock jumps after wake?
Does the baseline file detect the gap? Does `--story` handle a 10-hour gap?
Likely surfaces real bugs in time-based collectors and history.

**[HIGH] Battery vs AC power transitions**
Switch from AC to battery and back. Does CPU frequency scaling change visibly?
Does Battery collector show meaningful state transitions in story output?
Does dsd detect throttling under battery?

**[MEDIUM] Wi-Fi disconnect/reconnect**
Pull ethernet, switch to Wi-Fi. Does Network collector handle primary interface
change cleanly? Does it correctly detect the new gateway and primary route?

**[MEDIUM] GPU power state transitions**
Full burn → idle → burn again. Does Xid error detection work? Does VRAM
free correctly? Does dsd report stale process data after gpu_burn ends?

**[HIGH] Install Docker alongside k3s — build dsd docker v0 here**
RHEL has k3s (containerd). Adding Docker gives us a testbed for the new
`dsd docker` command without setting up a new machine. Test against:
- Deliberately broken containers (OOM, crash loop, unhealthy)
- Container detection when dsd itself runs inside docker
- cgroup v2 limits respected when inside container

**[LOW] Suspend laptop overnight**
See how baseline/story handles a long gap with no cron runs. Validates
the story is robust to non-continuous data.

### Proxmox Host — High Value, Multi-Disk, Production Workload

Hardware that the laptop doesn't have:
- Mixed disk types: HDD + SSD + NVMe (validates per-device IO thresholds)
- ZFS pools (whole new filesystem we haven't tested)
- LVM thin pools (Proxmox standard for VM disks)
- Server-class CPU (likely Xeon or Ryzen server, ECC RAM)
- Long uptime → real `power_on_hours` data, real wear patterns
- Server NIC (not consumer Realtek)
- Running VMs + LXC containers (real workload, not synthetic)

Scenarios to test:

**[HIGH] `dsd disk` with mixed drive types**
Currently only tested on NVMe. HDD detection via `/sys/block/DEV/queue/rotational=1`
is coded but unvalidated. Validate:
- HDD shows up as "HDD" in `dsd disk`
- SSD shows up as "SSD" (rotational=0, but not NVMe)
- NVMe shows up as "NVMe"
- IO thresholds applied correctly per device type (HDD=50/100ms, SSD=default,
  NVMe=5/15ms — coded in IOCollector but only NVMe tested)

**[HIGH] NVMe wear data on multi-year drives**
Laptop NVMe has 7000h power on, 0% wear (essentially new).
Proxmox NVMe likely has 20,000+ hours uptime — real wear patterns.
Validate: PercentageUsed, AvailableSparePct, MediaErrors on aged drives.

**[HIGH] ZFS pool support**
Does Disk collector read `/proc/mounts` entries for `zfs` filesystem type?
Does it handle ZFS pool names correctly (e.g. `rpool/ROOT/pve-1`)?
Does it ignore ZFS internal datasets we don't want to show?
May need a dedicated ZFS pool collector for pool health (zpool status equivalent).

**[HIGH] LVM mount detection**
Proxmox uses `/dev/mapper/pve-root` style devices. Does our mount parsing handle
device-mapper names? Does it correctly link back to physical disks?

**[MEDIUM] Running inside an LXC container**
Run dsd inside one of the Proxmox LXC containers. Does it correctly detect
LXC (vs Docker, vs k8s pod)? Does cgroup memory/CPU limit detection work?

**[MEDIUM] Running inside a Proxmox VM**
QEMU/KVM virtualization. Does platform detection identify it as virt?
Does `steal time` get surfaced correctly in CPU collector?

**[HIGH] Build dsd pve here**
Natural place to build the Proxmox-specific command. Read from:
- `/etc/pve/` — Proxmox config files
- `pvesh get /nodes/{node}/status` — node status API
- `qm list` — VM list
- `pct list` — LXC list
- `pvecm status` — cluster quorum (if clustered)
- `/etc/pve/storage.cfg` — storage pools

Would surface:
- VM/LXC status (running, stopped, paused)
- Storage pool usage and health
- Cluster quorum (if clustered)
- Backup status (PBS integration if available)
- Replication lag
- HA service status

Estimated scope: ~3-5 days. Strategic value: Proxmox users are exactly the
self-hosted SRE audience that values "no agent, no cloud" — high signal for
early adopters.

### Future Testbeds (Not Yet Acquired)

**Debian/Ubuntu via Hetzner CX22 (€4/month)**
- Validates apt vs dnf in Packages collector
- Standard cloud Linux for most deployments
- Sets up after RHEL laptop access ends

**Multi-socket / NUMA via Hetzner AX162-S (€0.50-2/hour)**
- 2x AMD EPYC dedicated server
- NUMA topology, IRQ affinity, cross-socket memory traffic
- Already in backlog under separate [DISCUSS] section

**Raspberry Pi / Oracle Cloud ARM**
- ARM Debian on real hardware
- Validates Linux/arm64 build
- Free (Oracle) or one-time cost (Pi)

---

## Test Coverage Matrix

What we have validated vs what we need:

| Scenario              | RHEL Laptop | Proxmox Host | Hetzner Debian | macOS arm64 |
| --------------------- | ----------- | ------------ | -------------- | ----------- |
| 18 collectors         | ✅          | TODO         | TODO           | ✅          |
| NVMe SMART            | ✅          | TODO (aged)  | N/A            | ✅ (no nvme-cli) |
| HDD detection         | N/A         | TODO         | N/A            | N/A         |
| SSD (non-NVMe)        | N/A         | TODO         | TODO           | N/A         |
| ZFS                   | N/A         | TODO         | TODO           | N/A         |
| LVM                   | N/A         | TODO         | possible       | N/A         |
| Mixed-OS drives       | ✅          | unlikely     | N/A            | N/A         |
| RTX 3070 GPU          | ✅          | depends      | depends        | N/A         |
| k3s / k8s             | ✅          | depends      | TODO           | N/A         |
| Docker                | ✅ (validated 2026-05-12) | depends | TODO      | TODO (Docker Desktop) |
| Battery               | ✅          | N/A          | N/A            | ✅          |
| Suspend/resume        | TODO        | N/A          | N/A            | TODO        |
| Wi-Fi switching       | TODO        | N/A          | N/A            | TODO        |
| Multi-socket / NUMA   | N/A         | depends      | N/A            | N/A         |
| Long uptime wear      | N/A         | ✅ likely    | TODO           | depends     |
| apt vs dnf            | dnf only    | apt likely   | apt            | brew        |
| Cloud detection       | bare metal  | bare metal   | cloud          | bare metal  |
