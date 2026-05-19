# DashDiag — Gap Analysis Specs v2
**Generated: May 2026 | Status: RESEARCH COMPLETE — Ready for implementation**
**Sources: Linux admin complaint research 2024–2026, nixCraft troubleshooting series,**
**DevOps Q&A collections, sysadmin guides, Docker/k8s official docs, YouTube transcripts (60+),**
**overcast.blog articles, kubernetes.io troubleshooting guides.**
**Merge sections into DashDiag_Project_Guide.md at v49+**

> **Research closure note (May 2026):** ~80 sources across Linux, Docker, Kubernetes,
> Proxmox, and networking troubleshooting fully processed. Spec is saturated.
> Every practical diagnostic signal available in public sysadmin content is either
> specced here or explicitly out of scope. Build order: fast before deep, always.
> Total: ~58.25d across 51 spec items.

---

## Context — What Already Exists vs What This Adds

Checked against BACKLOG.md and the project guide before writing. The following are
already shipped or in progress:

| Item | Status |
|------|--------|
| `dsd logs` | ✅ DONE — journal aggregation + journal size |
| `dsd security` | ✅ DONE — SSH, ports, sudo, SELinux/AppArmor denials |
| `dsd net deep` | ✅ DONE — jitter, TCP retrans, TIME_WAIT, conntrack |
| `dsd docker` | In backlog — not yet built |
| `dsd health deep` | In backlog — not yet built |

**Important disambiguation:** The existing `dsd services` is *port connectivity health*
(SSH :22, HTTP :80, DB :5432). It is NOT systemd service failure diagnosis. Both are
needed and do not overlap.

---

## What This Document Adds — Full Index

| # | Type | Command / Area | Sprint |
|---|------|----------------|--------|
| 1 | New command | `dsd services deep` — systemd failure diagnosis | 1 |
| 2 | Enhancement | `dsd net deep` — DNS resolver audit | 1 |
| 3 | Enhancement | `dsd logs` — cross-source triage improvements | 2 |
| 4 | New command | `dsd disk` — standalone disk + I/O diagnostics | 2 |
| 5 | Enhancement | `dsd health deep` — cgroup tree + process hierarchy | 3 |
| 6 | Enhancement | `dsd security` — permission root-cause disambiguation + SELinux primer refinements | 3 |
| 7 | Full spec | `dsd docker` — Docker/Podman triage | 3 |
| 8 | Architecture | `platform.Profile` distro normalization layer | 4 |
| 9 | New command | `dsd cron` — cron health + job failure triage | 2 |
| 10 | New command | `dsd proc <PID>` — /proc-based process inspector | 3 |
| 11 | Enhancement | `dsd net deep` — NFS stale mount detection | 3 |
| 12 | Enhancement | `dsd health deep` — package dependency integrity | 2 |
| 13 | Enhancement | `dsd security` — SSH hardening audit (sshd -T) | 2 |
| 14 | Enhancement | `dsd security` — user account hardening audit | 2 |
| 15 | New command | `dsd kvm` — KVM/libvirt VM diagnostics | 4 |
| 16 | Enhancement | `dsd net deep` — BIND/named server health | 3 |
| 17 | New command | `dsd steamos` — SteamOS RAUC/gamescope/partition health | 3 |
| 18 | New command | `dsd gpu` — GPU/APU temperature, TDP, VRAM, clocks | 3 |
| 19 | Enhancement | `dsd disk` — SteamOS BTRFS + partition layout block | 3 |
| 20 | Enhancement | `dsd net` — SteamOS Wi-Fi backend + SSID conflict check | 3 |
| 4a | Addendum | `dsd disk` — fuser filesystem/device busy check | 2 |
| 4b | Addendum | `dsd disk` — ZFS pool health (`zpool status`: DEGRADED, resilver, errors) | 2 |
| 10a | Addendum | `dsd proc` — pmap private vs shared memory breakdown | 3 |
| H1 | New sub-check | `dsd health` — active session list (w command) | 1 |
| 21 | Addendum | `dsd disk deep` — LVM layer health (VG space, snapshot overflow, RAID degraded) | 2 |
| 7a | Addendum | `dsd docker` — exit code interpretation (137=OOM, 139=segfault, 127=cmd not found) | 3 |
| 7b | Addendum | `dsd docker deep` — log driver config + unbounded json-file growth | 3 |
| 7c | Addendum | `dsd docker` — daemon health: API ping + version + journal errors | 3 |
| 7d | Addendum | `dsd docker` — Compose v1 vs v2 detection | 3 |
| 7e | Addendum | `dsd docker` — docker events recent history (OOM kills, unexpected stops) | 3 |
| 7f | Addendum | `dsd docker` — IP forwarding sysctl check (host networking prereq) | 3 |
| 7g | Addendum | `dsd docker` — container DNS trap (resolv.conf → 127.0.0.53) + daemon DNS fallback | 3 |
| 7h | Addendum | `dsd docker` — socket permission diagnosis (group membership) | 3 |
| 7i | Addendum | `dsd docker` — image architecture mismatch (exec format error) | 3 |
| 7j | Addendum | `dsd docker` — Swarm mode detection INFO | 3 |
| 7k | Addendum | `dsd docker` — firewalld nftables backend + docker0 trusted zone | 3 |
| 7l | Addendum | `dsd docker` — MTU mismatch on VPN/overlay networks | 3 |
| 7m | Addendum | `dsd docker` — container running as root detection | 3 |
| 7n | Addendum | `dsd docker` — Docker socket mounted inside container | 3 |
| 7o | Addendum | `dsd docker` — plaintext secrets in container environment variables | 3 |
| 23 | Full spec | `dsd k8s` — Kubernetes cluster + OS-layer diagnosis (fast + deep) | 3/4 |
| 24 | Full spec | `dsd pve` — Proxmox VE node diagnostics (fast + deep, PVEPerf) | 4 |
| 23a | Addendum | `dsd k8s` — pods stuck in Terminating + admission webhook detection | 3 |
| 23b | Addendum | `dsd k8s` — init container status (Init:Error, Init:CrashLoopBackOff) + log hint | 3 |
| 23c | Addendum | `dsd k8s` — `lastState.terminated.message` for crashed pods | 3 |
| 23d | Addendum | `dsd k8s` deep — kube-proxy pod health in kube-system | 3 |
| 23e | Addendum | `dsd k8s` deep — KUBE-SERVICES chain existence check (IPVS fallback) | 3 |
| 23f | Addendum | `dsd k8s` — Unknown pod status (StatefulSet network partition) | 3 |
| 23g | Addendum | `dsd k8s` — `kubectl logs --previous` tail for CrashLoopBackOff pods | 3 |

---

## Spec 1 — `dsd services deep` (Systemd Failure Diagnosis)

**Sprint:** 1
**Type:** Deep variant of existing `dsd services` command
**Pain source:** "Failed to start" errors show no root cause. systemd-analyze blame
outputs device/socket noise. User service failures (--user) are invisible.

### What `dsd services` (fast) does today
Port connectivity health: checks SSH :22, HTTP :80, DB ports, custom endpoints.
Returns reachable/unreachable per port. That is the right scope for fast.

### What `dsd services deep` adds
Everything in fast, plus systemd-layer diagnosis:

**Checks to run:**
- List all systemd units in `failed` state with exit code + last journal line
- Run `systemd-analyze blame` and filter results: exclude `.device` and `.socket`
  units, show only real service/mount/target units. Cap at top 5.
- Detect units with `NeedsDaemonReload=yes` — modified unit files pending reload
- Detect units that are masked (a silent trap — masking looks like disabled)
- If `systemd --user` daemon is running for current user, repeat the above for
  user units. If not running, show a single INFO line.
- Check journal health: attempt `journalctl --verify` — if it exits non-zero,
  report corruption and the last valid-log timestamp from the error message
- For each failed unit: pull last 8 lines from journalctl -u <unit> -n 8
- For each failed unit with AppArmor/SELinux active: cross-reference denials in
  /var/log/audit/audit.log or journalctl -t kernel for AVC/denied messages in the
  60 seconds around the unit failure timestamp


**Human-readable output example:**

```
⚙️  Services deep

[Port health — same as dsd services fast]
  ✅ SSH :22       reachable (2ms)
  ✅ HTTP :80      reachable (4ms)

[Systemd health]
  ❌ Failed units: 2
     postgresql.service   exit 1   "Failed to set up shared memory"
       → Last log: FATAL: could not create shared memory segment
       → Last log: DETAIL: Failed syscall: shmget(key=, size=56, 03600)
     nginx.service        exit 1   "Failed to read PID from file"

  ⚠️  Needs daemon-reload: 1 unit (ssh.service was modified)
  ✅  Masked units: none unexpected
  ✅  Journal integrity: OK (last entry 2m ago)

  Boot top offenders (real services only):
    4.2s  postgresql.service
    2.1s  docker.service
    1.8s  NetworkManager.service

Next:
  → systemctl status postgresql.service
  → journalctl -u postgresql.service -n 50 --no-pager
  → systemctl daemon-reload
```

**JSON output (`--json` keys to add to existing services schema):**

```json
{
  "systemd": {
    "failed_units": [
      {
        "name": "postgresql.service",
        "exit_code": 1,
        "last_log_lines": ["FATAL: could not create shared memory segment"],
        "apparmor_denials": []
      }
    ],
    "needs_daemon_reload": ["ssh.service"],
    "masked_units": [],
    "journal_healthy": true,
    "journal_last_valid": "2026-05-18T10:23:00Z",
    "boot_top_offenders": [
      {"unit": "postgresql.service", "duration_ms": 4200}
    ]
  }
}
```

**Collector design:**
- New file: `internal/collectors/services_deep_linux.go`
- Uses `systemctl --failed --plain --no-legend` (parseable output)
- Uses `systemctl show <unit> --property=NeedsDaemonReload,UnitFileState`
- Uses `systemd-analyze blame --plain` (filter by UnitType != device/socket)
- Uses `journalctl -u <unit> -n 8 --no-pager --plain` per failed unit
- Uses `journalctl --verify 2>&1` for journal health check
- Cross-distro: same on all systemd distros (RHEL, Debian, Ubuntu, SLES)

**Acceptance criteria:**
- [ ] `dsd services deep` lists failed units with last journal line
- [ ] Boot offenders exclude device/socket units
- [ ] NeedsDaemonReload correctly detected
- [ ] Journal corruption detected when present (simulate with truncated journal file)
- [ ] User unit check only runs if `systemctl --user status` succeeds
- [ ] `--json` output valid against schema
- [ ] Runs in < 8 seconds on a system with 2 failed units


---

## Spec 2 — `dsd net deep` DNS Resolver Audit Block

**Sprint:** 1
**Type:** Enhancement to existing `dsd net deep` command
**Pain source:** systemd-resolved stops/degrades silently. Admins see constant toggle
between full and limited DNS feature sets without understanding why. DNSSEC SERVFAIL
on stub mode breaks mail servers and other validation-sensitive services.

### What to add to the existing `dsd net deep` output

Insert a new `[DNS Resolver]` section after the existing `[DNS]` timing block.

**Checks to run:**

1. **Resolver detection:** determine which resolver is active:
   - Is systemd-resolved running? (`systemctl is-active systemd-resolved`)
   - Is `/etc/resolv.conf` the stub symlink, the uplink symlink, or a custom file?
     - Stub: `/run/systemd/resolve/stub-resolv.conf` → DNSSEC-aware, correct default
     - Uplink: `/run/systemd/resolve/resolv.conf` → bypasses stub, loses split-DNS
     - Custom/unmanaged: file edited directly → warn that resolved won't manage it
   - On non-systemd systems: is dnsmasq, unbound, or plain resolv.conf active?

2. **systemd-resolved feature set:** run `resolvectl status` and parse:
   - Current DNS Servers per interface
   - DNSSEC setting (yes/no/allow-downgrade)
   - DNS-over-TLS setting (yes/no/opportunistic)
   - Detect "degraded" mode: if `resolvectl status` shows `DNSSEC=no` on an
     interface where `/etc/systemd/resolved.conf` has `DNSSEC=yes`, flag mismatch
   - Detect feature set downgrade: if resolved is in "TCP" or "UDP" only mode
     instead of "TLS" or "EDNS0", surface it with the reason

3. **DNSSEC validation test:** run `resolvectl query sigok.verteiltesysteme.net`
   and check for DNSSEC-validated=yes in output (known-good DNSSEC domain).
   On failure: report and distinguish between SERVFAIL (DNSSEC broken) vs timeout.

4. **VPN DNS integration check:** detect if a VPN interface is active
   (check for tun0, wg0, nordlynx, proton0 etc.). If yes:
   - Verify that the VPN interface has DNS servers assigned in `resolvectl status`
   - If VPN is up but DNS not routed through it, warn (common misconfiguration)

**Human-readable output addition:**

```
[DNS Resolver]
  ✅ Resolver: systemd-resolved (active)
  ✅ resolv.conf: stub mode (correct — /run/systemd/resolve/stub-resolv.conf)
  ⚠️ DNSSEC: configured yes, but degraded to no on eth0
     Reason: upstream DNS 1.2.3.4 does not support DNSSEC validation
  ✅ DNS-over-TLS: opportunistic (connected)
  ✅ DNSSEC validation test: passed (sigok.verteiltesysteme.net)
  ✅ VPN DNS routing: not applicable (no VPN interface detected)

Next:
  → resolvectl status
  → resolvectl query sigok.verteiltesysteme.net
```

**JSON schema addition:**

```json
"dns_resolver": {
  "resolver_type": "systemd-resolved",
  "resolv_conf_mode": "stub",
  "dnssec_configured": "yes",
  "dnssec_active": "no",
  "dnssec_degraded": true,
  "dnssec_degraded_reason": "upstream does not support DNSSEC",
  "dot_status": "opportunistic",
  "dnssec_test_passed": true,
  "vpn_dns_integrated": null
}
```

**Cross-distro notes:**
- Debian 12+ and Ubuntu 22.04+: systemd-resolved enabled by default
- RHEL 9+: systemd-resolved available but often disabled; NetworkManager manages DNS
  → If systemd-resolved is NOT active, check NetworkManager DNS config instead
  → `nmcli dev show | grep DNS` and validate `/etc/resolv.conf` is not stale
- Older distros (RHEL 8, Ubuntu 20.04): may use plain resolv.conf — report INFO,
  not WARN; being non-systemd-resolved is not an error

**Acceptance criteria:**
- [ ] Correctly identifies stub vs uplink vs custom resolv.conf on Debian 12
- [ ] Detects DNSSEC degradation when configured but not active
- [ ] DNSSEC validation test passes on clean system, fails gracefully if no internet
- [ ] VPN DNS check correctly identifies wg0/tun0 interfaces with missing DNS routes
- [ ] On RHEL with resolved disabled: falls back to NetworkManager DNS check
- [ ] Does not break existing net deep checks — purely additive


---

## Spec 3 — `dsd logs` Cross-Source Triage Improvements

**Sprint:** 2
**Type:** Enhancement to existing `dsd logs` command
**Pain source:** journalctl and /var/log/* are never correlated. No single
"show me recent errors across all sources" command exists. Post-crash analysis
is blocked when journal is corrupted after a hard reset.

### What `dsd logs` does today
- OOM kills, segfaults, crash loops
- Journal size
- Reads journald directly

### What to add

**1. /var/log/* aggregation alongside journald:**
On systems where traditional log files coexist with journald (RHEL, older distros),
add a scan of:
- `/var/log/messages` or `/var/log/syslog` — last 500 lines, filter for ERR/CRIT/ALERT
- `/var/log/auth.log` or `/var/log/secure` — last 200 lines, filter for failures
- `/var/log/kern.log` — last 200 lines, kernel WARN+ messages
- Service-specific: `/var/log/nginx/error.log`, `/var/log/apache2/error.log`,
  `/var/log/mysql/error.log` if these paths exist
Deduplicate against journald output (skip /var/log files if journald has same content
via `Storage=persistent` or `Storage=auto`).

**2. Severity ranking in output:**
Current output is chronological. Add a severity-ranked summary at the top:
```
[Log triage — last 24h]
  CRITICAL (2):
    kernel: Out of memory: Kill process 8823 (java)  — 3h ago
    kernel: EXT4-fs error (sdb1): ext4_validate_block_bitmap — 18h ago
  ERROR (8):
    postgresql: FATAL: could not open file "/etc/postgresql/pg_hba.conf" — 1h ago
    nginx: connect() failed (111: Connection refused) while connecting to upstream — 45m ago
    ... and 6 more — run: journalctl -p err -n 50
  WARN (14): see dsd logs --all

Journal: 245MB used, 1.2GB free. Oldest: 14 days.
```

**3. Crash file detection:**
Check for kernel crash dumps and application core files:
- `/var/crash/` — Ubuntu crash reports
- `/var/lib/systemd/coredump/` — systemd coredump store
- `/sys/fs/pstore/` — kernel panic pstore entries
If found, report count, newest timestamp, and size. Do not read their content.

**4. Journal corruption resilience:**
If `journalctl` exits non-zero (corruption after hard reset), fall back to:
- Parse `/var/log/journal/*/system.journal` directly with `journalctl --file`
- If that also fails, fall back to `/var/log/messages` or `/var/log/syslog`
- Always report which source was used and whether corruption was detected

**JSON schema additions:**

```json
"logs": {
  "critical_count": 2,
  "error_count": 8,
  "warn_count": 14,
  "top_critical": [
    {"message": "Out of memory: Kill process 8823", "source": "kernel", "age_min": 180}
  ],
  "crash_files_found": 1,
  "crash_files_path": "/var/lib/systemd/coredump/",
  "journal_corrupted": false,
  "log_source_used": "journald"
}
```

**Acceptance criteria:**
- [ ] Severity-ranked summary appears before chronological detail
- [ ] /var/log/* files scanned only when not covered by journald
- [ ] Crash file detection works on Ubuntu (/var/crash) and systemd coredump store
- [ ] Graceful fallback when journal is corrupted — uses /var/log/syslog if available
- [ ] No duplication between journald and /var/log when both contain same entries
- [ ] `--json` output valid against updated schema

---

## Spec 4 — `dsd disk` (New Standalone Command)

**Sprint:** 2
**Type:** New top-level command
**Pain source:** Disk is buried inside `dsd health`. There is no command that combines
space + I/O accountability + filesystem health + mount point status into one view.
Admins use df, du, iostat, and smartctl separately — a prime DashDiag unification target.

### Why a standalone command (not just `dsd health deep`)
Disk problems are the second most common production incident type after network.
An admin with a "disk full" alert wants a dedicated command they can run instantly,
not a full health check. Also enables: `dsd disk --json | jq .mounts[]`.

### `dsd disk` (fast)
**Target runtime:** < 3 seconds

Checks:
- All mounted filesystems: device, mount point, type, used%, free (absolute + %)
  Flag WARN at 80%, CRIT at 90% (same thresholds as existing DiskCollector)
- Inode usage per filesystem: flag WARN at 80%, CRIT at 90%
- Device type per physical disk: NVMe / SSD / HDD (from /sys/block/*/queue/rotational)
- Any read-only mounts that should be read-write (check ro flag in /proc/mounts)
- Any failed/degraded mounts (check for "EXT4-fs error" or "XFS corruption" in dmesg
  last 5 minutes — fast scan only)

**Output example:**

```
💾 Disk

[Filesystems]
  ✅ /           ext4   120G free / 250G    (52% used)
  ⚠️ /var        ext4     2G free /  20G    (90% used)  ← WARN
  ✅ /boot       ext4   800M free / 1G      (20% used)
  ✅ /home       xfs     50G free / 100G    (50% used)

[Inodes]
  ✅ /           1.2M free / 16M     (8% used)
  ⚠️ /var/log    12 free / 1024      (98% used)  ← CRIT

[Physical disks]
  ✅ nvme0n1  NVMe  931G   SMART: healthy
  ✅ sda      HDD   2.0T   SMART: healthy

Checks: 6 | Passed: 4 | Warnings: 1 | Critical: 1
Next:
  → du -sh /var/log/* | sort -rh | head -10
  → dsd disk deep
```


### `dsd disk deep`
**Target runtime:** < 15 seconds (SMART read can be slow on spinning disks)

Everything in fast, plus:
- **I/O accountability:** sample `/proc/diskstats` twice (1 second apart) to identify
  which physical device is under I/O pressure. Report: device name, read/write kB/s,
  await ms, utilization%. Flag if any device > 80% utilization.
- **Top I/O processes:** read `/proc/<PID>/io` for all processes. Rank by
  `read_bytes + write_bytes`. Show top 5. (No root required for own processes;
  for others, report what is readable.)
- **SMART extended:** if smartctl available and device is NVMe/SSD, report:
  - Reallocated sectors (HDDs): WARN > 0
  - NVMe media errors: WARN > 0
  - Wear level / available spare (NVMe): WARN < 10%
  - Power cycle count and power-on hours for context
- **Large directory finder:** for any filesystem at WARN/CRIT, run
  `du -xm --max-depth=2 <mountpoint>` and show top 5 directories by size.
  Cap at 10 seconds total for this step.
- **Filesystem error log:** scan dmesg for I/O errors, EXT4/XFS corruption messages,
  and `blk_update_request: I/O error` in the last hour. Report count + last message.

**JSON schema (new `dsd disk` output):**

```json
{
  "dsd_disk": {
    "filesystems": [
      {
        "mount": "/var",
        "device": "/dev/sda2",
        "type": "ext4",
        "total_gb": 20.0,
        "used_gb": 18.0,
        "used_pct": 90,
        "inodes_used_pct": 98,
        "status": "warn"
      }
    ],
    "physical_disks": [
      {
        "name": "nvme0n1",
        "type": "nvme",
        "size_gb": 931,
        "smart_healthy": true,
        "wear_pct": 2,
        "media_errors": 0
      }
    ],
    "io_pressure": [
      {
        "device": "nvme0n1",
        "read_kbps": 12400,
        "write_kbps": 3200,
        "await_ms": 0.4,
        "util_pct": 12
      }
    ],
    "top_io_processes": [
      {"pid": 1234, "name": "postgres", "read_bytes": 45000000, "write_bytes": 12000000}
    ],
    "filesystem_errors_last_hour": 0
  }
}
```

**Collector design:**
- New file: `internal/collectors/disk_collector_standalone.go`
- Reuses DiskCollector logic from dsd health (avoid duplication — extract shared lib)
- I/O rate sampling: two reads of `/proc/diskstats` with 1s sleep between them
- Process I/O: iterate `/proc/*/io` — skip unreadable (permission), no root needed
  for basic stats on most processes
- SMART: shells out to `smartctl -A -j /dev/nvme0` — check binary availability first,
  gracefully degrade if not present

**Cross-distro notes:**
- ZFS: detect `type=zfs` in /proc/mounts. Do not report zfs dataset capacity via statvfs
  (gives incorrect results for thin pools). Instead, shell out to `zfs list -H -o name,used,avail`
  if zfs binary is available. This is the same Proxmox issue noted in BACKLOG.md.
- btrfs: stat-based capacity reporting is correct. No special handling needed.
- LVM: device names like `/dev/mapper/pve-root` — parse correctly in device type detection,
  report parent physical disk where possible via `/sys/block/dm-N/slaves/`

**Acceptance criteria:**
- [ ] `dsd disk` runs in < 3s and shows all mounted filesystems with status
- [ ] Inode usage reported per filesystem
- [ ] WARN/CRIT thresholds trigger correctly (match existing DiskCollector logic)
- [ ] `dsd disk deep` I/O sampling gives correct read/write rates
- [ ] Top I/O processes list populates without root privileges (graceful on permission gaps)
- [ ] SMART output present on NVMe, gracefully absent if smartctl not installed
- [ ] ZFS filesystems handled without incorrect capacity numbers
- [ ] `--json` output valid against schema
- [ ] Runs on RHEL 10, Debian 12, macOS (macOS: df + diskutil, no /proc)


---

## Spec 5 — `dsd health deep` Cgroup Tree + Process Hierarchy

**Sprint:** 3
**Type:** Enhancement to existing `dsd health deep` (which is already in backlog)
**Pain source:** htop and top show processes with no parent-child or cgroup context.
Container processes look identical to host processes. %iowait in top doesn't name
the culprit device. cAdvisor is required as a separate tool for container resource stats.

### What to add to `dsd health deep`

Insert a `[Process hierarchy]` section and extend the CPU section.

**1. cgroup-aware top-process list:**
For each of the top 10 CPU-consuming processes (already collected), add:
- The cgroup v2 path from `/proc/<PID>/cgroup` — parse the last path segment
- Map to human-readable scope: `system` / `user` / `docker:<name>` / `k8s:<pod>` /
  `container:<name>` / `unknown`
- This makes container-driven CPU obvious without extra tools

Example output addition:
```
[Top processes — cgroup context]
  PID    CPU%  MEM%  NAME              CGROUP SCOPE
  8823   42.1   8.2  java              docker:api-server
  1204   18.4   2.1  postgres          system:postgresql.service
  9901   12.3   1.4  python3           user:1000.slice
  12     11.8   0.1  kworker/0:1H      kernel
```

**2. Per-cgroup resource summary:**
Read `/sys/fs/cgroup/` to produce a per-group summary:
- For each Docker container cgroup: CPU usage % + memory used vs limit
- For each systemd service slice with significant usage (>5% CPU or >500MB RAM):
  report the slice name, CPU%, memory used
- Detect cgroup CPU throttling: read `cpu.stat` → `throttled_time` field.
  If throttled_time > 0 in the last sample, report: "X is being CPU throttled
  (container/service has a CPU limit that is being hit)"

**3. iowait culprit attribution:**
When CPU iowait > 5%:
- Sample `/proc/diskstats` to identify which device has the highest await
- Cross-reference with the top I/O process list (from /proc/*/io)
- Add to existing iowait line: "iowait 12% ← nvme0n1 (12ms await) ← postgres (PID 1204)"

**Collector design:**
- `internal/collectors/cgroup_linux.go` — new file
- Parse `/sys/fs/cgroup/` tree: iterate direct children of `/sys/fs/cgroup/system.slice/`,
  `/sys/fs/cgroup/docker/`, `/sys/fs/cgroup/kubepods/`
- Read `cpu.stat`, `memory.current`, `memory.max` per cgroup
- For Docker container cgroup names: read `/sys/fs/cgroup/docker/<ID>/` — map ID to
  container name via `/proc/<PID>/cgroup` and cross-reference with docker.sock if
  accessible (do not require docker.sock — fall back to raw cgroup name)
- Build tag: `//go:build linux` — cgroup paths don't exist on macOS

**cgroup v1 vs v2:**
- cgroup v2 (unified hierarchy): Debian 11+, Ubuntu 21.10+, RHEL 9+, Fedora 31+
  Path: `/sys/fs/cgroup/` (single hierarchy)
- cgroup v1 (legacy): Ubuntu 20.04 and earlier, RHEL 8 and earlier
  Path: `/sys/fs/cgroup/memory/`, `/sys/fs/cgroup/cpu/` etc. (split hierarchies)
- Detect via: check if `/sys/fs/cgroup/cgroup.controllers` exists → v2, else v1
- Implement v2 first (Sprint 3). Add v1 support in Sprint 4 if needed.

**Acceptance criteria:**
- [ ] Top process list shows cgroup scope labels (docker/system/user/kernel)
- [ ] Per-cgroup CPU and memory summary visible in `dsd health deep` output
- [ ] CPU throttling detection fires when a container has CPU limit being hit
- [ ] iowait culprit line names device AND top I/O process when iowait > 5%
- [ ] Works on cgroup v2 systems (Debian 12, RHEL 9, Ubuntu 22.04)
- [ ] Gracefully degrades on macOS (section not shown — not applicable)
- [ ] `--json` includes cgroup context on each process entry

---

## Spec 6 — `dsd security` Permission Root-Cause Disambiguation

**Sprint:** 3
**Type:** Enhancement to existing `dsd security` command
**Pain source:** "Permission denied" errors can be caused by file permissions,
SELinux AVC denials, AppArmor profile violations, or PAM restrictions — and they
look identical to the user. The research shows this is a major time sink.

### What `dsd security` does today
- SSH config hardening
- Failed login attempts
- Listening ports vs expected
- sudo NOPASSWD detection
- SELinux/AppArmor denials (basic)

### What to add

**New `[Permission diagnosis]` section in `dsd security`:**

Triggered by any of: recent AVC denials, AppArmor DENIED entries, or
PAM auth failures in the last 24 hours.

**1. AVC denial summary (SELinux):**
If SELinux is in enforcing or permissive mode:
- Count AVC denials in last 24h from `ausearch -m avc -ts today` or `journalctl -t audit`
- Group by: source_context → target_path → action (read/write/execute/connect)
- For each group, show: process name, what it was denied, suggested fix hint
  (`audit2allow -a -M mypolicy` or `semanage fcontext` with specific context)
- Distinguish enforcing (actual block) vs permissive (logged but allowed)

**2. AppArmor denial summary:**
If AppArmor is active (`aa-status` or `/sys/kernel/security/apparmor/profiles` exists):
- Parse `journalctl -t kernel -g 'apparmor="DENIED"'` for last 24h
- Group by: profile → operation → path
- For each group: show profile name, what it blocked, hint
  (`aa-logprof` to auto-suggest profile update)

**3. PAM failure context:**
If `/var/log/auth.log` or `/var/log/secure` has PAM errors (not just auth failures,
but PAM module failures like "pam_unix: authentication failure" with a non-login cause):
- Report PAM module failures separately from brute-force SSH failures
- Flag if `pam_faillock` or `pam_tally2` has locked out any accounts

**4. Disambiguation output:**
When a user asks "why is X failing with Permission denied", the output should guide:

```
[Permission diagnosis — last 24h]
  ⚠️  SELinux AVC denials: 3 unique rules
     nginx (httpd_t) DENIED read on /data/app/config.ini
     → File context is: unconfined_u:object_r:default_t (wrong)
     → Fix: semanage fcontext -a -t httpd_config_t '/data/app(/.*)?'
            restorecon -Rv /data/app/

  ✅  AppArmor: no denials in last 24h

  ✅  PAM: no module failures (2 failed SSH logins from 203.0.113.0 — brute force)
```

**Acceptance criteria:**
- [ ] AVC denial grouping works on RHEL 9/10 with SELinux enforcing
- [ ] AppArmor denial parsing works on Debian 12/Ubuntu 22.04
- [ ] Fix hints are correct and executable (tested against a deliberate denial)
- [ ] PAM module failures distinguished from normal auth failures
- [ ] On systems with no SELinux AND no AppArmor: section shows INFO "MAC: not active"
- [ ] No false positives — historical old denials should not fire as WARN

### Spec 6 Addendum — SELinux Primer Refinements
**Source: Red Hat SELinux Primer (Frank Caviggia, 2015)**
**4 additions to the spec above, all arising from the primer's troubleshooting section.**

**Addition 1 — Boolean-first diagnosis order (highest priority):**
The primer states explicitly: "Check Booleans First in Troubleshooting!"
Most service denials (httpd can't read home dirs, ftp can't write, etc.) are solvable
by toggling a pre-existing boolean — not by creating custom policy.

Updated check order for the SELinux section:
```
1. getsebool -a | grep <process_name>  ← FIRST: show relevant booleans
2. AVC denial grouping                 ← SECOND: if booleans don't explain it
3. semanage fcontext + restorecon hint ← THIRD: if context is wrong
4. audit2allow hint                    ← LAST RESORT: custom policy needed
```

For each failed service or AVC source (e.g., `httpd`):
- Run `getsebool -a | grep httpd` and show any currently-OFF booleans with names
  that match the denied operation (e.g., `httpd_can_network_connect`, `httpd_read_user_content`)
- Format: `[SELinux boolean] httpd_can_network_connect = off — may explain denial`
  with exact fix: `setsebool -P httpd_can_network_connect on`

**Addition 2 — Port context check (new sub-check):**
The primer shows services failing on non-standard ports because the port isn't labeled
for that service type. This is one of the most common unlabeled SELinux causes.

Add to the permission diagnosis section:
- For each failed systemd service: extract its configured port, run
  `semanage port -l | grep <port>` to check if labeled for that service
  If port is NOT labeled: show exact fix: `semanage port -a -t <service_port_t> -p tcp <port>`
- Also scan listening services from `ss -tlnp` against `semanage port -l`:
  any listening port with no SELinux label → flag WARN

**Addition 3 — chcon vs semanage fcontext distinction:**
The primer distinguishes temporary `chcon` (lost on `restorecon`) vs permanent
`semanage fcontext + restorecon`. DashDiag should detect which was used.

Detection: compare `matchpathcon <path>` (policy default) vs `ls -Z <path>` (actual).
If they differ: check if a `semanage fcontext` rule exists for that path.
If no semanage rule: flag "Context is temporary (chcon) — will be lost on relabel."
Fix hint: `semanage fcontext -a -t <type> '<path>(/.*)?'` then `restorecon -Rv`

**Addition 4 — Autorelabel detection:**
If `/.autorelabel` exists: flag WARN. System will do a full filesystem relabel on
next reboot (10-30 minutes on large systems). Triggered by re-enabling SELinux after
it was disabled, or by major policy changes.
- Check: `os.Stat("/.autorelabel")` — report:
  "⚠️  SELinux filesystem relabel pending on next reboot (10-30 min estimated)"

**Updated output example with all 4 additions:**

```
[Permission diagnosis — last 24h]

  [SELinux booleans — check first]
    httpd_can_network_connect = off  ← likely explains denial
    → setsebool -P httpd_can_network_connect on

  [AVC denials]
    nginx (httpd_t) DENIED read on /data/app/config.ini
    ⚠️  Context is temporary (chcon applied, no semanage rule)
    → semanage fcontext -a -t httpd_config_t '/data/app(/.*)?'
       restorecon -Rv /data/app/

  [Port labels]
  ⚠️  nginx listening on :8080 — no SELinux port label
    → semanage port -a -t http_port_t -p tcp 8080

  ✅  AppArmor: no denials in last 24h
  ✅  PAM: no module failures

  ⚠️  /.autorelabel present — full relabel queued for next reboot (~15 min)
```

**Addendum acceptance criteria:**
- [ ] Boolean check runs before AVC denial grouping in output
- [ ] Relevant booleans shown per denied service (httpd, sshd, vsftpd etc.)
- [ ] Port label check fires for services on unlabeled ports
- [ ] chcon vs semanage fcontext detected via matchpathcon comparison
- [ ] `/.autorelabel` triggers WARN with timing advisory
- [ ] All 4 additions tested on RHEL 9/10 with deliberate denials

---

## Spec 7 — `dsd docker` (Full Spec)

**Sprint:** 3
**Type:** New top-level command (already in BACKLOG.md — this adds full spec)
**Pain source:** Container resource pressure is not attributed to host. Volume mounts
and bridge networking are opaque. Container log errors don't surface in any health check.
dsd k8s exists; Docker deserves parity for the enormous Docker-without-k8s audience.

This spec extends and formalizes the notes already in BACKLOG.md.

### `dsd docker` (fast)
**Target runtime:** < 5 seconds

**Prerequisite check:** Detect Docker/Podman socket availability:
- Try `/var/run/docker.sock`, `/run/docker.sock`, `/run/podman/podman.sock`
- If none found: show INFO "Docker socket not found — is Docker running?"
  and suggest `systemctl status docker` then exit clean (no error)

**Checks:**

1. **Container status:** List all containers. Group by status:
   - Running: show name, image, uptime, restart count
   - Unhealthy: show name + health check last output (from `inspect`)
   - Restarting: show name + restart count + last exit code
   - Stopped: show name + stopped_since + last exit code
   - Flag CRIT if any container has restart_count > 5 in last hour
   - Flag WARN if any container has restart_count > 0 in last hour

2. **Resource pressure:** for running containers:
   - Read CPU% and memory usage via Docker stats API (one sample, non-streaming)
   - Flag WARN if any container uses > 80% of its memory limit
   - Flag WARN if any container uses > 80% of its CPU limit (if limit set)
   - Flag INFO if container has no memory limit set (unlimited = risk)

3. **Volume health:** run `docker system df -v`:
   - Total volumes size
   - Volumes not in use by any container (dangling) — flag if > 1GB total
   - Named volumes approaching their backing filesystem's capacity

4. **Network bridge check:**
   - List docker networks. For each bridge network in use:
   - Check if the docker0 bridge IP conflicts with any host route
   - Flag WARN if docker0 (172.17.0.0/16) overlaps with a VPN or corporate subnet
     (a common VPN break scenario)

5. **Disk usage summary:** `docker system df` — images, containers, volumes, build cache.
   Flag WARN if total > 80% of host disk used_pct or total docker disk > 50GB.

**Output example:**

```
🐳 Docker

[Container status]
  ❌ api-server      Restarting   exit 137 (OOM)   restarts: 8    ← CRIT
  ⚠️  worker         Unhealthy    last check: "timeout waiting for DB"
  ✅  nginx          Running      14d uptime       restarts: 0
  ✅  postgres       Running      14d uptime       restarts: 0
  ⬛  old-migrator   Stopped      3 days ago       exit 0

[Resource pressure]
  ❌ api-server  CPU: 12%   MEM: 490/512MB (95%) — near OOM limit  ← CRIT
  ✅  worker     CPU: 2%    MEM: 180/512MB (35%)
  ✅  nginx      CPU: 0%    MEM: 42/128MB  (33%)

[Volumes]
  ⚠️  Dangling volumes: 3 (4.2GB unused) — run: docker volume prune
  ✅  pgdata volume: 12GB used, 88GB free on /var

[Networks]
  ⚠️  docker0 bridge (172.17.0.0/16) overlaps with VPN subnet (172.17.0.0/16)
     This will break container networking when VPN is active.

[Disk usage]
  Images: 8.2GB  Containers: 240MB  Volumes: 16GB  Build cache: 2.1GB
  Total: 26.6GB

Checks: 12 | Passed: 7 | Warnings: 2 | Critical: 2
Next:
  → docker logs api-server --tail 50
  → docker inspect api-server | jq .[0].HostConfig.Memory
  → docker volume prune
  → dsd docker deep
```

### `dsd docker deep`
Everything in fast, plus:

1. **Container log error triage:** for each running container that is not healthy,
   pull last 50 log lines and scan for: ERROR, FATAL, CRIT, panic, exception, OOM.
   Show the most recent matching line per container with timestamp.

2. **Image age audit:** list all images with last pull date. Flag images older than
   30 days as INFO (may have unpatched CVEs). Do not attempt CVE lookup — just date.

3. **Stopped container audit:** list containers stopped > 7 days. These are typically
   safe to remove. Show total space that would be freed.

4. **Container-to-service correlation:** for each running container, attempt to find
   its backing systemd service (docker-compose projects show as a systemd service if
   using Compose v2 with `--start` integration). Report if the systemd service is
   in failed/activating state while the container appears running.

**Collector design:**
- `internal/collectors/docker_collector.go`
- Communicate via Docker socket using Go HTTP client (no docker CLI dependency)
- API endpoints used:
  - `GET /containers/json?all=1` — container list
  - `GET /containers/{id}/stats?stream=false` — resource stats (one sample)
  - `GET /containers/{id}/inspect` — health check, memory limit, restart count
  - `GET /volumes` — volume list
  - `GET /networks` — network list
  - `GET /system/df` — disk usage
  - `GET /containers/{id}/logs?tail=50` — for deep variant only
- Detect Podman compatibility: Podman implements the same Docker API on the socket
- No `docker` binary dependency — socket only
- If socket not found: graceful INFO, not error

**Cross-distro / cross-runtime notes:**
- RHEL uses Podman by default (socket: `/run/podman/podman.sock`)
- Ubuntu/Debian uses Docker (socket: `/var/run/docker.sock`)
- Detect which socket is active; try both; report which runtime was found
- cgroup v1 (Ubuntu 20.04): memory stats structure differs slightly in /stats response
- k3s (containerd, not Docker): `dsd docker` should not try containerd via docker API.
  If neither Docker nor Podman socket found, suggest `dsd k8s` if k8s is detected.

**Acceptance criteria:**
- [ ] `dsd docker` fast runs in < 5s on a host with 10 containers
- [ ] CrashLoopBackOff equivalent (restart count > 5) triggers CRIT
- [ ] Memory limit near-breach triggers WARN
- [ ] Bridge subnet overlap with VPN detected and flagged
- [ ] Graceful INFO (not error) when Docker is not installed
- [ ] Podman socket detected on RHEL 9/10
- [ ] `--json` output valid against schema
- [ ] Tested on: RHEL 10 with Docker 29.4.3 (BACKLOG already validated basics here)
- [ ] Tested on: Debian 12 with Docker

**Effort note:** Core spec ~4d. Addendum items 7a–7o add ~2.2d. Total Spec 7: ~6.2d.

---

## Spec 7a — `dsd docker` Exit Code Interpretation

**Sprint:** 3 (addendum to Spec 7 fast — formatter only)
**Effort:** +0.10d
**Source:** Multiple Docker troubleshooting guides (Medium, site24x7, dev.to 100-errors)
**Pain source:** Exit codes appear in container status but require manual lookup. Exit 137
(OOM kill) is the most common production container failure mode and is invisible without
knowing the code table.

### What to add

In the `[Container status]` section, annotate exit codes parenthetically in both
human-readable and `--json` output. Use a fixed lookup map.

**Exit code map:**
```go
var exitCodeLabels = map[int]string{
    0:   "clean exit",
    1:   "application error",
    125: "Docker daemon error",
    126: "command not executable",
    127: "command not found in image",
    130: "Ctrl+C (SIGINT)",
    137: "OOM kill (SIGKILL)",
    139: "segfault (SIGSEGV)",
    143: "graceful shutdown (SIGTERM)",
}
```

Codes not in the map: show raw number only.

**Output change (before/after):**
```
# Before:
  ❌ api-server  Restarting  exit 137  restarts: 8

# After:
  ❌ api-server  Restarting  exit 137 (OOM kill — out of memory)  restarts: 8
```

**JSON addition:**
```json
"exit_code": 137,
"exit_code_label": "OOM kill (SIGKILL)"
```

**Acceptance criteria:**
- [ ] Exit code 137 shows `(OOM kill)` label in output
- [ ] Exit code 0 shows `(clean exit)` on stopped containers
- [ ] Exit code 127 shows `(command not found in image)`
- [ ] Unknown codes show raw number only, no label
- [ ] `--json` includes both `exit_code` (int) and `exit_code_label` (string)
- [ ] No new API calls required — exit code already fetched in container inspect

---

## Spec 7b — `dsd docker deep` Log Driver Config + json-file Size Check

**Sprint:** 3 (addendum to Spec 7 deep)
**Effort:** +0.50d
**Source:** Sentry Docker troubleshooting guide
**Pain source:** Docker's default `json-file` log driver writes unbounded logs to
`/var/lib/docker/containers/<id>/<id>-json.log`. Without `max-size`/`max-file`
configured, these silently grow until disk is full. Common production disk explosion
that's completely invisible until it hits.

### What to add to `dsd docker deep`

Add a new `[Log driver]` section.

**Checks:**

1. **Daemon log driver config:** read `/etc/docker/daemon.json`.
   - If `log-driver` is `json-file` (or absent, which defaults to json-file):
     - Check for `log-opts.max-size` key. If absent: flag WARN.
     - Check for `log-opts.max-file` key. If absent: flag WARN.
   - If `log-driver` is `journald` or `local`: flag INFO (managed, bounded).
   - If `/etc/docker/daemon.json` does not exist: daemon uses all defaults → WARN.

2. **Per-container log file size:** scan
   `/var/lib/docker/containers/*/` for files matching `*-json.log`.
   Report any single file exceeding 500MB as WARN, exceeding 1GB as CRIT.
   Map container ID to container name using already-fetched container list.

**Output:**
```
[Log driver]
  ⚠️  Log driver: json-file — no max-size configured (logs grow unbounded)
     → Add to /etc/docker/daemon.json:
       {"log-driver":"json-file","log-opts":{"max-size":"100m","max-file":"3"}}
     → systemctl restart docker
  ❌ api-server log file: 2.3GB  ← CRIT
  ⚠️  worker     log file: 680MB  ← WARN
  ✅  nginx      log file: 12MB
  ✅  postgres   log file: 8MB
```

**JSON schema addition:**
```json
"log_driver": {
  "driver": "json-file",
  "max_size_configured": false,
  "max_file_configured": false,
  "status": "warn",
  "container_log_files": [
    {"name": "api-server", "size_mb": 2300, "status": "crit"},
    {"name": "worker",     "size_mb": 680,  "status": "warn"}
  ]
}
```

**Notes:**
- `/var/lib/docker/containers/` requires root or docker group access on most systems.
  Attempt read; if permission denied, skip per-container check and note it.
- Podman: log files at `~/.local/share/containers/storage/` for rootless,
  `/var/lib/containers/storage/` for rootful. Same size check logic applies.

**Acceptance criteria:**
- [ ] Missing `max-size` in daemon.json triggers WARN
- [ ] Container log file > 500MB triggers WARN
- [ ] Container log file > 1GB triggers CRIT
- [ ] journald/local driver shows INFO (not WARN)
- [ ] Permission denied on log directory: graceful skip with NOTE
- [ ] `--json` includes log_driver section
- [ ] Not shown in `dsd docker` fast — deep only

---

## Spec 7c — `dsd docker` Daemon Health Check

**Sprint:** 3 (addendum to Spec 7 fast)
**Effort:** +0.25d
**Source:** Docker official docs, TechTarget, Medium Chapter 12
**Pain source:** Spec 7 fast detects socket existence but not daemon health. Docker
can be socket-accessible but in a degraded state (storage driver errors, containerd
connectivity issues). Also, very outdated Docker versions have known CVEs and API
incompatibilities.

### What to add to `dsd docker` fast

Insert a `[Docker daemon]` section as the first section (before container status).

**Checks:**

1. **Daemon API ping:** call `GET /info` via socket. Parse response.
   - If call succeeds: daemon is healthy. Extract `ServerVersion`, `StorageDriver`,
     `Swarm.LocalNodeState` from the response for use by other checks.
   - If call fails after socket exists: flag CRIT
     "Docker socket exists but daemon not responding to API calls".

2. **Docker version check:** compare `ServerVersion` from `GET /version` against
   minimum acceptable version `24.0.0`. Flag WARN if older.
   Source `ApiVersion` and include in JSON for API consumers.

3. **Storage driver check:** from `GET /info`, `StorageDriver` field.
   If `devicemapper` (deprecated, known-buggy): flag WARN with migration hint.
   If `overlay2`: OK (current default).

4. **Daemon journal errors (last 10 minutes):** shell out to
   `journalctl -u docker -n 20 --no-pager --since '10 minutes ago' 2>/dev/null`.
   Scan for `level=error` or `level=warning` entries. Report count + last message.
   Skip gracefully if journalctl not available.

**Output:**
```
[Docker daemon]
  ✅  Daemon: responding
  ✅  Version: 29.4.3 (API 1.48)
  ✅  Storage driver: overlay2
  ⚠️  Recent daemon warnings: 2 (last: "containerd: failed to start shim for task")
     → journalctl -u docker -n 50 --no-pager
```

**JSON schema addition (top-level):**
```json
"daemon": {
  "responding": true,
  "version": "29.4.3",
  "api_version": "1.48",
  "storage_driver": "overlay2",
  "swarm_state": "inactive",
  "recent_error_count": 2,
  "last_daemon_error": "containerd: failed to start shim for task"
}
```

**Acceptance criteria:**
- [ ] `GET /info` success shows daemon version and storage driver
- [ ] Socket present but API unresponsive shows CRIT (not INFO)
- [ ] Docker < 24.0.0 triggers WARN
- [ ] `devicemapper` storage driver triggers WARN
- [ ] Daemon journal errors surfaced when journalctl available
- [ ] Graceful skip on journal unavailability (non-systemd hosts)
- [ ] Swarm state passed to 7j for reuse

---

## Spec 7d — `dsd docker` Compose Version Detection

**Sprint:** 3 (addendum to Spec 7 fast)
**Effort:** +0.10d
**Source:** Sentry Docker troubleshooting guide
**Pain source:** Transition from `docker-compose` (standalone Python v1, deprecated)
to `docker compose` (Go plugin v2) is a common confusion point. On RHEL/Amazon Linux,
the plugin is often missing. Scripts break silently with cryptic errors.

### What to add

Add to the `[Docker daemon]` section (Spec 7c) as a sub-check.

**Checks:**
- Is `docker compose version` (plugin) available? Shell out; parse version.
- Is `docker-compose version` (standalone) available? Shell out; parse version.
- Map to status:

| Situation | Status | Message |
|---|---|---|
| Plugin only | ✅ INFO | `docker compose` v2.x (plugin) |
| Both present | ⚠️ WARN | Both v1 and v2 present — scripts may use wrong one |
| Standalone only | ⚠️ WARN | `docker-compose` v1 (deprecated) — migrate to plugin |
| Neither | ℹ️ INFO | Compose not installed |

**Output addition (inline in daemon section):**
```
[Docker daemon]
  ...
  ✅  Compose: v2.29.1 (plugin)
  # OR:
  ⚠️  Compose: v1.29.2 (standalone — deprecated)
     → Install docker-compose-plugin and remove docker-compose
```

**JSON addition:**
```json
"compose": {
  "plugin_version": "2.29.1",
  "standalone_version": null,
  "status": "ok"
}
```

**Acceptance criteria:**
- [ ] Plugin detected via `docker compose version` exit 0
- [ ] Standalone detected via `docker-compose version` exit 0
- [ ] Both present triggers WARN
- [ ] Neither shows INFO (not WARN — not every system uses Compose)
- [ ] No crash if neither binary exists

---

## Spec 7e — `dsd docker` Recent Events History

**Sprint:** 3 (addendum to Spec 7 fast)
**Effort:** +0.25d
**Source:** TechTarget Docker guide, Medium Chapter 12
**Pain source:** Container status shows current state. A container that OOM-died and
restarted shows `Running` — the OOM event is invisible in the status view.
`docker events` is the only source for what happened in the last hour without reading
per-container logs.

### What to add

Add a `[Recent events]` sub-section inside `[Container status]`.

**API call:**
```
GET /events?filters={"type":["container"]}&since=<unix-1h>&until=<unix-now>
```

**Events to surface:**

| Event type | Action filter | Status | Message |
|---|---|---|---|
| container | oom | ❌ CRIT | `<name>` OOM killed at `<time>` |
| container | die (exitCode != 0) | ⚠️ WARN | `<name>` died (exit `<code>`) at `<time>` |
| container | health_status: unhealthy | ⚠️ WARN | `<name>` health check failed at `<time>` |
| container | die + start pattern | ❌ CRIT | `<name>` restart loop: 3 crashes in last 1h |

OOM events are CRIT even if the container has since restarted — they indicate the
container needs more memory or has a memory leak.

**Output:**
```
[Recent events — last 1h]
  ❌ api-server  OOM killed  14:22:01  (3 occurrences)
  ⚠️  worker      died exit 1  14:35:44 → restarted
  ✅  No other container events
```

If no notable events: single line `✅ No container events in last 1h` (no section header).

**JSON addition:**
```json
"recent_events": [
  {
    "container": "api-server",
    "event": "oom",
    "severity": "crit",
    "count": 3,
    "last_time": "2026-05-18T14:22:01Z"
  }
]
```

**Acceptance criteria:**
- [ ] OOM events surfaced as CRIT even for currently-running containers
- [ ] Non-zero exit events surfaced as WARN
- [ ] Repeated die+start pattern within 1h flagged as restart loop
- [ ] No events in 1h: section suppressed (no output noise)
- [ ] Events older than 1h not shown
- [ ] `--json` includes `recent_events` array

---

## Spec 7f — `dsd docker` IP Forwarding Sysctl Check

**Sprint:** 3 (addendum to Spec 7 fast — Networks section)
**Effort:** +0.10d
**Source:** Docker official daemon troubleshooting docs
**Pain source:** systemd 220+ disables IP forwarding per-interface by default
(`net.ipv4.conf.<interface>.forwarding=0`). Docker containers run fine but have
no outbound connectivity. Symptoms are identical to a network misconfiguration inside
Docker but the actual cause is a host-level sysctl. Most common on RHEL/Fedora with
systemd-networkd.

### What to add to `[Networks]` section

**Checks:**

1. Read `/proc/sys/net/ipv4/ip_forward`. If `0`: flag CRIT.
   Docker sets this to `1` on start, but it can be reset by `systemctl restart
   systemd-networkd` or a sysctl hardening script.

2. For each interface in `/proc/sys/net/ipv4/conf/*/forwarding`, check if the
   primary outbound interface (the one with the default route) has forwarding enabled.
   If `0` while Docker is running: flag WARN.

**Output:**
```
[Networks]
  ❌ IP forwarding disabled (net.ipv4.ip_forward = 0)
     Container networking is broken — all outbound traffic will fail.
     → sysctl -w net.ipv4.ip_forward=1
     → Persist: echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-docker.conf && sysctl -p
```

**JSON addition:**
```json
"network_prereqs": {
  "ip_forward_enabled": false,
  "status": "crit"
}
```

**Cross-distro note:** Only relevant on Linux. Skip entirely on macOS.

**Acceptance criteria:**
- [ ] `ip_forward = 0` triggers CRIT
- [ ] `ip_forward = 1` shows clean pass or no output
- [ ] Skip on macOS (build tag `//go:build linux`)
- [ ] Read is a single `/proc` file read — no shelling out

---

## Spec 7g — `dsd docker` Container DNS Trap

**Sprint:** 3 (addendum to Spec 7 fast — Networks section)
**Effort:** +0.15d
**Source:** Docker official daemon troubleshooting docs (explicitly named section)
**Pain source:** When `/etc/resolv.conf` on the host contains `nameserver 127.0.0.53`
(systemd-resolved stub) or `nameserver 127.0.0.1` (dnsmasq), containers inherit this
and attempt to query the nameserver. But `127.0.0.x` inside a container refers to the
container's own loopback, not the host's resolver. DNS works on the host, silently fails
inside every container. Docker falls back to `8.8.8.8`, which is often blocked by
corporate firewalls.

### What to add to `[Networks]` section

**Checks:**

1. Read `/etc/resolv.conf`. Parse `nameserver` lines.
   If any nameserver is `127.0.0.x` or `::1`: flag WARN.

2. If WARN triggered: call `GET /info` (already fetched in Spec 7c) and read the
   `DNS` array. Report what Docker is actually using as container DNS fallback.
   - If `DNS` array is empty in `/info`: Docker uses `8.8.8.8` by default.
   - Suggest explicit DNS config in `/etc/docker/daemon.json` as the fix.

3. Enhancement: check `/etc/docker/daemon.json` for an explicit `"dns"` key.
   If present: report it as the configured fallback (overrides the 8.8.8.8 default).

**Output:**
```
[Networks]
  ⚠️  Host resolv.conf uses 127.0.0.53 (systemd-resolved stub)
     Containers cannot reach this address — Docker falls back to 8.8.8.8
     If 8.8.8.8 is blocked by firewall, container DNS will fail silently.
     Daemon DNS override: not configured (using default 8.8.8.8)
     → Fix: add to /etc/docker/daemon.json:
       {"dns": ["1.1.1.1", "8.8.8.8"]}
```

**JSON addition:**
```json
"dns": {
  "host_resolv_uses_localhost": true,
  "daemon_dns_configured": false,
  "daemon_dns_servers": [],
  "effective_container_dns": ["8.8.8.8"],
  "status": "warn"
}
```

**Acceptance criteria:**
- [ ] `127.0.0.53` in resolv.conf triggers WARN
- [ ] `127.0.0.1` in resolv.conf triggers WARN
- [ ] Daemon DNS fallback shown in output (from `GET /info`)
- [ ] Explicit daemon.json DNS shown if configured
- [ ] Multiple nameservers: only flag if ALL are localhost addresses
  (partial localhost is still a mixed bag but less broken)

---

## Spec 7h — `dsd docker` Socket Permission Diagnosis

**Sprint:** 3 (addendum to Spec 7 fast — socket detection step)
**Effort:** +0.05d
**Source:** NVIDIA CUDA Docker guide, wiki.planetoid.info, dev.to 100-errors
**Pain source:** Socket exists but connection fails with `permission denied`. Without
diagnosis, this looks identical to a crashed daemon. The fix (`usermod -aG docker $USER`)
is simple but the cause is invisible. wiki.planetoid.info note: on some Debian environments
`newgrp docker` returns "Invalid password" — full SSH reconnect is required.

### What to add

Extend the existing socket detection step in Spec 7 fast.

**Current flow:**
```
1. Socket found → attempt connection → succeed or fail generically
```

**New flow:**
```
1. Socket found
2. Connection attempt fails with permission denied?
   a. Read socket GID via stat()
   b. Check if current user's groups include that GID
   c. If not: emit specific diagnosis
3. Connection attempt fails for other reason → existing CRIT handling
```

**Output when triggered:**
```
⚠️  Docker socket found at /var/run/docker.sock but permission denied
    Current user is not in the docker group (socket GID: 999 [docker])
    → sudo usermod -aG docker $USER
    → Then fully log out and reconnect (newgrp may not work on all systems)
```

**Acceptance criteria:**
- [ ] Socket exists + permission denied + user not in group → WARN with fix hint
- [ ] Socket exists + permission denied + user IS in group → different CRIT message
  ("group membership present but not active — log out and reconnect")
- [ ] Socket exists + connection succeeds → no change to existing flow
- [ ] Socket not found → existing INFO path unchanged

---

## Spec 7i — `dsd docker` Image Architecture Mismatch

**Sprint:** 3 (addendum to Spec 7 fast — container status section)
**Effort:** +0.15d
**Source:** dev.to 100 common Docker errors (Issue 11: exec format error)
**Pain source:** Running an `amd64` image on `arm64` host (or vice versa) causes
immediate container failure with `OCI runtime create failed: exec format error`.
Becoming more common as ARM servers (AWS Graviton, Ampere) proliferate and
developers on Apple Silicon build the wrong architecture. The error message is
completely opaque without checking architecture.

### What to add

For each container (running or recently stopped), compare the image architecture
against the host architecture. Both values come from already-fetched API responses.

**API calls (all already fetched in Spec 7 fast):**
- Host arch: `GET /info` → `Architecture` field (e.g., `x86_64`, `aarch64`)
- Image arch: `GET /images/{name}/json` → `Architecture` field (e.g., `amd64`, `arm64`)

**Architecture normalization map:**
```go
var archNorm = map[string]string{
    "x86_64": "amd64",
    "aarch64": "arm64",
    "armv7l": "arm/v7",
}
```

**When to flag:**
Only flag if container is stopped/restarting with an OCI error, OR proactively if
an architecture mismatch is detected on a running container (may not have started
due to other reasons).

**Output:**
```
[Container status]
  ⚠️  worker  Image architecture mismatch:
     Image: linux/amd64 | Host: linux/arm64
     Container will fail with "exec format error" on start.
     → Rebuild: docker buildx build --platform linux/arm64 -t worker .
     → Or pull a multi-arch image version
```

**JSON addition per container:**
```json
"image_arch": "amd64",
"host_arch": "arm64",
"arch_mismatch": true
```

**Acceptance criteria:**
- [ ] `amd64` image on `arm64` host detected and flagged WARN
- [ ] `arm64` image on `amd64` host detected and flagged WARN
- [ ] Matching architecture: no output
- [ ] Architecture normalization handles `x86_64` ↔ `amd64` mapping
- [ ] Only calls `GET /images/{name}/json` once per unique image (cache)

---

## Spec 7j — `dsd docker` Swarm Mode Detection INFO

**Sprint:** 3 (addendum to Spec 7c — one-field addition to daemon section)
**Effort:** +0.05d
**Source:** Habr article (Docker Swarm underweighting node diagnosis)
**Pain source:** If Docker Swarm is active, restart behaviour, resource limits,
and placement are controlled at the Swarm scheduler level, not the container level.
Spec 7's restart count and resource checks can mislead without surfacing this context.

### What to add

Reuse `Swarm.LocalNodeState` from `GET /info` response already fetched in Spec 7c.

**If `LocalNodeState` is `active`:**
```
[Docker daemon]
  ...
  ℹ️  Swarm mode: active (role: worker)
     Container restarts and placement may be controlled by the Swarm scheduler.
     → docker node ls          (check node health)
     → docker service ps <svc>  (check task-level failures)
```

**If `LocalNodeState` is `inactive` or absent:** no output.

**JSON addition:**
```json
"swarm": {
  "active": true,
  "role": "worker"
}
```

**Acceptance criteria:**
- [ ] Swarm active: INFO shown in daemon section
- [ ] Swarm inactive: no output (no noise on non-Swarm hosts)
- [ ] Role (`manager`/`worker`) shown when active
- [ ] No additional API calls — reuses `GET /info` response from 7c

---

## Spec 7k — `dsd docker` firewalld nftables Backend Check

**Sprint:** 3 (addendum to Spec 7 fast — Networks section)
**Effort:** +0.15d
**Source:** Russian Fedora 32 post-upgrade fix (Habr); confirmed by oneuptime.com network debugging
**Pain source:** On RHEL/Fedora/CentOS, when firewalld uses its `nftables` backend
(default from Fedora 32+ and RHEL 9+), Docker's iptables rules are silently dropped.
Container networking breaks completely even though `docker ps` shows containers running
and `net.ipv4.ip_forward` is enabled. The two checks (7f and 7k) are independent.

### What to add to `[Networks]` section

**Gate:** Only run these checks when `firewalld` is detected as active.
On Debian/Ubuntu (ufw or no firewall manager): skip silently.

**Checks:**

1. **firewalld active?** Check `systemctl is-active firewalld` (or `firewall-cmd --state`).
   If not active: skip this entire check.

2. **Backend check:** parse `/etc/firewalld/firewalld.conf` for `FirewallBackend=`.
   - If `nftables`: flag WARN with both fix options.
   - If `iptables`: OK.
   - If key absent (defaults to nftables on modern systems): treat as `nftables`.

3. **docker0 zone check:** run `firewall-cmd --get-active-zones` and check if
   `docker0` (or the Docker bridge interface) appears in any zone.
   If not in any zone: flag WARN (container traffic may be blocked).

**Output:**
```
[Networks]
  ⚠️  firewalld active with nftables backend
     Docker's iptables rules are being ignored.
     Container networking may be broken even if docker0 is up.
     Fix A — switch backend:
       sed -i 's/FirewallBackend=nftables/FirewallBackend=iptables/' \
         /etc/firewalld/firewalld.conf
       systemctl restart firewalld docker
     Fix B — trust docker0 interface:
       firewall-cmd --permanent --zone=trusted --add-interface=docker0
       firewall-cmd --reload
  ⚠️  docker0 not in any firewalld zone (container traffic may be dropped)
```

**JSON addition:**
```json
"firewalld": {
  "active": true,
  "backend": "nftables",
  "docker0_trusted": false,
  "status": "warn"
}
```

**Cross-distro:** Only RHEL family (RHEL, Fedora, CentOS Stream, Rocky, Alma,
SUSE with firewalld). Ubuntu/Debian: skip this check silently.

**Acceptance criteria:**
- [ ] firewalld inactive: entire check skipped, no output
- [ ] firewalld active + nftables + docker0 not trusted: WARN with both fix options
- [ ] firewalld active + iptables backend: OK
- [ ] firewalld active + nftables + docker0 in trusted zone: INFO only (not WARN)
- [ ] Check runs on RHEL 9/10, Fedora 32+; skips on Debian 12

---

## Spec 7l — `dsd docker` MTU Mismatch Detection

**Sprint:** 3 (addendum to Spec 7 fast — Networks section)
**Effort:** +0.10d
**Source:** oneuptime.com Docker network debugging (Jan 2026), 200-issue Docker guide (Issue 62)
**Pain source:** Container network MTU > effective host network MTU causes packets
to be silently dropped or fragmented. Zero errors in logs — just random timeouts and
failed large requests. Endemic on AWS/GCP/Azure with VPN overlays (tunnel reduces MTU),
and on any host where Docker's default 1500 MTU exceeds the underlay.

### What to add to `[Networks]` section

**Checks:**

1. Read host primary interface MTU from `/sys/class/net/<iface>/mtu`.
   Detect primary interface from the default route in `/proc/net/route`.

2. Check `/etc/docker/daemon.json` for `"mtu"` key (daemon-level default).
   If absent: Docker inherits host interface MTU.

3. For each custom Docker network, call `GET /networks` and check
   `Options["com.docker.network.driver.mtu"]`.
   If not set: network inherits daemon/host MTU.

4. **Flag condition:** if a VPN interface is active (from 7g VPN detection,
   or by checking for `tun0`, `wg0`, `tailscale0`, `nordlynx` interfaces)
   AND Docker MTU is not explicitly set to a lower value:
   flag WARN (VPN tunnel overhead reduces effective MTU below 1500).

   Also flag if host MTU != 1500 (sign of jumbo frames or non-standard setup)
   and Docker MTU is unset.

**Output:**
```
[Networks]
  ⚠️  VPN interface detected (wg0) + Docker MTU not configured
     Tunnel overhead may reduce effective MTU below Docker's default 1500.
     Intermittent large-packet failures (HTTP 502, DB timeouts) indicate this.
     → Set daemon default: {"mtu": 1450} in /etc/docker/daemon.json
     → Or per-network: docker network create --opt com.docker.network.driver.mtu=1450 ...
```

**JSON addition:**
```json
"mtu": {
  "host_interface_mtu": 1500,
  "daemon_mtu_configured": false,
  "vpn_active": true,
  "status": "warn"
}
```

**Acceptance criteria:**
- [ ] VPN interface active + MTU not configured: WARN
- [ ] Host MTU != 1500 + MTU not configured: WARN
- [ ] MTU explicitly configured in daemon.json or network: OK
- [ ] No VPN, standard host MTU: no output
- [ ] Host MTU read from sysfs without shelling out

---

## Spec 7m — `dsd docker` Container Running as Root

**Sprint:** 3 (addendum to Spec 7 fast — new `[Security]` sub-section)
**Effort:** +0.10d
**Source:** 200-issue Docker guide (Issue 151 — Running Containers as Root)
**Pain source:** Running containers as root is the single most common container
security misconfiguration. Every security scan flags it. The user override is
a single Dockerfile line but it's invisible from outside the container without
explicitly checking. Detectable via Docker API with zero exec required.

### What to add

Add a new `[Security]` sub-section to `dsd docker` fast.

**API check:** `GET /containers/{id}/json` → `Config.User`.
- Empty string `""`: container runs as root (image default, often root).
- `"0"` or `"root"` or `"root:root"`: explicitly root.
- `"1000"` or `"appuser"`: non-root — OK.

**Output:**
```
[Security]
  ⚠️  api-server   running as root (Config.User not set)
  ⚠️  worker       running as root (User: "0")
  ✅  nginx         running as: nginx (101)
  ✅  postgres      running as: postgres (999)
```

If ALL containers are non-root: show single `✅ All containers running as non-root`.
If ALL containers are root: show WARN count with single fix hint.

**JSON addition per container:**
```json
"user": "",
"runs_as_root": true
```

**Note:** A container with `User = ""` is not *guaranteed* to be running as root —
it depends on the image's `USER` instruction. However, the vast majority of images
without an explicit user run as root. Flag as WARN (not CRIT) — this is a security
best practice check, not a runtime failure.

**Acceptance criteria:**
- [ ] `Config.User = ""` triggers WARN
- [ ] `Config.User = "0"` or `"root"` triggers WARN
- [ ] `Config.User = "1000:1000"` or named user: OK
- [ ] All non-root: single OK line (not per-container noise)
- [ ] `--json` includes `runs_as_root` per container
- [ ] No new API calls — User already in inspect response

---

## Spec 7n — `dsd docker` Docker Socket Mounted in Container

**Sprint:** 3 (addendum to Spec 7 fast — `[Security]` sub-section)
**Effort:** +0.05d
**Source:** 200-issue Docker guide (Issue 152 — Exposed Docker Socket)
**Pain source:** Any container with `/var/run/docker.sock` mounted has root-equivalent
control over the entire host — it can start/stop/exec into any container, read any
volume, or escape to the host. Common in CI runners and monitoring agents but dangerous
in production services. Automatable via Docker API with zero exec.

### What to add

Add to the `[Security]` sub-section (Spec 7m).

**API check:** `GET /containers/{id}/json` → `HostConfig.Binds`.
Scan for any bind mount containing `docker.sock`.

**Output:**
```
[Security]
  ...
  ❌ ci-runner   Docker socket mounted (/var/run/docker.sock)
     Grants root-equivalent access to the host Docker daemon.
     Verify this is intentional; never in production workloads.
     → Remove the mount unless this container is explicitly a CI/Docker agent.
```

**JSON addition per container:**
```json
"docker_socket_mounted": true
```

**Acceptance criteria:**
- [ ] `/var/run/docker.sock` in `HostConfig.Binds` triggers CRIT (not just WARN — this is serious)
- [ ] `/run/docker.sock` alternative path also detected
- [ ] No socket mounts: no output in security section
- [ ] No new API calls — Binds already in inspect response

---

## Spec 7o — `dsd docker` Plaintext Secrets in Container Environment Variables

**Sprint:** 3 (addendum to Spec 7 fast — `[Security]` sub-section)
**Effort:** +0.10d
**Source:** 200-issue Docker guide (Issues 165, 197)
**Pain source:** Secrets passed as environment variables appear in `docker inspect`,
container logs, and `docker ps --no-trunc`. Common with DB_PASSWORD, API_SECRET,
TOKEN, and similar. Every compliance scan flags this. Automatable via Docker API.
**DashDiag cross-sell:** fix hint naturally references Keyorix (UnpackOps secrets manager).

### What to add

Add to the `[Security]` sub-section (Spec 7m, 7n).

**API check:** `GET /containers/{id}/json` → `Config.Env`.
Scan variable *names* (not values) against a pattern list.

**Pattern list (match as case-insensitive substring in the variable name):**
```go
var secretPatterns = []string{
    "PASSWORD", "PASSWD", "PWD",
    "SECRET", "TOKEN", "APIKEY", "API_KEY",
    "PRIVATE_KEY", "SIGNING_KEY", "ENCRYPTION_KEY",
    "CREDENTIALS", "ACCESS_KEY", "AUTH_TOKEN",
    "DATABASE_URL",  // often contains embedded credentials
}
```

**Flag condition:** variable name matches pattern AND value is non-empty AND
value is not obviously non-secret (e.g., not `true`, `false`, `0`, `1`, a path).
Do NOT log or display the value in any output — only the variable name.

**Output:**
```
[Security]
  ...
  ⚠️  api-server   plaintext secrets in env: DB_PASSWORD, API_TOKEN
  ⚠️  worker       plaintext secrets in env: SIGNING_KEY
     Env vars are visible in `docker inspect` and container logs.
     → Use Docker secrets, a vault, or Keyorix instead of plain env vars.
```

**JSON addition per container:**
```json
"plaintext_secret_vars": ["DB_PASSWORD", "API_TOKEN"]
```

**Important:** Never include secret *values* in any output (human or JSON).
Only report the variable names.

**Acceptance criteria:**
- [ ] `DB_PASSWORD=secret123` → flags `DB_PASSWORD` by name, never shows value
- [ ] `DEBUG=true` → not flagged (obvious non-secret value)
- [ ] `APP_PORT=8080` → not flagged (name doesn't match patterns)
- [ ] `DATABASE_URL=postgres://user:pass@host/db` → flagged (name match)
- [ ] Zero secret-pattern variables: no security section entry for this check
- [ ] `--json` includes `plaintext_secret_vars` array (names only, no values)
- [ ] Pattern matching is case-insensitive

---

## Spec 8 — Distro Detection Normalization Layer (Internal / Architectural)

**Sprint:** 4
**Type:** Internal abstraction — not user-facing
**Pain source:** Different distros use different networking stacks (Netplan vs NetworkManager
vs networkd), different security modules (AppArmor vs SELinux vs none), different log paths,
different package managers. Each collector currently has ad-hoc distro handling. As DashDiag
gains more commands, this becomes unmaintainable.

### What exists today
The project guide references `platform.DetectContainerContext()`. There is already
some distro/platform detection. This spec proposes formalizing it into a richer
`platform.Profile` struct that all collectors can query.

### What to build

**New struct: `platform.Profile`**

```go
// internal/platform/profile.go
type Profile struct {
    // OS identity
    OS           string   // "linux", "darwin"
    Distro       string   // "rhel", "debian", "ubuntu", "sles", "arch", "unknown"
    DistroVersion string  // "10.1", "12", "22.04"
    Codename     string   // "bookworm", "noble", etc.

    // Init system
    InitSystem   string   // "systemd", "openrc", "sysvinit", "unknown"

    // Networking stack (Linux only)
    NetworkStack string   // "networkmanager", "networkd", "netplan", "ifupdown", "unknown"
    HasNetplan   bool
    HasResolved  bool     // systemd-resolved active

    // Security modules
    SELinuxMode  string   // "enforcing", "permissive", "disabled", "not-present"
    AppArmorActive bool

    // Package manager
    PackageManager string  // "apt", "dnf", "yum", "zypper", "pacman", "brew", "unknown"

    // Container context (existing — keep)
    InContainer  bool
    ContainerRuntime string  // "docker", "containerd", "podman", "none"

    // Log paths (resolved per-distro)
    SyslogPath   string   // "/var/log/syslog" or "/var/log/messages"
    AuthLogPath  string   // "/var/log/auth.log" or "/var/log/secure"
    AuditLogPath string   // "/var/log/audit/audit.log" or via journald
}
```

**Detection logic:**
- Distro: read `/etc/os-release` → ID field. Map: `rhel`/`centos`/`rocky`/`almalinux`
  all normalize to distro family `"rhel"`. `debian`/`ubuntu` normalize to their own.
- NetworkStack: check in order:
  1. Is `netplan` binary present AND `/etc/netplan/*.yaml` exists? → `netplan`
  2. Is `NetworkManager` service active? → `networkmanager`
  3. Is `systemd-networkd` active? → `networkd`
  4. Does `/etc/network/interfaces` exist? → `ifupdown`
- HasResolved: `systemctl is-active systemd-resolved` exit 0 → true
- SELinuxMode: read `/sys/fs/selinux/enforce` (0=permissive, 1=enforcing); if file
  doesn't exist, not present
- AppArmorActive: check `/sys/kernel/security/apparmor/profiles` exists and is non-empty
- PackageManager: check binary existence in order: apt, dnf, yum, zypper, pacman, brew
- Log paths: set based on Distro:
  - rhel/fedora/centos: SyslogPath=/var/log/messages, AuthLogPath=/var/log/secure
  - debian/ubuntu: SyslogPath=/var/log/syslog, AuthLogPath=/var/log/auth.log
  - Both use AuditLogPath=/var/log/audit/audit.log if present, else journald fallback

**Usage in collectors:**
Every collector that currently has inline distro checks (`if distro == "rhel"`)
should instead accept a `*platform.Profile` and query it:

```go
// Before (scattered, hard to test):
if runtime.GOOS == "linux" {
    data, _ := os.ReadFile("/var/log/messages")  // RHEL only — breaks on Debian
}

// After (centralized, testable):
func (c *LogsCollector) Collect(p *platform.Profile) CollectorResult {
    data, _ := os.ReadFile(p.SyslogPath)  // correct path for any distro
}
```

**Where to apply in Sprint 4:**
1. `LogsCollector` — use `p.SyslogPath` and `p.AuthLogPath`
2. `SecurityCollector` — use `p.SELinuxMode`, `p.AppArmorActive`, `p.AuditLogPath`
3. `NetworkCollector` — use `p.HasResolved`, `p.NetworkStack`
4. New `ServicesDeepCollector` — use `p.InitSystem` to skip non-systemd systems
5. New `DiskCollector` (standalone) — detect ZFS via mount type, not distro name
6. New `DockerCollector` — use `p.ContainerRuntime` to pick correct socket path

**Test coverage required:**
- Unit test `platform.Detect()` with mocked `/etc/os-release` for each major distro
- Test that `NetworkStack` detection works correctly when all three stacks coexist on
  same machine (Netplan + NetworkManager is the Ubuntu Desktop case)
- Test that log paths resolve correctly for RHEL and Debian families

**Acceptance criteria:**
- [ ] `platform.Profile` struct implemented and returned by `platform.Detect()`
- [ ] All 5+ collectors updated to use Profile instead of inline checks
- [ ] Unit tests cover RHEL, Debian, Ubuntu, SLES, macOS profile detection
- [ ] No behaviour change visible to users — this is an internal refactor
- [ ] `--debug` flag prints detected profile at startup:
     `[debug] Platform: rhel 10.1, networkmanager, SELinux enforcing, dnf`



---

## Spec 13 — `dsd security` SSH Hardening Audit Block

**Sprint:** 2 (additive to existing `dsd security` — purely read-only checks)
**Type:** Enhancement to existing `dsd security` command
**Pain source:** The nixCraft SSH hardening guide documents 20 common misconfigurations.
`dsd security` already checks failed logins, ports, sudo, and SELinux denials — but
it does NOT audit the actual cryptographic strength of the SSH server config, or flag
the most common unsafe defaults that are shipped enabled on many distros.

### What to add: `[SSH config audit]` section in `dsd security`

**Checks (all via `sshd -T` — extended test mode, zero side effects):**

`sshd -T` dumps the full effective sshd config without restarting or touching the daemon.
It is the correct production-safe way to audit the active configuration.

1. **Root login:** `sshd -T | grep permitrootlogin` — flag WARN if not `no`
2. **Password authentication:** `sshd -T | grep passwordauthentication` — flag WARN if `yes`
3. **Empty password permits:** `sshd -T | grep permitemptypasswords` — flag CRIT if `yes`
4. **Protocol version:** `sshd -T | grep protocol` — flag CRIT if `1` or `1,2` (SSH1 is broken)
5. **Weak ciphers:** parse `sshd -T | grep ciphers` and flag any of:
   `aes128-cbc`, `aes192-cbc`, `aes256-cbc`, `3des-cbc`, `blowfish-cbc`, `arcfour`
   These are CBC-mode ciphers vulnerable to BEAST/Lucky13 and stream ciphers with known weaknesses.
6. **Weak MACs:** parse `sshd -T | grep macs` and flag any of:
   `hmac-md5`, `hmac-sha1`, `hmac-ripemd160`, `umac-64`
7. **Weak KEX:** parse `sshd -T | grep kexalgorithms` and flag:
   `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`
8. **Idle timeout:** `sshd -T | grep clientaliveinterval` — WARN if 0 (no idle timeout)
9. **AllowUsers/AllowGroups configured:** flag INFO if neither is set (any user can SSH)
10. **X11 forwarding:** flag WARN if `x11forwarding yes` (attack surface on servers)

**Also check:** if `ssh-audit` binary is installed, run `ssh-audit -n localhost` and
include its severity summary in the output. Do NOT make ssh-audit a requirement — it
is an optional enhancement. The sshd -T path must work standalone.

**Output example:**

```
[SSH config audit]
  ❌ PermitRootLogin: yes  ← CRIT
  ⚠️  PasswordAuthentication: yes  (prefer key-only)
  ✅ PermitEmptyPasswords: no
  ⚠️  Weak ciphers active: aes128-cbc, aes256-cbc (CBC mode — vulnerable to BEAST)
  ⚠️  Weak MAC active: hmac-md5
  ✅ KEX algorithms: strong only
  ⚠️  ClientAliveInterval: 0 (no idle session timeout)
  ✅ X11Forwarding: no

Next:
  → Edit /etc/ssh/sshd_config: PermitRootLogin no
  → Edit /etc/ssh/sshd_config: PasswordAuthentication no
  → sshd -t  (validate config before restart)
  → systemctl reload sshd
```

**Cross-distro notes:**
- `sshd -T` requires that sshd is installed. If not present: skip section with INFO.
- On some older RHEL 7 systems `sshd -T` may need root. Check return code and
  degrade gracefully if permission denied: fall back to parsing `/etc/ssh/sshd_config`
  directly (note: -T gives the *effective* merged config; direct file parse may miss
  `/etc/ssh/sshd_config.d/*.conf` drop-ins which are common on Ubuntu 22.04+).

**Acceptance criteria:**
- [ ] `sshd -T` used for config reading, NOT file parsing (drop-ins respected)
- [ ] Each weak cipher/MAC/KEX listed individually in output
- [ ] PermitRootLogin `yes`, `without-password`, `prohibit-password` all flagged differently
- [ ] Graceful degradation when sshd not installed (section absent)
- [ ] ssh-audit integration works when binary present, silently absent when not
- [ ] `--json` includes SSH audit section with per-check status

---

## Spec 14 — `dsd security` User Account Hardening Audit

**Sprint:** 2 (additive to existing `dsd security`)
**Type:** Enhancement to existing `dsd security` command
**Pain source:** The nixCraft hardening guide and monitoring docs identify three
specific /etc/passwd and /etc/shadow checks that are standard sysadmin hygiene
but are routinely skipped because they require knowing the right awk one-liners.
Also: SUID/SGID binary enumeration is a fundamental audit step never automated by
any existing status tool.

### What to add: `[User account audit]` section in `dsd security`

**Checks:**

1. **Empty password accounts:**
   `awk -F: '($2 == "") {print $1}' /etc/shadow`
   Flag CRIT for each result. Empty-password accounts can be logged into without any
   credential, from local console or (if PermitEmptyPasswords yes) over SSH.

2. **Non-root UID=0 accounts:**
   `awk -F: '($3 == "0") {print $1}' /etc/passwd` — expect only `root`
   Flag CRIT for any other account. Additional UID=0 accounts are often created by
   attackers to maintain privileged access after the initial compromise.

3. **Password aging check:**
   For each human user account (UID ≥ 1000), read `/etc/shadow` expiry fields.
   Flag WARN if `Maximum_days` is 99999 (effectively never expires) AND the account
   uses password auth (not key-only). Do not flag service accounts (UID < 1000).

4. **SUID/SGID binary audit:**
   `find /usr /bin /sbin -perm /6000 -type f 2>/dev/null`
   Maintain a hardcoded list of expected SUID/SGID binaries (su, passwd, sudo, ping,
   mount, newgrp, etc.) — flag any binary NOT on the expected list as WARN.
   This detects attackers planting backdoor SUID shells or unusual SUID installations.
   Cap runtime at 10 seconds — use `-maxdepth 5` to avoid traversing deep directories.

5. **World-writable directory check (fast scan):**
   `find /tmp /var/tmp /dev/shm -perm -0002 -type d -not -sticky 2>/dev/null`
   World-writable directories without the sticky bit are a privilege escalation vector.
   Flag each result as WARN. Note: /tmp itself should have sticky bit (+t) — flag if missing.

**Output example:**

```
[User account audit]
  ❌ Empty password accounts: deploy (CRIT — can login without password)
  ❌ Non-root UID=0 accounts: backdoor (CRIT — privilege escalation risk)
  ✅ No unexpected SUID/SGID binaries found
  ⚠️  /var/tmp: world-writable without sticky bit

Next:
  → passwd -l deploy  (lock the empty-password account)
  → grep backdoor /etc/passwd && userdel backdoor
  → chmod +t /var/tmp
```

**JSON schema:**
```json
"user_account_audit": {
  "empty_password_accounts": ["deploy"],
  "extra_uid0_accounts": ["backdoor"],
  "unexpected_suid_binaries": [],
  "world_writable_no_sticky": ["/var/tmp"]
}
```

**Acceptance criteria:**
- [ ] Empty password detection reads /etc/shadow (requires root or shadow group)
  Graceful degradation if not readable: show INFO "requires root to check shadow"
- [ ] UID=0 check shows only accounts beyond root
- [ ] SUID scan completes in < 10s with -maxdepth limit
- [ ] Unexpected SUID fires when a test binary is chmod +s'd (simulate in CI)
- [ ] Expected SUID list is configurable via policy file (dsd policy override)
- [ ] `--json` valid against schema

---

## Spec 9 — `dsd cron` (New Command)

**Sprint:** 2 (fast only — small scope, high pain ratio)
**Type:** New top-level command
**Pain source:** Cron jobs fail silently. They run in a different environment (PATH, user
context, no TTY, no MAILTO) than interactive shells — the most common "works on my
machine but not in cron" scenario. No existing DashDiag command surfaces cron health.

### User story
> As a sysadmin, when a scheduled job stops running silently, I want one command that
> shows me the cron daemon status, recent job failures, and common config pitfalls —
> without me knowing which log file to check or which user's crontab to look at.

### `dsd cron` (fast)
**Target runtime:** < 4 seconds

**Checks:**

1. **Cron daemon status:**
   - Is `cron` or `crond` running? (`systemctl is-active cron || systemctl is-active crond`)
   - On systems using `fcron`, `anacron`, or `dcron`: detect and report which variant
   - If not running: CRIT — no jobs will execute

2. **Recent cron failures from logs:**
   - Scan `/var/log/syslog`, `/var/log/cron`, or journalctl for cron CRIT/ERROR entries
     in the last 24h (use `platform.Profile.SyslogPath` for cross-distro path)
   - Look for: `(CRON) ERROR`, `command not found`, `permission denied`, exit codes
   - Group by user/job, show count + last message

3. **Crontab config quality checks:**
   - Iterate `/etc/cron.d/`, `/etc/crontab`, and `/var/spool/cron/crontabs/`
   - For each crontab entry, flag:
     a. **No PATH set:** if a crontab file has no `PATH=` declaration, relative commands
        will use `/usr/bin:/bin` only — flag as WARN
     b. **No MAILTO set:** silent failure mode — any job output (including errors) is lost
        unless MAILTO is set. Flag as WARN if any user crontab has no MAILTO.
     c. **Commands using relative paths:** e.g. `./backup.sh` instead of `/opt/scripts/backup.sh`
        Flag as WARN — working directory in cron is usually $HOME, not CWD at authoring time
     d. **Commands referencing missing files:** for each command path in crontab, check
        if the binary/script exists and is executable. Flag missing as CRIT.

4. **Anacron check:**
   - If `anacron` is installed: check `/var/spool/anacron/` timestamps. If any job
     timestamp is older than its scheduled frequency (e.g. daily job not run in 2+ days),
     report as WARN — usually indicates the machine was off during the scheduled window.

**Output example:**

```
⏰ Cron

[Daemon]
  ✅ crond: active (running)

[Recent failures — last 24h]
  ⚠️  /etc/cron.d/backup   FAILED 3 times   last: "pg_dump: command not found"
  ✅  All system cron jobs: no errors

[Crontab quality]
  ⚠️  /var/spool/cron/crontabs/deploy    no MAILTO set (failures are silent)
  ❌  /etc/cron.d/backup                 command not found: /opt/old/pg_dump.sh
  ⚠️  /etc/cron.d/cleanup               no PATH declaration (uses /usr/bin:/bin only)

[Anacron]
  ⚠️  daily job last run: 3 days ago (expected: daily) — was machine off?

Checks: 8 | Passed: 5 | Warnings: 3 | Critical: 1
Next:
  → MAILTO=you@example.com added to crontab header to capture output
  → which pg_dump  (find the correct path)
  → grep CRON /var/log/syslog | tail -20
```

**JSON schema:**

```json
{
  "cron": {
    "daemon_active": true,
    "daemon_name": "crond",
    "failures_24h": [
      {"source": "/etc/cron.d/backup", "count": 3, "last_error": "pg_dump: command not found"}
    ],
    "quality_issues": [
      {"file": "/var/spool/cron/crontabs/deploy", "issue": "no_mailto"},
      {"file": "/etc/cron.d/backup", "issue": "missing_command", "path": "/opt/old/pg_dump.sh"},
      {"file": "/etc/cron.d/cleanup", "issue": "no_path_declaration"}
    ],
    "anacron_issues": [
      {"job": "daily", "last_run_days_ago": 3, "expected_frequency_days": 1}
    ]
  }
}
```

**Collector design:**
- `internal/collectors/cron_linux.go`
- Parse crontab files with a simple line scanner — no external binary needed
- Check command existence via `os.Stat()` on the parsed path — no shell needed
- Log scan uses `platform.Profile.SyslogPath` for cross-distro correctness
- Anacron timestamps: read `/var/spool/anacron/cron.{daily,weekly,monthly}` — these
  contain a single date string. Compare to current date.

**Cross-distro notes:**
- Debian/Ubuntu: daemon is `cron`, logs in `/var/log/syslog`
- RHEL/Fedora: daemon is `crond`, logs in `/var/log/cron`
- Both: systemd can also run cron via timer units — if `cron` is not installed but
  systemd timers exist, report INFO "Using systemd timers (no crontab — see dsd services)"

**Acceptance criteria:**
- [ ] Daemon status detected correctly on RHEL (crond) and Debian (cron)
- [ ] Recent failure detection finds cron errors in system log
- [ ] Missing command detection works without executing the crontab
- [ ] No MAILTO detection works for user crontabs in /var/spool/cron/crontabs/
- [ ] Anacron stale job detected when timestamp > frequency
- [ ] Graceful INFO on systems using systemd timers only
- [ ] `--json` valid against schema
- [ ] Runs in < 4 seconds


---

## Spec 10 — `dsd proc <PID>` (New Command — /proc-based Process Inspector)

**Sprint:** 3
**Type:** New targeted command
**Pain source:** strace is the standard tool for deep process inspection but causes
significant slowdown in production. lsof requires installation and often root access.
Neither integrates with DashDiag's output format. Admins manually piece together
information from /proc/PID/* — there is no unified per-process inspector.

### User story
> As a DevOps engineer investigating a hung or misbehaving process in production,
> I want a single command that tells me: what is this process waiting for, what files
> does it have open, what network connections does it hold, what resources is it using —
> without slowing it down or requiring strace/lsof.

### `dsd proc <PID>`
**Target runtime:** < 2 seconds
**Invocation:** `dsd proc 8823` or `dsd proc $(pgrep nginx)`

**Note:** This is NOT a streaming monitor. It is a single-snapshot deep-dive on
one process. For ongoing monitoring, `dsd health` (all processes) is the right tool.

**Checks (all read from /proc — zero performance impact on target):**

1. **Identity:**
   - Name, full command line (`/proc/PID/cmdline`)
   - User (UID/GID → username lookup)
   - Parent PID and parent name
   - Start time, elapsed uptime
   - cgroup scope (docker/k8s/system/user) — reuse cgroup logic from Spec 5

2. **State:**
   - Process state from `/proc/PID/status`: R/S/D/Z/T
   - If state is D (uninterruptible sleep): report the wait channel from
     `/proc/PID/wchan` — this tells you WHAT kernel function it's stuck in
     (e.g. `pipe_wait`, `nfs_file_read`, `ext4_file_write_iter`)
   - If state is Z (zombie): report parent PID, note parent hasn't reaped it

3. **Resources:**
   - CPU time (user + sys) from `/proc/PID/stat`
   - Memory: VmRSS, VmPeak, VmSwap from `/proc/PID/status`
   - Open file descriptor count vs limit (`/proc/PID/limits` → Max open files)
   - Thread count

4. **Open files (lsof-equivalent, /proc-based):**
   - Iterate `/proc/PID/fd/` — count and categorize:
     - Regular files: show path (via readlink)
     - Sockets: resolve to connection info via `/proc/PID/net/tcp`, `/proc/PID/net/tcp6`
     - Pipes: show pipe inode (for cross-process pipe detection)
     - Devices: show device path
   - Flag if FD count > 80% of the process's open file limit

5. **Network connections:**
   - From socket FDs: resolve each socket inode to a TCP/UDP entry in
     `/proc/net/tcp` and `/proc/net/tcp6`
   - Show: local addr:port, remote addr:port, state (ESTABLISHED/LISTEN/CLOSE_WAIT etc.)
   - Group: listening ports vs active connections vs half-open connections

6. **Mapped libraries:**
   - Parse `/proc/PID/maps` — list unique shared libraries (.so files) loaded
   - Flag if any mapped file no longer exists on disk (deleted library — memory leak risk
     or security concern: binary updated but process still uses old version)

**Output example:**

```
🔍 Process 8823

[Identity]
  Name:     java
  Command:  java -jar /opt/app/api.jar --port 8080
  User:     deploy (uid 1001)
  Parent:   bash (PID 8801)
  Uptime:   3h 42m
  Cgroup:   docker: api-server

[State]
  ✅ Running (S — sleeping, waiting for I/O or event)
  Wait channel: futex_wait_queue_me  (waiting on a mutex/lock)

[Resources]
  CPU:      4.2% user + 0.8% sys  (12m 18s total)
  Memory:   490MB RSS / 1.2GB virtual  (2% swap)
  Threads:  48
  FDs:      842 open / 1024 limit  ← ⚠️ 82% of limit

[Open files — top by type]
  Regular:  12  (latest: /var/log/app/api.log, /opt/app/config.json)
  Sockets:  824  (see network section)
  Pipes:    4
  ⚠️  FD usage at 82% of limit — approaching exhaustion

[Network connections]
  Listening:    :8080 (TCP)
  Established:  42 connections to 10.0.1.x:5432 (postgres)
  CLOSE_WAIT:   18 connections  ← ⚠️ high CLOSE_WAIT count (remote closed, app not releasing)

[Mapped libraries]
  ✅ 84 shared libraries mapped
  ⚠️  1 deleted library still in use: /opt/java/lib/old-util.so (deleted)
     → Process is using updated package but still loaded old version — restart recommended

Next:
  → ulimit -n 4096  (increase FD limit for this user)
  → ss -tp src :8080  (full connection list)
  → systemctl restart api-server  (pick up deleted library update)
```

**JSON schema:**

```json
{
  "proc": {
    "pid": 8823,
    "name": "java",
    "state": "S",
    "wchan": "futex_wait_queue_me",
    "fd_count": 842,
    "fd_limit": 1024,
    "fd_pct": 82,
    "memory_rss_mb": 490,
    "memory_swap_mb": 12,
    "threads": 48,
    "network": {
      "listening": [{"port": 8080, "proto": "tcp"}],
      "established": 42,
      "close_wait": 18
    },
    "deleted_libraries": ["/opt/java/lib/old-util.so"],
    "cgroup_scope": "docker:api-server"
  }
}
```

**Collector design:**
- `internal/collectors/proc_inspector_linux.go`
- All data from /proc — zero external binary dependencies
- Socket resolution: read `/proc/net/tcp` and build an inode→connection map,
  then match each socket FD's inode against the map
- No root required for own processes. For other users' processes, /proc/PID/fd/
  may be restricted — gracefully report "FD details require same user or root"
- `dsd proc` without a PID: list top 10 CPU-consuming processes with a hint
  to run `dsd proc <PID>` on any of them

**Build tag:** Linux only (`//go:build linux`). macOS: `lsof -p <PID>` shell-out
as fallback (macOS has no /proc but lsof is pre-installed).

**Acceptance criteria:**
- [ ] Correct process identity, state, and wchan on a known-D-state process
  (simulate with: `dd if=/dev/zero of=/dev/null &` then `dsd proc <dd_pid>`)
- [ ] FD listing works without root for own processes
- [ ] CLOSE_WAIT detection correct for a process with half-open TCP connections
- [ ] Deleted library detection fires when a library is in use but file is removed
- [ ] `dsd proc` without PID shows top CPU process list
- [ ] Runs in < 2 seconds on a process with 800+ FDs
- [ ] `--json` valid against schema


---

## Spec 11 — `dsd net deep` NFS Mount Health Block

**Sprint:** 3
**Type:** Enhancement to existing `dsd net deep` command (additive section)
**Pain source:** NFS is one of the most common causes of production hangs. Stale NFS
mounts cause `ls`, `df`, and any process trying to access the mount to hang indefinitely
(uninterruptible D-state). There is no quick way to detect this without hanging yourself.
rpcbind failures and export mismatches are also common but require several commands to diagnose.

### What to add to `dsd net deep`

Insert a `[NFS mounts]` section. Only shown if NFS mounts are present in `/proc/mounts`.
If no NFS mounts: section omitted entirely (not shown as OK — just absent, reduce noise).

**Checks:**

1. **NFS mount detection:**
   - Parse `/proc/mounts` for `type=nfs` or `type=nfs4` entries
   - If none: skip this entire section

2. **Stale mount detection (without hanging):**
   - For each NFS mount: attempt a non-blocking stat with a timeout via goroutine
   - Implementation: `syscall.Statfs()` in a goroutine + `time.After(2s)` select
   - If the call returns within 2s: mount is healthy
   - If timeout fires: mount is stale/hanging → CRIT immediately, do NOT wait
   - This is the critical technique — a direct `df` or `ls` on a stale NFS mount
     hangs the caller process in uninterruptible sleep indefinitely

3. **NFS server reachability:**
   - From the mount source (e.g. `10.0.1.50:/exports/data`), extract server IP
   - Ping the server IP (1 packet, 1s timeout)
   - Check TCP port 2049 (NFS) reachable with a TCP connect (1s timeout)
   - If server is unreachable: explains why mount is stale

4. **rpcbind / portmapper status:**
   - Is `rpcbind` or `rpc.statd` service running?
   - `rpcinfo -p localhost` (if rpcinfo available) — list registered RPC programs
   - If rpcbind is not running and NFS mounts are present: WARN

5. **NFS statistics:**
   - Read `/proc/net/rpc/nfs` — parse retrans count and authrefrsh count
   - High retrans count indicates NFS transport reliability issues
   - Report: operations/s, retransmissions/s, read/write ops

6. **Mount options audit:**
   - For each NFS mount, parse options from `/proc/mounts`
   - Flag as WARN if:
     - `soft` mount without `timeo` (silent data loss on timeout)
     - `nolock` (file locking disabled — data corruption risk if shared)
     - `vers=3` with `tcp` (recommend vers=4 for reliability)
     - Missing `_netdev` in fstab (causes boot hang if network not ready)

**Output example:**

```
[NFS mounts]
  ❌ /data/backup  10.0.1.50:/exports/backup  STALE (timeout after 2s)
     → Server 10.0.1.50: unreachable (ping timeout)
     → NFS port 2049: unreachable

  ✅ /data/shared  10.0.1.51:/exports/shared  healthy (48ms)

  ⚠️  /data/shared  mount option: soft (data may be silently lost on timeout)

  [NFS stats]
  Retransmissions: 4/min  ← ⚠️ elevated (indicates transport issues)
  Read ops: 142/min  Write ops: 28/min

  [rpcbind]
  ✅ rpcbind: active

Next:
  → umount -l /data/backup  (lazy unmount the stale mount)
  → ping 10.0.1.50  (verify server reachability)
  → mount -o remount /data/backup  (remount after server recovery)
```

**Key implementation note:**
The non-blocking stat with goroutine+timeout is the ENTIRE value of this feature.
Every other NFS check is straightforward. Getting the stale mount detection right —
no hangs, correct timeout, correct CRIT signal — is the acceptance criteria that matters.

**JSON schema addition:**

```json
"nfs_mounts": [
  {
    "mount": "/data/backup",
    "server": "10.0.1.50",
    "export": "/exports/backup",
    "healthy": false,
    "stale": true,
    "server_reachable": false,
    "retrans_per_min": 4,
    "options_warnings": []
  }
]
```

**Acceptance criteria:**
- [ ] Stale mount detection does NOT hang — timeout fires within 3s worst case
- [ ] Healthy NFS mount correctly detected as healthy within 2s
- [ ] Server reachability check uses extracted server IP, not DNS (avoid DNS hang)
- [ ] Section completely absent (no output, no OK line) when no NFS mounts present
- [ ] Mount option audit flags `soft` without `timeo`
- [ ] rpcbind status checked on both systemd (is-active) and non-systemd systems
- [ ] `--json` includes NFS section only when NFS mounts are present

---

## Spec 12 — `dsd health` Package Dependency Integrity Check

**Sprint:** 2 (small addition — fold into existing `dsd health` or `dsd health deep`)
**Type:** Small enhancement — new check within existing command
**Pain source:** Broken package dependencies and partially-upgraded systems cause
mysterious failures (library version mismatches, missing shared objects, broken
post-install scripts). No existing DashDiag check catches this.

### What to add

Add a `package_integrity` check to `dsd health deep` (or optionally `dsd health` fast
if it runs quickly enough — see timing note below).

**Checks:**

1. **Debian/Ubuntu — broken package detection:**
   - Run `dpkg --audit` — exits 0 with no output if clean, exits non-zero with
     broken package descriptions if not. Cap at 5s.
   - Run `apt-get check 2>&1` — detects unsatisfied dependencies without
     modifying anything. Parse for "Unmet dependencies" or "broken packages".

2. **RHEL/Fedora — package integrity:**
   - Run `rpm --verify --all 2>/dev/null | grep -v "^..........  c "` to check
     for modified system files (excluding config files, which are expected to change).
     Cap at 10s (rpm verify can be slow on large systems).
   - Alternatively, just `dnf check` — faster, checks for dep inconsistencies.
     Flag if output is non-empty.

3. **Missing shared libraries:**
   - Run `ldconfig -p` to verify the ld.so cache is current.
   - Optionally (deep only): `ldd` on key system binaries to detect broken links.
     Limit to: /bin/ls, /usr/bin/python3, /usr/bin/ssh — canary binaries only.
     If any show "not found" for a dependency, flag CRIT.

**Output addition to `dsd health deep`:**

```
[Package integrity]
  ✅ dpkg: no broken packages
  ⚠️  apt: 1 unmet dependency (libssl1.1 required by old-package but not installed)
  ✅ ldconfig: shared library cache current
```

**Timing note:** `rpm --verify --all` can take 15-30s on large RHEL systems. Place this
in `dsd health deep` ONLY. Do not add to `dsd health` fast. `dpkg --audit` is fast (< 1s)
and can go in `dsd health` fast on Debian/Ubuntu.

**Acceptance criteria:**
- [ ] `dpkg --audit` result surfaced in `dsd health deep` on Debian/Ubuntu
- [ ] `dnf check` result surfaced in `dsd health deep` on RHEL
- [ ] Missing shared library detected when a .so file is deleted (simulate by
  moving /lib/x86_64-linux-gnu/libm.so.6 temporarily)
- [ ] `rpm --verify --all` capped at 10s — timeout with WARN "verify timed out" if exceeded
- [ ] Section absent on macOS (brew does not have equivalent)


---

## Spec 15 — `dsd kvm` (New Command)

**Sprint:** 4
**Type:** New top-level command
**Pain source:** KVM/libvirt is the second most common container/virtualisation
platform after Docker (Proxmox, bare-metal KVM on RHEL/Debian, cloud VMs all use it).
`dsd docker` and `dsd pve` exist or are planned. `dsd kvm` completes the virtualisation
trio for the large audience running KVM directly on Linux without Proxmox.
The KVM troubleshooting guide highlights that log files in `/var/log/libvirt/qemu/`
contain actionable errors that admins rarely check until a VM is already broken.

### `dsd kvm` (fast)
**Target runtime:** < 5 seconds
**Prerequisite:** detect libvirtd running via `systemctl is-active libvirtd` or
`virsh version` exit code. If not present: INFO "libvirt not found — is KVM installed?"

**Checks:**

1. **VM status:** `virsh list --all` — group by state:
   - Running: show name, state, uptime (if available)
   - Paused: show name — flag WARN (often indicates a problem)
   - Shut off with autostart=yes: flag WARN (should be running but isn't)
   - Crashed: flag CRIT
   Use `virsh dominfo <name>` for autostart status.

2. **Recent VM log errors:** for each VM in a non-running state, read last 20 lines
   of `/var/log/libvirt/qemu/<name>.log` and scan for:
   `error`, `failed`, `killed`, `abort`, `permission denied`, `no such file`
   Report the most recent matching line per VM.

3. **Libvirt network health:**
   - `virsh net-list --all` — flag any network in `inactive` state
   - Check that the default virbr0 bridge is up if default network is active:
     `ip link show virbr0` — flag WARN if DOWN

4. **Storage pool health:**
   - `virsh pool-list --all` — flag any pool in `inactive` state
   - For active pools: `virsh pool-info <pool>` — check available vs capacity
   - Flag WARN if any storage pool > 85% full

5. **Disk image integrity (fast):**
   For each running VM: `virsh domblkerror <name>` — if output is non-empty,
   a disk I/O error has been recorded. Flag CRIT immediately.

**Output example:**

```
🖥️  KVM / libvirt

[VMs]
  ✅ web-prod       Running   (autostart: yes)
  ✅ db-prod        Running   (autostart: yes)
  ❌ worker-01      Crashed   last log: "KVM internal error: suberror: 1"   ← CRIT
  ⚠️  backup-vm     Shut off  (autostart: yes — should be running)

[Networks]
  ✅ default        active (virbr0: up)
  ⚠️  isolated-net  inactive

[Storage pools]
  ✅ default        active  145GB free / 200GB
  ⚠️  nvme-pool     active  8GB free / 100GB  (92% full)  ← WARN

[Disk errors]
  ❌ worker-01: disk I/O error recorded on vda

Checks: 9 | Passed: 4 | Warnings: 2 | Critical: 2
Next:
  → virsh console worker-01
  → cat /var/log/libvirt/qemu/worker-01.log | tail -50
  → virsh start backup-vm
```

### `dsd kvm deep`
Everything in fast, plus:
- Full VM hardware config via `virsh dumpxml` for each non-running VM — check for
  missing disk images, invalid device paths, removed bridges
- NUMA topology check: `virsh capabilities | grep numa` — detect if VM vCPU count
  exceeds NUMA node capacity (common cause of poor performance on NUMA systems)
- `kvm_stat` output if available (requires debugfs mounted) — KVM hypervisor counters

**Collector design:**
- `internal/collectors/kvm_collector.go`
- Communicates via `virsh` shell-out (most reliable cross-distro approach)
  Alternative: libvirt Go bindings (github.com/libvirt/libvirt-go) for zero-shell
  path — use if available, fall back to virsh if binding not compiled in
- Log file reading: standard Go os.Open on `/var/log/libvirt/qemu/`
- Build tag: Linux only

**Acceptance criteria:**
- [ ] `dsd kvm` fast runs in < 5s with 5 VMs
- [ ] Crashed VM detected and log error surfaced
- [ ] Shut-off VM with autostart=yes flagged as WARN
- [ ] Storage pool capacity WARN fires at 85%
- [ ] Disk I/O error detection works via `virsh domblkerror`
- [ ] Graceful INFO when libvirt not installed
- [ ] `--json` valid against schema
- [ ] Tested on RHEL 10 with KVM (BACKLOG notes: RHEL testbed has k3s/containerd,
  need Docker added; can test KVM concurrently — already validated basic virsh on RHEL)

---

## Spec 16 — `dsd net deep` BIND/Named Server Health Block

**Sprint:** 3
**Type:** Enhancement to existing `dsd net deep` command (additive section)
**Pain source:** The nixCraft BIND troubleshooting guide identifies `named-checkconf`
and `named-checkzone` as essential validation tools. Many admins only discover config
errors when named crashes or refuses to start — not proactively. This is distinct
from Spec 2 (client-side DNS resolver). This spec is for servers *running* BIND as
an authoritative or recursive DNS server.

**Trigger:** Only shown if `named` or `bind9` process is running (detected via
`pgrep -x named` or `pgrep -x named-sdb`). If BIND not running: section absent.

**Checks:**

1. **Service status:** is `named` or `bind9` systemd service active?
   Use `systemctl is-active named.service || systemctl is-active bind9.service`

2. **Port 53 listening:** verify named is actually listening on :53:
   `ss -tulpn | grep :53` — check for both TCP and UDP
   Flag WARN if named is running but not listening (config error or firewall)

3. **Config file validation:** `named-checkconf /etc/named.conf` (RHEL) or
   `named-checkconf /etc/bind/named.conf` (Debian) — exit code 0 = clean.
   If non-zero: report error message as CRIT.

4. **Zone file validation:** parse `named.conf` to find zone file paths.
   For each zone: `named-checkzone <zone> <file>` — report any that fail as CRIT.
   Cap at 20 zones for fast variant; all zones in deep variant.

5. **DNS query test:** send a test query to localhost:
   `dig @127.0.0.1 localhost A +time=2 +tries=1` — should return a result.
   If timeout: CRIT (named running but not answering queries).

6. **RNDC stats (if available):** `rndc status 2>/dev/null` — parse for:
   - Server uptime
   - Query count
   - Any critical error messages

**Output example:**

```
[DNS server (BIND)]
  ✅ named: active (running 4d 12h)
  ✅ Port 53: listening (TCP + UDP)
  ✅ named-checkconf: no syntax errors
  ❌ Zone nixcraft.org: named-checkzone failed
     Error: dns_master_load: zone nixcraft.org: nixcraft.org.rev:1: no TTL specified
  ✅ DNS query test: localhost resolves in 1ms

Next:
  → named-checkzone nixcraft.org /var/named/nixcraft.org.rev
  → Add $TTL directive to the zone file
  → rndc reload nixcraft.org  (after fixing)
```

**Acceptance criteria:**
- [ ] Section absent when named not running
- [ ] `named-checkconf` path auto-detected for RHEL vs Debian layout
- [ ] Zone file paths parsed from named.conf correctly
- [ ] `named-checkzone` failures report the exact error message from output
- [ ] DNS query test uses localhost as target (not external — works air-gapped)
- [ ] Graceful degradation if rndc not accessible (no RNDC key configured)
- [ ] `--json` includes BIND section only when BIND running


---

## Sprint Roadmap (Summary) — Updated

| Sprint | Item | Estimated scope | Status |
|--------|------|-----------------|--------|
| 1 | `dsd services deep` — systemd failure diagnosis | ~2 days | Not started |
| 1 | `dsd net deep` DNS resolver audit block | ~1 day | Not started |
| 2 | `dsd logs` cross-source triage improvements | ~1.5 days | Not started |
| 2 | `dsd disk` standalone command (fast + deep) | ~3 days | Not started |
| 2 | `dsd cron` — cron health + job failure triage | ~1.5 days | Not started |
| 2 | `dsd health deep` package dependency integrity | ~0.5 days | Not started |
| 2 | `dsd security` SSH hardening audit (sshd -T) | ~1 day | Not started |
| 2 | `dsd security` user account hardening audit | ~1 day | Not started |
| 3 | `dsd health deep` cgroup tree + iowait attribution | ~3 days | Not started |
| 3 | `dsd security` permission disambiguation block | ~2 days | Not started |
| 3 | `dsd docker` full spec | ~4 days | Not started |
| 3 | `dsd proc <PID>` — /proc-based process inspector | ~2 days | Not started |
| 3 | `dsd net deep` NFS mount health block | ~1.5 days | Not started |
| 3 | `dsd net deep` BIND server health block | ~1 day | Not started |
| 4 | `dsd kvm` — KVM/libvirt diagnostics | ~3 days | Not started |
| 4 | `platform.Profile` normalization layer | ~2 days | Not started |

**Total estimated new scope: ~30 days of focused development**

Build order rule (unchanged): never build deep before fast is in production use.

---

*End of DashDiag_Gap_Specs.md — v2 (May 2026)*
*Sources: Admin complaints research (2024–2026), nixCraft troubleshooting series,*
*Linux sysadmin guides, DevOps scenario Q&A collections.*
*Merge key decisions into DashDiag_Project_Guide.md §Commands and §Backlog at v49+*

---

# SteamOS Gap Analysis — Feature Plan

## What SteamOS Is (Architecture Context)

SteamOS 3.x is Arch Linux-based with a gaming-optimised immutable rootfs.
It is fundamentally different from standard Linux in ways that affect every
existing DashDiag command, and introduces entirely new diagnostic domains.

### Key SteamOS-specific architecture facts:

**Partition layout (8 partitions, dual-slot A/B atomic updates):**
- Root A/B: BTRFS, 5GB each, read-only (immutable)
- /var A/B: ext4, 256MB each, writable (small — fills up causing update failures)
- /home: ext4, all remaining space, writable (user data, Proton prefixes, shaders)
- /home/.steamos/offload/: bind mounts for /opt, /root, /srv, pacman cache

**Update system:** RAUC atomic updates via `steamos-atomupd-client`.
Each update writes to the inactive slot and reboots into it.
A "bad" boot status in RAUC breaks the update system entirely.
`rauc status` is the ground truth for update health.

**Session compositor:** Gamescope — a Valve-built Wayland/DRM microcompositor.
Game Mode = Gamescope embedded session direct to DRM.
Desktop Mode = KDE Plasma on Wayland.
Mode switching: `steamos-session-select gamescope` / `steamos-session-select plasma`.
Session managed by: `gamescope-session.service` + `steam-launcher.service`.

**Hardware:** AMD APU (Zen 2/3/4 + RDNA 2/3). TDP limits configurable.
All GPU diagnostics are AMD-specific (AMDGPU driver, Mesa/RADV Vulkan).

---

## Gap Analysis Summary

| # | Gap | DashDiag Gap | Pain Level |
|---|-----|--------------|------------|
| S1 | RAUC partition health + boot slot status | Nothing | Critical |
| S2 | Gamescope session health | Nothing | Critical |
| S3 | steamos-update failure diagnosis | Nothing | Critical |
| S4 | /var partition filling up (only 256MB) | dsd disk ignores it | High |
| S5 | GPU/APU health for gaming | Nothing | High |
| S6 | Wi-Fi WPA supplicant mode + SSID band conflict | Nothing | High |
| S7 | Game mode ↔ desktop mode session diagnostics | Nothing | High |
| S8 | Proton prefix + shader cache size audit | Nothing | Medium |
| S9 | Flatpak health (SteamOS uses it for all apps) | Nothing | Medium |
| S10 | steamos-readonly status (rootfs RW = danger) | Nothing | Medium |

---

## Spec 17 — `dsd steamos` (New Command)

**Sprint:** 3 (after dsd health and dsd disk are validated)
**Type:** New top-level command — SteamOS-specific, not shown on standard Linux
**Detection:** Only activates when `/etc/os-release` contains `ID=steamos`
  or `VARIANT_ID=steamdeck`. On standard Linux: graceful INFO "not SteamOS".

**Pain sources:**
- RAUC boot status "bad" breaks updates silently (GitHub issue #1206, #1132)
- Gamescope session crashes leave device stuck in Game Mode
- /var (256MB) fills up and breaks updates/logging
- steamos-readonly accidentally left RW destroys next update
- Wi-Fi regression (3.7.x) requires WPA supplicant toggle in dev settings
- Update channel confusion (stable vs beta vs main)

### `dsd steamos` (fast)
**Target runtime:** < 5 seconds

**Checks:**

1. **OS version and update channel:**
   - Read `/etc/os-release`: VERSION_ID, BUILD_ID
   - Read `/etc/steamos-atomupd/client.conf`: which channel (rel/rc/beta/bc/main)
   - Show: `SteamOS 3.7.13 (stable channel)`
   - Flag INFO if on beta/main channel (not stable — unexpected on production)
   - Flag WARN if `/etc/steamos-atomupd/client.conf` is missing (breaks updater)

2. **RAUC slot health (the most important single check):**
   - Run `rauc status --output-format=json 2>/dev/null` or parse text output
   - Parse: which slot is currently booted (A/B), boot status of each slot
   - Flag CRIT if booted slot has `boot status: bad`
     (fix: `sudo rauc status mark-active booted`)
   - Flag WARN if inactive slot has `boot status: bad`
     (no rollback possible — update will fail to install)
   - Show: current slot (A/B), both slots' status
   - Example states: `booted (A)  ✅ | inactive (B)  ❌ bad — no rollback possible`

3. **rootfs read-only status:**
   - Run `steamos-readonly status` — should return `enabled`
   - Flag CRIT if returns `disabled` (rootfs is writable — next update will
     overwrite all manual changes AND disabling RO is a sign of user modification
     that could break the system)
   - This catches the #1 cause of "update broke my custom packages" complaints

4. **Session health:**
   - `systemctl is-active gamescope-session.service` — should be active in Game Mode
   - `systemctl is-active steam-launcher.service` — should be active
   - `systemctl is-active sddm.service` — should be active in Desktop Mode
   - If in Game Mode and gamescope-session is NOT active: CRIT (stuck session)
   - Determine current mode: check `XDG_SESSION_DESKTOP` env or
     read `/tmp/steamos-session-select` state file

5. **Storage health (SteamOS-specific):**
   - /var partition: df -h /var — flag WARN at 70%, CRIT at 85%
     (only 256MB total — this fills up with journal, update temp files, logs)
   - /home partition: df -h /home — flag WARN at 85%, CRIT at 95%
     (all user data: Proton prefixes, shader cache, game saves, flatpaks)
   - Show both with absolute sizes (256MB /var is not obvious without context)

6. **Wi-Fi + network:**
   - Check if `wpa_supplicant` or `iwd` is managing Wi-Fi
     (iwd is default in SteamOS; WPA supplicant is the dev-option workaround
      for 3.7.x regression — flag INFO if wpa_supplicant is active in dev mode)
   - SSID band conflict: `iw dev | grep SSID` — if two interfaces show the
     same SSID for different bands, flag WARN (documented Steam Deck OLED issue)
   - DNS: test resolve of `steamdeck-atomupd.steamos.cloud` (update server) —
     timeout = flag WARN "SteamOS update server unreachable"

**Output example:**

```
🎮 SteamOS

[System]
  ✅ SteamOS 3.7.13  stable channel  (BUILD_ID: 20250501.1)
  ✅ steamos-readonly: enabled (rootfs protected)

[RAUC update slots]
  ✅ Booted slot: A  (boot status: good)
  ❌ Inactive slot: B  (boot status: bad)
     No rollback available. Updates will fail to install.
     → sudo rauc status mark-good B
     → Or: re-image to restore slot B

[Session]
  ✅ Mode: Game Mode
  ✅ gamescope-session: active
  ✅ steam-launcher: active

[Storage]
  ⚠️ /var:  198MB / 256MB  (77% used)  ← nearing limit
     → journalctl --vacuum-size=50M
  ✅ /home: 120GB / 500GB  (24% used)

[Network]
  ✅ Wi-Fi: iwd  (default mode)
  ✅ SteamOS update server: reachable (42ms)

Checks: 8 | Passed: 6 | Warnings: 1 | Critical: 1
Next:
  → sudo rauc status mark-good B   (fix inactive slot)
  → dsd steamos deep               (full analysis)
```

### `dsd steamos deep`
Everything in fast, plus:

1. **Gamescope session errors:**
   - `journalctl -u gamescope-session -n 50 --no-pager` filtered for:
     `error|failed|assert|abort|crash|killed|drm`
   - Show last 5 matching lines with timestamps
   - `gamescopectl` output (if gamescope is running): connector name,
     display make/model, valid refresh rates, features supported

2. **RAUC detailed history:**
   - `journalctl -u rauc -n 30 --no-pager` — last update attempt result
   - Show: last successful update timestamp, last failed update error

3. **Proton prefix audit:**
   - Count directories in `~/.steam/steam/steamapps/compatdata/`
   - Total size of compatdata (can grow to 50GB+)
   - Count + size of `~/.steam/steam/shadercache/`
   - Flag WARN if shader cache > 10GB (common cause of /home filling up)

4. **Flatpak health:**
   - `flatpak list --app` — count installed apps
   - `flatpak remotes` — check Flathub remote is accessible
   - Total flatpak disk usage: `du -sh ~/.local/share/flatpak/`
   - Flag WARN if flatpak data > 20GB

5. **BIOS version:**
   - `dmidecode -s bios-version` (requires sudo)
   - Compare against known-problematic BIOS versions
     (e.g., SteamDeck: BIOS 0121 was stable; certain versions caused thermal crashes)
   - Report version + advisory if BIOS is outdated by >2 major versions

**JSON schema:**

```json
{
  "steamos": {
    "version": "3.7.13",
    "build_id": "20250501.1",
    "channel": "stable",
    "readonly_enabled": true,
    "rauc_booted_slot": "A",
    "rauc_booted_status": "good",
    "rauc_inactive_slot": "B",
    "rauc_inactive_status": "bad",
    "session_mode": "gamemode",
    "gamescope_session_active": true,
    "steam_launcher_active": true,
    "var_used_pct": 77,
    "var_used_mb": 198,
    "home_used_pct": 24,
    "wifi_backend": "iwd",
    "update_server_reachable": true,
    "update_server_latency_ms": 42
  }
}
```

**Collector design:**
- `internal/collectors/steamos_collector.go`
- Build tag: Linux only (`//go:build linux`)
- Detection: check `/etc/os-release` for `ID=steamos` before doing anything
- `rauc status` output: text-parse if `--output-format=json` not available
  (older RAUC versions don't support JSON)
- `steamos-readonly status`: shell out, check exit code and stdout
- `gamescopectl`: shell out, check binary exists first, skip if not running
- Session mode: read `$STEAM_DECK_SESSION` env or
  check active display manager via systemctl

**Cross-distro note:**
- Only runs on SteamOS (VARIANT_ID=steamdeck or ID=steamos)
- Also applies to SteamFork, HoloISO, and Bazzite variants that
  follow the same RAUC + Gamescope + Arch architecture
- On desktop Linux: section absent, INFO shown if user runs `dsd steamos` directly

**Acceptance criteria:**
- [ ] RAUC "bad" slot detected and correct fix command shown
- [ ] steamos-readonly "disabled" triggers CRIT
- [ ] /var at 80% triggers WARN (simulate with test)
- [ ] Gamescope session crash detected via unit status
- [ ] Update server DNS test uses `steamdeck-atomupd.steamos.cloud`
- [ ] WPA supplicant mode correctly identified vs iwd
- [ ] Command absent / INFO on non-SteamOS Linux
- [ ] `--json` valid against schema
- [ ] Runs in < 5s

---

## Spec 18 — `dsd gpu` (New Command)

**Sprint:** 3
**Type:** New top-level command — GPU health for gaming and compute workloads
**Detection:** All platforms, but SteamOS/AMD APU provides the richest data.
On standard Linux: works for AMD (amdgpu), Intel (i915), NVIDIA (nvidia-smi).

**Pain sources:**
- GPU temps spiking to 93°C during gameplay causing crashes (GitHub issue #2029)
- No single command showing GPU temp + clock + TDP + VRAM usage together
- TDP limit being hit causes sustained performance drops that look like game bugs
- Standard `dsd health` has no GPU section (CPU-focused)
- `sensors` output is fragmented and requires knowing which hwmon chip is GPU

### `dsd gpu` (fast)
**Target runtime:** < 2 seconds (all from sysfs/hwmon — no external tools needed)

**Checks:**

1. **GPU detection:** enumerate `/sys/class/drm/card*/device/vendor` and
   `/sys/class/drm/card*/device/device` to identify all GPUs.
   For each GPU: detect driver (amdgpu/i915/nvidia), VRAM size, device name.

2. **Temperature:** read from hwmon:
   - AMD: `/sys/class/hwmon/hwmon*/temp*_input` where `name` = `amdgpu`
     - GPU edge temp (`temp1_input`) — the surface temp
     - GPU junction temp (`temp2_input`) — the hotspot temp (die temp)
       Flag WARN at 90°C junction, CRIT at 100°C
   - Intel: `/sys/class/hwmon/hwmon*/temp*` where `name` = `i915`
   - NVIDIA: `nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader`
     (fall back to this if nvidia-smi available)

3. **GPU clock speeds (AMD):**
   - Read `/sys/class/drm/card*/device/pp_dpm_sclk` — current + available clocks
   - Show current GPU clock in MHz and as % of max
   - On SteamOS/Steam Deck: TDP limit will cap clocks — show if at limit

4. **TDP limit (SteamOS/AMD APU):**
   - Read `/sys/class/hwmon/hwmon*/power1_cap` (current TDP limit in microwatts)
   - Read `/sys/class/hwmon/hwmon*/power1_cap_max` (hardware maximum)
   - Read `/sys/class/hwmon/hwmon*/power1_input` (current actual power draw)
   - Show: `TDP: 15W / 30W limit  (current draw: 12W)`
   - Flag WARN if current draw ≥ 95% of cap (TDP throttled)

5. **VRAM usage (AMD):**
   - Read `/sys/class/drm/card*/device/mem_info_vram_used` (bytes used)
   - Read `/sys/class/drm/card*/device/mem_info_vram_total` (total bytes)
   - On APU (Steam Deck): VRAM is shared system memory — total is dynamic
   - Flag WARN if > 80% used

6. **GPU utilization:**
   - AMD: `/sys/class/drm/card*/device/gpu_busy_percent` — 0-100%
   - Show over a 1-second sample (read twice with 1s gap, show average)

7. **Driver + Mesa version:**
   - Parse `glxinfo -B 2>/dev/null` or read from `/sys/kernel/debug/dri/*/name`
   - Show: `AMDGPU (RADV VANGOGH) | Mesa 24.2.5`
   - Flag INFO if Mesa version < 23.0 (old, may cause Gamescope/Vulkan issues)

**Output example:**

```
🎮 GPU

[AMD Radeon Graphics (VANGOGH)]  Driver: amdgpu | Mesa 24.3.1 | RADV

  Temperature:
    ✅ Edge:     54°C
    ⚠️  Junction: 88°C  (approaching thermal limit)
    ✅ Memory:   48°C

  Performance:
    ✅ GPU clock:   1600 MHz / 1600 MHz max  (100% — at TDP limit)
    ⚠️  TDP:        15.0W / 15.0W limit  (current: 14.8W) ← throttling
    ✅ VRAM:        2.1GB / 16.0GB  (13% — shared system memory)
    ✅ Utilization: 72%

  Next:
    → On Steam Deck: Settings → Performance → TDP Limit (increase if plugged in)
    → dsd gpu deep  (thermal history + governor info)
```

### `dsd gpu deep`
Everything in fast, plus:

1. **Thermal history:** read `/sys/class/hwmon/hwmon*/temp*_crit` and `_emergency`
   thresholds. Check `/sys/kernel/debug/dri/0/amdgpu_pm_info` if available
   (requires root — graceful skip if not accessible).

2. **GPU governor (AMD):** read `/sys/class/drm/card*/device/power_dpm_force_performance_level`
   Valid values: `auto`, `low`, `high`, `manual`, `profile_standard` etc.
   Flag WARN if stuck in `low` (can happen after failed TDP management).

3. **Shader compilation queue:** on SteamOS, check if Mesa shader pre-compilation
   is running: `pgrep -x mesa-shader-cache` or
   `systemctl status --user mesa-shader-cache-run.service`
   If running: INFO "Shader pre-compilation in progress (may affect performance)"

4. **PCIe/memory bandwidth (AMD):** read `mem_busy_percent` from sysfs.
   On Steam Deck (iGPU/APU): memory bandwidth is shared — show
   `/sys/class/drm/card*/device/mem_info_gtt_used` (GTT = CPU-visible GPU memory pool)

**JSON schema:**

```json
{
  "gpu": [
    {
      "name": "AMD Radeon Graphics (VANGOGH)",
      "driver": "amdgpu",
      "mesa_version": "24.3.1",
      "temp_edge_c": 54,
      "temp_junction_c": 88,
      "clock_mhz": 1600,
      "clock_max_mhz": 1600,
      "tdp_current_w": 14.8,
      "tdp_limit_w": 15.0,
      "vram_used_gb": 2.1,
      "vram_total_gb": 16.0,
      "utilization_pct": 72,
      "throttling": true
    }
  ]
}
```

**Collector design:**
- `internal/collectors/gpu_collector_linux.go`
- Enumerate hwmon chips by reading `name` file, match to GPU vendor
- All reads from sysfs — zero external binaries required for AMD
- NVIDIA fallback: shell out to `nvidia-smi` if binary present
- Intel: hwmon + `/sys/kernel/debug/dri/0/` (may need root for some values)
- Build tag: `//go:build linux` (macOS: `system_profiler SPDisplaysDataType` fallback)
- 1-second GPU utilization sample runs in a goroutine alongside other checks

**Cross-platform notes:**
- AMD (Linux): full data from sysfs, no tools required
- Intel (Linux): partial — temps + some power data available
- NVIDIA (Linux): requires `nvidia-smi`, gracefully absent if not installed
- Steam Deck (APU): TDP data especially valuable; shared VRAM context important
- macOS: `system_profiler SPDisplaysDataType` gives minimal info; no thermal

**Acceptance criteria:**
- [ ] Temperature reads correct values on AMD (compare to MangoHud overlay)
- [ ] TDP throttling detection fires when power1_input ≥ 95% of power1_cap
- [ ] GPU utilization shows non-zero during a game (test: run glxgears)
- [ ] VRAM usage correct on APU (shared memory pool shown, not dedicated)
- [ ] Graceful INFO when GPU data not accessible (no sysfs path, no root)
- [ ] Mesa version parsed and shown
- [ ] `--json` valid against schema
- [ ] Runs in < 2s (utilization 1s sample is the floor)

---

## Spec 19 — `dsd disk` SteamOS Partition Layout Awareness

**Sprint:** 3 (additive to the existing `dsd disk` spec)
**Type:** Enhancement to `dsd disk` — conditional on SteamOS detection
**Pain source:** The standard `dsd disk` treats all partitions equally.
On SteamOS, /var at 256MB and the BTRFS root partition are architecturally
critical in ways a generic disk check misses.

**What to add (SteamOS-only section in `dsd disk`):**

When running on SteamOS (ID=steamos in /etc/os-release):

1. **BTRFS root health:**
   - `btrfs check --readonly /dev/disk/by-partsets/self/rootfs` — check for
     filesystem errors without mounting (read-only check, safe on live system)
   - Actually safer: `btrfs device stats /` — shows read/write errors, corruption
     This works on the live mounted filesystem, zero performance impact
   - Flag WARN if any error counter > 0
   - Flag CRIT if `read_io_errs` or `write_io_errs` > 0 (actual I/O errors)

2. **Inactive slot /var health:**
   - The inactive /var (e.g., /dev/disk/by-partsets/other/var) can become stale
     after failed updates. Check if it exists and is mountable (basic sanity).
   - This is an advanced check — skip if not accessible, just show INFO.

3. **SteamOS bind mount audit:**
   - Check that the critical bind mounts under /home/.steamos/offload/ exist:
     - `/opt` → `/home/.steamos/offload/opt`
     - `/root` → `/home/.steamos/offload/root`
   - If any bind mount is broken (target doesn't exist or isn't mounted):
     Flag WARN — this indicates /home filesystem issues

4. **Shader cache size warning:**
   - `du -sh ~/.steam/steam/shadercache/ 2>/dev/null`
   - Flag WARN if > 10GB
   - Flag CRIT if > 30GB
   - Shader cache can silently consume /home storage as games are played

**Output addition (SteamOS-only):**

```
[SteamOS partition layout]
  ✅ Root (BTRFS, slot A): healthy  (read errors: 0, write errors: 0)
  ⚠️  /var:  198MB / 256MB  (77% used)  ← see dsd steamos for cleanup hints
  ✅ /home: 120GB / 500GB  (24% used)
  ⚠️  Shader cache: 14GB at ~/.steam/steam/shadercache/  ← consider cleanup
     → steam://dialog/clearcache  (from Steam UI)
     → rm -rf ~/.steam/steam/shadercache/<AppID>  (per-game)
  ✅ Bind mounts: /opt, /root — intact
```

**Acceptance criteria:**
- [ ] btrfs device stats error count detected (test: inject a read error counter)
- [ ] /var 77% triggers WARN
- [ ] Shader cache > 10GB triggers WARN
- [ ] Section completely absent on non-SteamOS systems
- [ ] Bind mount check detects a broken /opt bind (simulate by unmounting)

---

## Spec 20 — `dsd net` SteamOS Wi-Fi Regression Checks

**Sprint:** 3 (additive to `dsd net` — conditional on SteamOS detection)
**Type:** Enhancement to existing `dsd net` command
**Pain source:** SteamOS 3.7.x had a major Wi-Fi regression documented in the
Steam community. The workaround is enabling WPA Supplicant in Dev Settings.
The root cause of slow downloads on Steam Deck is often DNS, not bandwidth.

**What to add to `dsd net` (SteamOS-only):**

1. **Wi-Fi backend detection:**
   - Check `systemctl is-active iwd` and `systemctl is-active wpa_supplicant`
   - Expected on modern SteamOS: iwd active, wpa_supplicant inactive
   - If BOTH active: WARN (conflicting backends — unusual configuration)
   - If wpa_supplicant is active and iwd is NOT: INFO "WPA Supplicant mode active
     (dev option workaround — consider switching back to iwd if no longer needed)"

2. **SSID band conflict check:**
   - Use `iw dev` to list all wireless interfaces and their current SSID
   - If two interfaces show the same SSID (2.4GHz and 5GHz adapters with same name):
     Flag WARN: "Duplicate SSID on 2.4GHz and 5GHz — known Steam Deck OLED issue.
     Consider giving each band a unique name in your router settings."
   - This was the #1 cause of Wi-Fi failures on OLED models (documented in 3.5.x era)

3. **Steam download speed sanity check:**
   - Measure DNS resolve time for `steamdeck-images.steamos.cloud` (update CDN)
   - If > 500ms: WARN "Update server DNS slow — adjust DNS settings"
   - EmuDeck explicitly recommends changing DNS to fix slow download issues

**Output addition (SteamOS-only):**

```
[SteamOS Wi-Fi]
  ✅ Wi-Fi backend: iwd (default)
  ⚠️  SSID conflict: 'HomeNetwork' appears on both 2.4GHz and 5GHz bands
     → Rename one band in your router (e.g. 'HomeNetwork_5G')
     → This is a known Steam Deck OLED connection reliability issue
  ⚠️  Steam CDN DNS: 680ms  ← slow (may cause slow updates)
     → Settings → Network → DNS → set to 1.1.1.1 or 8.8.8.8
```

**Acceptance criteria:**
- [ ] WPA supplicant vs iwd correctly detected
- [ ] SSID conflict detected when both bands share a name (test with two interfaces)
- [ ] Steam CDN DNS timing fires WARN at > 500ms
- [ ] Section absent on non-SteamOS systems (no unnecessary output on servers)

---

## Sprint Roadmap Addition (SteamOS)

| Sprint | Item | Estimated scope | Status |
|--------|------|-----------------|--------|
| 3 | `dsd steamos` — SteamOS health (RAUC, gamescope, /var) | ~4 days | Not started |
| 3 | `dsd gpu` — GPU/APU health for gaming + compute | ~2 days | Not started |
| 3 | `dsd disk` SteamOS partition layout block | ~1 day | Not started |
| 3 | `dsd net` SteamOS Wi-Fi regression checks | ~0.5 days | Not started |

**Total SteamOS scope added: ~7.5 days**
**New cumulative total: ~37.5 days**

---

*SteamOS gap analysis sources: ValveSoftware/SteamOS GitHub issues (#1132, #1206,*
*#1625, #2029, #2075), ValveSoftware/gamescope issues (#1042, #1243, #1398, #1636),*
*steamos-teardown partition docs, iliana.fyi SteamOS update internals, EmuDeck*
*troubleshooting guide, Steam Community SteamOS 3.7 bug thread, GamingOnLinux.*

---

## Master Sprint Roadmap — All Specs

| Sprint | Spec # | Item | Scope | Status |
|--------|--------|------|-------|--------|
| 1 | 1 | `dsd services deep` — systemd failure diagnosis | ~2d | Not started |
| 1 | 2 | `dsd net deep` — DNS resolver audit block | ~1d | Not started |
| 1 | H1 | `dsd health` — active session list (w command) | ~0.5d | Not started |
| 2 | 3 | `dsd logs` — cross-source triage improvements | ~1.5d | Not started |
| 2 | 4 | `dsd disk` — standalone command fast + deep | ~3d | Not started |
| 2 | 4a | `dsd disk` — fuser filesystem busy check | ~0.5d | Not started |
| 2 | 9 | `dsd cron` — cron health + job failure triage | ~1.5d | Not started |
| 2 | 12 | `dsd health deep` — package dependency integrity | ~0.5d | Not started |
| 2 | 13 | `dsd security` — SSH hardening audit (sshd -T) | ~1d | Not started |
| 2 | 14 | `dsd security` — user account hardening audit | ~1d | Not started |
| 3 | 5 | `dsd health deep` — cgroup tree + iowait attribution | ~3d | Not started |
| 3 | 6 | `dsd security` — SELinux boolean-first, port context, chcon/semanage, autorelabel | ~2d | Not started |
| 3 | 7 | `dsd docker` — Docker/Podman triage | ~4d | Not started |
| 3 | 10 | `dsd proc <PID>` — /proc process inspector | ~2d | Not started |
| 3 | 10a | `dsd proc` — pmap private/shared memory breakdown | ~0.5d | Not started |
| 3 | 11 | `dsd net deep` — NFS stale mount detection | ~1.5d | Not started |
| 3 | 16 | `dsd net deep` — BIND/named server health | ~1d | Not started |
| 3 | 17 | `dsd steamos` — RAUC/gamescope/partition health | ~4d | Not started |
| 3 | 18 | `dsd gpu` — GPU/APU health (AMD sysfs + nvidia-smi) | ~2d | Not started |
| 3 | 19 | `dsd disk` — SteamOS BTRFS + partition layout block | ~1d | Not started |
| 3 | 20 | `dsd net` — SteamOS Wi-Fi backend + SSID conflict | ~0.5d | Not started |
| 4 | 15 | `dsd kvm` — KVM/libvirt VM diagnostics | ~3d | Not started |
| 4 | 8 | `platform.Profile` — distro normalization layer | ~2d | Not started |

**Grand total: ~39.5 days of focused development across 23 spec items**
**Build order rule (unchanged): never build deep before fast is in production use.**

---

*End of DashDiag_Gap_Specs.md — v3 (May 2026)*
*Sources: Linux admin complaint research (2024–2026), nixCraft troubleshooting series,*
*DevOps Q&A collections, sysadmin hardening guides, Red Hat SELinux Primer,*
*ValveSoftware/SteamOS and gamescope GitHub issues, SteamOS architecture docs.*
*Merge key decisions into DashDiag_Project_Guide.md §Commands and §Backlog at v49+*


---

# Addenda from nixCraft 30 Linux Monitoring Tools (PDF)
**Source: nixCraft — 20/30 Linux System Monitoring Tools Every SysAdmin Should Know**
**Analysed: May 2026 | Added to: DashDiag_Gap_Specs.md**

## What this source adds vs existing specs

The document is the nixCraft monitoring tools article (saved PDF, 69 pages including
323 comments). The core tool list (top, vmstat, iostat, sar, ps, free, mpstat, pmap,
netstat/ss, strace, /proc) is already well-represented across existing DashDiag specs.

Three genuinely new gaps identified from the practitioner commentary:

1. **`fuser` — file-to-process and port-to-process reverse lookup** (new sub-check)
2. **`pmap` private vs shared memory breakdown** (addendum to dsd proc)
3. **`w` — active session list** (new sub-check in dsd security or dsd health)

The collectl author's canonical gap statement: "different output formats make
correlation VERY difficult; sar doesn't collect everything; 10-minute intervals are too
coarse; there is no unified API" — this is the problem DashDiag already solves.
The `--json` output is already specced as the platform API surface. Nothing new here.

---

## Spec 4 Addendum — `dsd disk` fuser: filesystem/device busy check

**Source:** nixCraft comment: "fuser command is missing from this list —
it tells you which command is using a file or device."

**Pain source:** When an admin tries to unmount a filesystem, remove a mount point,
or eject a device and gets "target is busy" or "device or resource busy" — there is
currently no DashDiag check that answers "what has this filesystem open?"

The existing `dsd proc <PID>` shows per-process open files. `fuser` inverts it:
given a path or port, show which processes have it open. Completely different use case.

### What to add to `dsd disk` (fast and deep)

**New check: filesystem/device in-use detection**

When a mounted filesystem is at WARN or CRIT usage level, or when `dsd disk` detects
a read-only remount or I/O errors, add:
- `fuser -m <mountpoint>` — list PIDs with files open on that filesystem
- For each PID: show process name, user, and whether it has the FS open for write
- Flag if the filesystem has > 10 processes with open files (risk if unmount needed)

Example output addition:

```
⚠️  /var: 90% used — 8 processes have files open
   PID 1234  journald       (write)
   PID 5678  rsyslog        (write)
   PID 9012  postgres       (write)
   → Cannot safely unmount while these processes are active
   → journalctl --vacuum-size=200M  (free space without unmounting)
```

**Also add to `dsd net` (port-in-use check):**
When a service fails to start because its port is already bound:
- `fuser -n tcp <port>` or `ss -tlnp | grep :<port>` — show which PID owns the port
- Already partially covered by `ss` in `dsd net`, but fuser gives the process name
  directly without parsing — use ss output as the primary path, fuser as fallback

**Collector design note:**
- `fuser` binary check first — `which fuser 2>/dev/null` — skip if not present
- Alternative when fuser absent: iterate `/proc/*/fd/` and match against mountpoint
  (same approach as `dsd proc` open file detection — reuse that collector logic)
- Only runs for WARN/CRIT filesystems, not all mounts (avoid slowness)

**Acceptance criteria:**
- [ ] fuser output shown for any filesystem at WARN/CRIT usage in `dsd disk`
- [ ] Graceful fallback to /proc/*/fd scan if fuser binary not installed
- [ ] Process names shown alongside PIDs (via /proc/<PID>/comm)
- [ ] Section absent for healthy filesystems (no unnecessary output)

---

## Spec 4b — `dsd disk` ZFS Pool Health

**Sprint:** 2 (addendum to Spec 4 fast — add to existing dsd disk output when ZFS detected)
**Effort:** +0.25d
**Source:** "15 Linux Troubleshooting Commands Every HomeLab Admin Should Know" (Virtualization Howto);
  confirmed by BACKLOG.md Proxmox test matrix (ZFS: TODO)
**Pain source:** A ZFS pool in DEGRADED state (failing drive, failed resilver) continues to
serve data normally — `df -h` shows healthy space numbers and no errors in application logs.
Only `zpool status` reveals the degraded state. On Proxmox nodes running TrueNAS or home lab
ZFS storage, a drive can sit FAULTED for days without anyone noticing. This is the exact type
of silent failure DashDiag is built to surface.

### What to add

**Gate:** Only run when ZFS is detected. Checks:
1. `zpool` binary exists in PATH (`which zpool 2>/dev/null`)
2. At least one ZFS filesystem is mounted (already detected in Spec 4 capacity check via
   `/proc/mounts` entries with `type=zfs`)

If gate passes, run:
```bash
zpool status -x 2>/dev/null   # -x: show only pools with errors or not ONLINE
```

`zpool status -x` outputs nothing when all pools are ONLINE with no errors. This makes
the healthy-path zero-cost — no parsing, no output, no performance overhead.

When any pool is not ONLINE, run full:
```bash
zpool status 2>/dev/null
```

Parse the output for:
- **Pool state**: ONLINE, DEGRADED, FAULTED, OFFLINE, UNAVAIL, REMOVED
- **Per-vdev state**: individual drive/mirror/raidz state
- **Errors**: read/write/checksum error counts per vdev
- **Resilver/scrub in progress**: parse `scan:` line for resilver/scrub status and %
- **Scrub recommendation**: if last scrub was > 30 days ago or never run

**Threshold table:**
| Pool/vdev state | Severity | Message |
|---|---|---|
| ONLINE, 0 errors | ✅ OK | Pool healthy |
| DEGRADED | ❌ CRIT | Pool degraded — drive failure, data at risk |
| FAULTED | ❌ CRIT | Pool faulted — data may be inaccessible |
| OFFLINE/UNAVAIL/REMOVED | ❌ CRIT | vdev offline or missing |
| Any checksum errors > 0 | ⚠️ WARN | Silent data corruption possible |
| Resilver in progress | ℹ️ INFO | Show % complete, estimated time |
| No scrub in > 30 days | ⚠️ WARN | Scrub recommended |

**Output (added to `dsd disk` fast output):**
```
[ZFS Pools]
  ❌  tank      DEGRADED
     mirror-0  DEGRADED
       sda     ONLINE   (0 read, 0 write, 0 cksum)
       sdb     FAULTED  (12 read, 5 write, 0 cksum)  ← drive failing
     Data at risk. Replace sdb immediately.
     → zpool status tank
     → zpool replace tank sdb /dev/sdc

  ⚠️  rpool     ONLINE   (resilver in progress: 42% done, ~14 min remaining)

  ℹ️  data      ONLINE   — last scrub: 47 days ago
     → zpool scrub data   (recommended monthly)
```

If `zpool status -x` returns nothing (all pools healthy): single line
`✅ ZFS pools: all healthy` OR suppress section entirely (no output).

**JSON schema addition:**
```json
"zfs_pools": [
  {
    "name": "tank",
    "state": "DEGRADED",
    "status": "crit",
    "vdevs": [
      {
        "name": "sdb",
        "state": "FAULTED",
        "read_errors": 12,
        "write_errors": 5,
        "cksum_errors": 0
      }
    ],
    "resilver_pct": null,
    "last_scrub_days": null
  }
]
```

**Collector design:**
- Parse `zpool status` output with Go string parsing (no external JSON — zpool has no
  machine-readable format in all versions; parse the human-readable text output)
- Key patterns to parse:
  - `pool: <name>` → pool name
  - `state: <STATE>` → pool state
  - `scan: scrub repaired ... on <date>` → last scrub date
  - `scan: resilver in progress ... <N>% done` → resilver status
  - Vdev lines: `\t<name>\t<STATE>\t<R>\t<W>\t<C>` → per-vdev errors
- Graceful skip if `zpool` binary not found (INFO line only)
- Graceful skip on non-Linux (macOS: zpool not standard; skip silently)
- No root required: `zpool status` is readable by any user in the `wheel` or `zfs` group
  on most systems; Proxmox root is the common case anyway

**Cross-references:**
- Spec 4 — `dsd disk` capacity (parent spec; ZFS `zfs list` already in cross-distro notes)
- Spec 21 — LVM layer health (parallel pattern: subsystem-specific disk health check)
- BACKLOG.md Proxmox testbed (ZFS: TODO) — validate there first

**Acceptance criteria:**
- [ ] All pools ONLINE, no errors: single OK line or section suppressed
- [ ] DEGRADED pool: CRIT with failing vdev name and error counts
- [ ] FAULTED pool: CRIT
- [ ] Checksum errors > 0: WARN (silent corruption signal)
- [ ] Resilver in progress: INFO with % and estimated time
- [ ] Last scrub > 30 days: WARN with scrub hint
- [ ] `zpool` binary absent: graceful INFO skip, no error
- [ ] `--json` includes `zfs_pools` array
- [ ] Zero overhead on non-ZFS systems (gate check only)

---

## Spec 10 Addendum

**Source:** nixCraft pmap section: "mapped: 933712K total amount of memory mapped
to files; writeable/private: 4304K the amount of private address space; shared: 768000K
the amount of address space this process is sharing with others."

**Pain source:** The `dsd proc` spec currently reads VmRSS, VmPeak, VmSwap from
`/proc/PID/status`. This gives total RSS but not the private/shared split.
For Java, Python, and any process with large shared library usage, the private vs
shared distinction is critical: shared pages are counted in RSS for every process
that maps them, making per-process RSS a misleading metric.

### What to add to `dsd proc <PID>` (both fast and deep)

Parse `/proc/<PID>/smaps_rollup` (Linux 4.14+, available on all modern distros):
- `Rss:` — total RSS (same as VmRSS in /proc/status, sanity check)
- `Private_Clean:` — clean private pages (can be discarded under memory pressure)
- `Private_Dirty:` — dirty private pages (must be written to swap before reclaim)
- `Shared_Clean:` — shared clean (mapped libraries, shared code)
- `Shared_Dirty:` — shared dirty (shared writable mappings — rare, often a concern)
- `Swap:` — pages currently in swap

**Why this matters:** `writeable/private` from pmap is the true memory footprint —
the memory that ONLY this process uses. If a Java process shows 2GB RSS but 200MB
private/dirty, the other 1.8GB is shared libraries that would exist anyway.

**Output addition to `dsd proc`:**

```
  Memory (detailed):
    RSS total:       2.1GB
    Private dirty:   210MB  ← true unique footprint
    Private clean:   45MB
    Shared libs:     1.8GB  (shared with 24 other processes)
    Swap:            12MB
```

Flag WARN if `Private_Dirty` > 80% of system free RAM (process is a real memory risk).
Flag INFO if `Shared_Dirty` > 100MB (unusual — shared writable mappings).

**Fallback:** if `/proc/<PID>/smaps_rollup` not available (kernel < 4.14):
parse `/proc/<PID>/smaps` directly and sum the fields. Slower but correct.

**Collector design:** pure /proc read, no external tools. Add to existing
ProcInspector collector as an optional second pass (smaps_rollup is fast — one file).

**Acceptance criteria:**
- [ ] Private dirty shown correctly for a Java process (compare to pmap -d output)
- [ ] Shared libs size correctly identified as shared (not counted as unique footprint)
- [ ] Fallback to /proc/smaps sum when smaps_rollup absent
- [ ] WARN fires when private_dirty > 80% of system free RAM

---

## New Sub-Check — `dsd health` active session list (from `w`)

**Source:** nixCraft tool #3: "w command displays information about the users
currently on the machine, and their processes."

**Pain source:** DashDiag `dsd health` has no check for who is currently logged in,
from where, how long they've been idle, and what command they're running. This is
both an operational check (is someone doing something that will interfere with my
work?) and a security signal (unexpected logins = potential compromise).

**This is distinct from `dsd security` failed login detection** (which looks at auth
log history). This is a real-time view of active sessions.

### What to add to `dsd health` (fast variant — new `[Active sessions]` section)

Only shown if > 0 users are logged in (collapse to INFO if only current user):

1. **Session list:** read `/var/run/utmp` (via `who` or `w`) — show for each session:
   - Username, TTY (pts/0 = SSH, tty1 = local console)
   - Login time
   - Idle time
   - Current command / process
   - Remote IP (for SSH sessions)

2. **Anomaly detection:**
   - Flag WARN if any session has been idle > 8 hours (unattended terminal risk)
   - Flag WARN if > 5 concurrent sessions (unusual for most servers)
   - Flag CRIT if root is logged in via SSH (PermitRootLogin issue — cross-reference
     with SSH audit from Spec 13)
   - Flag INFO for each unique remote IP (for security awareness)

3. **Load attribution:**
   - Cross-reference active session users with top CPU/memory consumers from existing
     health checks. If a logged-in user's processes are in the top 5 CPU consumers,
     show the connection: "User vivek (pts/1): running postgres (PID 1234, 42% CPU)"

**Output example:**

```
[Active sessions]
  2 users logged in

  vivek    pts/0  10.0.1.5    idle: 2m   vim /etc/nginx/nginx.conf
  root     pts/1  10.0.1.10   idle: 0s   bash  ← ⚠️  root SSH session active
  → PermitRootLogin may be enabled — see dsd security
```

**Collapse rule:** if only the current user (the one running `dsd`) is logged in,
show one line: `✅ Sessions: 1 (you)` — no detail needed.

**JSON schema:**

```json
"sessions": {
  "count": 2,
  "root_ssh_active": true,
  "sessions": [
    {"user": "vivek", "tty": "pts/0", "from": "10.0.1.5", "idle_min": 2,
     "cmd": "vim /etc/nginx/nginx.conf"},
    {"user": "root", "tty": "pts/1", "from": "10.0.1.10", "idle_min": 0,
     "cmd": "bash"}
  ]
}
```

**Collector design:**
- Read `/var/run/utmp` directly via Go `syscall` or shell out to `who -u` / `w -h`
- `w -h` is the cleanest cross-distro approach (no headers, tab-separated output)
- /var/run/utmp binary format: use `who` not utmp parsing to avoid struct differences
  across distros
- macOS: `w -h` works identically

**Acceptance criteria:**
- [ ] Root SSH session triggers WARN regardless of idle time
- [ ] Idle > 8h triggers WARN
- [ ] Single current-user session collapses to one INFO line
- [ ] Remote IP shown for SSH sessions, "local" shown for console sessions
- [ ] Cross-reference with top CPU processes works when process matches session user
- [ ] `--json` valid against schema

---

## Sprint and File Update Summary

These three additions modify:

| File | Change |
|------|--------|
| DashDiag_Gap_Specs.md | Spec 4 addendum (fuser), Spec 10 addendum (pmap), new `w` sub-check in dsd health |
| BACKLOG.md | Add notes to Spec 4, Spec 10, and dsd health entries |
| DashDiag_Project_Guide.md | Update dsd disk, dsd proc, dsd health descriptions |

Estimated additional scope: ~1.5 days total (all three are small additions to existing specs).

**Spec 21 addition (LVM layer health):**
Addendum to `dsd disk deep`. Adds ~0.5d. Three focused collectors (`vgs`, `lvs`,
`lvs --segments`), all read-only. No new command — appended to existing Spec 4 work.

Updated grand total: ~40.0 days across 24 spec items (21 numbered + H1 + 4a + 10a).


---

## Spec 21 — `dsd disk deep` — LVM Layer Health
*(Addendum to Spec 4: `dsd disk`)*

**Sprint:** 2 (append to dsd disk deep work)
**Type:** Sub-collector addition to existing `dsd disk deep`
**Pain source:** `df` and SMART only see the top and bottom of the storage stack.
The LVM middle layer — VG free space, snapshot overflow, mirror degradation — is
invisible to every check DashDiag currently runs. Silent snapshot invalidation
(Snap% = 100%) causes complete data loss with no warning visible to standard tools.
**Estimated additional scope:** ~0.5d (three focused collectors, all read-only)

---

### Background: Why This Is a Blind Spot

Linux storage is layered. DashDiag already covers:
- **Top layer:** filesystem usage, inode pressure (`df`, `statfs`) — in `dsd disk` fast
- **Bottom layer:** physical device health (SMART, I/O error counters) — in `dsd disk` deep

It does **not** cover the **LVM layer** that sits between them:

```
┌─────────────────────────────┐
│  Filesystem (ext4, xfs, …)  │  ← dsd disk fast covers this
├─────────────────────────────┤
│  Logical Volume (LV)        │  ← NOT COVERED
│  Volume Group (VG)          │  ← NOT COVERED  ← Spec 21 adds these
│  Physical Volume (PV)       │  ← NOT COVERED
├─────────────────────────────┤
│  Physical Device (disk)     │  ← dsd disk deep covers this (SMART)
└─────────────────────────────┘
```

The three failure modes this adds are each invisible to `df` and SMART:

| Failure | Why `df` Misses It | Severity |
|---|---|---|
| Classic snapshot overflow (Snap% = 100%) | Snapshot is a separate LV; `df` sees filesystem free space, not COW store usage | CRIT — silent data loss |
| Thin pool exhaustion (Data% near 100%) | Thin pool is a hidden LV; filesystems appear fine until the pool is full | CRIT — all thin LVs in pool go read-only |
| VG free space exhausted | `df` shows per-filesystem free space, not VG-level unallocated space | WARN — next `lvextend` fails |
| Mirror/RAID degraded or resyncing | RAID attribute only visible in `lvs` attribute string | WARN/CRIT |

---

### Fast Variant Addition (`dsd disk`)

Add a lightweight `[LVM overview]` section to the existing fast output.
**Target runtime: < 50ms** (single `vgs` + `lvs` call, no blocking I/O).

**Checks:**
1. Detect whether LVM is in use at all — if `lvs` returns nothing or LVM tools are
   absent, skip this section silently (INFO: no LVM detected).
2. For each Volume Group: show name, total size, free space, free%.
   - WARN if VG free < 15%
   - CRIT if VG free < 5%
3. Scan all LVs for classic snapshots (`lvs -o lv_attr` — attribute[0] = 's').
   For each snapshot: show origin LV, Snap%, COW store size.
   - WARN if Snap% > 70%
   - CRIT if Snap% > 90%
4. Scan all thin pools (`lv_attr[0] = 't'`). For each pool: show Data% and Meta%.
   - WARN if Data% > 70% or Meta% > 70%
   - CRIT if Data% > 90% or Meta% > 90%

**Human-readable output example (fast):**

```
[LVM overview]
  Volume Groups: 2

  vg_data    240G total    18G free  (8%)   ⚠️  VG low on space
  vg_system   40G total    12G free  (30%)  ✅

  Snapshots: 1
  ⚠️  vg_data/root_snap  →  origin: lv_root  Snap%: 78%  (store: 20G)
      → Snapshot will be invalidated at 100% — consider merge or removal

  Thin pools: 1
  ✅ vg_data/docker_pool  Data: 42%  Meta: 12%
```

**Collapse rule:** if no LVM is detected, show one line: `ℹ️  LVM: not in use`.
If LVM is clean (all VGs > 15% free, no snapshots, no thin pools), show one line:
`✅ LVM: 2 VGs healthy`.

---

### Deep Variant Addition (`dsd disk deep`)

Add LVM RAID/mirror state inspection on top of the fast checks.
**Target runtime: < 200ms additional** (one `lvs --segments` call).

**Checks (in addition to everything in fast):**
1. Scan all LVs for mirror/RAID type (`lv_attr[0]` = 'm' for mirror, 'r' for RAID).
   For each:
   - Parse the health attribute (`lv_attr[8]`): 'a' = active, 'p' = partial
     (one or more PVs failed), 'r' = read-only
   - Parse the sync attribute: if `lv_attr[9]` = 'r', a resync is in progress
   - Show mirror count / RAID level, which PVs are involved, sync %
2. Show PV-level status for PVs that are part of degraded/resyncing LVs.
3. Cross-reference degraded mirror PVs against SMART status if SMART data
   is available from the physical device layer (already collected in `dsd disk deep`).

**Additional output in deep mode:**

```
[LVM RAID / mirrors]
  vg_data/lv_data1   raid1   2 images
  ❌ DEGRADED — lab3_rimage_1 (/dev/sdc1) missing
     → Run: lvconvert --repair vg_data/lv_data1

  vg_system/lv_home  mirror  2 images
  ⚠️  Resync in progress — 64% complete
     → Performance impact expected until sync completes
```

---

### `--json` Schema Addition

Added to the existing `dsd disk` JSON output under a new `lvm` key:

```json
"lvm": {
  "detected": true,
  "volume_groups": [
    {
      "name": "vg_data",
      "size_bytes": 257698037760,
      "free_bytes": 19327352832,
      "free_pct": 7.5,
      "status": "warn"
    }
  ],
  "snapshots": [
    {
      "name": "root_snap",
      "vg": "vg_data",
      "origin": "lv_root",
      "cow_size_bytes": 21474836480,
      "snap_pct": 78.3,
      "status": "warn"
    }
  ],
  "thin_pools": [
    {
      "name": "docker_pool",
      "vg": "vg_data",
      "data_pct": 42.1,
      "meta_pct": 12.3,
      "status": "ok"
    }
  ],
  "raid_mirrors": [
    {
      "name": "lv_data1",
      "vg": "vg_data",
      "type": "raid1",
      "images": 2,
      "degraded": true,
      "resyncing": false,
      "sync_pct": null,
      "missing_pvs": ["/dev/sdc1"],
      "status": "crit"
    }
  ]
}
```

---

### Collector Design Notes

**Commands used (all read-only, no root required for basic `lvs`/`vgs`):**

| Command | Purpose |
|---|---|
| `vgs --noheadings --units b -o vg_name,vg_size,vg_free` | VG free space |
| `lvs --noheadings -o lv_name,vg_name,lv_attr,lv_size,origin,snap_percent,data_percent,metadata_percent,pool_lv` | Snapshot + thin pool state |
| `lvs --noheadings --segments -o lv_name,vg_name,lv_attr,segtype,devices` | RAID/mirror detail (deep only) |

**Privilege note:** `lvs` and `vgs` typically require root or membership in the
`disk` group. DashDiag already requires elevated privileges for SMART — the same
privilege context covers LVM tools. On systems where LVM tools are absent (e.g.
cloud VMs without LVM), the entire section should be gracefully skipped.

**Cross-distro notes:**
- `lvs`/`vgs` are part of the `lvm2` package, present on RHEL, Debian, Ubuntu, Arch.
- On systems using `btrfs` subvolumes instead of LVM snapshots, this section will
  show "not in use" — that is correct. BTRFS health is covered separately in Spec 19.
- macOS: LVM is not used. Skip silently.

**Platform.Profile hook (Sprint 4):** When `platform.Profile` is built (Spec 8),
the LVM collector should query it for `HasLVM bool` rather than attempting `lvs`
and parsing an error. Until then, attempt `lvs` and handle the failure gracefully.

---

### Acceptance Criteria

- [ ] `dsd disk` fast: shows `[LVM overview]` section when LVM is detected
- [ ] `dsd disk` fast: collapses to single OK line when all LVM healthy
- [ ] `dsd disk` fast: collapses to single INFO line when LVM not in use
- [ ] Snapshot Snap% > 70% → WARN; > 90% → CRIT
- [ ] Thin pool Data% > 70% → WARN; > 90% → CRIT (Data and Meta checked separately)
- [ ] VG free% < 15% → WARN; < 5% → CRIT
- [ ] `dsd disk deep`: degraded RAID/mirror → CRIT with suggested repair command
- [ ] `dsd disk deep`: resync in progress → WARN with sync% shown
- [ ] Absent LVM tools (no `lvs` binary): section skipped, no error output
- [ ] No LVM volumes present: single INFO line, no section shown
- [ ] `--json` output valid against schema above
- [ ] Runtime budget: fast addition < 50ms; deep addition < 200ms additional

---

### Cross-references

- Spec 4 — `dsd disk` (parent spec — this is an addendum)
- Spec 4a — `dsd disk` fuser busy check (parallel addendum to Spec 4)
- Spec 19 — `dsd disk` SteamOS BTRFS health (separate storage layer, non-overlapping)
- Spec 8 — `platform.Profile` (plug-in point for `HasLVM` flag in Sprint 4)

---

## Spec 22 — `dsd steamos` + `dsd net` — Remote Play Readiness
*(New SteamOS-specific spec. Source: Steam Support — Steam Link Suggested Network Settings)*

**Sprint:** 4 (SteamOS specs block)
**Type:** Two sub-collectors — one addition to `dsd steamos`, one extension to Spec 20 (`dsd net` SteamOS Wi-Fi)
**Pain source:** Steam Remote Play fails silently. "Can't locate your computer" and choppy streaming are the two most common SteamOS support complaints. Both have specific, machine-readable signals that no existing DashDiag check surfaces.
**Estimated scope:** ~0.75d total (0.5d Remote Play port + AP isolation check, 0.25d Wi-Fi quality profile extension)

---

### Background: Two Distinct Failure Classes

Steam Remote Play breaks in two ways on SteamOS:

**Class 1 — Discovery failure ("can't locate your computer"):**
The Steam Link or remote client cannot find the host at all. Root causes:
- Remote Play ports not bound (Steam not running, Remote Play disabled in settings)
- AP client isolation enabled on the router — devices on the same Wi-Fi cannot reach each other even though both can reach the internet
- Firewall blocking the Steam ports on the host

**Class 2 — Streaming quality failure (choppy, stuttering, freezing):**
Discovery works but the stream is degraded. Root causes:
- Connected to 2.4GHz instead of 5GHz
- On a congested Wi-Fi channel
- Running 20MHz channel width instead of 40/80MHz
- High UDP jitter to the local gateway (router firmware bug with UDP traffic)

DashDiag's existing `dsd net` checks cover internet-facing quality (DNS timing, external jitter, retransmission rates). None of it is LAN-facing or Remote Play-aware.

---

### Part A — Remote Play Port Binding Check (addition to `dsd steamos`)

Only runs when `ID=steamos` in `/etc/os-release`.

**Steam Remote Play ports (from Valve documentation):**

| Protocol | Ports | Purpose |
|---|---|---|
| UDP | 27031, 27036 | Remote Play discovery and streaming |
| TCP | 27036, 27037 | Remote Play control channel |
| UDP | 10400, 10401 | VR streaming (optional) |

**Checks:**

1. **Port binding:** `ss -tulpn` — are the Remote Play ports actually bound?
   - If Steam is running and Remote Play is enabled, 27031/27036 UDP and 27036/27037 TCP should be listed
   - If ports are absent: WARN — Steam may not be running or Remote Play may be disabled
   - Show which process has each port bound (the `users:` field from `ss`)

2. **Firewall rules:** inspect active firewall for rules blocking these ports
   - Check `nft list ruleset 2>/dev/null` first (SteamOS uses nftables by default)
   - Fall back to `iptables -L INPUT -n 2>/dev/null` if nft absent
   - Flag WARN if a rule exists that would block any of the four primary Remote Play ports

3. **AP client isolation inference:**
   - Get the default gateway IP from the routing table (`ip route show default`)
   - Confirm gateway is reachable: `ping -c 1 -W 1 <gateway>`
   - Check ARP table: `ip neigh show` — if entries exist beyond the gateway, isolation is likely not in effect
   - If gateway responds but ARP table is empty (only gateway visible) after >120s uptime: WARN — AP client isolation may be enabled
   - Guard: skip this check if uptime < 120s (ARP table may not be populated yet)
   - Note: inferential, not conclusive — show as WARN with explanation, never CRIT

**Human-readable output (dsd steamos — new `[Remote Play]` section):**

```
[Remote Play]
  Ports bound:
  ✅ UDP 27031  steam (PID 1842)
  ✅ UDP 27036  steam (PID 1842)
  ✅ TCP 27036  steam (PID 1842)
  ✅ TCP 27037  steam (PID 1842)

  Firewall: no blocking rules found  ✅

  LAN peer visibility: 3 peers in ARP cache  ✅
```

**Degraded example:**

```
[Remote Play]
  Ports bound:
  ❌ UDP 27031  not bound
  ❌ UDP 27036  not bound
  ❌ TCP 27036  not bound
  ❌ TCP 27037  not bound
  → Start Steam and enable: Steam > Settings > Remote Play

  Firewall: 1 potential blocking rule  ⚠️
  → nftables rule may block UDP 27031 — run: nft list ruleset

  LAN peer visibility: 0 peers in ARP cache  ⚠️
  → AP client isolation may be active — disable in router settings
```

---

### Part B — Wi-Fi Quality Profile (extension to Spec 20)

Spec 20 currently detects: iwd vs wpa_supplicant backend, SSID dual-band conflict.

This extension adds the **actual connected Wi-Fi quality profile** — the specific values needed to diagnose Remote Play streaming degradation. All data from `iw dev <interface> info` — a single fast call, no scanning required.

**New checks (SteamOS only, `dsd net` fast variant):**

1. **Connected band:**
   - Parse `channel X (YYYY MHz)` from `iw dev` output
   - 2412–2484 MHz = 2.4GHz → WARN (interference-prone, suboptimal for Remote Play)
   - 5180–5825 MHz = 5GHz → OK

2. **Channel number:**
   - For 5GHz: channels 149–165 (top-of-band) → OK; channels 36–64 → INFO
   - For 2.4GHz: channels 1, 6, 11 (non-overlapping) → INFO; any other channel → WARN

3. **Channel width:**
   - Parse `width: XX MHz` from `iw dev` output
   - 20 MHz → WARN (half throughput of 40MHz)
   - 40 MHz → INFO (adequate)
   - 80 MHz or 160 MHz → OK (optimal for 802.11ac/ax)

4. **Signal strength (RSSI):**
   - From `iw dev <interface> link` → `signal: -XX dBm`
   - > -50 dBm: excellent
   - -50 to -65 dBm: OK
   - -65 to -75 dBm: WARN — marginal, streaming quality may degrade
   - < -75 dBm: CRIT — poor signal, move device closer to router

**Human-readable output:**

```
[Wi-Fi — Remote Play profile]
  Backend:    iwd  ✅
  Band:       5GHz  ✅
  Channel:    149 (5745 MHz)  ✅  (top-of-band — low congestion)
  Width:      80 MHz  ✅  (802.11ac optimal)
  Signal:     -52 dBm  ✅  (good)
```

**Degraded example:**

```
[Wi-Fi — Remote Play profile]
  Backend:    wpa_supplicant  ✅
  Band:       2.4GHz  ⚠️  (switch to 5GHz for Remote Play)
  Channel:    6 (2437 MHz)  ℹ️  (non-overlapping, but congested band)
  Width:      20 MHz  ⚠️  (narrow — check AP settings for 40/80MHz)
  Signal:     -71 dBm  ⚠️  (marginal — move closer to router)
```

**Collapse rule:** entire section suppressed on non-SteamOS systems.

---

### `--json` Schema Additions

**Remote Play ports (dsd steamos):**
```json
"remote_play": {
  "ports": [
    {"protocol": "udp", "port": 27031, "bound": true, "process": "steam", "pid": 1842},
    {"protocol": "udp", "port": 27036, "bound": true, "process": "steam", "pid": 1842},
    {"protocol": "tcp", "port": 27036, "bound": true, "process": "steam", "pid": 1842},
    {"protocol": "tcp", "port": 27037, "bound": true, "process": "steam", "pid": 1842}
  ],
  "firewall_blocking": false,
  "lan_peers_visible": 3,
  "ap_isolation_suspected": false,
  "status": "ok"
}
```

**Wi-Fi quality profile (dsd net — SteamOS extension):**
```json
"wifi_remote_play": {
  "band_ghz": 5,
  "channel": 149,
  "frequency_mhz": 5745,
  "width_mhz": 80,
  "signal_dbm": -52,
  "band_status": "ok",
  "channel_status": "ok",
  "width_status": "ok",
  "signal_status": "ok"
}
```

---

### Collector Design Notes

**`ss` parsing:** `ss -tulpn` is standard on SteamOS (Arch base). Parse lines containing the target port numbers. The `users:(("steam",pid=XXXX,...))` field gives process and PID directly — no secondary lookup needed.

**nftables vs iptables:** SteamOS uses nftables. Try `nft list ruleset 2>/dev/null` first; if exit code non-zero or binary absent, fall back to `iptables`. A missing binary with no rules loaded is the normal stock SteamOS state — treat as "no blocking rules" not as an error.

**ARP table uptime guard:** `cat /proc/uptime` and parse the first field (seconds). Skip AP isolation inference if uptime < 120.0. Below that threshold emit: `ℹ️ LAN peer check deferred — system recently booted`.

**Interface name detection:** Parse `iw dev` output for `Interface` field — do not hardcode `wlan0`. SteamOS Steam Deck uses `wlan0` by convention but this must not be assumed.

**Not-connected state:** If `iw dev <iface> link` returns "Not connected", skip the Wi-Fi quality profile and emit a single INFO line. No WARN/CRIT — can't stream anyway when disconnected.

**VR ports (10400/10401):** Check binding and show in output, but emit INFO (not WARN) if unbound. VR streaming is optional and will not be active on most SteamOS hosts.

---

### Acceptance Criteria

**Part A — Remote Play ports:**
- [ ] All four primary ports checked (UDP 27031/27036, TCP 27036/27037)
- [ ] Unbound ports show actionable message pointing to Steam settings
- [ ] Process name and PID shown for each bound port
- [ ] nftables checked first; iptables fallback on non-SteamOS or if nft absent
- [ ] Blocking firewall rule triggers WARN with suggested diagnostic command
- [ ] AP isolation inference skipped if uptime < 120s
- [ ] ARP table with ≥1 non-gateway peer = no isolation suspected
- [ ] Empty ARP table (gateway only) after 120s uptime = WARN with explanation
- [ ] VR ports shown as INFO (not WARN) when unbound
- [ ] Entire section absent on non-SteamOS systems
- [ ] `--json` output valid against schema above

**Part B — Wi-Fi quality profile:**
- [ ] Band correctly identified as 2.4GHz or 5GHz from frequency value
- [ ] 2.4GHz → WARN with Remote Play recommendation
- [ ] Channel number correctly derived from MHz value
- [ ] 5GHz channel 149–165 → OK; 36–64 → INFO
- [ ] 2.4GHz channels 1, 6, 11 → INFO; others → WARN
- [ ] Channel width: 20MHz → WARN; 40MHz → INFO; 80/160MHz → OK
- [ ] Signal: > -65 OK, -65 to -75 WARN, < -75 CRIT
- [ ] Entire section absent on non-SteamOS systems
- [ ] Not-connected state: single INFO line, no WARN
- [ ] Interface name detected dynamically
- [ ] `--json` output valid against schema above
- [ ] Runtime < 100ms (single `iw dev` call + `ss` call + `ip neigh`)

---

### Cross-references

- Spec 17 — `dsd steamos` (parent for Part A — Remote Play port check lives here)
- Spec 20 — `dsd net` SteamOS Wi-Fi (parent for Part B — Wi-Fi quality profile extends this)
- Spec 8 — `platform.Profile` (Sprint 4 — `IsSteamOS bool` flag used as gate for both parts)
- `dsd net deep` — existing UDP jitter/retransmission checks are internet-facing; this spec adds the LAN-facing complement

**Grand total update:** ~40.75d across 25 spec items (22 numbered + H1 + 4a + 10a).

---

## Spec 17a — `dsd steamos` Device Identity + Recovery Readiness
*(Addendum to Spec 17. Source: Steam Support — SteamOS Installation and Repair)*

**Sprint:** 3 (append to Spec 17 work — same collector file)
**Type:** Sub-collector addition to `dsd steamos`
**Pain source:** Spec 17 was written assuming Steam Deck as the only SteamOS device. SteamOS 3.7 officially adds Legion Go S and improves compatibility with ROG Ally, ROG Ally X, and other AMD handhelds. Without device identification, `/var` size thresholds, GPU thermal limits (Spec 18), and partition assumptions (Spec 19) will be wrong on non-Steam Deck hardware. Additionally, non-Steam Deck SteamOS users can be silently locked out of USB recovery if Secure Boot is enabled — detectable, actionable, not currently checked.
**Estimated scope:** ~0.25d (three small sysfs/efivars reads)

---

### Background: Why Device Identity Is Now Required

When Spec 17 was written, SteamOS meant Steam Deck. As of SteamOS 3.7, Valve's own support page lists these as SteamOS targets:

| Device | APU | Notes |
|---|---|---|
| Steam Deck LCD | AMD Van Gogh | Original model |
| Steam Deck OLED | AMD Sephiroth | Updated model |
| Lenovo Legion Go S | AMD Z2 Extreme | Official |
| ASUS ROG Ally | AMD Ryzen Z1 Extreme | Improved compat |
| ASUS ROG Ally X | AMD Ryzen Z1 Extreme | Improved compat |
| Other AMD handhelds | Various | Best-effort |

Each device has different: `/var` partition size, APU TDP envelope, thermal limits, RAUC partition names, and Secure Boot behaviour. A `dsd steamos` that doesn't know which device it's on cannot apply correct thresholds or flag the right warnings.

---

### What to Add to `dsd steamos` (fast variant header)

**1. Device model detection:**

Read `/sys/class/dmi/id/product_name` (no root required). Map to known models:

| `product_name` value | Canonical name | Notes |
|---|---|---|
| `Jupiter` | Steam Deck LCD | Original hardware rev |
| `Galileo` | Steam Deck OLED | 2023+ |
| Contains `ROG Ally RC71L` | ASUS ROG Ally | |
| Contains `ROG Ally X` | ASUS ROG Ally X | |
| Contains `83E1` or `Legion Go S` | Lenovo Legion Go S | |
| Other / unrecognised | Unknown AMD handheld | |

Show device model as the first line of `dsd steamos` output.
If unrecognised but SteamOS is confirmed (`ID=steamos` in `/etc/os-release`): show INFO `Unknown SteamOS device — thresholds may not be accurate`.

**2. SteamOS build version:**

Read `/etc/os-release` — parse `BUILD_ID` (the build number, e.g. `20240531.1`) and `VERSION_ID` (e.g. `3.7.0`). Show both in the header line alongside device model.

This feeds into: knowing whether known bugs in a specific build apply, and whether the user is on a current release.

**3. Secure Boot state (non-Steam Deck only):**

Steam Deck's firmware does not enforce Secure Boot for SteamOS — this check is suppressed on `Jupiter`/`Galileo` models.

For all other SteamOS devices:
- Read `/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c`
  Bytes 0–3 are EFI variable attributes. Byte 4 is the Secure Boot state: `0x01` = enabled.
- If EFI vars not accessible (non-UEFI system): skip silently.
- If Secure Boot enabled on non-Steam Deck SteamOS device: WARN
  `Secure Boot is enabled. Recovery from USB requires disabling it in BIOS first.`
  `→ See your device manufacturer's instructions to disable Secure Boot.`
- If Secure Boot disabled: single OK line (no detail needed).
- Fallback: if `/sys/firmware/efi/efivars/` not present → skip with INFO `EFI not available`.

---

### Human-Readable Output (additions to `dsd steamos` header)

**Steam Deck (clean):**
```
🎮 SteamOS
  Device:       Steam Deck OLED (Galileo)
  Build:        SteamOS 3.7.0 (build 20240531.1)
  Secure Boot:  n/a (Steam Deck)
  ...
```

**ROG Ally with Secure Boot issue:**
```
🎮 SteamOS
  Device:       ASUS ROG Ally
  Build:        SteamOS 3.7.0 (build 20240531.1)
  Secure Boot:  ⚠️  ENABLED — USB recovery requires BIOS change first
                → Hold Volume+ at boot → BIOS → Security → Secure Boot → Disabled
  ...
```

**Unknown device:**
```
🎮 SteamOS
  Device:       Unknown AMD handheld (DMI: "OEMDEVICE")
                ℹ️  Unrecognised model — hardware thresholds may not be accurate
  Build:        SteamOS 3.7.0 (build 20240531.1)
  ...
```

---

### `--json` Schema Addition

Add a `device` key at the top level of the `dsd steamos` JSON output:

```json
"device": {
  "product_name_raw": "Galileo",
  "canonical_name": "Steam Deck OLED",
  "recognised": true,
  "steamos_version": "3.7.0",
  "steamos_build_id": "20240531.1",
  "secure_boot_enabled": null,
  "secure_boot_applicable": false
}
```

`secure_boot_applicable: false` = Steam Deck (check suppressed).
`secure_boot_enabled: null` = EFI vars not readable (non-UEFI).
`secure_boot_enabled: true/false` = state read successfully.

---

### Collector Design Notes

**DMI read:** `/sys/class/dmi/id/product_name` is world-readable on all Linux systems. No root required. Single `os.ReadFile` call — no binary dependency.

**EFI var read:** `/sys/firmware/efi/efivars/` requires the `efivarfs` filesystem to be mounted. It is mounted by default on modern systemd distros including SteamOS. The file is world-readable. Parse as binary: skip first 4 bytes (EFI attributes), check byte 4 for the Secure Boot flag.

**Model matching:** Use `strings.Contains` matching rather than exact equality — DMI product names occasionally include revision suffixes. The table above is illustrative; add entries as new SteamOS-compatible hardware is confirmed.

**Version parsing:** `/etc/os-release` is a standard key=value file. Parse `VERSION_ID` and `BUILD_ID`. If `BUILD_ID` is absent (some builds omit it), show `VERSION_ID` only.

**Impact on other specs:**
The device model detected here should be passed to:
- Spec 17 (RAUC check): partition names differ by device
- Spec 18 (`dsd gpu`): thermal thresholds differ by APU
- Spec 19 (`dsd disk` SteamOS): `/var` size threshold differs by device

Until `platform.Profile` (Spec 8) is built, store the detected model in a package-level variable in `internal/collectors/steamos_collector.go` that other SteamOS collectors can import.

---

### Acceptance Criteria

- [ ] Steam Deck LCD (Jupiter) correctly identified
- [ ] Steam Deck OLED (Galileo) correctly identified
- [ ] ROG Ally correctly identified via DMI string
- [ ] Unrecognised device shows INFO with raw DMI string, does not crash
- [ ] `VERSION_ID` and `BUILD_ID` correctly parsed from `/etc/os-release`
- [ ] Secure Boot check suppressed on Jupiter and Galileo
- [ ] Secure Boot enabled on non-Steam Deck → WARN with device-appropriate instructions
- [ ] Secure Boot disabled → single OK line
- [ ] EFI vars not mounted → graceful INFO skip
- [ ] `--json` output valid against schema above
- [ ] No root required for any of these checks
- [ ] Entire spec adds < 5ms to `dsd steamos` runtime (all sysfs/file reads)

---

### Cross-references

- Spec 17 — `dsd steamos` (parent spec — add to same collector file)
- Spec 18 — `dsd gpu` (uses device model for thermal threshold selection)
- Spec 19 — `dsd disk` SteamOS BTRFS (uses device model for `/var` threshold)
- Spec 22 — Remote Play Readiness (uses `IsSteamOS` gate from platform detection)
- Spec 8 — `platform.Profile` (Sprint 4 — device model migrates to Profile struct)

**Grand total update:** ~58.25d across 51 spec items
(24 numbered + 17a + H1 + 4a + 4b + 10a + 7a–7o + 23a–23g).

Spec 7 detail: 4d core + 2.2d addendum = ~6.2d total.
Spec 23 detail: 5d fast + 5d deep (OS-layer moat) + 0.8d addendum = ~10.8d total.
Spec 24 detail: 2d fast + 2d deep (PVEPerf + backup audit) = ~4d total.
Spec 4b: +0.25d (ZFS pool health via zpool status).

---

## Spec 23 — `dsd k8s` (Full Spec)

**Sprint:** 3 (fast) / 4 (deep)
**Effort:** ~5d fast (extending existing code) + ~5d deep (OS-layer moat) = ~10d core.
Addendum items 23a–23g add ~0.8d. Total Spec 23: ~10.8d.
**Collector:** `internal/collectors/k8s.go` (already exists — extend in place)
**Command:** `cmd/k8s.go` (already exists — fast/deep split to add)
**Pain source:** kubectl/Lens/k9s are viewers. DashDiag is a diagnostician. No existing tool
correlates pod failures with OS-level signals (kubelet logs, CNI config, iptables, firewalld,
SELinux) without shelling into each node. This is the moat validated on Rocky 10.1 hardware.

---

### What Already Exists (Code)

**`internal/collectors/k8s.go`:**
- Detects `k3s kubectl` or `kubectl` binary
- `kubectl get nodes --no-headers` → Name, Status, Roles, Age, Version
- `kubectl get pods -A --no-headers` → Namespace, Name, Ready, Status, Restarts, Age
- Counts: NodesNotReady, CrashLooping (status contains "CrashLoop" or "Error"),
  Pending, PodsNotReady (0/N Running), HighRestarts (≥10)

**`internal/models/k8s.go`:**
`K8sInfo` struct with `Nodes`, `Pods`, summary counts, `Detected`, `KubeBin`.

**`cmd/k8s.go`:**
- Nodes table (✅/❌ by Status), all pods table, problem pods highlighted, summary line.
- No fast/deep split yet. No PVCs, events, node conditions, or resource usage.

---

### `dsd k8s` (fast) — Extending Existing Code
**Target runtime:** < 10 seconds on a 10-node cluster

#### What to add to the existing fast checks:

**1. Node Conditions (beyond Ready status)**

Change node query from `get nodes --no-headers` to `get nodes -o json`.
Parse `.status.conditions[]` array for each node. Conditions to surface:

| Condition | Bad value | Meaning |
|---|---|---|
| MemoryPressure | True | Node is under memory pressure; pod evictions may occur |
| DiskPressure | True | Disk nearly full on node; evictions and kubelet instability |
| PIDPressure | True | Node is running out of process IDs |
| NetworkUnavailable | True | CNI plugin not correctly configured on this node |
| Ready | False / Unknown | Node not contactable or unhealthy |

For nodes with any pressure condition True:
```
  ⚠️  worker-node-2  Ready  (MemoryPressure, DiskPressure)
```

**2. Recent Warning Events (cluster-wide)**

`kubectl get events -A --field-selector type=Warning --sort-by=.lastTimestamp --no-headers`

Parse: Namespace, Object (Kind/Name), Reason, Message, Count, Last-Seen.
Show top 10 most recent. Suppress if 0 events.

High-signal Reason codes to flag explicitly:
| Reason | Severity | Meaning |
|---|---|---|
| OOMKilling | ❌ CRIT | Container exceeded memory limit |
| BackOff | ⚠️ WARN | Repeated restart backoff |
| FailedScheduling | ⚠️ WARN | Pod cannot be placed on any node |
| FailedMount | ⚠️ WARN | Volume mount failure (PVC issue) |
| Unhealthy | ⚠️ WARN | Liveness/readiness probe failing |
| NodeNotReady | ⚠️ WARN | Node went down |
| EvictionThresholdMet | ⚠️ WARN | Node under pressure, evictions starting |

**3. PVC Health**

`kubectl get pvc -A --no-headers`

Parse: Namespace, Name, Status, Volume, Capacity, StorageClass.

| Status | Severity | Meaning |
|---|---|---|
| Bound | ✅ | PVC is correctly provisioned |
| Pending | ⚠️ WARN | No matching PV or provisioner not running |
| Lost | ❌ CRIT | Underlying PV was deleted; data may be lost |

If all Bound: single `✅ All PVCs bound` line.
If any Pending/Lost: show full table with status.

**4. Deployment and StatefulSet Status**

`kubectl get deployments -A --no-headers` → parse READY column (e.g. "2/3").
`kubectl get statefulsets -A --no-headers` → same.

Flag WARN when `ready < desired` for any Deployment or StatefulSet.
Include Deployment name, namespace, ready/desired, and age.

If all fully ready: single `✅ All Deployments and StatefulSets ready` line.

**5. Resource Usage (kubectl top)**

`kubectl top nodes --no-headers` → CPU(cores), CPU%, MEM(bytes), MEM%.
`kubectl top pods -A --no-headers` → top 10 by CPU or MEM.

Graceful skip if metrics-server not installed (exit code non-zero):
`ℹ️ kubectl top not available (metrics-server not detected — resource usage unknown)`

Thresholds: CPU > 80% WARN, CPU > 95% CRIT. MEM > 80% WARN, MEM > 95% CRIT.

**6. Services Without Endpoints**

`kubectl get endpoints -A -o json` → parse `.items[].subsets`.

A Service with an empty `.subsets` array has no matching pod. This causes connection
refused for any consumer of that service.

Filter out known headless system services that legitimately have no endpoints:
`kubernetes`, `kube-scheduler`, `kube-controller-manager`, `kube-etcd`.

For user-facing services with empty subsets: WARN.

**7. Cluster Info**

`kubectl version -o json` → server GitVersion, platform.
`kubectl config current-context` → cluster name for output header.
`kubectl get namespaces --no-headers | wc -l` → namespace count.

Show in output header:
```
🧱 Kubernetes Health  (cluster: production, context: admin@prod)
   Server: v1.30.2  |  Nodes: 5  |  Namespaces: 12
```

**8. ImagePullBackOff / ErrImagePull Detail**

For pods currently in `ImagePullBackOff` or `ErrImagePull` status (already in existing pod
loop), additionally surface the image name:
`kubectl get pod <name> -n <namespace> -o jsonpath='{.spec.containers[*].image}'`

Output:
```
  ❌ api-server   ImagePullBackOff   myregistry.io/api:v2.1.0
     → Verify image tag exists and registry credentials are configured
```

---

### `dsd k8s` Fast Output Example

```
🧱 Kubernetes Health  (cluster: prod-k3s, context: admin@prod-k3s)
   Server: v1.30.2 (k3s)  |  Nodes: 3  |  Namespaces: 8

[Nodes]
  ✅  control-plane-01   Ready   control-plane   14d   v1.30.2
  ❌  worker-01          NotReady  <none>         2d    v1.30.2
  ⚠️  worker-02          Ready   <none>          14d   v1.30.2
                         └ MemoryPressure: True (pod evictions may occur)

[Node Resource Usage] (via kubectl top)
  worker-02   CPU: 88%  MEM: 76%   ← WARN (CPU high)
  control-plane-01   CPU: 12%  MEM: 45%

[Recent Warning Events — last 10]
  ❌  default/api-server   OOMKilling   3m   Container api exceeded memory limit
  ⚠️  db/postgres-0        FailedMount  8m   Unable to mount volume "pgdata"
  ⚠️  default/worker       BackOff      12m  Back-off restarting failed container

[Pods]
  Healthy: 41   Problem: 3
  ❌  default      api-server-7d4b8c9f6-x2j9k   OOMKilled          restarts: 12
  ❌  default      api-server-7d4b8c9f6-k8p2m   ImagePullBackOff   myregistry.io/api:v2.1.0
  ⚠️  monitoring   prometheus-0               Pending            0d

[Deployments & StatefulSets]
  ❌  default/api-server        2/3 ready  (1 unavailable)
  ✅  All other Deployments and StatefulSets ready

[PVCs]
  ❌  db/pgdata       Lost     (underlying PV deleted — data risk)
  ⚠️  monitoring/pvc  Pending  (StorageClass "fast-ssd" not found)
  ✅  2 other PVCs bound

[Services]
  ⚠️  default/api-service   No endpoints (0 backing pods — connection refused)

────────────────────────────────────────────────────────
Checks: 18 | Passed: 12 | Warnings: 3 | Critical: 3
Next:
  → kubectl describe node worker-01
  → kubectl describe pod api-server-7d4b8c9f6-x2j9k
  → kubectl describe pvc pgdata -n db
  → dsd k8s deep
```

---

### `dsd k8s` (deep) — The OS-Layer Moat
**Target runtime:** < 30 seconds
**Linux only** (`//go:build linux`). Graceful INFO on macOS.
**Prerequisite:** Must be running on a k8s node (control plane or worker).

Everything in fast, plus the following OS-level checks that no kubectl viewer exposes:

**1. kubelet Health**

```go
// systemctl is-active kubelet
status := runCmd(ctx, "systemctl", "is-active", "kubelet")
// journalctl -u kubelet -n 30 --no-pager
journalLines := runCmd(ctx, "journalctl", "-u", "kubelet", "-n", "30", "--no-pager")
```

- If `inactive` or `failed`: ❌ CRIT — node will show NotReady immediately
- If `active`: scan journal for `level=error`, `E0`, `failed`, `could not`
- Report: last error line + count of error lines in last 30
- Fix hint: `systemctl restart kubelet` / `journalctl -u kubelet -n 100 --no-pager`

**2. containerd / CRI Health**

- `systemctl is-active containerd` → CRIT if inactive
- Socket check: `/run/containerd/containerd.sock` exists and is a socket
- Journal scan: `journalctl -u containerd -n 20 --no-pager` → scan for errors
- If `crictl` available: `crictl info 2>/dev/null` → parse `status.conditions[].ready`
- Flag WARN if containerd is running but CRI is not healthy

Note: k3s bundles containerd. On k3s: check `k3s-agent.service` or `k3s.service` instead.
Detect k3s by checking if `KubeBin == "k3s kubectl"` (already set in existing collector).

**3. CNI Plugin Readiness**

CNI failure is one of the most common causes of node NotReady and pod networking
problems. Three-part check:

*Part A — Config file:*
- Check `/etc/cni/net.d/` contains at least one `*.conf` or `*.conflist`
- If empty or absent: ❌ CRIT `CNI config directory empty — node cannot assign pod IPs`
- Parse first config file to detect plugin name (flannel/calico/cilium/weave/bridge)

*Part B — Plugin binary:*
- Check `/opt/cni/bin/` contains the expected binary for the detected plugin
  - Flannel: `flannel` binary must exist
  - Calico: `calico` and `calico-ipam` binaries
  - Cilium: cilium manages its own bins; check cilium-cni symlink
- If detected plugin binary missing: ❌ CRIT with download hint

*Part C — Flannel-specific:*
- Check `/run/flannel/subnet.env` exists and has non-empty `FLANNEL_SUBNET` and `FLANNEL_MTU`
- If missing: ❌ CRIT `Flannel subnet not assigned — pod networking will fail`
- Flannel DaemonSet running check via `kubectl get pods -n kube-system -l app=flannel`

**4. IP Forwarding**

- `cat /proc/sys/net/ipv4/ip_forward`
- If `0`: ❌ CRIT — all inter-pod and pod→service traffic will fail
- kubelet should set this on startup, but systemd-networkd or sysctl hardening can reset it
- Fix: `sysctl -w net.ipv4.ip_forward=1`
- Persist: `echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/99-kubernetes.conf && sysctl -p`

**5. iptables FORWARD Chain**

`iptables -t filter -L FORWARD -n --line-numbers 2>/dev/null`

Kubernetes pod routing requires the FORWARD chain to permit traffic between pod CIDRs
and the node. kube-proxy adds KUBE-FORWARD rules; Flannel/Calico add their own.

Check for:
- `KUBE-FORWARD` jump rule in FORWARD chain → kube-proxy is managing
- `ACCEPT` rule for pod CIDR (e.g. 10.244.0.0/16 for Flannel)
- If FORWARD chain is entirely DROP/REJECT with no pod CIDR accepts: ❌ CRIT

Fallback: if `iptables` exits non-zero (nftables-only system), check
`nft list chain ip filter FORWARD 2>/dev/null` instead.

Graceful skip if neither iptables nor nft available.

**6. firewalld masquerade (RHEL/Fedora only)**

Only run if `systemctl is-active firewalld` returns `active`.

- `firewall-cmd --query-masquerade 2>/dev/null`
- Flannel requires masquerade for pod → service CIDR traffic (SNAT on node egress)
- If masquerade disabled + Flannel detected: ⚠️ WARN
  `Flannel requires masquerade. Fix: firewall-cmd --permanent --add-masquerade && firewall-cmd --reload`
- Also check nftables backend (same as Spec 7k):
  parse `/etc/firewalld/firewalld.conf` for `FirewallBackend=nftables`
  If nftables + k8s: WARN — iptables rules silently dropped
  Fix A: switch to iptables backend. Fix B: use nftables-native kube-proxy mode.

**7. SELinux AVC Denials (containerd / kubelet / flannel)**

Only if `getenforce` returns `Enforcing` or `Permissive`.

```bash
# Attempt ausearch first (audit daemon)
ausearch -m avc -ts recent 2>/dev/null | grep -E "containerd|kubelet|flannel|calico|cilium"
# Fall back to journal audit messages
journalctl -t kernel --since "1 hour ago" 2>/dev/null | grep "avc: denied" | grep -E "containerd|kubelet|flannel"
```

- Report: count + last denial message + affected process
- Fix hints:
  - Boolean-first (same order as Spec 6 addendum): `getsebool -a | grep container`
  - If file context: `semanage fcontext` + `restorecon`
  - Last resort: `audit2allow`
- Note: `container_t` and `container_file_t` are the standard SELinux types for containerd

**8. Certificate Expiry (Control Plane Only)**

Only if `/etc/kubernetes/pki/` exists (indicates this is a kubeadm control plane node).

Approach A (preferred): if `kubeadm` binary available:
`kubeadm certs check-expiration 2>/dev/null` → parse output table

Approach B (always works): read each `*.crt` in `/etc/kubernetes/pki/` with Go x509:
```go
certPEM, _ := os.ReadFile("/etc/kubernetes/pki/apiserver.crt")
block, _ := pem.Decode(certPEM)
cert, _ := x509.ParseCertificate(block.Bytes)
daysLeft := time.Until(cert.NotAfter).Hours() / 24
```

Thresholds:
- > 30 days: ✅ OK
- 7–30 days: ⚠️ WARN — `Certificate expires in X days. Run: kubeadm certs renew all`
- < 7 days: ❌ CRIT — cluster authentication will fail imminently
- Already expired: ❌ CRIT — cluster likely non-functional

Key certs to check: `apiserver.crt`, `apiserver-kubelet-client.crt`,
`front-proxy-client.crt`, `etcd/server.crt`, `etcd/peer.crt`.

**9. etcd Health (Control Plane Only)**

Only if etcd pod running in kube-system (detect via `kubectl get pods -n kube-system | grep etcd`).

Preferred (no exec needed): check etcd pod Status and Restarts in the existing pod scan.
If etcd pod is CrashLooping or Pending: ❌ CRIT.

Optional exec (if etcd pod healthy): 
```bash
kubectl exec -n kube-system etcd-<node> -- \
  etcdctl endpoint health \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt \
  --key=/etc/kubernetes/pki/etcd/healthcheck-client.key
```

Report: healthy/unhealthy, has leader (split-brain detection).
Graceful skip if exec fails or etcd pod not found.

**10. HPA Status**

`kubectl get hpa -A --no-headers`

Parse: Namespace, Name, Reference, Targets, MinPods, MaxPods, Replicas.

| Condition | Severity | Meaning |
|---|---|---|
| Replicas == MaxPods | ⚠️ WARN | At scaling ceiling — load may not be absorbed |
| Targets shows `<unknown>` | ⚠️ WARN | Metrics-server issue — autoscaler cannot function |
| MinPods == MaxPods == 1 | ℹ️ INFO | HPA configured but scaling disabled |

If no HPAs: section not shown.

---

### `dsd k8s deep` Output Example

```
🧱 Kubernetes Health  (cluster: prod-k3s, context: admin@prod-k3s)
   Server: v1.30.2 (k3s)  |  Nodes: 3  |  Namespaces: 8

[... all fast checks ...]

[OS-Layer Diagnosis] (this node: worker-02)

  [kubelet]
    ✅  kubelet: active (running, 14 days)
    ⚠️  2 errors in recent kubelet log
       Last: "failed to get node info: context deadline exceeded"
       → journalctl -u kubelet -n 100 --no-pager

  [CRI — containerd]
    ✅  containerd: active, socket present
    ✅  CRI health: ok

  [CNI — Flannel]
    ✅  CNI config: /etc/cni/net.d/10-flannel.conflist (flannel)
    ✅  CNI binaries: flannel present in /opt/cni/bin/
    ❌  Flannel subnet: /run/flannel/subnet.env missing
       Flannel DaemonSet: flannel pod on this node = CrashLoopBackOff
       Pod IPs cannot be assigned. This node will show NotReady.
       → kubectl logs -n kube-system -l app=flannel
       → kubectl describe pod -n kube-system -l app=flannel

  [Networking]
    ✅  IP forwarding: enabled (net.ipv4.ip_forward = 1)
    ⚠️  iptables FORWARD: no KUBE-FORWARD rule found
       Pod-to-pod routing may be broken if kube-proxy is not running.
       → kubectl get pods -n kube-system -l k8s-app=kube-proxy
    ✅  firewalld: not active (skip)

  [SELinux]
    ⚠️  Mode: Enforcing | 3 AVC denials in last 1h
       containerd (container_runtime_t) DENIED write on /var/lib/rancher
       → getsebool -a | grep container
       → semanage fcontext -a -t container_var_lib_t '/var/lib/rancher(/.*)?'
          restorecon -Rv /var/lib/rancher

  [Certificates] (control plane detected)
    ⚠️  apiserver.crt expires in 18 days — renew soon
    ✅  apiserver-kubelet-client.crt: 340 days
    ✅  etcd/server.crt: 340 days
    → kubeadm certs renew all

  [etcd]
    ✅  etcd pod: running (1 restart in 14d)
    ✅  etcd health: healthy, has leader

  [HPA]
    ⚠️  default/api-hpa   3/3 replicas (AT CEILING — cannot scale further)
       Targets: 94%/80% CPU  ← current load above threshold

────────────────────────────────────────────────────────
Checks: 28 | Passed: 19 | Warnings: 7 | Critical: 2
Next:
  → kubectl logs -n kube-system -l app=flannel
  → kubeadm certs renew all
  → journalctl -u kubelet -n 100 --no-pager
  → restorecon -Rv /var/lib/rancher
```

---

### JSON Schema

```json
{
  "k8s": {
    "detected": true,
    "kube_bin": "k3s kubectl",
    "server_version": "v1.30.2",
    "cluster_context": "admin@prod-k3s",
    "node_count": 3,
    "namespace_count": 8,
    "nodes": [
      {
        "name": "worker-01",
        "status": "NotReady",
        "roles": "<none>",
        "version": "v1.30.2",
        "conditions": {
          "memory_pressure": false,
          "disk_pressure": false,
          "pid_pressure": false,
          "network_unavailable": true
        },
        "cpu_pct": 88,
        "mem_pct": 76
      }
    ],
    "pods": [
      {
        "namespace": "default",
        "name": "api-server-7d4b8c9f6-x2j9k",
        "ready": "0/1",
        "status": "OOMKilled",
        "restarts": 12,
        "age": "2h",
        "image": "myregistry.io/api:v2.0.1",
        "exit_code": 137
      }
    ],
    "deployments": [
      {
        "namespace": "default",
        "name": "api-server",
        "ready": 2,
        "desired": 3,
        "status": "warn"
      }
    ],
    "pvcs": [
      {
        "namespace": "db",
        "name": "pgdata",
        "status": "Lost",
        "storage_class": "local-path",
        "capacity": "20Gi"
      }
    ],
    "warning_events": [
      {
        "namespace": "default",
        "object": "pod/api-server-7d4b8c9f6-x2j9k",
        "reason": "OOMKilling",
        "message": "Container api exceeded memory limit",
        "count": 4,
        "age_min": 3
      }
    ],
    "services_without_endpoints": [
      {"namespace": "default", "name": "api-service"}
    ],
    "nodes_not_ready": 1,
    "crash_looping": 0,
    "pending": 1,
    "pods_not_ready": 1,
    "high_restarts": 1,
    "os_layer": {
      "kubelet_active": true,
      "kubelet_error_count": 2,
      "kubelet_last_error": "failed to get node info: context deadline exceeded",
      "containerd_active": true,
      "containerd_socket_present": true,
      "cni_config_present": true,
      "cni_plugin": "flannel",
      "cni_binary_present": true,
      "flannel_subnet_env_present": false,
      "ip_forward_enabled": true,
      "iptables_kube_forward_present": false,
      "firewalld_active": false,
      "selinux_mode": "Enforcing",
      "selinux_avc_count": 3,
      "selinux_last_denial": "containerd denied write on /var/lib/rancher",
      "cert_expiry": [
        {"name": "apiserver", "days_remaining": 18, "status": "warn"}
      ],
      "etcd_healthy": true,
      "etcd_has_leader": true,
      "hpa": [
        {
          "namespace": "default", "name": "api-hpa",
          "replicas": 3, "max_replicas": 3,
          "at_ceiling": true, "targets_unknown": false
        }
      ]
    }
  }
}
```

---

### Collector Design Notes

**kubectl vs API server direct:**
All fast checks shell out to `kubectl`. This is intentional — kubectl handles kubeconfig,
context, and auth automatically. The existing `k8sRun()` helper already does this cleanly.
Do not add a `client-go` dependency for the CLI tool.

**Fast/deep split implementation:**
Add `--deep` flag to `k8sCmd` (same pattern as `dsd net deep`).
Fast: run all checks in parallel goroutines, merge results.
Deep: run fast first, then OS-layer checks sequentially (they require local access).

**OS-layer checks gate:**
```go
// Only run OS-layer checks if we are on a k8s node
// Evidence: kubelet process running, or /etc/kubernetes/pki/ exists,
// or /run/flannel/subnet.env exists, or /etc/cni/net.d/ exists
func isK8sNode() bool {
    for _, path := range []string{
        "/etc/kubernetes/pki",
        "/etc/cni/net.d",
        "/run/flannel",
        "/var/lib/kubelet",
    } {
        if _, err := os.Stat(path); err == nil {
            return true
        }
    }
    return false
}
```

If not on a k8s node (e.g. running from a laptop with kubectl configured):
Skip OS-layer section entirely with INFO:
`ℹ️  OS-layer checks skipped (not running on a k8s node — no kubelet/CNI detected)`

**k3s vs kubeadm differences:**
| Feature | k3s | kubeadm |
|---|---|---|
| kubectl bin | `k3s kubectl` | `kubectl` |
| containerd | bundled (`k3s service`) | separate (`containerd.service`) |
| systemd service | `k3s.service` or `k3s-agent.service` | `kubelet.service` |
| pki certs | `/var/lib/rancher/k3s/server/tls/` | `/etc/kubernetes/pki/` |
| CNI | bundled Flannel or external | external only |

Detect k3s by `KubeBin == "k3s kubectl"`. Adjust service name and cert path accordingly.
For k3s cert path: `/var/lib/rancher/k3s/server/tls/*.crt`.

**Concurrency:**
- Fast checks: run kubectl commands in parallel goroutines (nodes, pods, pvcs, deployments,
  events, endpoints, top — all independent). Use `sync.WaitGroup` or errgroup.
- Deep checks: OS-layer runs after fast completes (sequential is fine — local reads are fast).

---

### Validation Notes

**k3s on Rocky/RHEL 10 (kernel 6.12) — known issues from BACKLOG.md:**
- nftables masquerade issues: Spec 23 deep check 6 explicitly tests for this
- Flannel on RHEL with firewalld: Spec 23 deep checks 5+6 cover the iptables/firewalld combination
- Collector code already tested against running k3s cluster (from BACKLOG.md validation note)
- Full validation needed: set up deliberate failures (kill flannel DaemonSet, disable masquerade,
  expire a test cert, disable ip_forward) and verify DashDiag catches each

**Test matrix for `dsd k8s`:**
- k3s on Rocky/RHEL 10 (bare metal RHEL laptop, available) — PRIMARY
- kubeadm on Ubuntu 22.04 VM or `kind` — SECONDARY
- Multi-node cluster (at least 1 worker) for node-level checks
- Deliberate failure scenarios to validate each deep check:
  - Stop flannel pod → verify CNI check fires
  - `sysctl -w net.ipv4.ip_forward=0` → verify IP forwarding check fires
  - Create PVC with non-existent StorageClass → verify PVC Pending check fires
  - Scale deployment to 0 → verify services-without-endpoints check fires

---

### Acceptance Criteria

**Fast:**
- [ ] Node conditions (MemoryPressure/DiskPressure/PIDPressure) shown per node
- [ ] Warning events show top 10, suppress if none
- [ ] OOMKilling and FailedMount events explicitly flagged
- [ ] PVCs: Pending flags WARN, Lost flags CRIT, all Bound shows single OK line
- [ ] Deployments: ready < desired shows WARN with ratio
- [ ] `kubectl top` gracefully skipped if metrics-server absent
- [ ] Services with empty endpoints flagged (system services excluded)
- [ ] ImagePullBackOff shows image name
- [ ] Cluster info (server version, node count, namespace count) in output header
- [ ] `--json` valid against schema
- [ ] Fast runs in < 10s on a 10-node cluster
- [ ] Graceful INFO when kubectl not found (existing behaviour preserved)

**Deep:**
- [ ] kubelet service status shown; CRIT if stopped
- [ ] kubelet journal error count + last error shown
- [ ] containerd service status and socket check shown
- [ ] CNI config directory check: CRIT if empty
- [ ] CNI plugin binary check: CRIT if missing
- [ ] Flannel subnet.env check: CRIT if missing when Flannel is the plugin
- [ ] IP forwarding: CRIT if disabled
- [ ] iptables FORWARD: WARN if no KUBE-FORWARD rule
- [ ] firewalld masquerade: WARN if disabled + Flannel active
- [ ] nftables backend: WARN if active with k8s (RHEL)
- [ ] SELinux AVC denials: count + last denial + fix hint (if SELinux enforcing)
- [ ] Certificate expiry: WARN < 30 days, CRIT < 7 days (control plane only)
- [ ] etcd health shown (control plane only); graceful skip on worker nodes
- [ ] HPA at-ceiling flagged; targets unknown flagged
- [ ] OS-layer section skipped with INFO when not on a k8s node
- [ ] k3s vs kubeadm: service name and cert path correctly chosen
- [ ] Deep runs in < 30s
- [ ] `--json` includes `os_layer` object

---

### Cross-references

- Spec 7f — IP forwarding check (same sysctl, different command context)
- Spec 7k — firewalld nftables backend (same check, surfaces in k8s deep)
- Spec 6 addendum — SELinux AVC diagnosis order (boolean-first rule applies here too)
- BACKLOG.md `[HIGH VALUE] dsd k8s --deep` — this spec is the full implementation of that note
- BACKLOG.md validation note: k3s on Rocky/RHEL 10 nftables masquerade issue — covered by deep checks 5+6

---

## Spec 23a — `dsd k8s` Pods Stuck in Terminating

**Sprint:** 3 (addendum to Spec 23 fast — pod scanner extension)
**Effort:** +0.15d
**Source:** kubernetes.io Debug Pods guide
**Pain source:** A pod stuck in Terminating for > 5 minutes means the control plane cannot
delete the Pod object. This is caused by a finalizer held by an admission webhook that is
is blocking the removal. The pod shows in `kubectl get pods` indefinitely. No existing
DashDiag check surfaces this — it looks identical to a normal Running pod to the output.

### What to add

Extend the pod scan from `--no-headers` to `-o json` (already needed for init containers
in 23b and termination messages in 23c — one shared `kubectl get pods -A -o json` call
replaces multiple `--no-headers` calls; the JSON response contains all needed fields).

For each pod: parse `.metadata.deletionTimestamp`. If non-null and
`now - deletionTimestamp > 5 minutes`: pod is stuck in Terminating.

Additional context from the same JSON:
- `.metadata.finalizers[]` — which finalizer is blocking
- `.metadata.ownerReferences[]` to identify the controller type

If any stuck-terminating pods found: run one additional check:
`kubectl get validatingwebhookconfigurations --no-headers 2>/dev/null`
`kubectl get mutatingwebhookconfigurations --no-headers 2>/dev/null`
Report count of webhook configurations as a potential cause.

**Output:**
```
[Pods]
  ⚠️  default/old-migrator   Terminating  (stuck 23 min)
     Finalizers: ["kubernetes.io/pvc-protection"]
     3 ValidatingWebhookConfigurations present (may be blocking deletion)
     → kubectl describe pod old-migrator -n default
     → kubectl get validatingwebhookconfigurations
     → kubectl patch pod old-migrator -n default \
         -p '{"metadata":{"finalizers":null}}' --type=merge
```

**JSON addition per pod:**
```json
"terminating_stuck": true,
"terminating_since_min": 23,
"finalizers": ["kubernetes.io/pvc-protection"]
```

**Acceptance criteria:**
- [ ] Pod with deletionTimestamp set + > 5min flags WARN
- [ ] Pod with deletionTimestamp + non-empty finalizers shows finalizer names
- [ ] ValidatingWebhookConfiguration count shown when pod is stuck
- [ ] Pods terminating for < 5min not flagged (normal graceful shutdown)
- [ ] `--json` includes `terminating_stuck` and `terminating_since_min`
- [ ] No additional API calls when no pods are stuck

---

## Spec 23b — `dsd k8s` Init Container Status

**Sprint:** 3 (addendum to Spec 23 fast — pod scanner extension)
**Effort:** +0.15d
**Source:** kubernetes.io Debug Init Containers guide
**Pain source:** The current pod scanner checks `strings.Contains(p.Status, "CrashLoop")`
which catches `Init:CrashLoopBackOff` but misses `Init:Error`. More critically, when
an init container is failing, the pod STATUS column only shows the aggregate
(`Init:CrashLoopBackOff`) — not which init container is failing or what it logged.
Finding the root cause requires knowing the init container name to run
`kubectl logs <pod> -c <init-container>`.

### What to add

Extend pod status parsing to recognise init container status prefixes explicitly.
These come from the `-o json` call already introduced in 23a:

**Status classification:**

| STATUS value | Severity | Meaning |
|---|---|---|
| `Init:Error` | ⚠️ WARN | Init container exited non-zero once |
| `Init:CrashLoopBackOff` | ❌ CRIT | Init container in crash loop |
| `Init:N/M` (N < M) | ℹ️ INFO | Init container running (expected) |

For pods with Init:Error or Init:CrashLoopBackOff: parse
`.status.initContainerStatuses[]` from the JSON to find which init container
has `ready: false` and `lastState.terminated.exitCode != 0`. Surface the name,
exit code, and restart count.

**Output:**
```
[Pods]
  ❌  default/api-server   Init:CrashLoopBackOff   restarts: 5
     Failing init container: wait-for-db
     Exit code: 1 | Restarts: 5
     → kubectl logs api-server -n default -c wait-for-db
     → kubectl logs api-server -n default -c wait-for-db --previous
```

**JSON addition per pod:**
```json
"init_container_failing": "wait-for-db",
"init_container_exit_code": 1,
"init_container_restarts": 5
```

**Acceptance criteria:**
- [ ] `Init:Error` flagged as WARN
- [ ] `Init:CrashLoopBackOff` flagged as CRIT
- [ ] Failing init container name surfaced with exit code and restart count
- [ ] `kubectl logs -c <name>` and `--previous` hints both shown
- [ ] `Init:N/M` shown as INFO only (not a problem — init containers are expected to run)
- [ ] Uses `.status.initContainerStatuses[]` from the shared `-o json` pod fetch (23a)
- [ ] `--json` includes `init_container_failing` when applicable

---

## Spec 23c — `dsd k8s` Termination Message for Crashed Pods

**Sprint:** 3 (addendum to Spec 23 fast — pod scanner enrichment)
**Effort:** +0.10d
**Source:** kubernetes.io "Determine the Reason for Pod Failure"
**Pain source:** When a container crashes, it can write a human-readable reason to
`/dev/termination-log` (the default `terminationMessagePath`). This surfaces in
`status.containerStatuses[].lastState.terminated.message`. It is often a one-line
explanation of the crash — more useful than guessing from exit code alone, and
available with zero extra API calls (already in the `-o json` pod response from 23a).

### What to add

For each pod in CrashLoopBackOff, OOMKilled, or Error status:
parse `.status.containerStatuses[0].lastState.terminated.message` from the JSON.

If non-empty:
- Show as `Last termination:` sub-line under the problem pod entry
- Truncate at 200 characters
- Show only the first non-blank line (skip stack traces beyond first line)

This costs zero additional API calls — the termination message is in the same
`kubectl get pods -A -o json` response already introduced in 23a.

**Output change:**
```
# Before:
  ❌  default/api-server   CrashLoopBackOff   restarts: 8

# After:
  ❌  default/api-server   CrashLoopBackOff   restarts: 8
     Last termination: "database connection refused: dial tcp 10.0.0.5:5432"
```

**JSON addition per pod:**
```json
"last_termination_message": "database connection refused: dial tcp 10.0.0.5:5432"
```

**Acceptance criteria:**
- [ ] CrashLoopBackOff pods with non-empty termination message → message shown
- [ ] OOMKilled pods with termination message → message shown
- [ ] Empty or whitespace-only termination message → no change to output
- [ ] Message truncated at 200 chars; only first non-blank line shown
- [ ] Zero extra API calls — uses data already in 23a JSON response
- [ ] `--json` includes `last_termination_message` (omitted if empty)

---

## Spec 23d — `dsd k8s` deep kube-proxy Pod Health

**Sprint:** 3 (addendum to Spec 23 deep — extension of networking section)
**Effort:** +0.10d
**Source:** kubernetes.io Debug Services guide
**Pain source:** Spec 23 deep check 5 checks the iptables FORWARD/KUBE-FORWARD chain.
When that check fires (no KUBE-FORWARD rule), the root cause is almost always kube-proxy
being down or crashing. Explicitly surfacing kube-proxy pod health names the culprit
directly rather than leaving the admin to work backward from missing iptables rules.

### What to add to the `[Networking]` deep section

**Check:**
Look at the already-fetched pod list for pods in `kube-system` namespace with labels
`k8s-app=kube-proxy`. These are in the pod scan results from Spec 23 fast — no
additional kubectl call needed.

Expected state: all kube-proxy pods Running, restarts low.

If no kube-proxy pods found in kube-system: check if k3s (embedded kube-proxy).
- `KubeBin == "k3s kubectl"` → INFO "kube-proxy embedded in k3s (no separate pod)"

If kube-proxy pods found but unhealthy (CrashLoop, Error, Pending):
Additional call for logs: `kubectl logs -n kube-system -l k8s-app=kube-proxy --tail=10`
Scan for error lines. Show last error.

**Output (in `[OS-Layer Diagnosis]` section):**
```
[Networking]
  ...
  ❌  iptables FORWARD: no KUBE-FORWARD rule
  ❌  kube-proxy pod: CrashLoopBackOff (restarts: 12)
     Last log: "Failed to execute iptables-restore: exit status 1"
     → kubectl logs -n kube-system -l k8s-app=kube-proxy
     → kubectl describe pod -n kube-system -l k8s-app=kube-proxy
```

**When kube-proxy is healthy:**
```
[Networking]
  ✅  iptables FORWARD: KUBE-FORWARD present
  ✅  kube-proxy: 3 pods running (DaemonSet)
```

**JSON addition:**
```json
"kube_proxy_pods_healthy": false,
"kube_proxy_pod_count": 1,
"kube_proxy_last_error": "Failed to execute iptables-restore: exit status 1"
```

**Acceptance criteria:**
- [ ] kube-proxy pods in CrashLoop or missing → CRIT in networking section
- [ ] kube-proxy crash log shown (last error line)
- [ ] k3s: shows INFO (no kube-proxy pod expected — embedded)
- [ ] All kube-proxy pods healthy: single OK line
- [ ] Uses already-fetched pod list (no extra API call when pods are healthy)
- [ ] `--json` includes `kube_proxy_pods_healthy`

---

## Spec 23e — `dsd k8s` deep KUBE-SERVICES Chain Check

**Sprint:** 3 (addendum to Spec 23 deep check 5 — iptables extension)
**Effort:** +0.10d
**Source:** kubernetes.io Debug Services guide (iptables mode section)
**Pain source:** Spec 23 deep check 5 checks the FORWARD chain for pod-to-pod routing.
But the KUBE-SERVICES chain controls ClusterIP → pod DNAT routing (accessing services
by their cluster IP). If kube-proxy is running but KUBE-SERVICES has no entries, all
service connections are dropped silently — a different failure mode than the FORWARD
chain check catches.

### What to add

Extend deep check 5 with two additional sub-checks:

**Sub-check A — KUBE-SERVICES entries (iptables mode):**
```bash
iptables-save -t nat 2>/dev/null | grep -c "^-A KUBE-SERVICES"
```
If 0 entries: WARN. Expected: at least 2 (kubernetes + kube-dns services minimum).

**Sub-check B — KUBE-SVC chains (per-service chains):**
```bash
iptables-save -t nat 2>/dev/null | grep -c "^:KUBE-SVC-"
```
If 0: same implication as no KUBE-SERVICES entries.

**IPVS mode detection:**
If `iptables-save` returns empty KUBE-SERVICES but kube-proxy pod is present:
Check proxy mode from kube-proxy pod logs:
`kubectl logs -n kube-system -l k8s-app=kube-proxy --tail=30 2>/dev/null | grep -i "proxier"`

If `Using ipvs Proxier` found:
- Switch to IPVS check: `ipvsadm -ln 2>/dev/null | grep -c "^TCP"`
- If 0 TCP virtual servers: WARN
- If > 0: OK (IPVS is managing service routing)

If `Using iptables Proxier` found:
- KUBE-SERVICES=0 is a real problem

**Output:**
```
[Networking]
  ✅  iptables FORWARD: KUBE-FORWARD present
  ✅  kube-proxy: 3 pods running
  ⚠️  iptables KUBE-SERVICES: 0 entries
     Service ClusterIP routing is not programmed.
     kube-proxy may not have synced yet, or mode mismatch.
     → iptables -t nat -L KUBE-SERVICES -n --line-numbers
     → kubectl logs -n kube-system -l k8s-app=kube-proxy --tail=50
```

**JSON addition:**
```json
"iptables_kube_services_count": 0,
"iptables_kube_svc_chains": 0,
"kube_proxy_mode": "iptables"
```

**Acceptance criteria:**
- [ ] KUBE-SERVICES with 0 entries triggers WARN
- [ ] KUBE-SERVICES with > 0 entries: OK
- [ ] IPVS mode detected via kube-proxy pod logs
- [ ] IPVS mode: ipvsadm checked for virtual server count
- [ ] Graceful skip if iptables-save not available
- [ ] Not run if kube-proxy known absent (k3s embedded mode)
- [ ] `--json` includes `iptables_kube_services_count` and `kube_proxy_mode`

---

## Spec 23f — `dsd k8s` Unknown Pod Status

**Sprint:** 3 (addendum to Spec 23 fast — single addition to pod scanner)
**Effort:** +0.05d
**Source:** kubernetes.io Debug StatefulSet guide; kubernetes.io Troubleshooting Clusters
**Pain source:** When a node becomes unreachable (network partition, node crash),
pods on that node transition to `Unknown` status after ~5 minutes. `Unknown` pods
are not detected by the existing problem pod filter which only checks for
CrashLoop/Error/Pending/OOMKilled/0-ready. `Unknown` is especially dangerous for
StatefulSet pods because the controller will not create a replacement until the
existing pod is deleted (it cannot tell if the pod is still running on the partitioned node).

### What to add

One-line addition to the problem pod detection switch in the existing pod loop:

```go
case p.Status == "Unknown":
    info.UnknownStatus++
    // Add to problem pods list with WARN severity
```

For Unknown pods, additionally parse `.spec.nodeName` (available in `-o json` from 23a)
and `.metadata.ownerReferences[0].kind` to detect StatefulSet ownership.

**Output:**
```
[Pods]
  ⚠️  default/postgres-0   Unknown
     Node: worker-03 (may be unreachable)
     Owner: StatefulSet/postgres
     StatefulSet will not reschedule until this pod is deleted.
     → kubectl describe pod postgres-0 -n default
     → kubectl describe node worker-03
     → kubectl delete pod postgres-0 -n default  (only if node confirmed dead)
```

**JSON addition:**
`"unknown_status": 1` added to existing summary counts alongside `crash_looping`, `pending`.

Per-pod JSON:
```json
"status": "Unknown",
"node_name": "worker-03",
"owner_kind": "StatefulSet",
"owner_name": "postgres"
```

**Acceptance criteria:**
- [ ] Pod in Unknown status appears in problem pods list as WARN
- [ ] `UnknownStatus` counter added to `K8sInfo` struct + JSON summary
- [ ] Node name shown for Unknown pods
- [ ] StatefulSet ownership surfaced with scheduling-blocked warning
- [ ] Unknown pods from Deployments/ReplicaSets: note that new pods will be created
- [ ] Uses already-fetched `-o json` data (no extra API call)

---

## Spec 23g — `dsd k8s` Previous Container Logs for CrashLoopBackOff

**Sprint:** 3 (addendum to Spec 23 fast — enrichment for crashing pods)
**Effort:** +0.15d
**Source:** kubernetes.io Debug Running Pods; kubernetes.io Debug Init Containers
**Pain source:** For a pod in CrashLoopBackOff, `kubectl logs <pod>` often returns empty
or truncated output because the container crashes before it logs much. The critical
diagnostic data is in the *previous* container instance's logs, accessed via
`kubectl logs <pod> --previous`. This is the single most useful manual action for
CrashLoop diagnosis and it costs one extra API call per crashing pod — worth it.

### What to add

For each pod currently in CrashLoopBackOff with `restarts >= 3`:
```go
out, err := k8sRun(ctx, bin,
    "logs", p.Name, "-n", p.Namespace,
    "--previous", "--tail=10",
)
```

**Rules:**
- Only run for `restarts >= 3` (skip first 1–2 restarts — no previous instance yet)
- Cap at **5 pods total** per invocation (avoid slow clusters with many crashes)
- Prioritise by restart count (highest first)
- Skip gracefully if `--previous` returns error (`previous terminated container not found`)
- Strip blank lines; keep up to 10 non-blank lines
- Show in a dedicated `[CrashLoopBackOff details]` section, not inline in pods table

**Output:**
```
[CrashLoopBackOff details]
  ❌  default/api-server (restarts: 8)
     Last crash log:
       "Error: DATABASE_URL environment variable is not set"
       "Process exiting with code 1"
     → kubectl logs api-server -n default --previous
     → kubectl describe pod api-server -n default

  ❌  default/worker (restarts: 4)
     Last crash log:
       "panic: runtime error: invalid memory address or nil pointer dereference"
       "goroutine 1 [running]:"
     → kubectl logs worker -n default --previous
```

If no CrashLoopBackOff pods with >= 3 restarts: section not shown.

**JSON addition per crashing pod:**
```json
"previous_log_tail": [
  "Error: DATABASE_URL environment variable is not set",
  "Process exiting with code 1"
]
```

**Implementation notes:**
- Run these log fetches concurrently (goroutines) with a timeout of 5s per pod
- Show previous logs in `--json` output as array (up to 10 lines); never mid-line truncate
- In human output: indent with 7 spaces to align under the pod entry
- The `[CrashLoopBackOff details]` section appears after `[Pods]` and before `[Deployments]`

**Acceptance criteria:**
- [ ] CrashLoopBackOff pods with >= 3 restarts get previous log tail (up to 10 lines)
- [ ] Previous log shown in dedicated section (not inline in all-pods table)
- [ ] Empty previous logs: pod entry skipped in section (section still shown for others)
- [ ] No previous container instance: graceful skip (no error)
- [ ] Cap at 5 pods fetched; highest restart count prioritised
- [ ] Section entirely absent when no qualifying pods
- [ ] `--json` includes `previous_log_tail` array per crashing pod
- [ ] Concurrent fetches with 5s per-pod timeout

---

## Spec 24 — `dsd pve` (Full Spec)

**Sprint:** 4
**Effort:** ~2d fast + ~2d deep = ~4d total
**Collector:** `internal/collectors/pve.go` (new file)
**Command:** `cmd/pve.go` (new file)
**Pain source:** Proxmox is the most common home lab and SMB hypervisor. DashDiag
already tests on Proxmox hardware and Spec 4b (ZFS) targets it directly. Yet there
is no command that answers: are my VMs running, is my storage healthy, is my cluster
quorate, and is my storage I/O degraded? A sysadmin walks up to a slow Proxmox
node and currently has to know which of six different tools to run. `dsd pve` does it
in one shot.

### Gate

```go
func isProxmox() bool {
    _, err := os.Stat("/usr/share/pve-manager")
    return err == nil
}
```

This directory is always present on Proxmox VE nodes (part of `pve-manager` package).
`which pvesh` is a fallback check. Graceful INFO and exit on non-PVE hosts:
`ℹ️  Not a Proxmox VE node — dsd pve requires a Proxmox host`

### Fast Checks (target: < 5s)

**1. Node overview**
Source: `pvesh get /nodes/localhost/status --output-format json`

Surface:
- Proxmox version (from `/etc/pve/local/pve-ssl.pem` CN or `pveversion -v`)
- Kernel version
- CPU usage % (aggregate across all cores)
- Memory: used/total GB
- Uptime

Output:
```
[Proxmox Node]
  Host:     pve-node1   PVE 8.2.2 / kernel 6.8.4-3-pve
  CPU:      12% used (8 cores)
  Memory:   18.2 / 31.9 GB
  Uptime:   14 days
```

**2. VM and container status**
Sources:
- `pvesh get /nodes/localhost/qemu --output-format json` (VMs)
- `pvesh get /nodes/localhost/lxc --output-format json` (containers)

For each VM/CT: name, status (running/stopped/paused), vmid, onboot flag.

Flags:
- `status=paused` → WARN (unexpected — usually means a live-migration hung)
- `status=error` → CRIT
- `onboot=1` AND `status=stopped` → WARN (autostart VM not running after boot)

Output:
```
[VMs & Containers]  (12 running, 2 stopped, 0 paused)
  ⚠️  101  db-server     stopped   [autostart ON — should be running]
  ⚠️  205  dev-ct        paused    [unexpected pause state]
  ℹ️  108  backup-ct     stopped   [autostart OFF]
```

Stopped VMs with autostart OFF: show only as INFO count, not per-VM (noise).

**3. Storage pool health**
Source: `pvesh get /nodes/localhost/storage --output-format json`

For each configured storage: name, type (dir/lvm/zfs/nfs/cifs/rbd), active, used/total.

Flags:
- `active=0` → CRIT (storage unavailable — VMs on it cannot migrate or backup)
- usage > 85% → WARN
- usage > 95% → CRIT
- NFS/CIFS storage: check if mounted (`pvesh` active field covers this)

Output:
```
[Storage]
  ✅  local-lvm   lvm-thin   245 / 930 GB  (26%)
  ✅  local       dir        12 / 100 GB   (12%)
  ❌  nfs-backup  nfs        — UNAVAILABLE (mount failed or NFS server down)
     → pvesh get /nodes/localhost/storage/nfs-backup/status
     → systemctl status nfs-client.target
```

**4. Recent task errors**
Source: `pvesh get /nodes/localhost/tasks --limit 50 --output-format json`

Filter for tasks with `status` containing "ERROR" or `exitstatus` != "OK" in last 24h.
Group by type (backup/migration/resize/snapshot) and count.

Flags: any task error → WARN. 3+ task errors of same type → CRIT.

Output:
```
[Recent Tasks]  (last 24h)
  ⚠️  2 backup errors
     vzdump 101 db-server — 05:42 — "No space left on device"
     vzdump 108 backup-ct — 05:43 — "No space left on device"
     → pvesh get /nodes/localhost/tasks --typefilter=vzdump
```

**5. Cluster quorum** (only if clustered)
Source: `pvesh get /cluster/status --output-format json`
Gate: check if `/etc/pve/corosync.conf` exists (single-node PVE has no corosync).

Flags:
- quorate=0 → CRIT (split-brain or node isolation)
- Any node with `online=0` → WARN (cluster member unreachable)

Output:
```
[Cluster]  (3-node cluster: pve1, pve2, pve3)
  ✅  Quorate: yes
  ⚠️  pve3: offline (last seen 8 min ago)
     → pvecm status
     → journalctl -u corosync -n 50
```

**6. Subscription status**
Source: `pvesh get /nodes/localhost/subscription --output-format json`

Shown as INFO only (no subscription = valid free tier). Flags:
- `status=Active` + `serverid` present → ✅ INFO
- `status=NotFound` → ℹ️ INFO (free tier, no warnings in output)
- `status=Active` + days_until_expiry < 30 → ⚠️ WARN

Never shown as CRIT — no subscription doesn't break Proxmox.

### Deep Checks (target: < 30s)

**7. PVEPerf storage benchmark**
Binary: `pveperf` (installed with `proxmox-ve` package, at `/usr/bin/pveperf`)
Gate: `which pveperf 2>/dev/null` — skip gracefully if absent.

Run:
```bash
pveperf /var/lib/vz 2>/dev/null   # tests default VM storage path
```

If `/var/lib/vz` doesn't exist, fall back to `/tmp`.
Runtime: ~5–10 seconds. Writes ~1MB of temp data (cleaned up by pveperf itself).

Parse output key-value pairs:
| Metric | WARN threshold | CRIT threshold | Note |
|---|---|---|---|
| `FSYNCS/SEC` | < 500 | < 100 | Critical for VM stability |
| `HDPARM MB/s` | < 200 | < 50 | Sequential read throughput |
| `DD MB/s` | < 100 | < 30 | Sequential write throughput |
| `FIO randwrite` | < 100 IOPS | < 20 IOPS | Random write (VM workload proxy) |

Thresholds are conservative (well below even spinning-disk baselines on healthy hardware).
Proxmox community typical values on good hardware: fsync 1000–5000/s, hdparm 2000+ MB/s.

Output:
```
[Storage Performance (pveperf /var/lib/vz)]
  ⚠️  FSYNCS/SEC:      87   (expected: > 500)   ← low I/O throughput
  ✅  HDPARM:          1842 MB/s
  ✅  DD:              628 MB/s
  ✅  FIO randwrite:   340 IOPS
  Possible causes: ZFS resilver in progress, dying drive, misconfigured cache
  → zpool status
  → iostat -xz 1 5
```

If all metrics pass: `✅ Storage performance: healthy (pveperf /var/lib/vz)`

**8. VM resource over-commitment**
Sources: `pvesh get /nodes/localhost/qemu` + node CPU/memory status.

Compute:
- Total vCPUs assigned (sum of `cpus` field for running VMs) vs physical cores
  WARN if ratio > 4:1, CRIT if > 8:1
- Total memory assigned (sum of `maxmem`) vs total RAM
  WARN if > 100% (actual overcommit with balloons)
  CRIT if > 150% (very risky without balloon drivers in all VMs)

Output:
```
[Resource Allocation]
  CPU:     32 vCPUs assigned / 8 physical cores  (4:1 ratio — acceptable)
  Memory:  42.0 GB assigned / 31.9 GB RAM        (131% — overcommitted)
     ⚠️  Memory overcommit requires balloon drivers in all VMs
     → pvesh get /nodes/localhost/qemu/<vmid>/config | grep balloon
```

**9. Backup audit**
Source: `pvesh get /nodes/localhost/tasks --typefilter=vzdump --limit 200 --output-format json`

For each VM/CT that exists:
- Find the most recent successful backup task
- Calculate days since last successful backup

Flags:
- No successful backup in > 7 days → WARN
- No successful backup in > 30 days → CRIT  
- Never backed up (no vzdump task found) → CRIT

Output:
```
[Backup Status]
  ❌  101  db-server     last backup: 45 days ago
  ⚠️  205  dev-ct        last backup: 9 days ago
  ✅  108  backup-ct     last backup: 1 day ago
  ℹ️  999  template-vm   no backups (template — expected)
```

Templates (`template=1`) skipped silently from backup audit.

**10. Network bridge health**
Source: `pvesh get /nodes/localhost/network --output-format json` + kernel `ip link`

For each bridge (`type=bridge`):
- Bridge UP/DOWN status
- Physical interface attached check (a bridge with no uplink = misconfiguration)
- Bond/LACP status if `bond` devices present

Flags:
- Bridge DOWN → CRIT (VMs on this bridge lose network)
- Bridge with no uplink interface → WARN
- Bond member interface down → WARN
- **STP enabled on VM bridge → WARN** (causes ~30s boot delay per bridge;
  read `/sys/class/net/<bridge>/bridge/stp_state` — 1=enabled, 0=disabled;
  Proxmox disables STP by default; home-lab KVM bridges often have it on)

Output:
```
[Network]
  ✅  vmbr0    UP   ← eth0 (1Gbps)  STP: off
  ⚠️  vmbr1    UP   ← no uplink interface attached
     This bridge exists but has no physical NIC — VMs on vmbr1 are isolated.
  ⚠️  br0      UP   ← eth1  STP: ON (may cause ~30s boot delay)
     → nmcli connection modify br0 bridge.stp no
     → nmcli connection up br0
```

### Collector Design

```
internal/collectors/pve.go
    PVECollector struct
    CollectFast()  → checks 1–6
    CollectDeep()  → checks 7–10
    isProxmox() bool
    runPVEPerf(path string) PVEPerfResult
    parsePVEPerfOutput(s string) PVEPerfResult
    parseTaskErrors(tasks []PVETask, since time.Duration) []TaskError
    backupAudit(vms []PVEVM, tasks []PVETask) []BackupStatus

cmd/pve.go
    Command: dsd pve
    Flags:   --deep, --json, --timeout
    Renders: PVEInfo struct to table
```

All data from `pvesh` (JSON output via `--output-format json`). No Proxmox Go SDK
needed — shell-out like the rest of DashDiag. `pvesh` is always available on PVE nodes.

**pvesh timeout:** wrap all calls with 10s timeout (Proxmox API can be slow when
cluster is degraded — exactly when you need `dsd pve` most).

### JSON Schema

```json
"pve": {
  "version": "8.2.2",
  "node": "pve-node1",
  "cpu_pct": 12.3,
  "memory_used_gb": 18.2,
  "memory_total_gb": 31.9,
  "vms_running": 10,
  "vms_stopped": 2,
  "vms_paused": 0,
  "autostart_not_running": ["db-server"],
  "storage": [
    {"name": "local-lvm", "type": "lvm-thin", "active": true, "used_pct": 26},
    {"name": "nfs-backup", "type": "nfs", "active": false, "used_pct": null}
  ],
  "task_errors_24h": 2,
  "cluster_quorate": true,
  "cluster_nodes_offline": ["pve3"],
  "pveperf": {
    "fsyncs_sec": 87,
    "hdparm_mbs": 1842,
    "dd_mbs": 628,
    "fio_randwrite_iops": 340,
    "storage_path": "/var/lib/vz"
  },
  "overcommit_vcpu_ratio": 4.0,
  "overcommit_memory_pct": 131,
  "backups_warn": ["dev-ct"],
  "backups_crit": ["db-server"]
}
```

### Cross-references

- Spec 4b — ZFS pool health (`zpool status`) — shown in `dsd pve` fast output as
  `[ZFS Pools]` section when ZFS storage detected on PVE node
- Spec 15 — `dsd kvm` — completes the virtualisation trio: `dsd docker`, `dsd pve`, `dsd kvm`
- BACKLOG.md Proxmox testbed — primary validation environment for both `dsd disk` and `dsd pve`

### Acceptance criteria

**Fast:**
- [ ] Non-PVE host: graceful INFO exit (no error)
- [ ] Node overview: version, CPU%, memory, uptime
- [ ] Autostart VMs not running: flagged WARN with VM name
- [ ] Paused VMs: flagged WARN
- [ ] Unavailable storage: flagged CRIT with storage name
- [ ] Storage > 85%: WARN, > 95%: CRIT
- [ ] Task errors in last 24h: WARN with type and message
- [ ] Cluster quorate=false: CRIT
- [ ] Cluster node offline: WARN
- [ ] Single-node PVE (no corosync.conf): cluster section silently absent
- [ ] Subscription: INFO only (never CRIT/WARN for no-subscription tier)
- [ ] All pvesh calls wrapped with 10s timeout
- [ ] `--json` includes full `pve` object

**Deep:**
- [ ] pveperf absent: graceful skip with INFO
- [ ] pveperf FSYNCS/SEC < 100: CRIT with cause suggestions
- [ ] pveperf all pass: single OK line
- [ ] Memory overcommit > 100%: WARN
- [ ] VM with no backup > 7 days: WARN
- [ ] VM with no backup > 30 days or never: CRIT
- [ ] Templates excluded from backup audit
- [ ] Bridge DOWN → CRIT
- [ ] Bridge with no uplink: WARN
- [ ] Bond member down: WARN
- [ ] STP enabled on bridge: WARN with nmcli fix hint (read `/sys/class/net/<bridge>/bridge/stp_state`)
- [ ] `--json` includes `pveperf` sub-object and `backups_warn`/`backups_crit`
