# DashDiag Bug Log — Testbed Discoveries

Bugs found during real hardware validation that would not have been
caught in CI, unit tests, or documentation. Ordered by discovery date.

Each entry: what broke, why, what it affected, the fix, and the commit.

---

## macOS arm64

### BUG-001 — macOS locale decimal separator in load average parser
**Found:** macOS arm64 validation session
**Symptom:** Load average parsed as 0 on non-English macOS locales
**Root cause:** `uptime` output uses locale-specific decimal separator
  (comma instead of dot on European locales). `strconv.ParseFloat` failed
  silently, returning 0.
**Affected:** CPU collector, CPUInfo.LoadAvg fields, all load-based insights
**Fix:** Normalize decimal separator before parsing — replace comma with dot
**Commit:** `d00db10`

### BUG-002 — macOS zombie detection reading wrong ps column
**Found:** macOS arm64 validation
**Symptom:** Zombie count always 0 on macOS even with real zombie processes
**Root cause:** macOS `ps` output column order differs from Linux.
  Reading stat before comm gave wrong field for state detection.
**Affected:** ProcessesCollector, zombie count, Processes insight
**Fix:** Read comm before stat in macOS ps output parsing
**Commit:** `54f7906`

### BUG-003 — macOS battery `-l` flag hangs ioreg
**Found:** macOS arm64 validation
**Symptom:** `dsd health` hangs indefinitely on battery collection
**Root cause:** `ioreg -l` (list all properties) hangs on some Apple Silicon
  configurations. The battery collector was using `-l` flag.
**Affected:** BatteryCollector, `dsd health` (hangs entire run)
**Fix:** Use `ioreg -rn AppleSmartBattery` without `-l` flag
**Commit:** early macOS fixes session
**Note:** Documented in handover notes — critical gotcha for macOS

---

## RHEL 10.1 (AMD Ryzen 7 5800H, RTX 3070, k3s)

### BUG-004 — efivarfs and /sys/ pseudo-mounts polluting disk output
**Found:** RHEL 10.1 first run
**Symptom:** `dsd disk` showed dozens of pseudo-filesystem entries
  (efivarfs, sysfs, cgroup, etc.) mixed with real disk mounts
**Root cause:** Disk collector iterated all mount entries from /proc/mounts
  without filtering pseudo-filesystems
**Affected:** DiskCollector, `dsd disk`, disk insights (false WARNs possible)
**Fix:** Filter efivarfs and /sys/ mount paths from disk collector
**Commit:** `cc94416`

### BUG-005 — Hung process details not captured at collection time
**Found:** RHEL 10.1 validation
**Symptom:** Processes insight said "N hung processes" but drilldown
  showed no process details — couldn't see which processes were hung
**Root cause:** Hung process details captured during drilldown phase,
  by which time the processes had often recovered (stress window passed)
**Affected:** ProcessesCollector, drilldown, usefulness of hung process info
**Fix:** Capture process details (PID, name, wchan) at collection time,
  store in ProcessInfo, surface in summary
**Commit:** `6909b6d`

### BUG-006 — Collector errors shown as empty output instead of INFO
**Found:** RHEL 10.1 validation
**Symptom:** Some collectors silently showed nothing when they couldn't
  run (e.g. ZramCollector on systems without zram) — no indication to user
**Root cause:** Error path returned nil data with no insight
**Affected:** Multiple collectors, user visibility of limited checks
**Fix:** Surface collector errors as INFO insights; populate ZramUsedPct
**Commit:** `39573cd`

### BUG-007 — Network privilege error — gateway probe failing silently
**Found:** RHEL 10.1 validation
**Symptom:** Gateway ping always -1 (unreachable) when run as non-root,
  despite the gateway being reachable
**Root cause:** ICMP raw socket requires root or CAP_NET_RAW. Collector
  didn't check ICMP availability upfront, just failed silently.
**Affected:** NetworkCollector, gateway/internet ping, network insights
**Fix:** Detect ICMP availability upfront; skip dead syscalls gracefully;
  add debug mode
**Commit:** `15c217b`

### BUG-008 — AppArmor "unknown" vs "disabled" conflation
**Found:** RHEL 10.1 + macOS validation
**Symptom:** On systems where AppArmor profiles file is root-only
  (/sys/kernel/security/apparmor/profiles, mode 0440), collector
  reported "disabled" — a false system-fact claim
**Root cause:** EACCES error silently mapped to "disabled" instead of
  being distinguished from genuinely absent AppArmor
**Affected:** KernelSecurityCollector, KernelSec insight, user trust
**Fix:** Return "unknown" on EACCES; analysis layer surfaces as INFO
  "AppArmor present but mode unreadable — re-run as root"
**Commit:** `ab562ea`

### BUG-009 — SELinux denial detection blind when auditd is running
**Found:** RHEL 10.1 with auditd active — the only testbed with SELinux
**Symptom:** KernelSec showed OK despite 17 real AVC denials existing
  in /var/log/audit/audit.log
**Root cause:** When auditd runs, the kernel sends AVC messages to the
  audit netlink socket — they NEVER reach journald. collectSELinux() was
  reading journald, so always returned 0 on any production RHEL system.
  This affects every monitoring tool reading journald for SELinux events:
  Prometheus node_exporter, Datadog agent, Netdata, Nagios SELinux checks.
**Affected:** KernelSecurityCollector, KernelSec insight, CRIT threshold
**Fix:** countAVCsFromAuditLog() reads /var/log/audit/audit.log directly
  (same source as auditd). Falls back to journald when audit.log unreadable.
  security_linux.go refactored to call shared helper instead of duplicating.
**Commit:** `968a097`
**Marketing:** Full story in MARKETING.md "The SELinux Blind Spot" section.
  Evidence in marketing-assets/selinux-blind-spot-evidence.md
  Nagios connection: founder contributed to Nagios 20 years ago; Nagios
  has this same blind spot. Not a bug — the auditd architecture postdates
  Nagios. The problem evolved; the tools didn't.

### BUG-010 — KernelSec drilldown dumped 200+ disabled SELinux booleans
**Found:** RHEL 10.1 final validation run
**Symptom:** KernelSec CRIT triggered a drilldown table of 200+ rows,
  all showing SELinux booleans set to "off" — pure noise
**Root cause:** policiesLinux() ran `getsebool -a` and listed every boolean
  set to "off". On RHEL, 200+ booleans are "off" by default. This is normal
  system state, not a security finding.
**Affected:** KernelSec drilldown, readability, `dsd health` output length
**Fix:** Flip logic — show only booleans explicitly set to ON (relaxed
  policies worth surfacing). Never show "off" booleans.
**Commit:** `6c195fe`

---

## Debian 13.4 (same hardware, kernel 6.12.73)

### BUG-011 — Failed login detection blind on Debian 13
**Found:** Debian 13 first run — predicted from distro research
**Symptom:** `dsd security` reported 0 failed logins despite connection
  attempts having been made. No error shown.
**Root cause:** parseFailedLogins() tries /var/log/secure (RHEL) then
  /var/log/auth.log (Debian 8-12). Debian 13 uses journald-only auth
  logging — neither file exists. Function silently returned 0.
**Affected:** SecurityCollector, failed login count, Hardening insight
**Fix:** Add parseFailedLoginsFromJournal() fallback using
  `journalctl _COMM=sshd --since=1 hour ago`
**Commit:** `34ba5ce`

### BUG-012 — OpenSSH 9 log format not recognized
**Found:** Debian 13 first run (OpenSSH 9.9p2)
**Symptom:** Even with the journalctl fallback, failed logins returned 0.
  journalctl showed entries but they didn't match the parser.
**Root cause:** OpenSSH 9 replaced the traditional log format:
  OLD: "Failed password for invalid user X from 1.2.3.4 port 12345 ssh2"
  NEW: "drop connection #0 from [1.2.3.4]:12345 on [IP]:22 penalty: failed authentication"
  Parser only looked for "Failed password" and "Invalid user".
**Affected:** parseFailedLoginsFromJournal(), failed login count and IPs
**Fix:** Switch statement handling both formats. Modern format: extract
  bracketed IP from "from [IP]:port". Both commit and IP extraction tested.
**Commit:** `34ba5ce` (same commit, discovered during fix of BUG-011)
**Note:** The two bugs compound — tool reading /var/log/auth.log on Debian 13
  fails twice: file missing AND wrong format if it somehow got the file.

### BUG-013 — Failed login hint pointing to wrong log file
**Found:** Debian 13 — noticed in output after BUG-011/012 fix
**Symptom:** Hardening WARN hint said:
  "grep 'Failed password' /var/log/secure | tail -20"
  This command doesn't work on any Debian/Ubuntu system.
**Root cause:** Hint string hardcoded RHEL-specific path and old format.
**Affected:** Hardening insight hints — misleads engineers on Debian/Ubuntu
**Fix:** Hint updated to:
  "journalctl _COMM=sshd | grep -E 'Failed|penalty' | tail -20"
  Works on both legacy and modern OpenSSH across all distros.
**Commit:** `07df7b8`

### BUG-014 — Fresh Debian install missing security repo — silent zero updates
**Found:** Debian 13.4 first run
**Symptom:** `dsd health --packages` reported 0 security updates on a freshly
  installed Debian 13 system that had real security updates available.
  No error, no warning — just silent zero.
**Root cause:** Debian installer only configures the main mirror in
  sources.list. The security repository (security.debian.org) is a separate
  entry that must be added manually. Without it, `apt-get -s upgrade` never
  shows security packages. The collector returned 0 with no indication why.
**Affected:** PackagesCollector, Packages insight — any fresh Debian/Ubuntu
  install without explicit security repo configuration
**Fix:** aptHasSecurityRepo() probes sources.list + sources.list.d/* before
  running apt-get. If no security repo found, returns Status='no-security-repo'.
  checkPackages() surfaces this as WARN with exact fix instructions for both
  Debian (security.debian.org) and Ubuntu (security.ubuntu.com) formats.
**Commit:** `3ee96cd`
**Note:** Silent zero is worse than an error — user thinks system is patched.
  This is the most dangerous category of monitoring failure.

---

## Proxmox VE 9.1.1 (Debian base, i7-6700)

Five false positives found running `dsd` directly on the PVE base system.
PVE diverges from a generic Debian host in ways that tripped distro-blind
heuristics: it manages QEMU without libvirt, ships its own firewall and
web-management ports, and mandates root SSH. Each fix is PVE-conditional —
non-PVE behaviour is unchanged.

### BUG-015 — dsd kvm returns false on PVE host
**Found:** Proxmox host validation
**Symptom:** `dsd kvm` reported no VMs despite active QEMU guests running.
**Root cause:** KVMAvailable() and KVMCollector only probe libvirt (virsh /
  libvirtd). Proxmox does not use libvirt — it manages QEMU directly, leaving
  one /var/run/qemu-server/<vmid>.pid file per running VM. With no libvirt,
  virsh exits non-zero and the collector returned an empty, undetected result.
**Affected:** KVMCollector, KVMAvailable() gate, `dsd kvm`, `dsd health` KVM row
**Fix:** KVMAvailable() falls back to globbing /var/run/qemu-server/*.pid when
  the virsh probe fails. KVMCollector gained a PVE path (kvmCollectPVEFromDir)
  that enumerates guests from the pid files, reading each pid and confirming a
  live "kvm" process via /proc/<pid>/status. The libvirt path is untouched for
  non-PVE hosts.
**Commit:** 4f5e668

### BUG-016 — false-positive port warnings for PVE ports 8006, 3128, 111
**Found:** Proxmox host validation
**Symptom:** `dsd security` and `dsd health` WARNed on ports 8006 (PVE web UI),
  3128 (spiceproxy), and 111 (rpcbind) — all legitimate PVE services.
**Root cause:** The port heuristic had no PVE awareness: these ports are not in
  the universally-expected list and their processes (pvedaemon, spiceproxy,
  rpcbind) are not known-service processes, so they fell through to "unexpected
  port" WARN.
**Affected:** checkSecurity port analysis, `dsd security`, `dsd health` Hardening
**Fix:** SecurityCollector sets SecurityInfo.IsPVE (via IsPVEHost()). When set,
  checkSecurity routes ports 8006/3128/111 to an INFO "PVE service port
  (expected)" line instead of the unexpected-port WARN. Non-PVE hosts still WARN.
**Commit:** 4f5e668

### BUG-017 — incorrect nftables warning on PVE
**Found:** Proxmox host validation
**Symptom:** `dsd health` WARNed "nftables installed but no rules active — host
  is unprotected" even though pve-firewall protects the host.
**Root cause:** checkFirewall flagged an empty base ruleset as unprotected with
  no knowledge that pve-firewall is the active manager (it loads rules
  dynamically, so the base ruleset is legitimately sparse).
**Affected:** FirewallCollector, checkFirewall, `dsd health` Firewall row
**Fix:** FirewallCollector sets FirewallInfo.PVEFirewallActive when IsPVEHost()
  and `systemctl is-active pve-firewall` reports active (the single subprocess
  lives in the collector layer, not analysis). checkFirewall then emits INFO
  "PVE firewall active (pve-firewall)" instead of the unprotected WARN.
**Commit:** 4f5e668

### BUG-018 — SSH root login flagged as CRIT on PVE
**Found:** Proxmox host validation
**Symptom:** `dsd health` emitted CRIT for PermitRootLogin=yes. Root SSH is
  required for PVE cluster management — not a misconfiguration.
**Root cause:** The SSH hardening check treated PermitRootLogin=yes as CRIT on
  every host except offensive distros, with no PVE awareness.
**Affected:** checkSecurity SSH hardening, `dsd security`, `dsd health` Hardening
**Fix:** When SecurityInfo.IsPVE is set, PermitRootLogin=yes is downgraded to
  INFO "Root SSH login enabled — required for PVE management. Restrict to
  key-based auth if not already done." Non-PVE hosts still CRIT.
**Commit:** 4f5e668

### BUG-019 — "no backup" CRIT not surfaced in dsd health PVE summary
**Found:** Proxmox host validation
**Symptom:** `dsd pve` correctly flagged "no successful backup found" (❌), but
  `dsd health`'s PVE row only surfaced it as WARN — under-reporting the worst
  finding relative to `dsd pve`.
**Root cause:** checkPVEBackups emitted WARN for BackupAgeDays < 0, while
  `dsd pve` renders the same condition as a ❌ (CRIT-equivalent). The severity
  was inconsistent between the two commands, so the health summary understated it.
**Affected:** checkPVEBackups, `dsd health` PVE summary row
**Fix:** Promote the no-backup finding (BackupAgeDays < 0) from WARN to CRIT in
  checkPVEBackups. It is aggregated by checkPVE, so the CRIT now bubbles into the
  PVE summary row, matching `dsd pve`. Only affects PVE hosts (gated by IsPVE).
**Commit:** 4f5e668

---

## Ubuntu 24.04 LXC

### BUG-020 — dsd disk false "smartctl not installed" inside LXC containers
**Found:** Ubuntu 24.04 LXC validation
**Symptom:** `dsd disk` (and the Disk section of `dsd health`) surfaced
  "smartctl not installed" concerns inside an LXC container, where SMART is
  irrelevant — the container has no real block devices and smartctl is absent.
**Root cause:** The SMART gate in collectLinuxExtras() only skipped hypervisor
  virtual disks via isVirtualDisk(). It had no awareness of containers, so for
  each enumerated drive it called collectSMART(), which reported
  "smartctl not installed" as an Error and produced a false concern.
**Affected:** DiskCollector.collectLinuxExtras(), SMART collection, `dsd disk`
  and `dsd health` Disk section — any LXC/Docker container without smartctl
**Fix:** DiskCollector gained a ContainerCtx field (constructor signature now
  matches NewMemoryCollector). The SMART gate is extended to
  `if isVirtualDisk(*d) || c.ContainerCtx.InContainer { continue }`, so SMART is
  skipped entirely inside a container. isVirtualDisk() is unchanged; non-container,
  non-virtual hosts behave exactly as before.
**Commit:** d89324f

---

## Summary — Bugs by Category

| Category | Count | Notes |
|---|---|---|
| Platform-specific parsing | 4 | BUG-001, 002, 003, 013 |
| Silent failures / blind spots | 4 | BUG-006, 007, 009, 011 |
| Data quality / noise | 3 | BUG-004, 008, 010 |
| Timing / race conditions | 1 | BUG-005 |
| New format not handled | 1 | BUG-012 |

**Bugs only findable on real hardware:** BUG-003, 007, 009, 010, 011, 012
— 6 out of 13 required a physical testbed to discover.
BUG-009 (SELinux/auditd) required specifically RHEL with auditd active.
BUG-011/012 required specifically Debian 13 with OpenSSH 9.

---

## Testbed Coverage — What Each Platform Unlocked

| Platform | Bugs Found | Key discovery |
|---|---|---|
| macOS arm64 | 3 | ioreg hang, locale parsing, ps column order |
| RHEL 10.1 | 7 | SELinux/auditd blind spot (the big one) |
| Debian 13.4 | 3 | journald-only auth, OpenSSH 9 format |
| Ubuntu 24.04 | TBD | next testbed |
## Summary — Bugs by Category

| Category | Count | Notes |
|---|---|---|
| Platform-specific parsing | 4 | BUG-001, 002, 003, 013 |
| Silent failures / blind spots | 5 | BUG-006, 007, 009, 011, 014 |
| Data quality / noise | 3 | BUG-004, 008, 010 |
| Timing / race conditions | 1 | BUG-005 |
| New format not handled | 1 | BUG-012 |

**Bugs only findable on real hardware:** BUG-003, 007, 009, 010, 011, 012, 014
— 7 out of 14 required a physical testbed to discover.
BUG-009 (SELinux/auditd) required specifically RHEL with auditd active.
BUG-011/012 required specifically Debian 13 with OpenSSH 9.
BUG-014 required a fresh Debian install without post-install hardening.

---

## Testbed Coverage — What Each Platform Unlocked

| Platform | Bugs Found | Key discovery |
|---|---|---|
| macOS arm64 | 3 | ioreg hang, locale parsing, ps column order |
| RHEL 10.1 | 7 | SELinux/auditd blind spot (the big one) |
| Debian 13.4 | 4 | journald-only auth, OpenSSH 9 format, missing security repo |
| Ubuntu 24.04 | TBD | next testbed |

---

## BUG-021 — Zombie subprocess during dsd health run (unconfirmed, needs investigation)

**Found:** PVE01 host, observed in process table during health run
**Symptom:** `dsd health` spawns a zombie subprocess — `parent 48436 child 48451`
  visible as `<defunct>` in `ps aux` output during the run
**Root cause:** Unknown. `runCmd` in `internal/collectors/collector.go` uses
  `cmd.Run()` which calls `Wait()` internally — should not leave zombies. Possible
  causes: (a) a goroutine starting a subprocess but not calling `cmd.Wait()` on
  a non-zero exit path, (b) a collector using `cmd.Start()` + `cmd.Stdout.Read()`
  without `cmd.Wait()`, (c) race between context cancellation and process cleanup
**Affected:** Unknown — may only affect PVE01 (Debian PVE base) or may be broader
**Status:** OPEN — needs reproduction and root cause identification
**Investigate:**
```bash
# On PVE01 during a health run:
watch -n0.5 'ps aux | grep defunct'
# Also check which collector spawns the zombie:
strace -ff -p $(pgrep dsd) 2>&1 | grep clone
```
**Look for:** any collector using `exec.Command` without going through `runCmd()`,
  or any goroutine that starts a process inside a goroutine where context
  cancellation could skip the `cmd.Wait()` call (e.g. early return on error)
