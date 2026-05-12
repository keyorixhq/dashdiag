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
