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

### BUG-053 — Hardening fix-hint emits Linux-only `ss` command on macOS
**Found:** macOS arm64 validation (native build, `go1.26.4 darwin/arm64`)
**Symptom:** On macOS, the Hardening WARN for unexpected listening ports tells
  the user to run `ss -tlnp` (and `ss -tlnp | grep :PORT`). `ss` (iproute2) does
  not exist on macOS, so following the hint yields "command not found".
**Root cause:** Fix-hint text is hardcoded to the Linux toolset; the *finding*
  is platform-correct but the *remedy* is not branched by platform. Same family
  as the locale-safe-exec discipline — the boundary between "right diagnosis" and
  "runnable remedy" is not surfaced per-platform.
**Affected:** Hardening insight fix-hints on darwin (port-inspection guidance).
  Reduced-coverage platform, so low severity, but it's a silent cross-platform
  wrongness that erodes trust in the hint layer.
**Fix (proposed, not yet done):** Branch port-inspection hint on GOOS — on darwin
  emit `lsof -nP -iTCP -sTCP:LISTEN` instead of `ss -tlnp`. Audit other hardcoded
  `ss`/iproute2 hints for the same issue.
**Commit:** _open_

### BUG-054 — Hardening/Logs fix-hints emit systemd commands on Alpine (OpenRC)
**Found:** Alpine LXC (PVE CT210 `alpine-dsd`) validation, `v0.6.11-1-g54769ef`
**Symptom:** On Alpine, hardening findings are correct (weak MACs umac-64/hmac-sha1,
  password auth) but fix-hints tell the user to run `systemctl restart sshd` and to
  edit `/etc/systemd/journald.conf`. Alpine uses OpenRC + busybox, has no systemd and
  no `systemctl`, so the remedies fail.
**Root cause:** Same family as BUG-053 — fix-hint text is hardcoded to the systemd
  toolset and not branched by the host's init system. The *diagnosis* is
  platform-correct; the *remedy* is not. Confirms the cross-platform-hint gap is not
  macOS-specific but affects every non-systemd target.
**Affected:** Hardening + Logs insight fix-hints on OpenRC/non-systemd Linux (Alpine,
  and any sysvinit/runit host). Diagnosis valid; remedy non-runnable.
**Fix (proposed, not yet done):** Detect init system (already have non-systemd
  handling per the Alpine hardening pass) and branch service-restart hints — emit
  `rc-service sshd restart` / OpenRC log guidance on Alpine instead of `systemctl`.
  Audit all hint strings that hardcode `systemctl`/`/etc/systemd/*`.
**Commit:** _open_

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
**Note:** auditd architecture postdates most legacy monitoring tools, which still
  read journald for SELinux events and so see zero on auditd-enabled hosts. Not a
  bug — the problem evolved after those tools were designed.

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
**Status:** CLOSED (2026-06-04) — cannot reproduce / no offending code; likely a
  ps sampling artifact. See resolution below.
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

**Resolution (2026-06-04):** Full audit of `internal/` found **no offending code**:
- No `.Start()` anywhere in the tree — Patterns A/B/C (Start-without-Wait,
  abandoned goroutine subprocess) all require it and none exist.
- Every subprocess uses `.Run()`, `.Output()`, or `.CombinedOutput()`, all of
  which call `Wait()` internally on success, non-zero exit, and context-cancel
  paths — so children are always reaped.
- The two timeout-select goroutines are non-leaking: `logs_linux.go` parseKmsg
  reads `/dev/kmsg` (a file, no subprocess); `timeline_linux.go` joins its
  goroutines (`<-jCh; <-dCh`) which use `.Output()`. An abandoned Go goroutine
  keeps running to completion and still reaps — it is not force-terminated.
- The lone `sh -c` (`cve_linux.go isUbuntu`) runs a single `grep` (no pipeline,
  no orphaned grandchild) and is not in the `dsd health` path (report mode only).

The transient `<defunct>` (parent 48436 / child 48451) was almost certainly a
`ps aux` sample landing in the microsecond window between a helper's `exit()` and
its parent's `Wait()` returning, during the ~2s concurrent run of ~20 collectors
each spawning short-lived helpers (journalctl, ps, systemctl, dmesg, ip, …). This
is normal and harmless. Documented the reaping guarantee in `runCmd` (collector.go).
Re-open only if a `<defunct>` process *persists* (survives the dsd process exit).

---

## Fleet-review (code-review discoveries, 2026-06-09)

Unlike the entries above, these were found by a systematic **code review** of every
collector that produces a health verdict — not by hardware validation. They share
one root class: **false-OK** — a green/OK verdict (or silence) shown when the check
had not actually verified health, hiding the real problem. They escaped CI because
unit tests existed but encoded the buggy behavior (or used unrealistic fixtures).
Shipped in v0.6.9 (#130–#144) and v0.6.10 (#145–#146). The 7 grep-able anti-patterns
live in the agent memory `false-ok-bug-class`.

### BUG-040 — failing SMART drive silently skipped (highest impact)
`smartctl -H` returns a non-zero **bitmask** exit on "DISK FAILING" (bit 3) while
still printing the verdict to stdout. `collectSMART` treated any non-zero exit as a
read error and returned early with `Error` set; the analysis layer skips drives with
`SMART.Error != ""` — so a genuinely failing drive never produced the CRIT. Fixed by
parsing stdout regardless of exit code (`parseSMARTHealth`). **#138.**

### BUG-041 — docker OOM kills undercounted on busy hosts
`collectDockerEvents` broke the parse loop after 10 events (a display cap), which
also stopped OOM counting — so an `oom` later in a >10-event window was never
counted and the OOM CRIT never fired. Split display cap from detection. **#140.**

### BUG-042 — PVE per-VM backup gap hidden by healthy global age
`checkPVEBackups` only checked the node-wide `BackupAgeDays`; a single never-backed-up
guest was invisible when others backed up nightly. Now flags per-VM gaps. **#143.**

### BUG-043 — ceph cluster-unreachable reported as silent/OK
`ceph health detail` failing was treated as "no cluster" (silent). A node configured
for a cluster (`/etc/ceph/ceph.conf`) whose mons are unreachable was hidden. Now
CRITs when configured. **#145.**

### BUG-044 — cloud-init / IPMI error states swallowed
`cloud-init status` exits non-zero to report error/degraded (JSON still on stdout) —
the error JSON was discarded. IPMI set `Status="error"` on a failed BMC read but the
heuristic returned nil on `!Available`. Both now surface. **#146.**

### Others (same class)
Security drift missing added/removed SSH drop-ins (#137), TLS <24h-expired
misclassified (#136), CVE scan-unavailable shown OK (#135), timeline false CRITs from
missing PRIORITY + dropped non-UTF-8 messages (#134), k8s oldest-not-newest events +
abort-on-short-line (#141), BIND phantom "not answering" when `dig` absent (#142),
LVM snapshot origin misparse (#139), phantom "OK" rows across live/report/json
(#131, #132), rune-split truncation (#144).

**Meta-lesson:** "gated collector → covered by the `runner.IsAvailable` gate" was
asserted without checking and proved wrong — the gate only covers the phantom-row
pattern, not command-failed-is-ambiguous. Verifying the gated collectors found
BUG-043/044. Never assert "gated → fine"; check.

---

## Pre-pilot verification sweep (2026-06-10)

Found by deploying current `main` to the pve01 guest matrix (Debian/PVE, Ubuntu
24.04 LXC, AlmaLinux 9.4 LXC) and reading the live output — the "walk the real
output on real distros" discipline, run before putting `dsd` in front of a VMware
pilot. pve01 + `health deep` were clean; the two below surfaced on the LXC guests.

### BUG-045 — memory total renders "0 GB" on sub-1GB hosts
On a 512 MB Ubuntu LXC, `inlineMemory` showed `0.1/0 GB (12%)` — the total used
`%.0f GB`, which floors a 0.5 GB total to "0", producing a broken-looking "X/0 GB".
Hits any small container or minimal VM (exactly what a pilot runs). Fixed: render
sub-1 GB totals in MB (`66/512 MB`); GB format unchanged ≥1 GB. Test
`TestInlineMemorySubGB`. **(this PR)**

### BUG-046 — week-old crash loop reported as a live CRIT
On AlmaLinux, a `test-nginx` quadlet that failed **6 days ago** and that systemd had
given up on still produced `Logs CRIT: crash loop detected … (restarted 5 times)`.
Root cause: systemd's `NRestarts` is **cumulative and never resets**, so
`detectCrashLoops` (which lists `--state=failed` units with `NRestarts≥5`) reports a
long-dead loop as current — indefinitely. A stale present-tense CRIT about real infra
is the exact "says something wrong" failure the pilot runbook warns against. Fixed
with a wall-clock recency gate (`crashLoopRecent`, `InactiveEnterTimestamp` within 1h;
blank/unparseable/future ⇒ report, conservative). Wall-clock, not monotonic, because
lxcfs virtualizes `/proc/uptime` but not `CLOCK_MONOTONIC` — verified they disagree
(6.4d vs 2.5d) on the repro container. The genuine failure is still surfaced by the
`Systemd: unit … has failed` CRIT, which is the correct, non-stale signal. Test
`TestCrashLoopRecent`. **(this PR)**

### BUG-047 — pstore kernel-panic records flagged forever (no recency gate)
Follow-up sweep of every counter/event collector for the BUG-046 anti-pattern
(historical signal reported as current). `/sys/fs/pstore` is **not cleared on
reboot**, yet `countPstorePanics` (→ `KernelPanics` → a **CRIT**) and the pstore
loop in `collectCrashFiles` (→ `CoreDumpCount`) counted panic dumps of any age —
while the sibling `/var/crash` path in the *same function* already filtered to 30
days, and the crash-dump verdict literally says "in the last 30 days". So a panic
record from months ago (host long since rebooted past it) produced a perpetual
CRIT and made the "last 30 days" wording false. Fixed with a shared
`crashFileMaxAgeDays` (30d) gate via `crashFileTooOld`, applied to pstore in both
readers. Test `TestCrashFileTooOld`. **(#157)**

Audited and found **correctly time-scoped** (no bug): OOM (journal `--since 24h`),
failed logins (24h), cron failures (24h), security AVC denials (1h/24h), timeline
(windowed), and the whole kmsg counter set — segfaults / soft+hard lockups /
in-kmsg panics / NVMe timeouts — which `parseKmsg` filters by `lookback` (1h).
Deliberately-persistent health flags left as-is (NOT the anti-pattern): btrfs
`device stats` and NVMe/SMART lifetime error counters are documented cumulative
signals you reset after investigating, not stale transient events.

**Meta-lesson (again):** BUG-045/046 escaped CI because the unit tests used
clean/normal fixtures; only running on a real small container + a host with an old
failed unit exposed them. And BUG-047 came from *asking "where else?"* after 046 —
the same anti-pattern hid one file away, behind an inconsistency with its own
sibling code. Verify on the actual matrix; then sweep the class, don't stop at one.

---

## ARM64 (aarch64) hardening — software pass (2026-06-10)

Run on **native (non-emulated) linux/arm64 containers** (Debian 13 / Ubuntu /
AlmaLinux 9) on Apple-Silicon OrbStack. `dsd health` / `deep` / `inventory` run
clean on aarch64; the install one-liner is already CI-tested on linux/arm64 (#125).
Notably, dsd has **no** x86-only CPU-mitigation/microcode checks (a common ARM
false-positive trap it sidesteps), and hugepages reads the kernel's real
`Hugepagesize` (page-size aware), so those are fine on ARM. Fixed here:

- **CPU core identification** — ARM `/proc/cpuinfo` has no "model name" line. Added
  `CPU part` parsing + a kernel-canonical part map (`armPartName`, from
  `cputype.h`): Neoverse-N1/V1/N2, Cortex-A53/55/57/72/76, AmpereOne. A server now
  reads e.g. `ARM Neoverse-N1 (aarch64)` (Ampere Altra / Graviton2) instead of a
  bare vendor string. Tests cover Neoverse-N1 + AmpereOne. **Verified on real
  silicon (AWS Graviton2 t4g, 2026-06-10):** reports implementer `0x41` + part
  `0xd0c` → renders `ARM Neoverse-N1 (aarch64)`; `health`/`deep` anomaly-free.
- **Killed redundant "ARM ARM (aarch64)"** — the implementer-only fallback now reads
  `ARM (aarch64)` / `Ampere (aarch64)`. Removed a dead duplicate model-fallback in
  `collectCPU` (the parser already resolves it).
- **grub EFI lock check is now arch-aware** — `checkSUSEMigrationRisks` hardcoded
  `grub2-x86_64-efi`, so on an aarch64 SUSE host it searched the wrong package and
  silently skipped the grub-lock risk. Now `grub2-arm64-efi` via `runtime.GOARCH`.

**Still needs a real aarch64 server (e.g. the offered Ampere Altra box) — cannot be
validated in a container:**
1. **Thermal** — `/sys/class/hwmon` ARM SoC sensors (absent in containers/VMs).
2. **DMI/SMBIOS** — the SoC/system product name ("Ampere Altra") that gives the
   *real* CPU identity cpuinfo can't (cpuinfo only reports the IP core, e.g.
   Neoverse-N1). Verify `dsd inventory` / hardware model on real firmware.
3. **SMART** on real NVMe/SAS; **EDAC/ECC** on server RAM; **IPMI/BMC** reachability.
4. **Real cpufreq governors** + per-core scaling on many-core Ampere (80+ cores).
5. **Ampere-specific SoC id.** Graviton2 (Neoverse-N1) confirmed reporting
   implementer `0x41` + part `0xd0c` on real silicon. Ampere Altra uses the same
   core but its SoC-vendor reporting (`0x41` vs `0xc0`) is still unconfirmed — pin a
   verified fixture from a real Altra if the Ampere box lands.

See agent memory `tencent-arm-goodwill-infra` for the hardware source.

### BUG-048 — NVMe drive reported "healthy" when SMART was never read (false-OK)
Surfaced while re-validating the AWS collectors on the live Graviton2 (smartctl AND
nvme-cli both absent — typical of minimal cloud/ARM images). The `Drives` collector
finds NVMe controllers via `/sys/class/nvme/` (no tooling needed), then tries `nvme
smart-log`; when nvme-cli is absent it stored the device with **all SMART fields at
zero-defaults** — indistinguishable from a genuinely healthy drive. The heuristic
correctly stayed silent (no false CRIT — every check is `>0`-gated), but with no
insight the drive defaulted to OK and `inlineDrives` printed `<name> healthy`
unconditionally. So `dsd health` claimed `Drives OK /dev/nvme0 healthy` while `dsd
disk` (smartctl path) correctly said "smartctl not installed". Fixed: added
`NVMeDevice.SmartRead` (true only when smart-log parsed); the renderer shows
`detected (SMART not read)` and the heuristic emits an INFO ("nvme-cli not
installed", health unverified) instead of implying healthy. Verified live on
Graviton2: now reads `Drives INFO … SMART health not read`. Tests
`TestInlineDrivesSmartUnread`, `TestCheckNVMe/nvme smart unread is INFO`. **(#159)**

### BUG-049 — `dsd timeline` keyword-escalated benign kernel warnings to CRIT
Found running the full subcommand sweep on the live Graviton2: `dsd timeline` reported
2 CRIT "incidents" on a healthy fresh boot — one of them
`faux_driver regulatory: Direct firmware load for regulatory.db failed`, a benign
message the kernel logs at **warn** (priority 4) on nearly every minimal Linux boot.
Root cause: the journal path classifies severity by kernel `PRIORITY` (correct), but
the **dmesg sibling** (`parseDmesgLine`) ignored the level and escalated to CRIT on
any message containing `"error"`/`"fail"` — so kernel *warnings* became CRIT. Same
"inconsistent sibling" shape as BUG-047. Fixed: fetch `dmesg -T -x` (decodes
`facility:level:` into each line) and classify by the kernel's own level (err+ →
CRIT, warn → WARN); only catastrophe keywords (panic/oops/OOM/bug:) still override
upward — the generic `error`/`fail` escalation is gone. Verified live: regulatory.db
is now WARN; the genuinely err-rated `PCI: OF: of_root … NULL` stays CRIT (faithful
to the kernel — not our job to override an err rating). Tests updated to the `-x`
format + a regulatory.db regression case. **(#160)**

### BUG-050 — `dsd disk` capacity verdicts diverged from `dsd health`
Found by the "diff the sibling" audit (the meta-pattern from BUG-047/049). `cmd/disk.go`
hardcoded **85% WARN / 95% FAIL** for filesystems, ZFS pools, and inodes, while
`dsd health` uses **80/90** (`DiskWarnPct/CritPct`, default 80/90; ZFS `levelPct(80,90)`).
So the same volume at 82% read OK in `dsd disk` but WARN in `dsd health`; at 92%, WARN
vs CRIT — a different verdict depending on which command you ran. Worse, `cmd/disk.go`
never loaded policy, so it also ignored user threshold overrides. Fixed by making the
defaults a single source of truth — exported `analysis.DefaultDiskWarnPct` (80) /
`DefaultDiskCritPct` (90), referenced by `DefaultThresholds`, the ZFS heuristic, and all
five capacity checks in `cmd/disk.go`. **(#161)**

Audited and found consistent / not bugs: docker crash-loop threshold (both `cmd` and
collector use `>=5`; the heuristic message's ">5 times" wording is a harmless nit, and
the const is duplicated but identical). `inlineDrives` "healthy" is only reached when no
insight fired (the grid shows the insight's severity/message otherwise — confirmed live
on Graviton2), so it is not a false-OK.

---

## Alpine / non-systemd hardening (2026-06-10)

Ran the full suite in a native `alpine:latest` arm64 container (musl, busybox, **no
systemd** — `/proc/1/comm` = `sh`). Most systemd-dependent collectors already gate
correctly (`services`, `logs`, `timeline`, `security` all clean — 0 anomalies, 0 false
CRITs, no stray `systemctl`/`journalctl` in output). Two did NOT gate:

### BUG-051 — DBus + journald checks fire phantom warnings on non-systemd hosts
On Alpine, `dsd health` showed `DBus CRIT: D-Bus system message bus has failed` and
`Logs WARN: journald logs are volatile` — both false. `DBusCollector` ran `systemctl
is-active dbus.service`; with `systemctl` absent the error path set status "unknown" →
`Active=false` → a CRIT (the remediation even said `systemctl status dbus.service`, a
command Alpine lacks). `checkJournalHealth` never checked that journald exists, so an
absent `/var/log/journal` read as "volatile". Both also fired on minimal containers
without an init. Fixed with the established gate (`platform.SystemdAvailable()`, as the
systemd collector already uses): DBus and the journald-health section return/skip when
systemd isn't the init system. Verified live on Alpine — both gone, health now 0 CRIT.
**(#162)**

Minor, left as-is: `Hardening INFO: SSH idle timeout not set` still shows on a host with
no sshd installed (INFO-level, low stakes).

---

## Trustworthiness: mark unverified results instead of false "OK" (2026-06-10)

The generalised antidote to the whole false-OK class: **a check that couldn't fully
run should report low confidence with the reason, not a green OK.**

### BUG-052 — `Packages OK up to date` claimed without fresh metadata
`dsd health` rendered `Packages OK up to date` whenever the package manager was queried
and found 0 security updates — but the collectors read CACHED metadata (apt deliberately
never runs `apt update`; dnf/zypper can be offline/never-refreshed). So "0 updates" from
a stale or absent cache was shown as a confident "up to date". `inlinePackages` even
discarded the cautionary `StatusReason` the apt collector already set. Surfaced on the
cross-distro container sweep (bare images → "up to date" despite never refreshing).
Fixed: `markStaleMetadata` checks the newest update-metadata cache age per manager
(apt `/var/lib/apt/lists`, dnf/yum `/var/cache/dnf|yum/*/repodata/repomd.xml`, zypper
`/var/cache/zypp/{raw/*/repodata/repomd.xml,solv/*/solv}`); when absent or
>`packageMetadataStaleDays` (7), it sets `Status=stale-metadata` and the heuristic emits
an **INFO** ("update metadata is N days old / not found — cannot confirm packages are up
to date; refresh and re-run"), and `inlinePackages` no longer claims "up to date".
Managers whose cache we don't read (brew/pacman) are left untouched (no false stale).
This resolves the earlier-flagged open item. **(#163)**

**Validated both directions on real hosts + containers:** apt — debian empty-lists →
INFO, Ubuntu fresh → not flagged; dnf — fedora cleared → INFO, AlmaLinux fresh (2d) →
not flagged (38 real updates); zypper — glob confirmed against real `repomd.xml`/`solv`
after `zypper ref`, openSUSE fresh → up to date. No false-stale on healthy hosts.

---

## AWS EC2 RHEL 10.2 — cold-cache validation (2026-06-24)

Live validation on a stock RHEL 10.2 instance on AWS (`c7i-flex.large`, x86_64,
RHUI repos). The theme is the **cold cache / fresh-boot** state — the moment an
operator actually runs a health check on a new cloud box — which neither warm
laptop runs nor self-written fixtures reproduce.

### BUG-055 — RHEL/RHUI security scan times out on a cold cache → false "could not verify" (hiding criticals)
**Found:** AWS EC2 RHEL 10.2 (RHUI), cold cache (fresh-boot simulation via `dnf clean all`)
**Symptom:** On the first run against a cold box, `dsd health` reported
  `Packages INFO: could not verify security updates: dnf advisory/updateinfo unavailable`
  — while the box actually had **8 Critical advisories pending, including a Critical
  kernel RHSA**. Other cold runs instead emitted a false `rpm --verify timed out` WARN.
  Warm runs were always correct.
**Root cause:** The whole `PackagesCollector` (security scan + `dnf check` + `rpm
  --verify` + `ldconfig`) ran under one flat **8s** deadline (`Timeout()`). A *cold*
  `dnf updateinfo` over RHUI takes ~6s (metadata download), so the budget blew —
  starving either the security scan itself (→ false "could not verify") or the
  integrity sub-checks that run after it (→ false `rpm --verify timed out`). The
  same starvation class as the apt-side fix shipped in v1.8.1 (#469, found on Azure);
  the dnf/RHUI side was only flushed out by a cold cache on real hardware.
**Affected:** `dsd health` / `dsd health --packages` / `dsd health deep` on RHEL/Rocky/
  Alma/Fedora cloud images on a cold cache — i.e. the common fresh-boot case.
**Fix:** `Timeout()` is now Deep-aware (20s fast / 40s deep), reserving room for the
  integrity sub-checks; the advisory scan is capped at 18s so a wedged mirror degrades
  to an honest "could not verify" instead of starving the integrity checks or hanging.
  Validated live: 3× cold-cache runs → correct `CRIT 8 critical security update(s)`,
  no false integrity WARNs; non-root still degrades honestly (the RHUI client cert
  `/etc/pki/rhui/product/content-rhel10.crt` is root-only).
**PR:** #476

### BUG-056 — `dsd disk` counts unreadable SMART as a drive fault (false WARN)
**Found:** AWS EC2 RHEL 10.2, EBS NVMe volume, `nvme-cli` absent
**Symptom:** `dsd disk` ended with `WARN 1 disk concern(s) found` on a perfectly
  healthy box, while `dsd health` rated the same drive INFO — the standalone command
  disagreed with health on identical data.
**Root cause:** When SMART can't be read (smartctl/nvme-cli absent, or an EBS/virtual
  disk with no SMART log), the collector returns a *non-nil* `SMARTInfo` with `Error`
  set and `Healthy` defaulting to `false`. `countDiskIssues` read `Healthy==false` as
  a fault and bumped the concern tally — conflating "couldn't measure" with "unhealthy."
  Sibling of BUG-050 (cmd-vs-health divergence) and BUG-048 (unread-SMART false-OK).
**Affected:** `dsd disk` summary line on any host without smartctl/nvme-cli or with an
  EBS/virtual disk — i.e. most cloud guests.
**Fix:** Skip drives whose `SMART.Error` is set (or nil SMART) before the health check,
  mirroring `printSMARTLine`'s early return on `Error`. A genuinely FAILED drive
  (`Healthy` false, *no* Error) still counts, so no real fault is masked. Regression
  cases added (`cmd/disk_issues_test.go`). Validated live: `dsd disk` now reads
  `OK Disk healthy. Checks passed`.
**PR:** #477

### BUG-057 — RHEL 10 subscription state undetected + RHUI false-alarm (two coupled bugs)
**Found:** AWS EC2 RHEL 10.2 (RHUI), while checking whether dsd detects Red Hat
  Lightspeed/`rhc` enrollment (it does not — and a "not enrolled" warning was
  deliberately not added; non-enrollment is a choice, not a fault).
**Symptom:** `dsd health` showed *no* Subscription section at all on RHEL 10 — the
  collector silently never ran.
**Root cause (A):** `HasSubscriptionManager()` and the collector dispatch checked only
  `/usr/bin/subscription-manager`. RHEL 10 ships it at `/usr/sbin/` (+ a `/sbin/` compat
  link), so the gate returned false → the Subscription collector was skipped. A
  genuinely EXPIRED subscription (security patches actually cut off — the dangerous
  case) would go unwarned.
**Root cause (B):** Fixing (A) alone would false-alarm on every AWS/Azure/GCP PAYG RHEL
  image: those are RHUI-managed, where "not registered" is normal and `dnf` updates work
  without `subscription-manager` registration. The `unregistered → WARN "security updates
  may be unavailable"` verdict was RHUI-blind.
**Affected:** `dsd health` Subscription verdict on RHEL 10 (silent) and on all cloud PAYG
  RHEL (would false-alarm once detection was fixed).
**Fix:** Detect `subscription-manager` at all three locations; add `rhuiManaged()`
  (`/etc/pki/rhui` / `redhat-rhui.repo`) + an `unregistered-rhui` status the heuristic
  treats as OK. Genuine non-RHUI unregistered still WARNs; expired still CRITs. Validated
  live with a reversible A/B (RHUI present → `Subscription OK`; RHUI hidden → WARN "not
  registered"). Unit test added.
**PR:** #479

**Bonus hardware note (no bug):** the box is Sapphire Rapids (Xeon Platinum 8488C) on
a CPU-burstable `c7i-flex`, exposing the full AMX + AVX-512 surface on 2 vCPUs. Nitro
abstracts the physical layer — ECC = Unknown, no EDAC, no real thermal zones, EBS SMART
unreadable — and dsd degrades honestly on every one (no false-green), confirming the
cloud-guest honest-degradation paths.

---

## AWS EC2 SLES 16.0 (arm64) validation — 2026-06-24

First **enterprise SLES** validation (we previously had only openSUSE Leap). Live on
a t4g.small Graviton2 running brand-new **SUSE Linux Enterprise Server 16.0** (PAYG via
`cloud-regionsrv-client`). dsd handled the SLES-16 changes well — correctly detected
SELinux-enforcing (SLES 16 switched from AppArmor to SELinux), the AWS collector fired,
and the PAYG **Subscription** verdict was correct (`OK` registered as root, honest
"not verified" non-root — no RHUI-style false alarm). One real bug found:

### BUG-058 — zypper security-update scan false-negatives under the global zypp lock
**Found:** AWS EC2 SLES 16.0, live (`dsd health --packages`)
**Symptom:** dsd reported `Packages INFO: could not verify security updates: zypper
  list-patches unavailable (try running as root)` — **as root** — while the box had **28
  pending security patches (18 critical/important)**. On this box it was a *consistent*
  false-negative (not just occasional). The "try running as root" hint was also wrong: it
  showed even when already root.
**Root cause:** zypper holds ONE global lock (`/run/zypp.pid`). dsd runs collectors in
  parallel, so the Packages collector's `zypper list-patches` races the SUSEConnect
  collector (and any other zypp user) for the lock; the loser exits 7 (ZYPP_LOCKED:
  "System management is locked by the application with pid N"). `collectZypper` treated
  any non-zero exit as "couldn't verify (run as root)", conflating a transient lock with
  a permission problem. Non-deterministic in isolation (1 of 5 raced) but consistent in
  the real parallel run. Same false-negative *class* as the RHEL cold-cache scan (BUG-055).
**Affected:** `dsd health` / `--packages` security-update verdict on any openSUSE/SLES host
  (security patches silently unreported when a sibling collector holds the zypp lock).
**Fix:** Retry `list-patches` on a detected zypp-lock (up to 5×, 800ms backoff — mirrors
  `rpmDBHealth`'s transient-lock retry), and report the *accurate* reason when it still
  fails (locked / run-as-root / other) instead of the blanket "try running as root".
  Validated live: pre-fix 3/3 runs false-negative; post-fix **6/6 runs** correctly report
  `CRIT 18 critical security update(s)`, root AND non-root. Unit test for the lock detector.
**Sibling (logged, not yet fixed):** `pkgIntegrityZypper` (deep `zypper verify`) hits the
  same lock and currently reads clean on a lock error (a deep-mode false-OK) — same retry
  guard should be applied. See TRIAGE §U.
**PR:** #480

### BUG-059 — zypper counts "important" patches as "critical" (severity over-escalation)
**Found:** AWS EC2 SLES 16.0 — the patch count didn't match `zypper lp` severities (28
  security = 18 important + 8 moderate + 2 low; **0 critical**), yet dsd reported "18
  *critical* security update(s)" as **CRIT**.
**Root cause:** `collectZypper` incremented `CriticalUpdates` for *both* `critical` and
  `important` severities and never set `ImportantUpdates` — so 18 important patches read
  as 18 critical, and the heuristic (CriticalUpdates>0 → CRIT) raised CRIT. Every other
  collector (`collectDNF` etc.) counts the two separately, and the heuristic already
  renders critical→CRIT / important→WARN — only the zypper path was wrong. This is a
  false-ALARM-direction bug (overstates severity); it's why RHEL's "8 critical" was
  genuine but SLES's "18 critical" was not.
**Affected:** `dsd health` Packages verdict on openSUSE/SLES — important-only patch sets
  mislabelled "critical" and escalated CRIT instead of WARN.
**Fix:** count `critical`→`CriticalUpdates`, `important`→`ImportantUpdates` (match the
  other collectors). Validated live: now reports `WARN 18 important security update(s)`
  — accurate to the 0-critical/18-important ground truth. Heuristic rendering already
  guarded by `heuristics_round6_test`.
**PR:** #480

**Other SLES-16 observations (no bug):** `snapper` is NOT installed on the minimal SLES-16
  cloud image despite a btrfs root with `/.snapshots` — dsd correctly does not false-alarm
  about missing snapshots. The btrfs subvolume layout surfaces as 12 separate Filesystem
  rows (cosmetic; all the same underlying fs).

---

## pve01 bare-metal validation (2026-06-24)

First validation of the hardware-sensor collectors on **real bare metal** — every cloud
guest (Nitro/Hyper-V) hides thermal/EDAC/SMART, so these paths had never run against real
silicon. Host: pve01, HP ProDesk 600 G2 SFF, **Intel i7-6700** (Skylake), Debian 13 / PVE
9.1.1, real coretemp + real SATA SMART (LITEONIT SSD + WDC 2 TB HDD). dsd read the real
sensors correctly (coretemp, SMART PASSED, power-on hours, ECC counters). One false-WARN:

### BUG-060 — `dsd hardware` false-WARNs a normal-temperature CPU at low load
**Found:** pve01 (i7-6700), live — `dsd hardware`
**Symptom:** `CPU Thermals` showed `WARN 61°C — high at 10% load` on idle cores at 61°C.
  **61°C is a normal CPU temperature** (this chip throttles at ~100°C).
**Root cause:** the per-core thermal grading in `cmd/hardware.go` had a "warm at low load"
  rung — `tempC >= 60 && load < 20%` → WARN — meant to catch a cooling fault (dried paste,
  blocked vents, dead fan). The intent is sound but **60°C is a normal idle temp** for a
  desktop/SFF CPU, so it false-WARNed on healthy metal. It never fired on cloud guests
  (no coretemp → `TempC==0` → skipped), so it shipped uncaught.
**Affected:** `dsd hardware` per-core thermal display on any physical machine whose CPU
  idles in the 60–84°C band. Display-only — the `dsd health` thermal verdict uses the
  correct 85/95°C thresholds and was not affected.
**Fix:** raised the "warm at low load" threshold to **75°C** (above normal idle, below the
  85°C "elevated" rung) and extracted a testable `coreThermalLevel` helper + regression
  test. Validated live on pve01 (cores OK at 51–61°C; a genuinely hot idle core ≥75°C still
  WARNs).
**PR:** #482

### BUG-061 — `dsd hardware` reports ECC "available/OK" on non-ECC hardware (false-OK)
**Found:** pve01 (i7-6700, non-ECC), live — `dsd hardware` Memory section
**Symptom:** `ECC (UE): OK 0 uncorrected` / `ECC (CE): OK 0 corrected` on a box with **no
  ECC at all** (i7-6700 is non-ECC; `dmidecode` → "Error Correction Type: None"; no `mc*`
  controllers; no edac module). Implies ECC memory protection exists and is healthy when
  there is none.
**Root cause:** `readEDACCountsFrom` set `available=true` whenever the
  `/sys/devices/system/edac/mc` *class* dir existed — but that dir exists on non-ECC
  hardware too (just `power`/`subsystem`/`uevent`, no `mc*` controller).
**Affected:** `dsd hardware` ECC reporting on every non-ECC Linux box where the edac core
  is built in / loaded. False-OK (claims protection that isn't present).
**Fix:** `available` is true only when a real controller (`mc0`/`mc1`/… with a `ce_count`
  file) is registered; otherwise dsd renders the honest "EDAC not available". Validated
  live: `ECC OK 0 uncorrected` → `EDAC not available`. Regression test added.
**PR:** #483

### BUG-062 — `dsd hardware` false-WARNs a normal-temperature SATA/HDD
**Found:** pve01, live — WDC 2 TB HDD at 52°C
**Symptom:** `Temperature WARN 52°C` on a drive running at its **normal** temp — the drive's
  own SMART reported `Under/Over Temperature Limit Count: 0/0` (never over its limit) and a
  lifetime max of 58°C. Spinning disks routinely run 45-55°C in racks/SFF cases.
**Root cause:** non-NVMe drive temp warned at ≥50°C — too aggressive for HDDs.
**Fix:** raised the non-NVMe warn threshold to **55°C** (fail unchanged at 60°C). The HDD
  now reads `OK 52°C`. **PR:** #483

### BUG-063 — `dsd hardware` false-WARNs virtual NICs with "unknown" operstate
**Found:** pve01 (PVE host), live — `tap101i0`
**Symptom:** `WARN unknown @ 10000 Mbps` on a tap interface whose link is actually **up**
  (`carrier=1`). tap/tun/veth devices leave `operstate` "unknown" even when up.
**Root cause:** the NIC state read `operstate` only; anything ≠ "up" → WARN. "unknown" is
  normal for virtual interfaces.
**Affected:** `dsd hardware` Network section on **every virtualization host** (PVE, libvirt,
  Docker) — each tap/veth NIC false-WARNs. Squarely dsd's target environment.
**Fix:** when `operstate` is "unknown", fall back to `carrier` — `carrier==1` → "up".
  Validated live: `tap101i0 OK up @ 10000 Mbps`. **PR:** #483

---

## AWS EC2 SLES 16.0 (arm64) — firewall + container-runtime sweep (2026-06-25)

Second pass on a t4g.small SLES 16.0 box (rootless podman installed, nftables installed
but unconfigured), running `dsd` as both non-root and root and diffing — the dual-privilege
methodology. Three false-WARN/false-OK bugs, all in the "couldn't measure surfaced as a
verdict" class, two of them divergences between `dsd security` and `dsd health` on identical
data.

### BUG-064 — permission-denied container socket false-WARNs (non-root measurement gap)
**Found:** AWS EC2 SLES 16.0 (arm64), non-root (`dsd health`)
**Symptom:** non-root `dsd health` raised `Docker ⚠️ WARN: podman socket found at
  /run/podman/podman.sock but permission denied`, with the remediation `systemctl status
  docker` — a false alarm about a runtime it merely couldn't read, and naming the wrong
  runtime (the socket is podman's). As root the check correctly drops away (podman has
  nothing to report).
**Root cause:** `checkDocker` emitted a WARN for any unavailable runtime carrying a
  `StatusReason`. The `SocketPermDenied` branch was dead code — its comment promised to
  "surface specific fix" but it only `return`ed. A non-root measurement gap was rendered as
  a fault.
**Affected:** non-root `dsd health` on any host with a permission-gated docker/podman/crio
  socket (rootless podman is the common case) — an unprivileged operator alarmed about
  something dsd couldn't measure.
**Fix:** permission-denied now degrades to INFO ("couldn't measure"), matching the
  `checkFirewall`/`checkFirmware` non-root pattern; dropped the wrong-runtime hint
  (`collectSocketPermReason` already carries the correct `usermod -aG <runtime>` fix).
  Genuine daemon-down stays WARN. Regression test added. Verified live: Docker line now
  reads INFO non-root. **PR:** #508

### BUG-065 — `dsd security` reports "Firewall: none detected" on an unprotected host
**Found:** AWS EC2 SLES 16.0 (arm64), root (`dsd security` vs `dsd health`)
**Symptom:** with nftables installed but an **empty ruleset**, `dsd security` printed a
  benign "Firewall: none detected" (no warning), while `dsd health` correctly WARNed
  "nftables is installed but no rules are active — host is unprotected". Same data, two
  verdicts — security under-reported the genuinely-unprotected misconfiguration.
**Root cause:** `detectNFTables`/`detectIPTables` returned false when the ruleset was empty
  (`TotalRules==0`), so `parseFirewall` fell through to `FirewallActive=false` and the
  renderer's neutral "none detected" — conflating "tooling present but no rules" with "no
  firewall tooling at all".
**Affected:** `dsd security` on any host where nft/iptables is installed with no active
  rules — false reassurance about an unprotected host.
**Fix:** record `FirewallToolingPresent` when the binary is present but the ruleset is empty;
  the renderer surfaces ⚠️ "<backend> installed but no active rules — host is unprotected",
  mirroring the health verdict. Verified live: security and health now agree. **PR:** #509

### BUG-066 — nft/iptables in sbin missed on non-root → "no tooling" instead of "not verified"
**Found:** AWS EC2 SLES 16.0 (arm64), non-root (`dsd health` + `dsd security`)
**Symptom:** non-root `dsd health` reported `Firewall ℹ️ no firewall tooling (nft/iptables)
  found` and `dsd security` reported "Firewall: none detected" — both implying no firewall
  exists — on a box where nftables IS installed (`/usr/sbin/nft`, `/sbin/nft`). The honest
  state is "installed but unreadable without root".
**Root cause:** `nft`/`iptables` live in `/sbin` + `/usr/sbin`, absent from a typical
  non-root `$PATH`. `lookPath`/bare-name exec failed for unprivileged runs, so dsd concluded
  the tooling was *not installed* rather than *installed but unreadable*.
**Affected:** non-root `dsd health` / `dsd security` firewall verdict on any distro that
  keeps net tools in sbin and omits sbin from the user `$PATH` (SLES and others) — a
  misleading "no firewall" in place of an honest "couldn't verify".
**Fix:** new `sbinToolPath()` resolves via `$PATH` then the standard sbin dirs (both lookups
  source-routed for capture/replay) and is used as a DETECTION gate — so a non-root run knows
  the binary exists instead of concluding "no tooling". The tools are still invoked by BARE
  name (an absolute path would change the capture/replay command key and break replay of every
  pre-existing bundle — caught in adversarial review before merge); a bare-name exec that
  fails to launch on a sbin-less non-root `$PATH` is treated as the honest "could not read
  ruleset (run as root?)" (health) / "state not verified — run as root" (security), driven by
  a new `FirewallUnreadable` flag. The security collector's on-disk-config fallback was also
  gated to "binary truly absent" so a present-but-unreadable nft can't be masked as a false
  "active". Regression guard added (`firewall_barename_linux_test.go`). Verified live across
  both privilege levels, incl. with `/etc/nftables.conf` present. **PR:** #509

## AWS EC2 Debian 13 (arm64 / t4g.small) validation — 2026-06-25

A fresh-boot Graviton (t4g.small) Debian 13 box. Privilege-pair pass (non-root +
root JSON diff) was otherwise clean — the degradation contract held — but the
non-root `Drives` line gave a wrong remediation.

### BUG-067 — non-root NVMe SMART blamed privilege when nvme-cli was simply absent
**Found:** AWS EC2 Debian 13 (arm64), non-root `dsd health`, `nvme-cli` not installed
**Symptom:** non-root `dsd health` reported `Drives ℹ️ … SMART health not read (/dev/nvme0)
  — running unprivileged (nvme smart-log needs root)` with the hint "re-run as root (sudo
  dsd health)". But `sudo` does NOT help — `nvme-cli` is not installed at all; the root run
  correctly said "nvme-cli not installed". A misleading remediation, not a verdict bug (both
  stay INFO, no false-OK), but exactly the honesty class dsd exists to avoid.
**Root cause:** `nvmeUnreadReason()` checked `os.Geteuid() != 0` FIRST and returned
  `needs_root` for any non-root failure — deliberately, to avoid a false "absent" on SUSE/RHEL
  where `nvme` lives in `/usr/sbin` (off a non-root `$PATH`, so a bare `lookPath` would miss an
  installed tool). The ordering overcorrected: when the binary is genuinely absent everywhere,
  a non-root run still blamed privilege.
**Affected:** non-root `dsd health` `Drives` remediation on any host without `nvme-cli`
  installed — tells the operator to `sudo` when the real fix is `apt/dnf/zypper install
  nvme-cli`.
**Fix:** reorder `nvmeUnreadReason()` to test genuine ABSENCE first via `sbinToolPath("nvme")`
  (the same `$PATH`+sbin-dirs probe BUG-066 introduced) — a miss there means the binary is
  truly not on the box → `tool_absent` regardless of privilege; only a *present* tool that
  fails for a non-root caller is `needs_root`. Resolves the Debian case without regressing the
  SLES/RHEL `/usr/sbin` case the original ordering guarded. Regression guard added
  (`nvme_unread_reason_linux_test.go`, euid-independent). Verified live on the box: non-root
  and root now both report "nvme-cli not installed". **PR:** #523

### BUG-068 — "host unprotected" firewall WARN ignores the cloud Security Group layer
**Found:** AWS EC2 Debian 13 (arm64), root `dsd health`, no host iptables/nft rules
**Symptom:** `dsd health` reported `Firewall ⚠️ iptables is installed but no rules are active
  — host is unprotected`. True at the host level, but on EC2 the actual network firewall is
  the **Security Group** — a layer dsd cannot read from inside the guest. A flat "unprotected"
  on a normally-configured cloud instance reads as cloud-naive and is a credibility hit in
  exactly the demo a prospect is watching (sibling framing to the PVE-firewall BUG-017 and the
  NVMe-timeout-on-virt false-WARN).
**Root cause:** `checkFirewall` asserted "unprotected" on any empty host ruleset with no
  awareness of the cloud-guest context, even though the provider Security Group / NSG / VPC
  firewall is the real (and unreadable-from-inside) enforcement layer.
**Affected:** `dsd health` / `dsd security` firewall verdict on any AWS/Azure/GCP guest that
  relies on the cloud network firewall (the common case) — a false WARN.
**Fix:** the firewall collector now flags `CloudGuest`/`CloudProvider` via the existing
  DMI-based guest gates (`AWSGuestAvailable`/`AzureGuestAvailable`/`GCPGuestAvailable` — cheap,
  no root, no IMDS). On a detected cloud guest an empty host ruleset is INFO, not WARN, naming
  the provider construct (Security Group / NSG / VPC firewall) dsd can't see and how to verify
  it — without false-greening (it still says "add rules if you don't rely on the cloud
  firewall"). Non-cloud hosts still WARN. Regression guard added (`TestCloudGuestFirewall…`).
  Verified live on the box: the WARN became an honest cloud-aware INFO. **PR:** #524

### BUG-069 — `dsd capture`→`dsd mock` silently dropped all but one insight per check
**Found:** while turning the AWS EC2 Debian 13 (arm64) capture into a fixture
**Symptom:** a fixture captured from a host with several `Hardening` findings (SSH weak
  MACs, NOPASSWD sudo, password-never-expires, X11/AgentForwarding, LoginGraceTime)
  replayed via `dsd mock` showing only ONE of them. The **SSH weak-MAC WARN — the single
  most security-relevant finding — vanished**. `dsd health --json` itself was complete; the
  loss happened in the capture→fixture conversion.
**Root cause:** `dsd capture` built `insightMap[check] = highest-severity insight` — one
  insight per check name — and `dsd mock` reconstructed the insight list one-per-row. Any
  check that emits multiple insights kept only its top one (and among equal-severity ties,
  whichever was seen first — here NOPASSWD won over the equally-WARN weak-MAC). Every
  multi-insight check (Hardening, Logs, …) was lossy; demos/screenshots built from fixtures
  silently under-reported findings.
**Affected:** `dsd mock` output for any fixture captured from a host with multi-insight
  checks — i.e. all of them in practice. Marketing screenshots and doc fixtures understated
  what dsd actually finds.
**Fix:** capture now preserves the COMPLETE insight list (`MockFixture.Insights`, every
  finding in emit order, mirroring `--json insights[]`); `dsd mock` renders that full set,
  falling back to the legacy one-per-row reconstruction only for older fixtures that lack it
  (`resolveMockInsights`). Round-trip regression guard added (`capture_insights_test.go`)
  asserting the weak-MAC WARN survives. Verified end-to-end against the EC2 capture: all six
  Hardening insights now replay. **PR:** #525

## AWS EC2 Fedora 43 Cloud (arm64 / t4g.small) validation — 2026-06-26

A stock Fedora 43 Cloud arm64 Graviton box — btrfs root, SELinux enforcing, dnf.
First RPM/SELinux/btrfs-default surface in the EC2 arm64 sweep. The privilege-pair
pass otherwise degraded honestly, but a CRIT false-alarm fired non-root.

### BUG-070 — non-root `dsd health` false-CRITs a healthy btrfs as "DEGRADED — missing device"
**Found:** AWS EC2 Fedora 43 Cloud (arm64), non-root `dsd health`, healthy single-device btrfs root
**Symptom:** non-root `dsd health` reported `Disk ❌ CRIT btrfs / is DEGRADED — 1 missing
  device(s), data at risk` (exit 2) on a perfectly healthy single-device btrfs. Raw
  `btrfs filesystem show` as root: `Total devices 1`, the device present, 0 errors. As ROOT
  dsd was clean (`Disk ✅`). A CRIT false-alarm — the loudest, worst class — on the DEFAULT
  filesystem of Fedora, openSUSE, SteamOS, so the unprivileged blast radius is large.
**Root cause:** run unprivileged, `btrfs filesystem show` cannot OPEN the block devices, so it
  prints every present device as `devid 1 size 0 used 0 path /dev/nvme0n1p3 MISSING` — its REAL
  path with a `MISSING` suffix. The collector's regex matched `MISSING` → `MissingDevs++` →
  status "degraded" → CRIT. The device wasn't gone; btrfs just couldn't read it without root.
  A genuinely-absent device is instead shown with the `<missing disk>` placeholder path.
**Affected:** non-root `dsd health` / `dsd disk` on ANY host with a btrfs filesystem — a
  spurious DEGRADED CRIT (exit 2) for every unprivileged run.
**Fix:** `applyBtrfsShow` now distinguishes a real `/dev` path flagged `MISSING` under a
  non-root run (the "couldn't open device" artifact → new `DevReadUnverified` flag, volume
  "unverified", NOT counted as missing) from the genuine `<missing disk>` placeholder (still a
  DEGRADED CRIT, even non-root, so a real fault is never hidden). As root a real-path MISSING is
  still counted (root CAN open devices, so it'd be anomalous — no false-OK). The heuristic emits
  an honest INFO "btrfs <mount> device state could not be verified — run as root" instead of the
  CRIT. Regression guards added (collector + heuristic) using the exact Fedora output. Verified
  live: non-root CRIT → INFO, root stays `Disk ✅`. **PR:** #526

## AWS EC2 Alpine 3.22 (x86_64 / t3.small) validation — 2026-06-26

A stock Alpine Linux 3.22 EC2 box — **musl + busybox + OpenRC, no systemd, no
glibc**. The non-systemd surface nothing else in the matrix currently covers.
Degradation was honest throughout (systemd/DBus rows correctly absent, firewall
"no tooling" not a false "unprotected", nvme "needs root" correct per BUG-067),
but OOM detection was silently dead.

### BUG-071 — OOM detection dead on Alpine/busybox even as root (`dmesg --time-format` unsupported)
**Found:** AWS EC2 Alpine 3.22 (x86_64), root `dsd health`
**Symptom:** the OOM check reported `OOM ℹ️ not verified — kernel log unreadable (journalctl -k
  and dmesg both failed)` even as root — yet `doas dmesg` worked fine and `/dev/kmsg` was
  readable. So OOM-kill detection was entirely unavailable on Alpine (and any busybox host),
  not just unprivileged. Honestly reported (INFO, not a false-OK "0 kills"), but a real
  coverage gap on the default OOM signal.
**Root cause:** the OOM collector's dmesg fallback called `dmesg --time-format iso` (util-linux
  syntax). Alpine's `dmesg` is **busybox**, which doesn't support `--time-format`, so the call
  errored and the collector concluded the kernel log was unreadable — despite a bare `dmesg`
  working. (journalctl is absent on Alpine, so the dmesg path was the only one.)
**Affected:** `dsd health` OOM section on every busybox/non-systemd host (Alpine, and busybox
  embedded systems) — OOM kills undetectable even with privilege.
**Fix:** when `dmesg --time-format iso` fails, retry **bare `dmesg`** before giving up (the same
  two-step pattern kernel_security.go already uses). Plain dmesg's boot-relative timestamps are
  already handled conservatively by filterOOMRecent. Regression guard added
  (`oom_busybox_dmesg_test.go`, a fake busybox source: iso-flag fails, bare dmesg succeeds).
  Verified live on the Alpine box: `OOM ✅ 0 events` at root (was "not verified"). **PR:** #529

## cmd↔health consistency guard — extension to net/k8s/security — 2026-06-26

Extending the cmd↔health verdict-consistency guard (#528) to net/k8s/security
(see [[#528]]). net and k8s aligned cleanly; the guard surfaced a real security
divergence below.

### BUG-072 — `dsd security` verdict undercounts SSH hardening vs `dsd health`
**Found:** extending the cmd↔health consistency guard to security (2026-06-26); corroborated
  by the live Alpine 3.22 run where `dsd health` WARNed weak-MAC + password-never-expires.
**Symptom:** `dsd security`'s "N concern(s)" verdict (`countSecurityIssues`) tallies a NARROWER
  set than `dsd health`'s `checkSecurity`: cmd counts SSHPermitRoot, SSHPasswordAuth, failed
  logins, unexpected ports, NOPASSWD sudo, SUID, SELinux denials — but NOT StrictModes-disabled,
  PermitEmptyPasswords (a health CRIT!), weak SSH MACs, or password-never-expires, all of which
  checkSecurity WARNs/CRITs on. So `dsd security` can summarize "healthy / fewer concerns" while
  `dsd health` flags real SSH hardening issues on the same host — the sibling-divergence class
  (#235/#275/#335) again, in security.
**Affected:** `dsd security` summary verdict on any host with those SSH hardening gaps — the
  detail section may even print the weak MAC while the verdict reads healthy.
**Fix:** `dsd security`'s verdict now derives from the SAME heuristic `dsd health` uses — new
  exported `analysis.SecurityConcernCount` counts the WARN/CRIT insights `checkSecurity` raises —
  replacing the parallel `countSecurityIssues` tally (deleted). The two can no longer diverge by
  construction. Verified safe at non-root: the collector defaults `SSHStrictModes=true` (only
  flips false when sshd config is actually read and says `StrictModes no`), so a non-root run
  where the config is unreadable does NOT gain a false StrictModes concern. Side effect (accepted):
  the `dsd security` "N concern(s)" count is now grouped like health (e.g. 3 unexpected ports = 1
  concern, not 3). Consistency test extended to the previously-missed conditions (StrictModes,
  PermitEmptyPasswords) as a revert guard. **PR:** _guard #530; fix #532_

---

## Gentoo on real VMware/vCD — first validation (2026-06-28)

First Gentoo guest validated on **real VMware**. A Gentoo `di-amd64-console` (systemd,
UEFI) qcow2 was converted to a stream-optimized VMDK + a hand-built OVA, imported to the
vCD tenant, and **boots under UEFI/OVMF** — the generic dracut initramfs carries every
VMware storage controller (`mptspi`/`mptsas`/`vmw_pvscsi`) with XFS + AHCI + NVMe built
into the kernel, so the KVM-built image's virtio dependency was a non-issue. The
`dsd health` **two-pass (root vs non-root) was clean**: every privileged check (Hardening
SSH-root-login, Firewall, OOM, LVM, Logs, PostBoot) degrades to an explicit "could not
verify / run as root" unprivileged — none to a false-OK. The VMware collector correctly
flagged all four real guest-config issues (no open-vm-tools, e1000, 30s SCSI timeout,
`disk.EnableUUID` off). One finding below.

### BUG-073 — package-install fix hints name the wrong tool on Gentoo (omit `emerge`)
**Found:** Gentoo-on-real-VMware validation, vCD tenant guest (2026-06-28)
**Symptom:** `dsd health` remediation hints read `to fix: apt install <pkg>  (RHEL/SUSE:
  dnf/zypper install <pkg>)` on a Gentoo host — naming package managers the host doesn't
  have. Hit live on the open-vm-tools and rsyslog "to fix" lines.
**Root cause:** the install-suggestion hint strings are hardcoded apt/dnf/zypper across
  ~12 sites in `internal/analysis`; none emit `emerge`, and the detected package manager
  was never routed into the remedy text.
**Affected:** every `to fix: <pm> install …` hint on Gentoo. Cosmetic/UX only — the
  diagnosis and verdict are correct; just the suggested command names the wrong tool.
**Fix:** host-gated `gentooifyHints` pass (mirrors the existing `nixosifyHints`) rewriting
  any package-install hint to `to fix (Gentoo): emerge <pkg>`, preserving a trailing
  `&& <service-enable>`. Gated on `/etc/os-release ID=gentoo`, so no other host is
  affected. Tests in `internal/analysis/gentoo_hints_test.go`. Out of scope: the
  standalone `dsd gpu`/`dsd kvm` printf hints (separate surface).
**Commit:** `d9968e3` (PR #611)

---

## openSUSE Leap Micro on real VMware/vCD — immutable/transactional validation (2026-06-28)

First **immutable/transactional** OS validated on real VMware: openSUSE Leap Micro 6.2
(`ID=opensuse-leap-micro`, `/sbin/transactional-update`, root mounted `ro` on a btrfs
snapshot subvol). The `dsd health` two-pass (root vs `nobody`) surfaced three findings —
one a genuine non-root false-OK. All fixed in PR #620, validated live (root + non-root).

### BUG-074 — non-root SELinux reads "not enforced" while SELinux is enforcing (false-OK)
**Found:** Leap Micro two-pass (root vs nobody), vCD tenant guest (2026-06-28)
**Symptom:** as root, `KernelSec` reports "SELinux enforcing"; as a non-root user it reports
  **"kernel security module not enforced"** — telling an unprivileged operator security is
  OFF when it is enforcing.
**Root cause:** `collectSELinux` probed only `getenforce`, absent from Leap Micro's non-root
  PATH; on failure it returned `present=false`. The authoritative source,
  `/sys/fs/selinux/enforce`, is world-readable (`nobody` reads `1`).
**Affected:** every non-root `dsd health` on a SELinux host where `getenforce` isn't on PATH.
  A same-level INFO→INFO **semantic** flip, so the non-root verdict-invariant CI (severity
  diff) does not catch it. **Independently reproduced on openSUSE Tumbleweed** (`192.168.30.166`,
  real VMware) with user `andrei` (PATH lacks `/usr/sbin` → no `getenforce`): OLD binary →
  "not enforced", #620 binary → "SELinux enforcing".
**Fix:** read the world-readable `/sys/fs/selinux/enforce` first; fall back to `getenforce`;
  if the mode is genuinely unreadable but the SELinux fs is mounted, report
  present-but-`"unknown"` → "mode unreadable, re-run as root", never a false "not enforced".
  Resolution order guarded by `resolveSELinuxMode` (PR #626).
**Commit:** `92a5a48` (PR #620); regression guard PR #626

### BUG-075 — read-only root false-WARNs as an I/O-error remount on every immutable OS
**Found:** Leap Micro validation (2026-06-28)
**Symptom:** `Disk WARN: filesystem / (btrfs …) is mounted READ-ONLY — the kernel likely
  remounted it after an I/O error` on every MicroOS / Leap Micro / SLE Micro host, where the
  read-only btrfs snapshot root is read-only BY DESIGN.
**Fix:** the disk collector sets `DiskInfo.ImmutableRootFS` (reusing `rootImmutableByDesign`:
  ostree / transactional-update / SteamOS; internal `json:"-"`, recomputed on replay → no
  schema change) and the heuristic skips the WARN for `/` there.
**Commit:** `92a5a48` (PR #620)

### BUG-076 — package-install hints suggest live `zypper install` on a read-only root
**Found:** Leap Micro validation (2026-06-28)
**Symptom:** fix hints read `zypper install <pkg>`, but on a transactional system the root is
  read-only — a live `zypper install` won't persist; packages go in via
  `transactional-update pkg install <pkg>` + reboot.
**Fix:** host-gated `transactionalifyHints` rewrites install hints to
  `to fix (transactional): transactional-update pkg install <pkg> (then reboot)`, gated on a
  `*-micro` distro ID; mirrors the NixOS/Gentoo hint passes.
**Commit:** `92a5a48` (PR #620)

## Fedora CoreOS on real VMware/vCD — ostree/immutable validation (2026-06-29)

Hand-repackaged the FCOS VMware OVA (ustar, Ignition baked) for vCD; two-pass
(root + non-root) on the live guest. Five defects, all the "collector assumes a
mainstream distro shape" class; the non-root→root invariant held throughout.

### BUG-077 — SELinux booleans rendered as a "non-enforcing" policy on an enforcing host
**Symptom:** on `getenforce`=Enforcing, KernelSec printed "Security policies not in
  enforcing mode" listing ~64 enabled SELinux booleans as "policy relaxed", with an
  AppArmor `aa-status` hint that doesn't apply.
**Fix:** `buildPolicyTable` reports only genuinely non-enforcing MAC state (AppArmor
  complain profiles, SELinux permissive/disabled mode); booleans are no longer an input.
**Commit:** PR #634

### BUG-078 — `dnf install` hints on an ostree/immutable host
**Symptom:** open-vm-tools / rsyslog fix hints said `dnf install`, which can't persist on
  the read-only `/usr` of an ostree host.
**Fix:** `ostreeifyHints` (AdaptHostHints chain) rewrites install hints to
  `rpm-ostree install <pkg> (then reboot)`, gated on `/etc/os-release` ostree variants.
**Commit:** PR #635

### BUG-079 — read-only `/sysroot` + `/boot` false-WARN on an ostree root
**Symptom:** `Disk WARN: filesystem /sysroot … mounted READ-ONLY — kernel likely remounted
  after an I/O error` on FCOS, where those mounts are ro by design. The #620 immutable fix
  only covered `/`; ostree keeps `/` writable but `/sysroot`/`/boot`/`/usr` ro.
**Fix:** broadened the suppression to the immutable-infra mount set when `ImmutableRootFS`;
  data mounts (`/var`,`/home`) still WARN.
**Commit:** PR #636

### BUG-080 — `permissive=1` AVCs counted as enforced denials (false denial-flood CRIT)
**Symptom:** 12 first-boot `bootupd_t` AVCs, all `permissive=1` (logged, not enforced),
  drove a CRIT (KernelSec ≥10) plus a contradictory Hardening WARN.
**Fix:** a shared `avcIsPermissive` excludes `permissive=1` from every denial-counting path
  (audit.log, ausearch, journald, sample, grouping).
**Commit:** PR #637

### BUG-081 — duplicate SELinux-denial verdict (KernelSec CRIT + Hardening WARN)
**Symptom:** `dsd health` runs both collectors, so the same denials produced a CRIT and a
  WARN for one event.
**Fix:** `dedupeSELinuxDenials` post-pass keeps the KernelSec verdict, folds in Hardening's
  grouped fix-hints, drops the duplicate. Standalone `dsd security` unaffected.
**Commit:** PR #638

## VMware Photon OS (redeployed) — cloud-init false-OK (2026-06-29)

### BUG-082 — a genuinely failed cloud-init service reads green on a VM
**Found:** Photon 5.0 redeploy validation (2026-06-29)
**Symptom:** `cloud-config`/`cloud-final`/`cloud-init` were in the unconditional
  `cloudInitUnits` ignore set (meant for LXC/live-ISO), so a failed cloud-init service on a
  real VM was filtered out of the failed-units list and Systemd read OK — a false-OK.
**Fix:** split the cloud-init services into `cloudInitServiceUnits`, suppressed in the
  failed-unit verdict only when `InContainer`; on a VM the failure surfaces. Guarded by a
  container-vs-host suppression invariant (#642).
**Commit:** PR #640 (guard #642)

## Devuan (sysvinit) + Artix (OpenRC) on real VMware — non-systemd hints (2026-06-29)

### BUG-083 — systemd-only remedy commands on non-systemd inits
**Found:** Artix/OpenRC and Devuan/sysvinit validation (2026-06-29)
**Symptom:** dsd suggested `systemctl status chronyd ntpd`, `timedatectl status`,
  `systemctl restart sshd`, `journalctl …` on hosts with no systemd. Init detection only
  knew systemd+openrc; sysvinit (Devuan) and runit (Void) fell through to "unknown" and
  were never adapted; even openrc left the `status`/`timedatectl`/`journalctl` inspect
  forms. (Trap: Devuan ships the runit *package*, so /run/runit exists while sysvinit is
  PID1 — a file-marker check mis-detected runit.)
**Fix:** init detection is PID1-based (`classifyInit`/`/proc/1/comm`); the adapter covers
  openrc/sysvinit/runit (`serviceCmd`) + status-inspect + timedatectl/journalctl drop +
  embedded-restart, and adds pacman/apk install hints. CI Alpine smoke now asserts no
  leaked systemd commands in hints.
**Commit:** PRs #644, #646, #647

## Oracle Linux 9.8 + 10.1 on real VMware/vCD — CIS / Drives / SELinux + maintenance checks (2026-06-29)

Validated `dsd` two-pass (root + non-root) on clean OL 9.8 (RHCK) and OL 10.1 (UEK)
guests on real VMware vCloud Director. Verdicts were honest throughout (no false-OK);
the bugs below were remediation-/message-accuracy defects, plus a gap-analysis that
drove five new checks.

### BUG-084 — `dsd cis` auditd remediation hardcoded Debian path/command on RHEL
**Found:** Oracle Linux 9.8, real VMware vCD
**Symptom:** CIS rules 4.1.1/4.1.2 advised `apt install auditd` and `cp
  /usr/share/doc/auditd/examples/stig.rules …` — a package/path absent on RHEL-family;
  the real sample rules live at `/usr/share/audit/sample-rules/30-stig.rules` and the
  package installs via `dnf install audit`.
**Root cause:** `dsd cis` renders `CISResult.Remediation` directly and does NOT route
  through `analysis.AdaptHostHints` (the apt→dnf hint adapter `dsd health` uses), so a
  hardcoded apt-ism leaked verbatim. A verdict-focused validation can't catch it — the
  CIS verdict was correct; only the prose was wrong.
**Affected:** `dsd cis` on every RHEL/SUSE/Arch host
**Fix:** thread the detected package manager into `cis.Evaluate`; rewrite the two
  auditd hints per family. **Guard:** `TestRulesHaveNoHardcodedDistroHints` fails the
  build if a CIS rule inlines a package-install command or distro path (the helper in
  `remediation.go` is the only sanctioned home).
**Commit:** PRs #649 (fix), #650 (guard)

### BUG-085 — Drives claimed "running unprivileged" when run as root on a virtual disk
**Found:** Oracle Linux 9, real VMware vCD (virtual `/dev/sda`)
**Symptom:** As **root**, the SMART-unread INFO led with "running unprivileged
  (smartctl needs root)" — false; the operator was root and smartctl was installed.
**Root cause:** the SATA unread-SMART path lumped every cause into one message. A
  VMware virtual disk exposes no SMART even to root, but shared the "needs root"
  wording. `runCmd` also discards stdout on a non-zero exit, so the non-root
  permission JSON was lost — the reason had to come from `smartctl --scan-open`'s
  per-device `open_error`.
**Affected:** `dsd health` / `dsd disk` Drives on any virtual/cloud disk
**Fix:** record `SmartUnreadReason` (`needs_root` vs `no_smart`) like the NVMe path;
  root+virtual → "no SMART data exposed (virtual disk / USB / RAID)", non-root-blocked
  → "running unprivileged". Verdict unchanged (INFO). Verified live both ways.
**Commit:** PR #651

### BUG-086 — SELinux "mode unreadable" advised "re-run as root" (privilege wouldn't help)
**Found:** post-OL guard sweep
**Symptom:** when SELinux mode read `unknown`, KernelSec said "re-run as root."
**Root cause:** the enforce state comes from the **world-readable**
  `/sys/fs/selinux/enforce` (the BUG-074 privilege-independent source) — if it can't
  be read, root can't either, so the advice is useless. Same false-privilege class as
  BUG-085.
**Affected:** `dsd health` KernelSec on hosts with an indeterminate SELinux mode (rare)
**Fix:** reword to "enforce state could not be read." AppArmor's mode lives in a
  root-only node, so it correctly KEEPS "re-run as root" — tests pin both sides.
**Commit:** PR #652

### Gap analysis → 5 new RHEL/Oracle maintenance checks (not bugs — missing coverage)
Mapping deep-check gaps against the live OL boxes surfaced five silent-failure classes
dsd didn't cover, shipped as gated checks (#653): **Kdump** (enabled but not armed →
no dump), **Tuned** (active≠recommended profile — caught OL9 on `balanced`), **Kernel**
(newer kernel installed than running → reboot to apply), **Ksplice** (Oracle live
patches pending), **ServiceRestart** (procs on `(deleted)` libs after update — caught
live on OL10 after `dnf reinstall glibc`, 30 services; non-root → honest INFO partial).
**Commit:** PR #653

### BUG-087 — #653 maintenance checks: cross-distro quasi-false-OK (found on the pve fleet)
**Found:** running #653 on pve01 — AlmaLinux LXC (CT213) + Oracle Linux UEK VM (121)
**Symptom (three):** (a) on an **Alma LXC** the Kernel check reported the *host's*
  `6.17-pve` kernel as "Kernel OK" — a container can't reboot its own (host) kernel;
  (b) on a standard **OL UEK** host the Kernel check silently no-op'd — Oracle packages
  UEK as `kernel-uek-core`, which the query missed (it had `kernel-uek`/`kernel-core`);
  (c) on **SUSE** the check would show a fake "OK" — `kernel-default`'s NVRA doesn't
  line up with `uname` (the `-default` flavor), so the rpm-compare can't match.
**Root cause:** host-kernel checks weren't container-gated; the kernel-package name set
  was RHEL-incomplete; SUSE's kernel versioning needs a different signal.
**Affected:** `dsd health` Kdump/Kernel/Ksplice in containers; Kernel on OL UEK + SUSE
**Fix:** gate Kdump/Kernel/Ksplice off in a container (`ContainerContextViaSource`);
  add `kernel-uek-core` to the query; cover SUSE via `zypper needs-rebooting`; leave the
  check unavailable (no row) rather than show a "Kernel OK" that checked nothing.
  Validated: CT213 → rows gone; OL9 UEK VM 121 → Kernel row restored.
**Commit:** PR #655

### BUG-088 — SUSE Kernel check silently dropped under root (zypp-lock race)
**Found:** validating dsd on real SLES 16 (VMware vCloud Director tenant, 2026-06-30).
**Symptom:** `dsd health` showed the Kernel reboot-to-apply row as **non-root** (Kernel
  OK), but the row **vanished entirely when run as root** — no Kernel check at all, on
  every root run. A check that disappears under privilege is the dangerous silent-drop
  class: the root operator gets no signal and assumes nothing's wrong.
**Root cause (proven via a `capture --raw` bundle):** the #655 SUSE path keyed on the
  **stdout text** of `zypper needs-rebooting`. dsd runs the package collector's
  `zypper verify` concurrently, which holds the one global zypp lock (`/run/zypp.pid`);
  needs-rebooting then fails fast with **exit 7 (ZYPP_LOCKED)** and EMPTY stdout (the
  lock error is on stderr). Empty stdout → no text match → `Available` stayed false →
  the row was dropped. Non-root never hit it: the locking zypper collectors fail fast
  unprivileged, so there's no contention. The capture recorded `needs-rebooting exit:7`.
  This is the lock-race sibling of the #480 `zypper verify` integrity false-OK.
**Affected:** `dsd health` Kernel check on SUSE/openSUSE, root runs only.
**Fix:** key on the **exit code** (0 → no reboot, 102 → reboot needed, 7 → locked) via a
  `suseRebootSignal` helper that retries the lock like the package collector does; if it
  stays locked for the whole budget, surface `CheckUnverified` → INFO "could not be
  determined" rather than dropping the row or implying "Kernel OK". Registered in the
  false-OK signal tripwire; unit-tested per exit code (`maintenance_linux_test.go`).
  Validated live: three root runs → Kernel OK restored; the re-captured bundle now
  records `needs-rebooting exit:0` (the retry obtained the lock).
**Commit:** #661

### BUG-089 — `dsd gpu` / `dsd docker` verdicts diverged from `dsd health` (two cases)
**Found:** extending the cmd↔health consistency guard (`cmd_health_consistency_test.go`)
  to cover every concern-condition, not just the ~4 per command it previously exercised
  (2026-06-30). Two previously-untested conditions surfaced live divergences — the same
  sibling-divergence class as #275/BUG-050 (a standalone `dsd <cmd>` verdict disagreeing
  with `dsd health` on identical data because each path tallies concerns independently).
**Symptom (two):**
  (a) **GPU** — `dsd gpu` reported "GPU elevated" (WARN) on a GPU at ≥95% utilization,
      while `dsd health` stayed clean. A GPU at 95–100% util is just *busy* (like a CPU
      under load); `checkGPUDevice` correctly treats sustained load as an INFO
      correlation signal (util≥80 AND power≥80), never a WARN. `gpuConcerns` wrongly
      counted bare `UtilPct≥95` → a false-WARN on a working GPU.
  (b) **Docker** — `dsd docker` reported a concern when containers existed but were ALL
      stopped (`StoppedCount>0 && RunningCount==0`), while `dsd health` stayed clean.
      A stopped container is a state, not a fault (it may be intentionally stopped), and
      a container that died badly is already caught by UnhealthyCount / CrashLooping /
      exit-code checks. `checkDocker` has no all-stopped rule; `dockerConcerns` did.
**Root cause:** both cmd tallies carried a concern condition that the health heuristic
  (correctly) does not — the exact drift the consistency guard exists to catch, in
  conditions the guard didn't yet exercise.
**Affected:** `dsd gpu` (busy GPU), `dsd docker` (all containers stopped). Standalone
  commands only; `dsd health` was always correct.
**Fix:** align both cmd tallies to health — drop bare `UtilPct≥95` from `gpuConcerns`
  and the all-stopped rule from `dockerConcerns`. Extended the consistency guard to
  boundary-cover every concern-condition in gpu/docker/net/k8s (net/k8s agreed — pure
  coverage gain), so these can't silently re-diverge.
**Commit:** #663

### BUG-090 — CVE zypper scans dropped the patch table on a non-zero exit (missed-CVE under-report)
**Found:** auditing the two zypper CVE call sites flagged by the #662 lock tripwire
  registry (2026-06-30).
**Symptom:** `zypper lp` / `zypper list-patches` EXIT NON-ZERO when patches are
  applicable (`ZYPPER_EXIT_INF_*_UPDATE_NEEDED`), writing the patch table to stdout.
  Both CVE collectors used plain `runCmd`, which DISCARDS stdout on a non-zero exit —
  so a SUSE system that genuinely HAD pending security patches read as:
  - `dsd cve <id>` → **CVEUnknown** ("zypper lp failed") instead of **VULNERABLE**;
  - `dsd health --cve` / `dsd cve --all` → **ScanFailed** ("list-patches failed")
    instead of listing the advisories.
  Either way a vulnerable host under-reported its exposure. `scanAllZypper` also had
  no zypp-lock retry (the BUG-088 class), so a sibling zypper collector holding the
  lock flapped it to "failed" too.
**Root cause:** `runCmd` drops findings-bearing stdout when a tool signals via a
  non-zero exit — the same class as the #366/#480/#481 apt/dnf/zypper false-OKs. The
  CVE paths never adopted the `runCmdOutput`/`runCmdCombined` fix the package collector
  already uses.
**Affected:** `dsd cve <id>` and `dsd health --cve` / `dsd cve --all` on SUSE/openSUSE
  whenever security patches are actually pending.
**Fix:** `checkCVEZypper` → `runCmdOutput` (keeps the table on a non-zero exit; a real
  lock/permission failure still arrives as err with empty stdout → honest CVEUnknown).
  `scanAllZypper` → `runCmdCombined` + `zypperLocked` retry ×5 mirroring `collectZypper`,
  checking the lock BEFORE emptiness (the combined output folds the lock message in, so
  a len==0 test would miss it → a false "no CVEs"); only a genuinely empty/non-table
  result → ScanFailed, with a distinct "locked" reason. Unit-tested per exit code
  (`cve_zypper_linux_test.go`); registered in the zypper-lock tripwire.
**Commit:** (this PR)

## NixOS 25.05 (Warbler) — first full SSH-driven validation (2026-06-30)

First proper two-pass (root + non-root) + capture validation on real NixOS, after a
fresh scripted install (live ISO → `nixos-install` with SSH + pve01 key baked into
`configuration.nix`) on pve01 VM 212. dsd's distro handling was already strong —
NixOS detected, and every remedy hint correctly routed through `nixosifyHints`
(`…in configuration.nix, then nixos-rebuild switch`, never editing files NixOS would
clobber). One false-alarm found and fixed.

### BUG-091 — `/nix/store` read-only bind false-WARNed as an I/O-error remount
**Found:** live on NixOS 25.05, the deep validation pass (2026-06-30).
**Symptom:** `dsd health` raised `Disk WARN: filesystem /nix/store (ext4 …) is mounted
  READ-ONLY — the kernel likely remounted it after an I/O error` on a perfectly
  healthy NixOS host. NixOS bind-mounts `/nix/store` **read-only off the read-write
  root** for immutability/tamper-protection — by design, not a fault. `dmesg` had zero
  I/O errors.
**Root cause:** the writable-fs-mounted-ro check (`checkDisk`) only suppressed the WARN
  for ostree/transactional/SteamOS immutable infra (`ImmutableRootFS`), which NixOS is
  not. It never considered that the SAME backing device (`/dev/disk/by-uuid/407cadeb…`)
  was mounted **rw** at `/` and **ro** at `/nix/store` — a topology a kernel I/O-error
  remount cannot produce (an error remount flips the whole block device to ro at once,
  so `/` would be ro too). That signature is unique to an intentional ro bind.
**Affected:** NixOS (every host — `/nix/store` is always a ro bind), and any host with a
  ro bind mount of an otherwise-rw filesystem.
**Fix:** in `checkDisk`, build the set of devices mounted rw (writable on-disk fstypes)
  up front; a ro mount whose device is in that set is an intentional ro bind →
  suppressed. Distro-agnostic (no NixOS special-case). A genuine error remount — a ro
  mount whose device is **not** mounted rw anywhere — still WARNs. Real-bytes unit test
  `nixos_nix_store_ro_test.go` (the captured bundle `nixos-2505-20260630.tar.gz` replays
  the bug pre-fix and clean post-fix).
**Commit:** (this PR)

## Alpine + Docker — "no-systemd Docker host" validation (2026-07-01)

First validation of the minimal-footprint Docker-host use case: Alpine 3.22 (OpenRC,
musl) + Docker on pve01 VM 106. dsd's core path was clean — Alpine detected, OpenRC-
native hints (`rc-service …`), Docker folded into health (socket-mount CRIT + root-user
WARN caught), no false LVM/k8s/bonding, two-pass honest (Docker CRIT→INFO under non-root,
no false-OK). One class of defect found and fixed.

### BUG-092 — host service collectors detect containerized processes as host services
**Found:** live on the Alpine Docker host. `dsd health` reported
  `Nginx INFO — config not validated (the config test needs root to read the config)`
  while running as **root** — the nginx was actually inside a container (`nginx:alpine`),
  not on the host, and the "needs root" reason was wrong (the real reason: no host nginx).
**Root cause:** host service collectors detect their service by scanning `/proc/<pid>/comm`
  via two shared helpers — `procCommRunning` (Nginx/Apache/HAProxy) and `anyProcessNamed`
  (BIND, + host daemons cron/multipathd/rpcbind/auditd). On a Docker host the container's
  processes are visible in the **host PID namespace**, so the scan matched the container's
  `nginx`/`named` and then ran a host-level check (`nginx -t`, etc.) against a service that
  isn't on the host — a misleading INFO here, but on another service (a containerized DB or
  resolver) it could yield a genuinely wrong host-level verdict. Container health is already
  the Docker/k8s collector's job.
**Affected:** any Docker/Podman/k8s host running a service (nginx/apache/haproxy/named/…)
  in a container while dsd reads the host. Real bytes: the container's nginx had cgroup
  `0::/docker/4d41585046dd…`.
**Fix:** both process-scan helpers now skip a match whose cgroup says it lives in a
  container, via a shared `pidIsContainerizedIn(procDir, pid)` that reuses the existing
  `parseCgroupPath` (classifies `/docker/`, `libpod-`, `/kubepods/` → container/k8s/pod).
  Distro-agnostic, choke-point fix (no per-collector special-casing). An unreadable cgroup
  defaults to **host** (never hide a real host service). Host daemons are unaffected (they
  run under `/system.slice/…` / root cgroup → host scope). Real-bytes unit test
  `containerized_proc_linux_test.go`; capture `alpine-docker-20260701.tar.gz` replays clean.
**Commit:** (this PR)

## RKE2 (Rancher Kubernetes Engine 2) — first live "beyond k3s" validation (2026-07-01)

First validation of the k8s OS-layer on a real **RKE2** cluster (the freshly-shipped
RKE2 detection #667 + Rancher mgmt-plane check #668 had only been fixture-tested). Built
a single-node RKE2 v1.35.6 cluster on pve01 VM 108 (Debian 13). dsd correctly auto-found
the RKE2 kubeconfig (`/var/lib/rancher/rke2/bin/kubectl --kubeconfig=/etc/rancher/rke2/
rke2.yaml`), read nodes/pods, applied k8s-aware sysctl checks (inotify watches, swappiness),
and the Rancher mgmt-plane check correctly stayed silent (RKE2 ≠ Rancher). One false-CRIT
found and fixed.

### BUG-093 — node condition `EtcdIsVoter=True` false-CRIT'd as a fault
**Found:** live on the RKE2 node — `dsd health` raised
  `K8s CRIT — node rke2-test: EtcdIsVoter condition True — workloads may be evicted`
  on a perfectly healthy single-node control plane.
**Root cause:** `checkK8sNodes` (`heuristics_virt.go`) blanket-CRIT'd **any** node
  condition whose status was `True`, except `Ready`. That holds for the standard
  Kubernetes pressure conditions (MemoryPressure/DiskPressure/PIDPressure) and
  NetworkUnavailable — but RKE2/k3s managed-etcd nodes add **`EtcdIsVoter`**, where
  `True` means the node is a HEALTHY voting member of the etcd cluster (the node's own
  condition message: *"Node is a voting member of the etcd cluster"*). dsd assumed
  every True condition was bad → a false-CRIT on every RKE2 (and k3s-with-embedded-etcd)
  control-plane node.
**Why k3s never caught it:** the existing k3s rig runs the default **sqlite** datastore,
  which has no etcd node conditions at all — exactly the gap that going "beyond k3s" to
  RKE2 exposed.
**Affected:** every RKE2 node, and k3s clusters using embedded etcd (`--cluster-init`).
**Fix:** replace the blanket "any True condition" rule with an **allowlist** of the
  standard node-problem conditions (`MemoryPressure`, `DiskPressure`, `PIDPressure`,
  `NetworkUnavailable`); a condition outside the set is never assumed bad-when-True, so
  distro/vendor conditions with their own polarity (confirmed: `EtcdIsVoter`) can't
  generate false-CRITs. Real-bytes unit test `k8s_node_conditions_test.go` (the
  live RKE2 node's exact conditions); a genuine MemoryPressure=True still CRITs.
  Verified live: `K8s` dropped CRIT→WARN (only the transient bootstrap warning events
  remain); capture `rke2-debian-20260701.tar.gz`.
**Commit:** (this PR)

## kubeadm — second "beyond k3s" validation (2026-07-01)

Validated the k8s OS-layer on a real **kubeadm** v1.31 cluster (the canonical reference
distribution; static-pod control plane, flannel CNI) on pve01 VM 109. Confirmed BUG-093
does NOT over-fire (kubeadm has no `EtcdIsVoter` condition — different control-plane
shape), and dsd honestly reported a genuinely-degraded coredns. One root-access gap found
and fixed.

### BUG-094 — `sudo dsd k8s`/`health` can't reach a kubeadm cluster (no admin.conf detection)
**Found:** live on the kubeadm node — `sudo dsd k8s` reported
  `cluster API unreachable — cluster health NOT verified` on a healthy cluster, while the
  operator's **non-root** `dsd k8s` (via `~/.kube/config`) worked fine. The privilege
  polarity is inverted from the usual: non-root saw the cluster, root didn't.
**Root cause:** `k8sDetectBin` resolves a kubeconfig for k3s (`/etc/rancher/k3s/…`) and
  RKE2 (`--kubeconfig=/etc/rancher/rke2/rke2.yaml`) but for generic/kubeadm it returned
  bare `kubectl`. kubeadm writes its admin credential to **`/etc/kubernetes/admin.conf`**
  (root-readable, 0600) and copies it to the *operator's* `~/.kube/config` — but never to
  `/root/.kube/config`. So `sudo kubectl` has no kubeconfig, falls back to localhost:8080,
  and every cluster query fails → dsd reads "API unreachable" on a healthy cluster (the
  most common invocation, `sudo dsd health`, is exactly the broken one).
**Affected:** every kubeadm (and generic-kubectl) control-plane node when dsd runs as
  root without a root kubeconfig — i.e. the default `sudo dsd health` path.
**Fix:** `kubeadmKubeconfigFlag()` appends `--kubeconfig=/etc/kubernetes/admin.conf` to a
  plain-kubectl invocation **only** as root (admin.conf is root-only), and only when root
  has no kubeconfig of its own (`KUBECONFIG` env / `/root/.kube/config`) — so the non-root
  operator path is untouched. kubectl reads admin.conf to authenticate; its content is
  never captured (we record kubectl's output, not the credential). Pure decision extracted
  to `kubeadmKubeconfigFlagFor` + table test `kubeadm_kubeconfig_test.go`. Verified live:
  `sudo dsd k8s` now reads the cluster via admin.conf; capture `kubeadm-debian-20260701.tar.gz`.
**Commit:** (this PR)

## k0s — third "beyond k3s" validation (2026-07-01)

Validated on a real **k0s** v1.36.2 single-node cluster (Mirantis's single-binary k8s) on
pve01 VM 111. One false-NEGATIVE found and fixed; no EtcdIsVoter false-CRIT; two-pass
honest (K8s WARN→INFO non-root).

### BUG-095 — dsd is blind to a k0s cluster (no k0s in kubectl detection)
**Found:** live on the k0s node — `dsd health` showed **no K8s section at all** on a
  running control plane. k0s installs a single `/usr/local/bin/k0s` binary and NO standalone
  `kubectl` (it wraps it as `k0s kubectl`), and `k8sDetectBin` only knew k3s/RKE2/kubectl/
  microk8s → found nothing → `K8sAvailable()` false → the whole K8s collector was skipped.
  A running Kubernetes control plane whose health is entirely unchecked — a silent
  false-negative (worse than a false verdict: no verdict).
**Affected:** every k0s node (controller / controller+worker).
**Fix:** add k0s to `k8sDetectBin` (direct paths `/usr/local/bin/k0s`, `/usr/bin/k0s`, and
  the PATH fallback) returning `<bin> kubectl`, and to `k8sDistribution` (marker
  `/var/lib/k0s`, checked BEFORE kubeadm since k0s also writes /var/lib/kubelet/config.yaml).
  Detection tests `TestK8sDetectBinK0s` + `k0s`/`k0s beats kubeadm` distribution cases.
  Verified live: `dsd k8s` now reads the cluster via `k0s kubectl` (node Ready, pods healthy,
  distribution=k0s); capture `k0s-debian-20260701.tar.gz`.
**Commit:** (this PR)

### BUG-096 — k8s OS-layer kubelet/containerd detection was k3s-only (wrong on RKE2/k0s/MicroK8s)
**Found:** during the beyond-k3s OS-layer hardening pass — `dsd k8s --deep` reported
  `kubelet_active=false` and `containerd_active=false` on healthy RKE2, k0s, and MicroK8s
  nodes (all three of the tested distros that aren't kubeadm/k3s).
**Root cause:** `collectK8sOSLayer` probed only the systemd units `kubelet`/`k3s`/`k3s-agent`
  and the containerd socket `/run/k3s/containerd/containerd.sock` — a k3s-specific fix that
  was never generalized. Every other distro embeds/wraps the kubelet under a different unit
  (RKE2 `rke2-server`, k0s `k0scontroller`, MicroK8s `snap.microk8s.daemon-kubelite`) and its
  containerd under a different socket (k0s `/run/k0s/containerd.sock`, MicroK8s
  `/var/snap/microk8s/common/run/containerd.sock`).
**Impact:** LOW — these fields are collected into the OS-layer struct and `--json` but no
  heuristic or renderer currently consumes them, so there was no false CRIT/OK verdict; the
  bug was an inaccurate `--json` field (a machine consumer would read a healthy kubelet as
  down) and a "deep check" that silently verified nothing on 3 of 5 distros. Fixed now so the
  data is correct and the check is real if/when a verdict starts using it.
**Fix:** generalize the kubelet unit list (add rke2-server/rke2-agent/k0scontroller/k0sworker/
  snap.microk8s.daemon-kubelite) and the containerd detection (add the
  snap.microk8s.daemon-containerd unit + a bundled-socket list covering k3s/RKE2, k0s, MicroK8s
  via `k8sBundledContainerdSockPresent`). Unit/socket names taken from the live nodes; socket
  helper unit-tested (`k8s_oslayer_containerd_test.go`). Verified live: kubelet_active and
  containerd_active are now TRUE on all three (RKE2 v1.35.6, k0s v1.36.2, MicroK8s v1.35.5).
**Commit:** (this PR)
