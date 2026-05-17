# DashDiag — Diagnostic Gap Analysis v1
**Sources:** Red Hat SELinux/D-Bus boot failure case + Microsoft Azure Linux/Windows VM Performance Troubleshooting Docs
**Date:** May 2026
**Reconciled against actual codebase as of:** May 17, 2026

---

## Purpose

This document captures the diagnostic pain points identified from real-world cloud VM and Linux boot failure cases and maps them against DashDiag's actual collector coverage. It is the authoritative record of what was already built, what was added as a result of this analysis, and what remains on the roadmap.

---

## Already Implemented Before This Analysis

Reading the actual codebase revealed that many gaps were already covered. This is the honest reconciliation.

| Gap | Collector | Status |
|---|---|---|
| OOM killer event detection | `oom_linux.go` → `OOMCollector` | ✅ Done — journalctl + dmesg scan |
| Cloud metadata / IMDS detection | `cloudmeta_linux.go` → `CloudMetaCollector` | ✅ Done — AWS IMDSv2, Azure, GCP; spot termination detection |
| HugePages / THP configuration | `hugepages_linux.go` → `HugePagesCollector` | ✅ Done — reserved-but-unused detection, THP mode |
| PSI memory/io/cpu pressure | `pressure_linux.go` → `PressureCollector` | ✅ Done — full stall and some stall, avg10/60/300 |
| NUMA topology | `numa_linux.go` → `NUMACollector` | ✅ Done |
| Entropy pool | `entropy_linux.go` → `EntropyCollector` | ✅ Done — WARN < 256, CRIT < 64 |
| Swap activity rate (pages/sec) | `swap.go` → `SwapCollector` | ✅ Done — PagesInPerSec / PagesOutPerSec from /proc/vmstat delta |
| D-state (hung) process detection | `processes.go` → `ProcessesCollector` | ✅ Done — HungCount + HungProcs with wchan, kernel threads filtered |
| Zombie process tracking | `processes.go` → `ProcessesCollector` | ✅ Done — ZombieCount + ZombieProcs |
| Correlation engine (base) | `analysis/correlate.go` | ✅ Done — 5 rules, validated on RHEL 10.1 |
| Sysctl / swappiness | `sysctl.go` → `SysctlCollector` | ✅ Done — 6 workload profiles |
| SELinux denial counting | `kernel_security.go` → `KernelSecurityCollector` | ✅ Done — AVC count + samples |
| Network error / drop counters | `network_quick.go` → `NetworkCollector` | ✅ Done — RxErrors, TxErrors, RxDrops, TxDrops per interface |
| Memory overcommit policy | `memory.go` → `MemoryCollector` | ✅ Done — OverCommitted flag |

---

## Real Gaps Found and Fixed in This Session (May 17, 2026)

These were genuinely missing from the codebase and have been implemented.

### GAP-01 — CPU Steal Time ✅ FIXED
**Pain:** On cloud VMs, the `st` column in `/proc/stat` shows CPU time stolen by the hypervisor. High steal means the VM is CPU-starved by its host — not by its own workload. This was invisible in DashDiag.

**What was missing:** `parseCPUStat()` in `cpu.go` only extracted idle/total. The steal and iowait columns were discarded.

**Fix:** Added `parseCPUStatFull()` returning a `cpuStatSample` struct with idle, total, steal, iowait. `Collect()` now populates `StealPct` and `IOwaitPct` on `models.CPUInfo`. New insights in `heuristics.go`: WARN > 10% steal, CRIT > 20% steal; WARN > 20% iowait, CRIT > 40% iowait.

**Files changed:** `internal/models/cpu.go`, `internal/collectors/cpu.go`, `internal/analysis/heuristics.go`

---

### GAP-02 — SELinux Policy Type (SELINUXTYPE=) Validation ✅ FIXED
**Pain (the Red Hat case):** `SELINUXTYPE=` in `/etc/selinux/config` was set to `permissive` — which is a valid SELINUX mode value but NOT a valid SELINUXTYPE. The policy directory `/etc/selinux/permissive/` did not exist. When dbus-daemon tried to open `/etc/selinux/permissive/contexts/dbus_contexts`, it failed. This cascaded to systemd-logind, NetworkManager, and 6+ other services. The operator saw 8 failed units with no clear root cause.

DashDiag already counted SELinux denials but never validated whether SELINUXTYPE itself was correct.

**Fix:** Added `validateSELinuxPolicyType()` to `KernelSecurityCollector`. Checks: SELINUXTYPE is one of targeted/minimum/mls; policy directory exists; package `selinux-policy-<type>` is installed (rpm or dpkg); `/.autorelabel` existence. New CRIT insights in `checkKernelSecurity()` surface the exact failure with the exact fix command.

**Files changed:** `internal/models/kernel_security.go`, `internal/collectors/kernel_security.go`, `internal/analysis/heuristics.go`

---

### GAP-03 — D-Bus Health Collector ✅ FIXED
**Pain:** D-Bus is the IPC backbone of Linux. When it fails, all dependent services cascade-fail. There was no explicit D-Bus health check in DashDiag — it would only appear as one entry in a generic failed-units list, with nothing to indicate it was the root cause of everything else.

**Fix:** New `DBusCollector` (`dbus_linux.go` + `dbus_notlinux.go`). Checks `systemctl is-active dbus.service`, extracts last error line from journal if failed. New `checkDBus()` heuristic fires CRIT with cascade annotation hints.

**Files changed:** `internal/models/dbus.go` (new), `internal/collectors/dbus_linux.go` (new), `internal/collectors/dbus_notlinux.go` (new), `internal/analysis/heuristics.go`

**Remaining:** Wire `NewDBusCollector()` into the command runner (wherever other collectors are registered in `cmd/` or `runner/`).

---

### GAP-04 — Three New Correlation Rules ✅ FIXED
**Pain:** The existing correlation engine had no rules for the three most important cloud VM diagnostic patterns identified in the Azure docs.

**Fix — `ruleIODrivenLoad`:** CPU Load WARN + CPU/IOWait WARN (no steal) → "Load is I/O driven, not CPU bound." This is the most commonly misdiagnosed cloud VM pattern — operators escalate to CPU when disk is the actual constraint.

**Fix — `ruleCPUStealUnderLoad`:** CPU Load WARN + CPU/Steal WARN → "VM is under load AND losing CPU to the hypervisor — adding vCPUs will not help." Requires escalation to cloud provider.

**Fix — `ruleDBusCascade`:** DBus CRIT + Systemd CRIT → "D-Bus failure is root cause of all other service failures." Turns "8 failed services" into "1 root cause + 7 cascades."

**File changed:** `internal/analysis/correlate.go`

---

## Remaining Roadmap Items (Not Yet Built)

### Tier 1 — High value, low effort (next sprint)

**Wire DBusCollector into runner**
The collector is built but not registered in the command runner. Check `cmd/health.go` or the runner package and add `NewDBusCollector()` following the same pattern as other collectors. 30 minutes.

**Service dependency chain analysis (dsd health deep)**
Build the dependency graph of failed systemd units to classify root cause vs cascade. Uses `systemctl show <unit> --property=After,Requires`. Maps each failed unit to whether its failure is explained by another failed dependency. Estimated: 1 day. Build after `dsd health` fast is in stable production use.

### Tier 2 — Medium effort (post-first-customer)

**Per-process I/O usage**
Top 5 processes by disk write bytes/sec from `/proc/[pid]/io` delta. Identifies which process is causing disk saturation. Estimated: 3 hours. Deep only.

**Disk IOPS throttling detection**
`util% > 90` AND `await_ms > 20` simultaneously → throttle suspected. From `/proc/diskstats` delta. The "IOPS ceiling hit" signal specific to cloud block storage. Estimated: 2 hours.

**Per-CPU utilization (deep)**
Parse per-cpu lines from `/proc/stat` (lines starting `cpu0`, `cpu1`, etc.) to detect single-threaded bottlenecks invisible in aggregate CPU%. Estimated: 3 hours. Deep only.

### Tier 3 — Post-MVP / strategic

**Network throughput vs VM SKU ceiling**
Requires a lookup table of cloud instance type → network bandwidth cap. Complex to maintain across AWS/Azure/GCP SKUs. Defer until cloud-specific features become a revenue driver.

**Cloud agent process health**
Track known cloud background agents (waagent, omsagent, amazon-ssm-agent, google_guest_agent) by process name scan and report their CPU/RSS. Useful for "why is CPU high on a fresh VM" diagnosis. Estimated: 2 hours.

**Performance baseline recording**
`dsd health --baseline` to snapshot current metrics for future comparison. Requires persistent state. Already partially present via `dsd baseline` — evaluate whether the existing baseline system covers this.

---

## Two Architecture Principles Promoted to Permanent Policy

These emerged from the gap analysis and are now locked decisions in the project bible (§29).

**Principle A — Tier-0 Dependencies First**
Before the main parallel collector goroutines run, DashDiag checks Tier-0 infrastructure: D-Bus (and by extension SELinux policy validity). If D-Bus is failed, all subsequent service failure insights should be annotated with the cascade context. This transforms 8 confusing failures into 1 clear root cause.

**Principle B — Correlation Over Isolation**
DashDiag's highest-value output is the cross-resource diagnosis, not raw metrics. The `DIAGNOSIS` block from `analysis/correlate.go` is the primary API surface for the UnpackOps RCA product. Every new metric added to a collector should be evaluated for whether it unlocks a new correlation rule.

---

## Source Cases Summary

**Red Hat SELinux / D-Bus boot failure (verified, Solution KB):**
Root cause: `SELINUXTYPE=permissive` in `/etc/selinux/config`. "permissive" is a valid SELINUX mode but not a valid SELINUXTYPE. The policy directory `/etc/selinux/permissive/` did not exist. dbus-daemon failed trying to open its contexts file. All services dependent on D-Bus then failed. The operator saw multiple unrelated-looking failures with no single obvious cause. Correct SELINUXTYPE values: `targeted`, `minimum`, `mls`.

**Microsoft Azure VM Performance Troubleshooting Docs:**
Key diagnostic patterns: high load + high iowait + low CPU user = disk bottleneck (not CPU); CPU steal time is a cloud-specific signal invisible on bare metal; D-state process count is the bridge between "load is high" and "disk is the reason"; the correlation between metrics is more diagnostic than any individual metric alone.
