# Collector unknown-vs-pass sweep

Enumeration of every `Collect()` implementation in `internal/collectors/` (99
implementations across ~90 collector types, Linux + macOS), classifying each
fallible read/exec path: does a failure to gather produce an explicit
unknown/unverified sentinel, or could it produce a zero-value result that
`analysis/` (or a human) reads as "checked, clean"? This is the sweep Task 1
of the follow-up engineering pass asked for, run before writing the C1/C2
fix, because its result determines the fix's shape.

Method: 6 parallel batches, ~17 collectors each, every `Collect()` and every
parsing/permission-handling helper it calls read directly (not inferred).
Each collector classified CORRECT / BUG / N/A per the rubric below.

## Headline result

**73 of 99 collectors (74%) are CORRECT.** The codebase already has a working,
established convention for this — a per-collector, per-field boolean/reason
sentinel (`FooUnreadable`, `FooChecked`, `FooRead`, `NeedsRoot`, a `-1`/`"unknown"`
sentinel where 0 is a legitimate value) — applied with real discipline: dozens
of sites carry inline comments citing a specific prior bug ID
(`internal-collectors-NN-NN`, `BUG-0xx`) for exactly this failure class, and a
governance test already exists — `internal/models/falseok_signal_registry_test.go`
— tracking known sentinel fields.

**26 collectors (or sub-paths within them) have at least one real gap of this
shape** (C2's `/dev/kmsg` is one of them, already known). None of the 26 share
a single root cause that a type-level rewrite would close in one move — they
fall into a few repeating shapes instead (see "Recurring shapes" below).
**This means the fix for C1/C2 does not need to be a shared result-type
change across every collector/model** — the per-field sentinel convention
already works where it's applied. It means there are ~25 *more* individual
instances of the same fix C2 needs, following an existing, provable-correct
template already present in the same codebase (e.g. `security_linux.go:557`
and `drbd_linux.go`'s `Unverified` field are explicitly the version of this
pattern C2 is missing).

The one candidate for a genuine shared-code fix (not per-collector) is the
`filepath.Glob` root cause below — that's a library-level footgun, not a
convention gap, and fixing the helper once closes it everywhere it's used.

## Recurring shapes (grouping the 26)

1. **`filepath.Glob`/`glob()` conflates "permission denied" with "no matches"** —
   Go's stdlib `Glob` treats a directory-read error encountered while matching
   as a nil-error empty result. Confirmed root cause for `NetworkdConfigCollector`
   (`networkd_config_linux.go:67-82`) and structurally identical to
   `ProcessesCollector`'s `hidepid=2`/`ProtectProc=invisible` gap (`processes.go:76-78`
   — technically a different mechanism, restricted *visibility* not a glob error,
   but the same "valid-looking short list, no error, no sentinel" shape).
   **This one is worth a shared fix** — a `globChecked` wrapper in `internal/source`
   that distinguishes "0 matches, dir was readable" from "read failed" — rather
   than patching each call site's interpretation independently.
2. **Detection requires both reachability AND a fast protocol handshake** —
   `GrafanaCollector`, `MemcachedCollector`: if the service is up but
   overloaded/slow, the handshake step timing out reads as "not installed."
   Same shape, two collectors, no shared helper currently exists for this one
   either (both hand-roll their own detect-then-probe).
3. **A collector's OWN sibling sub-check in the same file does this correctly,
   right next to the one that doesn't** — `KdumpCollector`/`TunedCollector`
   (missing the sentinel `KernelPatchCollector`/`KspliceCollector`/
   `TransactionalCollector`/`ServiceRestartCollector` all have, same file,
   `maintenance_linux.go`); `ServicesDeepCollector`'s `MaskedUnits` (missing
   what `FailedUnitsQueried` in the same file has, and the file's own comment
   calls masked units "a silent trap"); `LogsCollector`'s crash-loop/crash-file/
   journal-size sub-paths (missing what its own journal-severity sub-path has).
   These are the cheapest fixes — copy the neighboring pattern in the same file.
4. **A sub-resource query fails independently of the top-level reachability
   check that gates it** — `K8sCollector` (Events/PVCs/Workloads fail
   independently of the `APIReachable` node/pod check that "vouches" for them),
   `PVECollector` (`collectPVEHAFencing` assumes a `pvesh` error means "endpoint
   absent" without checking, unlike its sibling `collectPVECluster`),
   `RancherCollector` (RBAC-scoped kubeconfig can read `namespaces` but not
   `deployments`).
5. **One-off, lowest-severity** — `CPUCollector.RunQueue` (2s ctx timeout under
   host contention, ironically most likely during real saturation),
   `KVMGuestCollector.cumulativeStealPct` (malformed `/proc/stat`, field has
   existed since 2.6.11, low likelihood), `SwapCollector` (`/proc/swaps`
   normally world-readable), `ThermalCollector` (sensor file unreadable while
   driver name file is readable — analysis's own `CPUTempC==0` skip compounds
   it), `TimelineCollector` (dmesg-only source fails, journal succeeds —
   partial not total), `NFSCollector` (benign — retrans-rate denominator is
   also 0), `TLSCollector` (`/etc/ssl/private` 0710 on Debian/Ubuntu — directly
   contradicts the model's own doc comment promising this can't happen),
   `HealthDeepCollector.collectMemDetail`, darwin `SecurityCollector` (SSH
   config path missing the sentinel every other platform's has), darwin/generic
   `PackagesCollector` stub (sets `Checked:true` *before* running `brew
   outdated`, never corrected on failure — the only stub-vs-real-implementation
   asymmetry found).

## Status after the follow-up engineering pass

Two of the 26 are now fixed: `LogsCollector`'s `/dev/kmsg` gap (C2 — the euid
proxy replaced with a real read-result check) and `NetworkdConfigCollector`
(the shared `globChecked` helper). The remaining 24 are tracked, not fixed,
in `internal/collectors/unknown_vs_pass_registry_test.go` —
`TestUnknownVsPassRegistryComplete` fails if a `Collect()` implementation
(collector #100 included) has no entry, so this list cannot silently rot;
each `trackedBug` entry there cites this ranking.

Ranked by consequence (likelihood a real host hits it × how bad the silent
miss is), not file order — an unranked backlog gets worked top-to-bottom by
accident, which is what this ranking is for.

**High** — silently masks a check the collector specifically exists to catch, on a scenario common in production:
1. `DiskCollector` — a stale/hung NFS/CIFS mount is silently dropped from `Filesystems` entirely (not shown as unreachable — absent, as if the mount didn't exist). No CRIT/WARN can ever fire for it.
2. `K8sCollector` — Events/PVCs/Workloads fail independently of the `APIReachable` gate that "vouches" for them; an RBAC-scoped viewer kubeconfig (a realistic production setup) reads as 0 unbound PVCs/0 down workloads on a genuinely broken cluster.
3. `TLSCollector` — a top-level/directory `readDirEntries` failure silently drops the whole scan root (e.g. Debian/Ubuntu's default `/etc/ssl/private` 0710) — contradicts the model's own doc comment promising this can't happen.
4. `ServicesDeepCollector` (masked units) — no sentinel, unlike its sibling `FailedUnitsQueried` in the same file; the file's own comment already calls masked units "a silent trap."
5. `LogsCollector` (crash loops / crash files / journal size / corruption — 4 sub-paths beyond the now-fixed kmsg one) — crash-loop detection is a core reliability signal; `systemctl`/unreadable `/var/crash`/unreadable journal dir all fold silently to "clean."

**Medium** — real miss, narrower window or lower stakes:
6. `NetworkCollector` — `cachedJSON` errors discarded (`_ = ...`); a `/proc/net/*` read failure silently disables interface checks AND the CLOSE_WAIT leak detector together.
7. `CloudMetaCollector` — the registration gate is itself a live IMDS probe; a transient hiccup on a real cloud host masks time-sensitive spot-termination/maintenance-event warnings.
8. `ProcessesCollector` — `hidepid=2`/`ProtectProc=invisible` yields a valid, short, no-error process list; `ZombieCount`/`HungCount` are real verdict inputs, not just display.
9. `GrafanaCollector` / `MemcachedCollector` — a service overloaded enough to fail its handshake probe (exactly when visibility matters most) reads as "not installed."
10. `RancherCollector` — an RBAC-scoped kubeconfig that can list namespaces but not deployments masks a crash-looping management plane.
11. `PVECollector` (HA fencing) — assumes a `pvesh` error means "endpoint absent," unlike its sibling `collectPVECluster`, which checks.
12. `CPUCollector` (`RunQueue`) — zeroes out on exactly the host-contention scenario the field exists to detect (2s ctx timeout under load).

**Low** — real gap, low likelihood or low blast radius:
13. `KdumpCollector` / `TunedCollector` — no sentinel, unlike 5 siblings in the same file; lower-stakes maintenance checks.
14. `ThermalCollector` (linux) — sensor file unreadable while the driver-name file is readable; analysis's own `CPUTempC==0` skip compounds it.
15. `ContainerdCollector` — post-socket-dial `ctr namespaces list` failure, narrow.
16. `TimelineCollector` (partial source failure) — forensic/investigative use, not a live verdict driver.
17. `KVMGuestCollector` (`cumulativeStealPct`) — malformed `/proc/stat`, field stable since kernel 2.6.11.
18. `SwapCollector` — `/proc/swaps` normally world-readable.
19. `NFSCollector` — benign in practice (retrans-rate denominator is also 0).
20. `HealthDeepCollector.collectMemDetail` — `/proc/meminfo` normally world-readable.
21. `SecurityCollector` (darwin, SSH sub-check) — secondary platform.
22. `PackagesCollector` (darwin/generic stub) — secondary platform, `brew` failure only.

## Full table

Legend: **CORRECT** = failure surfaces as an explicit sentinel. **BUG** =
failure can be silently pass-shaped. **N/A (gate)** = collector is only
registered when a presence-gate returns true; not-present correctly yields no
row (the project's own documented, accepted convention — not a defect).

| Collector | file:line | Verdict | Note |
|---|---|---|---|
| AuditCollector | auditd_linux.go:21 | CORRECT | `RulesUnreadable`/`AuditLogSizeUnreadable`/`EventsUnreadable` |
| AlertmanagerCollector | alertmanager_linux.go:72 | CORRECT | `ConfigReloadRead` |
| ApacheCollector | apache_linux.go:30 | CORRECT | `ConfigTested` via shared `webConfigTest` |
| AWSCollector | aws_linux.go:64 | CORRECT | `EBSNeedsRoot`/`EBSReadFailed`/`IMDSChecked`/`TimeSyncChecked` |
| AuthCollector (linux) | auth_linux.go:23 | CORRECT | `Checked` |
| AzureCollector | azure_linux.go:60 | CORRECT | `TimeSyncChecked`/`DisksChecked`/`NVMeIOTimeoutChecked` |
| BINDCollector | bind_linux.go:30 | CORRECT | `PortsChecked`/`QueryTested` |
| **CPUCollector** | cpu.go:287 | **BUG** | `sampleCPUUsage` zero-value on ctx timeout/`/proc/stat` failure; `RunQueue` has no fallback (unlike `UsagePct`) |
| **CloudMetaCollector** | cloudmeta_linux.go:66 | **BUG** | Gate itself is a live IMDS probe; transient IMDS hiccup on a real cloud host reads as "not cloud" |
| **ContainerdCollector** | containerd_linux.go:107 | **BUG (narrow)** | `containerdNamespaces` silent `(nil,false)` on `ctr` failure post-socket-dial |
| CronCollector | cron_linux.go:26 | CORRECT | `FailureScanOK` |
| CVEHealthCollector | cve_health.go:33 | CORRECT | `ScanFailed`+`StatusReason`, stale-metadata guard |
| DNSCollector | dns_linux.go:31 | CORRECT | fails closed (alarms rather than silence) |
| DNSResolverCollector | dns_resolver_linux.go:41 | CORRECT | `DNSSECTestRan`, nil-not-false pattern |
| DRBDCollector | drbd_linux.go:33 | CORRECT | `Unverified` — cited elsewhere as the fixed version of C2's pattern |
| FirewallCollector | firewall_linux.go:46 | CORRECT | `Status="unverified"` (doc claim verified) |
| ElasticsearchCollector | elasticsearch_linux.go:93 | CORRECT | `HealthRead` |
| FDLimitsCollector | fdlimits.go:145 | CORRECT | real error → `checks[].status=ERROR` |
| GPUCollector | gpu_linux.go:42 | CORRECT | `Unreadable` (NVIDIA); AMD/Intel sysfs absence isn't privilege-gated |
| **GrafanaCollector** | grafana_linux.go:72 | **BUG** | reachable-but-slow `/api/health` reads as "not installed" (shape 2) |
| HardwareCollector | hardware_linux.go:27 | CORRECT (mixed) | SMART/EDAC sentineled; RAM/System DMI blank silently but not verdict-consulted |
| GCPCollector | gcp_linux.go:60 | CORRECT | `MaintenanceChecked` etc. |
| ClockCollector | clock.go:20 | CORRECT (fails loud) | `Synced=false`→CRIT, opposite-direction risk only |
| **KVMGuestCollector** | kvmguest_linux.go:47 | **BUG (narrow)** | `cumulativeStealPct` malformed `/proc/stat` → 0 (shape 5) |
| LVMCollector | lvm_linux.go:73 | CORRECT | per-subcommand `*ReadFailed` |
| **MemcachedCollector** | memcached_linux.go:135 | **BUG** | overloaded server fails version probe → "not installed" (shape 2) |
| CephCollector | ceph_linux.go:19 | CORRECT | `Health="HEALTH_UNKNOWN"` |
| MemoryCollector | memory.go:57 | CORRECT | `MeminfoUnreadable` |
| KafkaCollector | kafka_linux.go:69 | CORRECT | `Detected`/`MetricsRead`/`UnderReplicatedRead` |
| CloudInitCollector | cloudinit_linux.go:45 | CORRECT | `StatusUnverified` |
| **NetworkCollector** | network_quick.go:59 | **BUG** | `cachedJSON` errors discarded (`_ = ...`) — interfaces + CLOSE_WAIT both silently empty |
| KVMCollector | kvm_linux.go:40 | CORRECT | `kvmStatusEnumFailed`/`VMsUnreadable`/`PoolsCapUnknown` — exemplary |
| IPMICollector | ipmi_linux.go:37 | CORRECT | read-result-first, euid-second — the correct order C2 lacks |
| PostBootCollector | postboot_linux.go:50 | CORRECT | explicit FOUND/ABSENT/UNMEASURABLE trichotomy (doc claim verified) |
| PrometheusCollector | prometheus_linux.go:61 | CORRECT | `MetricsRead`/`ConfigReloadRead` |
| MySQLCollector | mysql_linux.go:45 | CORRECT | `PeerVerified`/`MetricsRead`/`ConnStatsRead` |
| **LogsCollector — kmsg** | logs_linux.go:69,178-200 | **FIXED** | was: euid proxy, not a read-result check (C2). Now `KmsgUnreadable` set from the real `readKmsgLive` open error. |
| LogsCollector — journal severity | logs_linux.go:787-848 | CORRECT | `ErrorScanFailed`/`ErrorCountUnverified` — the good sibling |
| **LogsCollector — crash loops/files/journal size/corruption** | logs_linux.go:340-567,1008-1043 | **BUG** | no sentinel for any of 4 sub-paths (shape 3) |
| NetworkDeepCollector | network_deep.go:26 | CORRECT | `SockstatUnreadable`/`NetstatUnreadable` |
| **NFSCollector** | nfs_linux.go:26 | **BUG (minor)** | `nfsReadStats` silent no-op; denominator also 0 so low practical impact |
| DockerCollector | docker.go:70 | CORRECT | `SocketPermDenied`/`DetailUnavailable`/`UnverifiedContainers` |
| MongoDBCollector | mongodb_linux.go:56 | CORRECT | `MetricsRead`/`ReplStatusRead` |
| **KdumpCollector** | maintenance_linux.go:63 | **BUG** | no sentinel, unlike 5 siblings in same file (shape 3) |
| **TunedCollector** | maintenance_linux.go:107 | **BUG (minor)** | same shape 3, lower severity |
| KernelPatchCollector | maintenance_linux.go:162 | CORRECT | `CheckUnverified` — cites BUG-088 |
| KspliceCollector | maintenance_linux.go:282 | CORRECT (minor caveat) | `CheckUnverified`; one untracked sub-field |
| ServiceRestartCollector | maintenance_linux.go:357 | CORRECT | `NeedsRoot` — also catches silent hidepid=2 |
| TransactionalCollector | maintenance_linux.go:609 | CORRECT | `Unverified` |
| ProcCollector | proc_linux.go:29 | CORRECT/N/A | real error propagation; most fields are display-only detail |
| **ServicesDeepCollector — masked units** | services_deep_linux.go:99-103 | **BUG** | no `*Queried` sentinel, unlike sibling `FailedUnitsQueried` (shape 3); file's own comment calls this "a silent trap" |
| ServicesDeepCollector — failed units | services_deep_linux.go:43-55 | CORRECT | `FailedUnitsQueried` |
| MTECollector | mte_linux.go:54 | CORRECT | `StatusReason` on both fallible reads |
| FirmwareCollector | firmware.go:24 | CORRECT | 4 distinct `StatusReason` branches |
| EnvoyCollector | envoy_linux.go:65 | CORRECT | `StatsRead` |
| **SwapCollector** | swap.go:87 | **BUG (low likelihood)** | `/proc/swaps`/zram reads have no sentinel, unlike its own vmstat `-1` sentinel in the same function (shape 5) |
| SysctlCollector | sysctl.go:70 | CORRECT | `-1` sentinels where 0 is legitimate; elsewhere guarded by `>0` thresholds |
| **TimelineCollector — partial source failure** | timeline_linux.go:70-72 | **BUG** | `SourcesUnavailable` only fires when BOTH sources fail; dmesg-only failure (common: `dmesg_restrict=1`) is silent (shape 5) |
| TraefikCollector | traefik_linux.go:72 | CORRECT | `APIRead` |
| VMwareCollector | vmware_linux.go:55 | CORRECT | `ToolsRunningVerified`/`StatAvailable` |
| SecurityCollector (linux) | security_linux.go:62 | CORRECT (one theoretical exception) | ~12 distinct sentinels; `parseWorldWritable` gap is theoretical only |
| ZFSCollector | zfs.go:29 | CORRECT | `ListReadFailed`/`StatusReadFailed` |
| SnapperCollector | snapper_collector.go:18 | CORRECT | string sentinel |
| SystemdCollector | systemd.go:346 | CORRECT | `FailedUnitsUnknown`/`SSHDStatusUnverified` (doc claim verified) |
| **ThermalCollector (linux)** | thermal_linux.go:33 | **BUG** | no sentinel; analysis's `CPUTempC==0` skip compounds it (shape 5) |
| VaultCollector | vault_linux.go:33 | CORRECT | `Reachable`/`StatusRead`/`IdentityUnverified` |
| ISCSICollector | iscsi_linux.go:21 | CORRECT | `NeedsRoot`/`SessionsParseFailed`, cross-checked against world-readable sysfs count |
| MultipathCollector | multipath_linux.go:23 | CORRECT | `Status="error"`+`StatusReason` |
| IOCollector | io.go:125 | CORRECT | real error propagation |
| DBusCollector | dbus_linux.go:24 | CORRECT | `status="unknown"` tri-state |
| HACollector | ha_collector.go:108 | CORRECT | `StatusReadable` |
| **NetworkdConfigCollector** | networkd_config_linux.go:60 | **FIXED** | was: root cause of shape 1 (`filepath.Glob` swallows permission errors). Now uses `globChecked`; `ConfigDirUnreadable` set. |
| **K8sCollector** | k8s.go:52 | **BUG** | Events/PVCs/Workloads fail independently of `APIReachable` (shape 4); `--deep` sub-checks (`K8sOSLayer`) are correct |
| **DiskCollector** | disk.go:119 | **BUG** | stale/hung mount silently dropped from `Filesystems`, not flagged unreachable |
| HWRaidCollector | hwraid_linux.go:56 | CORRECT | `NeedsRoot`/`ReadFailed`, `rawCount` schema-drift guard |
| KernelSecurityCollector | kernel_security.go:371 | CORRECT | SELinux mode + AVC `-1` (doc claims verified) |
| OOMCollector | oom_linux.go:30 | CORRECT | `StatusReason` gates `EventsLast24h` read order in consumer too |
| PostgresCollector | postgres_linux.go:47 | CORRECT | `MetricsRead` |
| NVMeCollector (linux) | nvme_linux.go:52 | CORRECT | `SmartUnreadReason` (doc claims verified) |
| NginxCollector | nginx_linux.go:26 | CORRECT | `ConfigTested` |
| **ProcessesCollector** | processes.go:67 | **BUG** | `hidepid=2`/`ProtectProc=invisible` — valid short glob result, no error, no sentinel (shape 1, structurally) |
| OCICollector | oci_linux.go:47 | CORRECT | per-check `*Checked` |
| RabbitMQCollector | rabbitmq_linux.go:58 | CORRECT | `DiagnosticsRead`/`AlarmsRead` |
| PackagesCollector (linux) | packages_linux.go:69 | CORRECT | extensive, incl. stale-metadata guard |
| RedisCollector | redis_linux.go:77 | CORRECT | `MetricsRead`/`MaxClientsRead` |
| **PVECollector — HA fencing** | pve_linux.go:262-285 | **BUG** | assumes `pvesh` error = absent without checking, unlike sibling `collectPVECluster` (shape 4) |
| PVECollector — other sub-checks | pve_linux.go:215-253 | CORRECT | `reachable`/`verified` bools |
| HAProxyCollector | haproxy_linux.go:25 | CORRECT | `ConfigTested` (StatusReason cosmetic gap only) |
| ServicesCollector | services.go:24 | CORRECT | explicit WARN+`Error` on missing probe/config |
| **HealthDeepCollector — collectMemDetail** | health_deep_linux.go:629-632 | **BUG** | no sentinel; low likelihood (`/proc/meminfo` normally world-readable) |
| HealthDeepCollector — top-procs/CPU/IO | health_deep_linux.go:79,101-116 | CORRECT | `TopProcsNeedsRoot` etc., registered |
| SUSEConnectCollector | suseconnect_collector.go:78 | CORRECT | `StatusUnverified` |
| SteamOSCollector | steamos_linux.go:53 | CORRECT | every sub-check has a "checked" companion |
| **RancherCollector** | rancher_collector.go:50-65 | **BUG** | RBAC-scoped kubeconfig collapses "can't query" into "0" (shape 4) |
| NspawnCollector | nspawn_linux.go:22 | CORRECT | `Status="query-failed"` |
| SessionsCollector | sessions.go:46 | CORRECT | `Checked` |
| **TLSCollector** | tls.go:104,111-114 | **BUG** | top-level/directory `readDirEntries` failure silently drops whole scan roots (e.g. Debian's 0710 `/etc/ssl/private`) — contradicts the model's own doc comment (shape 5) |
| AuthCollector (darwin) | auth_darwin.go:19 | CORRECT | `Checked` unset on SIP-restricted `log show` |
| BatteryCollector (darwin) | battery_darwin.go:23 | CORRECT | `StatusReason` |
| LaunchdCollector (darwin) | launchd_darwin.go:24 | CORRECT | `Checked` |
| NVMeCollector (darwin) | nvme_darwin.go:27 | CORRECT | `DrivesListUnreadable` |
| **SecurityCollector (darwin) — SSH sub-check** | security_darwin.go:85-89 | **BUG** | missing the `SSHConfigUnreadable`-equivalent every other platform has (shape 5) |
| SecurityCollector (darwin) — other sub-checks | security_darwin.go:44-84 | not exhaustively re-verified | flagged, not confirmed, per batch's "quick check" budget |
| ThermalCollector (generic/darwin stub) | thermal_notlinux.go:32 | CORRECT | `Available=false` is explicit |
| **PackagesCollector (generic/darwin stub)** | packages_notlinux.go:23 | **BUG** | sets `Checked:true` before running `brew outdated`, never corrected on failure — the only stub-vs-real asymmetry found |

## Cross-cutting euid-proxy check

Grepped every `os.Getuid()|Geteuid()|SUDO_USER` site in `internal/collectors/*.go`
(non-test) to check whether C2's specific shape — euid alone, no read-result
check — repeats elsewhere. **It does not.** Every other euid-adjacent site is
either: (a) selecting an error *message*, gated behind an actual exec/read
failure already (`aws_linux.go:367`, `btrfs_linux.go:88`, `packages_linux.go:722`);
(b) an intentional blanket-disclosure pattern, applied uniformly regardless of
whether a specific read succeeded, and documented as such
(`SecurityInfo.NeedsRoot`, `K8sOSLayer.NeedsRoot`, `disk_busy_linux.go:61`);
(c) not a degrade signal at all (`containerguest_linux.go:43`'s `RunAsRoot`,
a real finding not a caveat); or (d) the *already-fixed* version of C2's
pattern — `security_linux.go:557` ORs euid with the real glob-error result
from `buildInodeProcMap`, and `drbd_linux.go`'s `Unverified` keys off
`drbdsetup`'s actual exit code. **C2 is the outlier, not the template** — the
fix for C2 has a working example already living in the same package.

## Conclusion for the C1/C2 fix

1. **No shared result-type change is warranted.** The existing per-field
   sentinel convention is real, applied correctly 74% of the time, has its
   own governance test, and has documented precedent (bug IDs) for exactly
   this failure class. Introducing a wrapper type (`Result[T]` or similar)
   across ~90 models would be a large, high-risk rewrite to replace a
   pattern that already works where it's used — not what the evidence
   supports.
2. **C2's fix is a one-file patch**: replace the euid proxy with a real
   read-result check, following the exact template already present in
   `security_linux.go:557` / `drbd_linux.go`.
3. **The other 25 gaps are genuine, independently confirmed instances of the
   same bug shape** — not hypothetical, not a difference of interpretation.
   They were out of the original C1/C2/C3/P2/C6 scope but were surfaced by
   doing the sweep the task asked for. They need a scoping decision (see the
   question posed after this document): fix now, fix a prioritized subset,
   or track as a backlog for separate follow-up work.
4. **One shared-code fix is warranted**: a `globChecked`-style wrapper
   distinguishing "empty, dir was readable" from "read failed" in
   `internal/source`, closing shape 1 (`NetworkdConfigCollector`,
   structurally `ProcessesCollector`) in one place instead of two
   independent patches.
