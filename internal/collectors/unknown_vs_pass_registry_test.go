package collectors

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// This is the COLLECTOR-level completeness tripwire for the "unknown vs
// pass" defect class (see ~/DEFECT-CLASSES.md and ~/COLLECTOR-SWEEP.md at
// the repo root — the derivation and the full sweep this registry tracks).
//
// internal/models/falseok_signal_registry_test.go is a FIELD-NAME-PATTERN
// tripwire: it fires when a new struct field matching a naming convention
// (*Unreadable, *Checked, NeedsRoot, ...) has no registered guard. Its own
// doc comment already names the blind spot this registry closes: it "does
// NOT prove the guard is correct" and — the gap that matters here — it
// cannot see a fallible read that was NEVER GIVEN a field at all. C2
// (/dev/kmsg) and the 24 other gaps the sweep found are exactly that shape:
// a real failure path with no sentinel field to register.
//
// This registry is the collector-level answer: every Collect() method in
// this package gets exactly one entry, forced to a decision —
//   - sentinelKind:   governed by an existing Unverified-shaped field(s);
//     cite the field(s) — cross-reference internal/models' registry.
//   - exemptKind:     no fallible read that could produce a pass-shaped
//     result, or the failure mode is provably benign — state why.
//   - trackedBugKind: a confirmed gap, not yet fixed. Cite
//     COLLECTOR-SWEEP.md's ranking so the backlog stays a ranked, bounded
//     list instead of a markdown table nobody re-reads.
//
// TestUnknownVsPassRegistryComplete fails when a Collect() method exists
// with no entry (collector #100 cannot be added silently) or when an entry
// no longer matches a real collector (stale, e.g. after a rename).

type verdictKind int

const (
	sentinelKind verdictKind = iota
	exemptKind
	trackedBugKind
)

type collectorVerdict struct {
	kind verdictKind
	note string
}

func sentinel(note string) collectorVerdict   { return collectorVerdict{sentinelKind, note} }
func exempt(note string) collectorVerdict     { return collectorVerdict{exemptKind, note} }
func trackedBug(note string) collectorVerdict { return collectorVerdict{trackedBugKind, note} }

// unknownVsPassRegistry maps each Collect()-implementing type name to its
// verdict. Keyed by type name (not file) — a collector with both a linux and
// a darwin implementation (build-tag-separated files defining the same type
// name) gets ONE entry; a platform-specific gap is called out in the note
// rather than needing a second key, since Go's build tags mean only one
// implementation is ever compiled into a given binary.
var unknownVsPassRegistry = map[string]collectorVerdict{
	"AuditCollector":          sentinel("auditd_linux.go: RulesUnreadable/AuditLogSizeUnreadable/EventsUnreadable"),
	"AlertmanagerCollector":   sentinel("ConfigReloadRead; gate returns nil when absent"),
	"ApacheCollector":         sentinel("ConfigTested via shared webConfigTest"),
	"AWSCollector":            sentinel("EBSNeedsRoot/EBSReadFailed/EBSDeltaReadFailed/ENADeltaReadFailed/IMDSChecked/TimeSyncChecked"),
	"AuthCollector":           sentinel("linux: Checked. darwin: Checked unset on SIP-restricted `log show`."),
	"AzureCollector":          sentinel("TimeSyncChecked/DisksChecked/NVMeIOTimeoutChecked"),
	"BINDCollector":           sentinel("PortsChecked/QueryTested/PortsOwnershipUnverified"),
	"CPUCollector":            trackedBug("COLLECTOR-SWEEP.md Medium #12: sampleCPUUsage zero-value on ctx timeout/`/proc/stat` failure; RunQueue has no fallback (unlike UsagePct)"),
	"CloudMetaCollector":      trackedBug("COLLECTOR-SWEEP.md Medium #7: registration gate is itself a live IMDS probe; a transient hiccup on a real cloud host reads as \"not cloud\""),
	"ContainerdCollector":     trackedBug("COLLECTOR-SWEEP.md Low #15: containerdNamespaces silent (nil,false) on `ctr` failure post-socket-dial"),
	"CronCollector":           sentinel("FailureScanOK"),
	"CVEHealthCollector":      sentinel("ScanFailed+StatusReason; stale-metadata guard"),
	"DNSCollector":            sentinel("empty Nameservers surfaces as a misconfiguration finding, not silence; ProbeSkipped gates the live probe"),
	"DNSResolverCollector":    sentinel("DNSSECTestRan; nil-not-false pattern for VPNDNSIntegrated"),
	"DRBDCollector":           sentinel("Unverified (the template C2's fix now matches)"),
	"FirewallCollector":       sentinel("Status=\"unverified\" both when no tooling exists and when the ruleset read fails"),
	"ElasticsearchCollector":  sentinel("HealthRead; gate returns nil when genuinely absent"),
	"FDLimitsCollector":       sentinel("primary read failure propagates as a real error -> checks[].status=ERROR"),
	"GPUCollector":            sentinel("Unreadable (NVIDIA); AMD/Intel sysfs absence isn't privilege-gated"),
	"GrafanaCollector":        trackedBug("COLLECTOR-SWEEP.md Medium #9: a reachable-but-slow /api/health fetch reads as \"no Grafana here\""),
	"HardwareCollector":       sentinel("SMART/EDAC sentineled (SmartctlAvailable/Error/ZeroDevicesReported, EDACCountersUnreadable); RAM/System DMI blanks silently but isn't verdict-consulted"),
	"GCPCollector":            sentinel("MaintenanceChecked/OSLoginChecked/TimeSyncChecked"),
	"ClockCollector":          sentinel("adjtimex failure -> Synced=false -> CRIT (fails loud, not silently OK)"),
	"KVMGuestCollector":       trackedBug("COLLECTOR-SWEEP.md Low #17: cumulativeStealPct malformed /proc/stat -> 0, same as genuine zero steal"),
	"LaunchdCollector":        sentinel("Checked"),
	"LVMCollector":            sentinel("PresenceReadFailed/VGReadFailed/PVReadFailed/LVReadFailed/RaidReadFailed"),
	"MemcachedCollector":      trackedBug("COLLECTOR-SWEEP.md Medium #9: same shape as GrafanaCollector — an overloaded server fails the version probe within its deadline and reads as \"not installed\""),
	"CephCollector":           sentinel("Configured/StatusReason/NeedsRoot; Health=\"HEALTH_UNKNOWN\" sentinel on unparseable JSON"),
	"MemoryCollector":         sentinel("MeminfoUnreadable/EDACCountersUnreadable/CgroupMemMeasured/MemHotplugChecked"),
	"KafkaCollector":          sentinel("Detected/Accepting/MetricsRead/UnderReplicatedRead"),
	"CloudInitCollector":      sentinel("StatusUnverified"),
	"NetworkCollector":        trackedBug("COLLECTOR-SWEEP.md Medium #6: cachedJSON errors discarded (`_ = ...`) — interfaces + CLOSE_WAIT leak detector both silently empty on a /proc/net/* read failure"),
	"KVMCollector":            sentinel("kvmStatusEnumFailed/DiskErrorCheckFailed/VMsUnreadable/PoolsCapUnknown — exemplary"),
	"IPMICollector":           sentinel("NeedsRoot set only after BOTH the read fails AND geteuid()!=0 — read-result-first, euid-second (the correct order C2 was missing)"),
	"PostBootCollector":       sentinel("explicit FOUND/ABSENT/UNMEASURABLE trichotomy, per-finding *Checked booleans"),
	"PrometheusCollector":     sentinel("MetricsRead/ConfigReloadRead"),
	"MySQLCollector":          sentinel("PeerVerified; MetricsRead/ConnStatsRead"),
	"LogsCollector":           trackedBug("COLLECTOR-SWEEP.md High #5 (kmsg sub-path FIXED — C2): crash-loop detection, crash-file scanning, and journal-size/corruption checks (logs_linux.go detectCrashLoops/collectCrashFiles/dirSizeViaSource/hasCorruptArchived) have no sentinel, unlike this same file's own journal-severity sub-path (ErrorScanFailed/ErrorCountUnverified)"),
	"NetworkDeepCollector":    sentinel("SockstatUnreadable/NetstatUnreadable"),
	"NFSCollector":            trackedBug("COLLECTOR-SWEEP.md Low #19: nfsReadStats silent no-op on /proc/net/rpc/nfs failure; low practical impact, the retrans-rate denominator is also 0"),
	"DockerCollector":         sentinel("SocketPermDenied/DetailUnavailable/UnverifiedContainers/IPForwardChecked"),
	"MongoDBCollector":        sentinel("MetricsRead/ReplStatusRead; PeerVerified"),
	"KdumpCollector":          trackedBug("COLLECTOR-SWEEP.md Low #13: no sentinel, unlike 5 siblings in maintenance_linux.go (KernelPatch/Ksplice/Transactional/ServiceRestart/LivePatch)"),
	"TunedCollector":          trackedBug("COLLECTOR-SWEEP.md Low #13: same gap as KdumpCollector, same file"),
	"KernelPatchCollector":    sentinel("CheckUnverified (cites BUG-088)"),
	"KspliceCollector":        sentinel("CheckUnverified; one untracked secondary sub-field, low severity"),
	"ServiceRestartCollector": sentinel("NeedsRoot — also catches the silent hidepid=2 case"),
	"TransactionalCollector":  sentinel("Unverified"),
	"ProcCollector":           sentinel("missing-PID propagates a real error; FDReadable gates the one field (FDPressure) that feeds a threshold — the rest is display-only detail"),
	"ServicesDeepCollector":   trackedBug("COLLECTOR-SWEEP.md High #4: MaskedUnits has no *Queried sentinel, unlike sibling FailedUnitsQueried in the same file — the file's own comment calls masked units \"a silent trap\""),
	"MTECollector":            sentinel("StatusReason set on both fallible reads (exception-trace file, journalctl+dmesg)"),
	"FirmwareCollector":       sentinel("4 distinct StatusReason branches — not-installed / daemon-down / query-failed / unparseable"),
	"EnvoyCollector":          sentinel("StatsRead"),
	"SwapCollector":           trackedBug("COLLECTOR-SWEEP.md Low #18: /proc/swaps and zram reads have no sentinel, unlike this function's own vmstat -1 sentinel; /proc/swaps normally world-readable"),
	"SysctlCollector":         sentinel("-1 sentinels where 0 is a legitimate value; other fields' consuming thresholds are all >0 guards, so 0-on-failure never fires a false verdict"),
	"ThermalCollector":        trackedBug("COLLECTOR-SWEEP.md Low #14 (linux): sensor file unreadable while the driver-name file is readable -> CPUTempC stays 0; analysis's own CPUTempC==0 skip compounds it. darwin/generic stub is CORRECT (Available=false is explicit)."),
	"TimelineCollector":       trackedBug("COLLECTOR-SWEEP.md Low #16: SourcesUnavailable only fires when BOTH journalctl and dmesg fail — a dmesg-only failure (common: kernel.dmesg_restrict=1) is silent. Total-failure case is handled correctly."),
	"TraefikCollector":        sentinel("APIRead"),
	"NVMeCollector":           sentinel("linux: SmartUnreadReason (needs_root/tool_absent/error), SmartRead, SmartDangerousFieldsUnread. darwin: DrivesListUnreadable."),
	"VMwareCollector":         sentinel("ToolsRunningVerified/StatAvailable"),
	"SecurityCollector":       trackedBug("COLLECTOR-SWEEP.md Low #21 (darwin only): parseDarwinSSHFile has no SSHConfigUnreadable-equivalent, unlike every other platform's SSH parser (including this file's own linux/notlinux siblings). linux implementation is CORRECT (~12 distinct sentinels)."),
	"ZFSCollector":            sentinel("ListReadFailed/StatusReadFailed"),
	"SnapperCollector":        sentinel("string sentinel on `snapper list` failure/no-permissions"),
	"PackagesCollector":       trackedBug("COLLECTOR-SWEEP.md Low #22 (darwin/generic stub only): Checked:true is set BEFORE `brew outdated` runs and never corrected on failure — the only stub-vs-real-implementation asymmetry found. linux implementation is CORRECT (extensive, incl. stale-metadata guard)."),
	"SystemdCollector":        sentinel("FailedUnitsUnknown/SSHDStatusUnverified"),
	"VaultCollector":          sentinel("Reachable/StatusRead/IdentityUnverified"),
	"ISCSICollector":          sentinel("NeedsRoot/SessionsParseFailed, cross-checked against world-readable sysfs session count"),
	"MultipathCollector":      sentinel("Status=\"error\"+StatusReason"),
	"IOCollector":             sentinel("openFile/parseDiskstats failures propagate as a real error -> checks[].status=ERROR"),
	"DBusCollector":           sentinel("status=\"unknown\" tri-state, distinct from failed/inactive/active"),
	"HACollector":             sentinel("StatusReadable"),
	"NetworkdConfigCollector": sentinel("ConfigDirUnreadable (FIXED via globChecked — was the root cause example for the shared glob fix)"),
	"K8sCollector":            trackedBug("COLLECTOR-SWEEP.md High #2: Events/PVCs/Workloads fail independently of the APIReachable gate that \"vouches\" for them — an RBAC-scoped viewer kubeconfig reads as 0 unbound PVCs/0 down workloads. --deep K8sOSLayer sub-checks ARE correct (explicit *Checked fields throughout)."),
	"DiskCollector":           trackedBug("COLLECTOR-SWEEP.md High #1: a stale/hung mount is silently dropped from Filesystems entirely on a statfs timeout/error — not shown as unreachable, just absent"),
	"HWRaidCollector":         sentinel("NeedsRoot/ReadFailed; rawCount schema-drift guard distinguishes a garbled response from a genuine \"no card\""),
	"KernelSecurityCollector": sentinel("SELinux mode resolveSELinuxMode two-source fallback; AVC denial count -1 sentinel (not 0) on full read failure"),
	"OOMCollector":            sentinel("StatusReason set before EventsLast24h is touched on a kernel-log-unreadable failure; checkOOM consults StatusReason first"),
	"PostgresCollector":       sentinel("MetricsRead; PeerVerified"),
	"NginxCollector":          sentinel("ConfigTested distinguishes a real syntax failure from \"couldn't run\""),
	"ProcessesCollector":      trackedBug("COLLECTOR-SWEEP.md Medium #8: hidepid=2/ProtectProc=invisible yields a valid, short, NO-ERROR glob result — Total/ZombieCount/HungCount silently reflect only the caller's own process tree, and these ARE real verdict inputs"),
	"OCICollector":            sentinel("per-check *Checked (IMDSChecked/AgentChecked/TimeSyncChecked/VNICChecked)"),
	"RabbitMQCollector":       sentinel("DiagnosticsRead/Pinged/AlarmsRead"),
	"RedisCollector":          sentinel("MetricsRead/MaxClientsRead"),
	"PVECollector":            trackedBug("COLLECTOR-SWEEP.md Medium #11: collectPVEHAFencing assumes a pvesh error means \"endpoint absent\" without checking, unlike its sibling collectPVECluster which does. Every other sub-check (Storages/Guests/Backups/TaskErrors/Bridges) is CORRECT (explicit verified bools)."),
	"HAProxyCollector":        sentinel("ConfigTested via shared webConfigTest; StatusReason cosmetic gap only, does not affect the ConfigTested signal"),
	"ServicesCollector":       sentinel("config.Load failure propagates as a real error; checkService returns an explicit WARN both when probing is off and when a replay bundle has no recorded probe"),
	"HealthDeepCollector":     trackedBug("COLLECTOR-SWEEP.md Low #20: collectMemDetail's /proc/meminfo read has no sentinel on models.HealthDeepInfo (distinct model from MemoryInfo, which IS guarded); low likelihood, /proc/meminfo is normally world-readable. TopProcsNeedsRoot/TopCPUProcsNeedsRoot/TopIOProcsNeedsRoot sub-checks ARE correct."),
	"SUSEConnectCollector":    sentinel("StatusUnverified (RHEL subscription-manager path and Ubuntu Pro JSON path both)"),
	"SteamOSCollector":        sentinel("every sub-check that can fail carries its own explicit \"checked\" companion set only on success"),
	"RancherCollector":        trackedBug("COLLECTOR-SWEEP.md Medium #10: rancherDeployReady returns (0,0) both when the Deployment genuinely doesn't exist AND when the kubectl call itself fails (RBAC denial) — no distinct field, and checkRancher only fires when ServerDesired>0, so a query failure is total silence"),
	"NspawnCollector":         sentinel("Status=\"query-failed\"+StatusReason, distinct from the genuine \"no containers\" empty-output case"),
	"SessionsCollector":       sentinel("Checked"),
	"TLSCollector":            trackedBug("COLLECTOR-SWEEP.md High #3: a top-level/directory readDirEntries failure silently drops the whole scan root (e.g. Debian/Ubuntu's default /etc/ssl/private 0710) — contradicts the model's own doc comment promising this can't happen. Per-FILE read/parse failures ARE correctly reported via Uncheckable."),
	"BatteryCollector":        sentinel("darwin: StatusReason distinct from the genuine no-battery empty-output case. Only implementation (no cross-platform Collect() found)."),

	// The 16 below use `_ context.Context` (unnamed param) rather than `ctx
	// context.Context` — outside the original 6-batch sweep's grep pattern,
	// found and classified directly when this registry's own AST scan (which
	// has no such blind spot) first ran.
	"BondingCollector":         exempt("glob(\"/proc/net/bonding/bond*\") error discarded — structurally shape-1, but this /proc path returns ENOENT (module not loaded) when bonding is absent, not EACCES; a genuine permission-denied on a /proc virtual file here is not a realistic failure mode (unlike /etc/systemd/network's real-world 0750 case)"),
	"CPUFreqCollector":         exempt("readSysfsStr(\"scaling_governor\") empty -> \"not available\"; kernel sysfs governor file is world-readable whenever cpufreq exists, empty content genuinely means cpufreq absent (VM/container/old kernel)"),
	"ContainerGuestCollector":  sentinel("CgroupV1Measured/CgroupV2Measured (already registered in the models falseok registry)"),
	"EntropyCollector":         sentinel("/proc/sys/kernel/random/entropy_avail read failure returns a real error -> checks[].status=ERROR, not a zero-value pass"),
	"FstabDriftCollector":      sentinel("Checked (already registered in the models falseok registry)"),
	"HBACollector":             exempt("glob(\"/sys/class/fc_host/host*\") error discarded — same sysfs-class reasoning as BondingCollector: world-readable when the class exists, EACCES unrealistic"),
	"HugePagesCollector":       sentinel("StatusReason set on /proc/meminfo read failure — comment explicitly documents this as a fix for a prior backwards Available:true-on-failed-read bug"),
	"InfiniBandCollector":      sentinel("ReadFailed, with an explicit Stat-first (not glob) check specifically to distinguish EACCES from ENOENT — already registered in the models falseok registry"),
	"KernelRetentionCollector": trackedBug("New (this pass), Medium: glob(\"/boot/vmlinuz-*\") error discarded. Unlike the sysfs-class collectors above, /boot IS realistically permission-restricted on some hardened images (0700) — a permission-denied /boot silently reports InstalledKernels=0, and Available becomes false (looks not-applicable, not couldn't-verify)."),
	"LivePatchCollector":       sentinel("UnverifiedPatches, per-patch enable-read failures — exemplary, explicit doc comment on the false-WARN this avoids. Top-level glob(\"/sys/kernel/livepatch/*\") is a kernel sysfs dir gated by LivePatchAvailable(); EACCES unrealistic."),
	"NUMACollector":            exempt("glob(\"/sys/devices/system/node/node[0-9]*\") error discarded — same sysfs-class reasoning as BondingCollector/HBACollector"),
	"PressureCollector":        trackedBug("New (this pass), Low: once Available=true (gated on fileExists), each of the 3 PSI file reads (memory/cpu/io) silently leaves its metric at zero on a mid-read failure (readPSIFile err discarded) — narrow race, the gate already confirmed the files exist moments earlier"),
	"RAIDCollector":            sentinel("ReadFailed, fs.ErrNotExist distinguished from a real failure (internal-models-11-01) — already registered in the models falseok registry"),
	"RootFSCollector":          sentinel("/proc/mounts read failure returns a real error (cmd-09-04, explicit comment) -> checks[].status=ERROR"),
	"SRIOVCollector":           exempt("glob(\"/sys/bus/pci/devices/*/sriov_numvfs\") error discarded — same sysfs-class reasoning as BondingCollector/HBACollector/NUMACollector"),
	"VLANCollector":            exempt("/proc/net/vlan/config read failure treated as \"8021q not loaded\" — module-not-loaded (ENOENT) is the realistic failure mode for this /proc path, not EACCES"),
}

func TestUnknownVsPassRegistryComplete(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read internal/collectors: %v", err)
	}

	fset := token.NewFileSet()
	found := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			// Files gated by an unsatisfied build tag on this GOOS parse fine
			// (build tags don't affect parsing) — a real syntax error here
			// would already fail `go build`, so this can't mask one.
			t.Fatalf("parse %s: %v", name, perr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "Collect" || fn.Recv == nil || len(fn.Recv.List) != 1 {
				return true
			}
			recvType := fn.Recv.List[0].Type
			if star, ok := recvType.(*ast.StarExpr); ok {
				recvType = star.X
			}
			ident, ok := recvType.(*ast.Ident)
			if !ok || !strings.HasSuffix(ident.Name, "Collector") {
				return true
			}
			found[ident.Name] = true
			return true
		})
	}

	var unregistered, stale []string
	for name := range found {
		if _, ok := unknownVsPassRegistry[name]; !ok {
			unregistered = append(unregistered, name)
		}
	}
	for name := range unknownVsPassRegistry {
		if !found[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(unregistered)
	sort.Strings(stale)

	if len(unregistered) > 0 {
		t.Errorf("%d Collect()-implementing type(s) have no entry in unknownVsPassRegistry:\n  %s\n\n"+
			"Each must be classified sentinel/exempt/trackedBug — see this file's doc comment. "+
			"(Completeness tripwire for the unknown-vs-pass defect class.)",
			len(unregistered), strings.Join(unregistered, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("%d unknownVsPassRegistry entr(y/ies) no longer match a real Collect() type (remove or rename):\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}
}
