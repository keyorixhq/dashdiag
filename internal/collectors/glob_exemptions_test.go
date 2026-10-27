package collectors

// globExemptions lists the production functions allowed to call filepath.Glob
// or the raw glob() helper. Key: "<repo-relative file>:<Func or Type.Method>".
// Every row carries a reason; see TestNoRawGlobInProduction for what counts.
// To remove a row, switch the call to source.GlobChecked / globChecked and
// surface the unreadable-directory flag.
const (
	rsProc  = "procfs listing: /proc is always listable (hidepid hides per-PID entries, it does not make the directory unreadable)"
	rsSys   = "sysfs listing: /sys class/device directories are world-readable; empty means the hardware is absent"
	rsCgrp  = "cgroupfs listing: world-readable; failure to find units degrades to the documented fallback path"
	rsProbe = "presence probe only (IsXPresent/Available gate): the collector proper re-checks with its own reads and discloses on failure"
)

var globExemptions = map[string]string{
	// procfs
	"internal/baseline/since_deploy.go:newestProcStartFrom":                    rsProc,
	"internal/collectors/fdlimits.go:FDLimitsCollector.scanProcesses":          rsProc + "; per-PID read failures are counted separately",
	"internal/collectors/health_deep_linux.go:readAllProcCPU":                  rsProc,
	"internal/collectors/health_deep_linux.go:readAllProcIO":                   rsProc,
	"internal/collectors/health_deep_linux.go:topMemoryProcs":                  rsProc,
	"internal/collectors/maintenance_linux.go:ServiceRestartCollector.Collect": rsProc + "; unreadable per-PID maps are a read error, handled separately",
	"internal/collectors/processes.go:ProcessesCollector.collectLinux":         rsProc + "; hidepid partial-count disclosure is COLLECTOR-SWEEP Medium #8 (Task 3)",
	"internal/collectors/security_linux.go:buildInodeProcMap":                  rsProc + "; hasRoot return already signals missing fd access",
	"internal/collectors/sysctl.go:countProcDirs":                              rsProc,
	"internal/collectors/sysctl.go:detectWorkload":                             rsProc,

	// sysfs
	"internal/collectors/battery_linux.go:BatteryCollector.Collect":       rsSys,
	"internal/collectors/cpufreq_linux.go:CPUFreqCollector.Collect":       rsSys,
	"internal/collectors/gpu_linux.go:amdCardPaths":                       rsSys,
	"internal/collectors/gpu_linux.go:collectIntelGPUs":                   rsSys,
	"internal/collectors/gpu_linux.go:detectNvidiaWithoutSMI":             rsSys,
	"internal/collectors/gpu_linux.go:hasNvidiaCard":                      rsSys,
	"internal/collectors/gpu_linux.go:readSysfsFirstGlob":                 rsSys,
	"internal/collectors/hardware_linux.go:collectHwmonThermals":          rsSys,
	"internal/collectors/hba_linux.go:HBACollector.Collect":               rsSys,
	"internal/collectors/hba_linux.go:IsHBAPresent":                       rsSys + "; " + rsProbe,
	"internal/collectors/infiniband_linux.go:InfiniBandCollector.Collect": rsSys + "; parent dir is Stat-checked first (see the comment in Collect)",
	"internal/collectors/infiniband_linux.go:IsInfiniBandPresent":         rsSys + "; " + rsProbe,
	"internal/collectors/iscsi_linux.go:iscsiSessionDirCount":             rsSys,
	"internal/collectors/maintenance_linux.go:LivePatchAvailable":         rsSys + "; " + rsProbe,
	"internal/collectors/maintenance_linux.go:LivePatchCollector.Collect": rsSys + "; unreadable patch state is reported via UnverifiedPatches",
	"internal/collectors/numa_linux.go:IsNUMAPresent":                     rsSys + "; " + rsProbe,
	"internal/collectors/numa_linux.go:NUMACollector.Collect":             rsSys,
	"internal/collectors/nvme_linux.go:NVMeCollector.Collect":             rsSys,
	"internal/collectors/sriov_linux.go:IsSRIOVPresent":                   rsSys + "; " + rsProbe,
	"internal/collectors/sriov_linux.go:SRIOVCollector.Collect":           rsSys,
	"internal/collectors/swap.go:SwapCollector.Collect":                   rsSys + " (zram); /proc/swaps read gap is COLLECTOR-SWEEP Low #18 (Task 4)",
	"internal/collectors/thermal_linux.go:ThermalCollector.Collect":       rsSys + "; sensor-read gap is COLLECTOR-SWEEP Low #14 (Task 4)",
	"internal/collectors/thermal_linux.go:readHwmonTemps":                 rsSys,
	"internal/collectors/thermal_linux.go:readThermalZone":                rsSys,
	"internal/collectors/bonding_linux.go:BondingCollector.Collect":       "/proc/net/bonding listing: procfs, world-readable",
	"internal/collectors/bonding_linux.go:IsBondingPresent":               "/proc/net/bonding listing: procfs, world-readable; " + rsProbe,
	"internal/collectors/bonding_linux.go:collectBonds":                   "/proc/net/bonding listing: procfs, world-readable",
	"internal/collectors/kvm_linux.go:kvmCollectPVEFromDir":               "/var/run/qemu-server is 0755 root:www-data by Proxmox package default; empty means no PVE guests running",
	"internal/collectors/kvm_linux.go:pveHasRunningQEMU":                  rsProbe,

	// cgroupfs
	"internal/collectors/health_deep_linux.go:candidateCgroupUnitDirs": rsCgrp,
	"internal/collectors/health_deep_linux.go:collectCgroupV2":         rsCgrp,

	// config / log directories that are world-readable by default, or already guarded
	"internal/baseline/security_baseline.go:hashSSHConfigFiles":        "/etc/ssh/sshd_config.d is 0755 root by package default; the documented contract of this function is that unreadable files are omitted from the hash map",
	"internal/collectors/k8s.go:checkCertExpiry":                       "the directory is readDirNames-checked first (CertDirUnreadable on permission denied); the glob only runs on a proven-readable directory",
	"internal/collectors/networkd_config_linux.go:NetworkdAvailable":   rsProbe + " (Collect uses globChecked -> ConfigDirUnreadable)",
	"internal/collectors/packages_linux.go:packageMetadataAgeDays":     "package-manager metadata dirs (/var/lib/apt/lists, /var/cache/dnf, ...) are 0755; no match yields the (-1, false) unknown-age result, never a clean age",
	"internal/collectors/pve_linux.go:collectPVEBackupAgeFromLogs":     "/var/log/vzdump is 0755 on PVE; PVE sub-check error handling is the PVECollector registry row (COLLECTOR-SWEEP Medium #11, Task 3)",
	"internal/collectors/pve_linux.go:scanBackupDumpDirs":              "dump directories are PVE storage mounts; PVE sub-check error handling is the PVECollector registry row (COLLECTOR-SWEEP Medium #11, Task 3)",
	"internal/collectors/security_darwin.go:parseDarwinSSHConfig":      "darwin /etc/ssh/sshd_config.d is 0755; the SecurityCollector registry row (COLLECTOR-SWEEP Low #21, Task 4) owns the darwin audit gaps",
	"internal/collectors/security_darwin.go:parseDarwinSudoers":        "darwin /etc/sudoers.d is 0755 root:wheel; sudoers read failures here are silent today and belong to the SecurityCollector registry row (COLLECTOR-SWEEP Low #21, Task 4)",
	"internal/collectors/security_darwin.go:parseDarwinSuspectLaunchd": "/Users/*/Library/LaunchAgents: a non-root scan cannot traverse other users' Library; darwin SSH/launchd audit gap is COLLECTOR-SWEEP Low #21 (Task 4)",
	"internal/collectors/security_linux.go:detectNFTables":             "tool-absent fallback: a hit sets FirewallConfigOnlyUnverified, an empty listing falls through to the iptables chain below",
	"internal/collectors/security_linux.go:parseSSHConfig":             "/etc/ssh/sshd_config.d is 0755 root by package default; when no source is readable SSHAuditSource records 'unavailable' (see the readAny branch)",
	"internal/collectors/security_linux.go:parseSudoers":               "/etc/sudoers.d is 0750 root: whenever it is unlistable /etc/sudoers (0440) is unreadable too, and that read failure is the disclosed signal (parseSudoersFile)",
	"internal/collectors/security_linux.go:parseSupportconfig":         "the log directory is os.IsPermission-checked first (logDirUnreadable); the glob runs per pattern after that check",
	"internal/collectors/systemd.go:sysupdateUnconfigured":             "/etc/sysupdate.d and /usr/lib/sysupdate.d are 0755 package-owned directories; the result only decides whether to suppress the benign no-transfer-definitions failure",
}
