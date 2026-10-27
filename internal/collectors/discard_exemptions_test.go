package collectors

// discardExemptions lists the production functions allowed to discard the error of
// a source/exec/read helper (see TestNoErrorDiscardInProduction). Key:
// "<repo-relative file>:<Func or Type.Method>". Every row carries a reason.
// To remove a row, handle the error and set (or reuse) a sentinel.
const (
	rsGlobVetted      = "raw glob() on a world-readable procfs/sysfs/config directory, already vetted in globExemptions (same function); the discarded error is only a malformed pattern"
	rsGlobChecked     = "globChecked: the unreadable-directory flag carries the read failure and is handled; the discarded error is only a malformed pattern"
	rsCachedNoErr     = "the cachedJSON closure never returns an error; the only failure is a replay recording gap (older bundle), where the documented fallback is the zero value (see cachedJSON)"
	rsExitCarriesData = "the command signals findings through its exit status, so runCmdTimeout/runCmdOutput's error is expected; its output is parsed regardless"
	rsDisplayOnly     = "display-only field (instance type / region / name); the reachability or identity check around it is handled"
)

var discardExemptions = map[string]string{
	"internal/collectors/auth_linux.go:readAuthLogFrom":                            "grep exits 1 on no match: the output (not the exit code) is the result, and the caller already tracks denied/readable separately",
	"internal/collectors/aws_linux.go:awsInstanceType":                             rsDisplayOnly,
	"internal/collectors/battery_linux.go:BatteryCollector.Collect":                rsGlobVetted,
	"internal/collectors/bonding_linux.go:IsBondingPresent":                        rsGlobVetted,
	"internal/collectors/cloudinit_linux.go:CloudInitCollector.Collect":            "cloud-init status exits non-zero for degraded/error states: parse whatever it prints; an empty result falls through to the file-based path and then to StatusUnverified",
	"internal/collectors/cloudmeta_linux.go:collectAWS":                            rsDisplayOnly + "; the spot-termination probe error IS handled (SpotCheckFailed)",
	"internal/collectors/cloudmeta_linux.go:collectGCP":                            rsDisplayOnly,
	"internal/collectors/cpufreq_linux.go:CPUFreqCollector.Collect":                rsGlobVetted,
	"internal/collectors/disk_busy_linux.go:fuserBusyProcesses":                    rsExitCarriesData + "; fuser exits 1 when nothing uses the mount",
	"internal/collectors/disk_linux.go:collectSMART":                               rsExitCarriesData + "; smartctl exit bits flag drive findings, the attribute text is parsed regardless; the identity/health read before it is checked",
	"internal/collectors/dns_linux.go:detectDNSManager":                            "resolv.conf header is a hint to confirm NetworkManager; an unreadable file just leaves the manager as detected from the unit state",
	"internal/collectors/dns_linux.go:runDNSProbe":                                 rsCachedNoErr,
	"internal/collectors/docker.go:collectFirewalldCheck":                          "firewall-cmd --get-active-zones exits non-zero when firewalld is not running; FirewalldActive is gated and read separately, this only refines the zone",
	"internal/collectors/fdlimits.go:FDLimitsCollector.scanProcesses":              rsGlobVetted,
	"internal/collectors/fdlimits.go:hotProcInfo":                                  "comm is a display name for a process already found hot; an unreadable name does not change the FD count",
	"internal/collectors/gpu_linux.go:detectNvidiaWithoutSMI":                      rsGlobVetted,
	"internal/collectors/gpu_linux.go:hasNvidiaCard":                               rsGlobVetted,
	"internal/collectors/hardware_linux.go:collectHwmonThermals":                   rsGlobVetted,
	"internal/collectors/hba_linux.go:IsHBAPresent":                                rsGlobVetted,
	"internal/collectors/health_deep_linux.go:HealthDeepCollector.Collect":         rsCachedNoErr + "; the top-IO/CPU samples carry TopIOProcsNeedsRoot/TopCPUProcsNeedsRoot",
	"internal/collectors/health_deep_linux.go:collectCgroupV2":                     rsGlobVetted,
	"internal/collectors/infiniband_linux.go:InfiniBandCollector.Collect":          rsGlobVetted,
	"internal/collectors/infiniband_linux.go:IsInfiniBandPresent":                  rsGlobVetted,
	"internal/collectors/iscsi_linux.go:iscsiSessionDirCount":                      rsGlobVetted,
	"internal/collectors/k8s.go:checkCertExpiry":                                   rsGlobVetted,
	"internal/collectors/k8s.go:collectK8sOSLayer":                                 "journalctl is best-effort kubelet log tail; firewall-cmd --query-masquerade exits 1 for \"no\" and FirewalldChecked records that the query ran",
	"internal/collectors/kvm_linux.go:kvmCollectNetworks":                          "per-network bridge name / link state are display refinements; the network list itself is checked",
	"internal/collectors/kvm_linux.go:kvmCollectPVEFromDir":                        rsGlobVetted,
	"internal/collectors/kvm_linux.go:pveHasRunningQEMU":                           rsGlobVetted,
	"internal/collectors/logs_linux.go:kmsgRecords":                                "the produce closure never returns an error: the open error is captured in openErr and surfaces as KmsgUnreadable (DD-COLLECTOR C2)",
	"internal/collectors/maintenance_linux.go:KdumpCollector.Collect":              "an empty answer is detected and recorded as StateUnverified; the exit code is meaningless (is-enabled/is-active exit non-zero for \"disabled\"/\"inactive\")",
	"internal/collectors/maintenance_linux.go:KernelRetentionCollector.Collect":    rsGlobChecked,
	"internal/collectors/maintenance_linux.go:LivePatchAvailable":                  rsGlobVetted,
	"internal/collectors/maintenance_linux.go:LivePatchCollector.Collect":          rsGlobVetted,
	"internal/collectors/maintenance_linux.go:ServiceRestartCollector.Collect":     rsGlobVetted,
	"internal/collectors/maintenance_linux.go:TunedCollector.Collect":              "an empty answer is detected and recorded as StateUnverified; the exit code is meaningless (is-active exits non-zero for \"inactive\")",
	"internal/collectors/memcached_linux.go:memcachedCmdSampled":                   "the closure never returns an error: failure is carried in the cached {Out, Ok} pair, and callers read Ok",
	"internal/collectors/netaccess.go:dialOutcome":                                 "documented: the probe outcome is recorded as one byte and a recording gap (older bundle) returns dialUnreachable by design",
	"internal/collectors/network_deep.go:NetworkDeepCollector.Collect":             rsCachedNoErr,
	"internal/collectors/network_quick.go:probeConnectivity":                       "closure never errors; a recording gap leaves the zero probe, which the Disabled/ICMPBlocked/DNSFailed flags already qualify (documented at the call)",
	"internal/collectors/networkd_config_linux.go:NetworkdAvailable":               rsGlobVetted,
	"internal/collectors/networkd_config_linux.go:NetworkdConfigCollector.Collect": rsGlobChecked,
	"internal/collectors/numa_linux.go:IsNUMAPresent":                              rsGlobVetted,
	"internal/collectors/numa_linux.go:NUMACollector.Collect":                      rsGlobVetted,
	"internal/collectors/nvme_linux.go:NVMeCollector.Collect":                      rsGlobVetted,
	"internal/collectors/packages_linux.go:aptHasSecurityRepo":                     "an unreadable sources.list.d only makes the repo look absent, which raises the loud no-security-repo WARN, never a false OK",
	"internal/collectors/packages_linux.go:checkSUSEMigrationRisks":                "zypper locks / uname / ls /boot feed advisory risk lines; a failure leaves the risk visible (not locked) or absent from an advisory list, not a verdict",
	"internal/collectors/packages_linux.go:packageMetadataAgeDays":                 rsGlobVetted,
	"internal/collectors/postgres_linux.go:PostgresCollector.Collect":              "pg_isready exits non-zero when not accepting; its text is the reason and the earlier probe output is the fallback",
	"internal/collectors/redis_linux.go:redisPing":                                 "documented: the ping outcome is a recorded byte; a recording gap returns false (unreachable) by design",
	"internal/collectors/security_linux.go:detectNFTables":                         rsGlobVetted,
	"internal/collectors/sriov_linux.go:IsSRIOVPresent":                            rsGlobVetted,
	"internal/collectors/sriov_linux.go:SRIOVCollector.Collect":                    rsGlobVetted,
	"internal/collectors/steamos_linux.go:SteamOSCollector.collectNetwork":         rsCachedNoErr,
	"internal/collectors/steamos_linux.go:SteamOSCollector.collectRemotePlay":      "ARPChecked is set only when the gateway route was found and the neighbour table read is best-effort LAN-peer evidence",
	"internal/collectors/steamos_linux.go:collectSteamOSWifi":                      rsCachedNoErr,
	"internal/collectors/swap.go:SwapCollector.Collect":                            rsGlobChecked,
	"internal/collectors/sysctl.go:countProcDirs":                                  rsGlobVetted,
	"internal/collectors/sysctl.go:detectWorkload":                                 rsGlobVetted,
	"internal/collectors/systemd.go:systemRunningState":                            "is-system-running exits non-zero for degraded/maintenance and prints the state: the text IS the result, empty means unknown",
	"internal/collectors/systemd.go:sysupdateUnconfigured":                         rsGlobVetted,
	"internal/collectors/thermal_linux.go:ThermalCollector.Collect":                rsGlobVetted,
	"internal/collectors/thermal_linux.go:readHwmonTemps":                          rsGlobChecked,
	"internal/collectors/thermal_linux.go:readThermalZone":                         rsGlobVetted,
}
