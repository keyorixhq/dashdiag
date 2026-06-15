package analysis

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func ApplyThresholds(results []runner.Result, thresh Thresholds, _ platform.CloudEnvironment, ctrCtx platform.ContainerContext) []models.Insight {
	// Pre-scan results to extract context shared across checks.
	// SELinux enforcing state is needed by checkSystemd to add double-layer hints.
	selinuxEnforcing := false
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		switch d := r.Data.(type) {
		case models.PackagesInfo:
			if d.PackageManager != "" {
				thresh.PackageManager = d.PackageManager
			}
		case *models.PackagesInfo:
			if d != nil && d.PackageManager != "" {
				thresh.PackageManager = d.PackageManager
			}
		case models.CPUInfo:
			thresh.CPULoadPct = d.LoadPct
		case *models.CPUInfo:
			if d != nil {
				thresh.CPULoadPct = d.LoadPct
			}
		case models.KernelSecurityInfo:
			if d.SELinuxPresent && d.SELinuxMode == "enforcing" {
				selinuxEnforcing = true
			}
		case *models.KernelSecurityInfo:
			if d != nil && d.SELinuxPresent && d.SELinuxMode == "enforcing" {
				selinuxEnforcing = true
			}
		}
	}

	// Inject SELinux enforcing state into SystemdInfo for cross-check hints
	for i, r := range results {
		if r.Name == "Systemd" {
			switch d := r.Data.(type) {
			case *models.SystemdInfo:
				if d != nil {
					d.SELinuxEnforcing = selinuxEnforcing
				}
			case models.SystemdInfo:
				d.SELinuxEnforcing = selinuxEnforcing
				results[i].Data = d
			}
		}
	}

	var insights []models.Insight
	for _, r := range results {
		if r.Err != nil {
			insights = append(insights, insight("INFO", r.Name,
				fmt.Sprintf("check could not run — %v", r.Err), nil))
			continue
		}
		insights = append(insights, applyOne(r.Data, thresh, ctrCtx)...)
	}
	// On NixOS the imperative fix hints (/etc/sysctl.d, /etc/ssh/sshd_config,
	// apt/dnf/zypper) don't apply — rewrite them to the configuration.nix form.
	if hostIsNixOS() {
		insights = nixosifyHints(insights)
	}
	// Remedy text is generated in its Linux/systemd form; rewrite commands that
	// don't exist on this platform (ss on macOS; systemctl on OpenRC/Alpine) so the
	// hint is runnable where dsd actually runs. Diagnosis is already correct; this
	// fixes only the "to inspect/to fix" line. (TRIAGE §A.)
	insights = adaptHintsToPlatform(insights, runtime.GOOS, hostInitSystem())
	return insights
}

// hostInitSystem returns the init system ("systemd", "openrc", "unknown") so the
// hint adapter can pick the right service command. Indirection keeps
// adaptHintsToPlatform unit-testable without the real host.
var hostInitSystem = func() string { return platform.Detect().InitSystem }

// adaptHintsToPlatform rewrites each hint's platform-specific command for goos +
// initSystem. Pure dispatch over adaptHint so it can be tested per platform.
func adaptHintsToPlatform(insights []models.Insight, goos, initSystem string) []models.Insight {
	if goos != "darwin" && initSystem != "openrc" {
		return insights // Linux/systemd: hints already correct
	}
	for i := range insights {
		if len(insights[i].Hints) == 0 {
			continue
		}
		out := make([]string, 0, len(insights[i].Hints))
		for _, h := range insights[i].Hints {
			if nh, drop := adaptHint(h, goos, initSystem); !drop {
				out = append(out, nh)
			}
		}
		insights[i].Hints = out
	}
	return insights
}

var (
	// macOS has no `ss`; lsof is the listening-socket equivalent.
	reSSPortGrep = regexp.MustCompile(`^to inspect: ss -t(?:u)?lnp \| grep :(\d+)$`)
	reSSListen   = regexp.MustCompile(`^to inspect: ss -t(?:u)?lnp$`)
	// OpenRC (Alpine/Gentoo) uses rc-service / rc-update, not systemctl.
	reSystemctlAction  = regexp.MustCompile(`^to fix: systemctl (restart|start|stop) (\S+)$`)
	reSystemctlEnable  = regexp.MustCompile(`^to fix: systemctl enable --now (\S+)$`)
	reSystemctlDisable = regexp.MustCompile(`^to fix: systemctl disable (\S.*)$`)
)

// adaptHint rewrites a single hint for the platform, or returns drop=true when no
// runnable equivalent exists (the diagnosis still stands; only the remedy line is
// removed). Unknown hints pass through unchanged.
func adaptHint(hint, goos, initSystem string) (string, bool) {
	if goos == "darwin" {
		if m := reSSPortGrep.FindStringSubmatch(hint); m != nil {
			return "to inspect: lsof -nP -iTCP:" + m[1] + " -sTCP:LISTEN", false
		}
		if reSSListen.MatchString(hint) {
			return "to inspect: lsof -nP -iTCP -sTCP:LISTEN", false
		}
		return hint, false
	}
	if initSystem == "openrc" {
		if m := reSystemctlAction.FindStringSubmatch(hint); m != nil {
			return fmt.Sprintf("to fix: rc-service %s %s", m[2], m[1]), false
		}
		if m := reSystemctlEnable.FindStringSubmatch(hint); m != nil {
			return fmt.Sprintf("to fix: rc-update add %s && rc-service %s start", m[1], m[1]), false
		}
		if m := reSystemctlDisable.FindStringSubmatch(hint); m != nil {
			return fmt.Sprintf("to fix: rc-update del %s", m[1]), false
		}
		return hint, false
	}
	return hint, false
}

// PlatformServiceCmd rewrites a systemd service-management command (e.g.
// "systemctl restart docker") into the form runnable on the running host's init
// system, returning it unchanged on systemd/macOS. It exists so subcommands that
// print remedy lines directly to stdout — outside the insight pipeline that
// adaptHintsToPlatform covers — share the same one source of truth as the
// adapter (it delegates to adaptHint). (TRIAGE §A audit.)
func PlatformServiceCmd(systemdCmd string) string {
	return platformServiceCmd(systemdCmd, runtime.GOOS, hostInitSystem())
}

// platformServiceCmd is the host-independent core, split out so it is
// unit-testable without the real GOOS/init system (see hostInitSystem).
func platformServiceCmd(systemdCmd, goos, initSystem string) string {
	out, _ := adaptHint("to fix: "+systemdCmd, goos, initSystem)
	return strings.TrimPrefix(out, "to fix: ")
}

// PlatformServiceCmdSudo is like PlatformServiceCmd but for callers that print the
// remedy as a privileged command. It applies `sudo` to EACH command in the result,
// because the OpenRC rewrite of `enable --now` is a `&&` pair (rc-update + rc-service)
// and a single leading `sudo` only elevates the first — the second (`rc-service X
// start`, which needs root) would fail for a non-root user copy-pasting the line.
func PlatformServiceCmdSudo(systemdCmd string) string {
	return platformServiceCmdSudo(systemdCmd, runtime.GOOS, hostInitSystem())
}

func platformServiceCmdSudo(systemdCmd, goos, initSystem string) string {
	cmd := platformServiceCmd(systemdCmd, goos, initSystem)
	parts := strings.Split(cmd, " && ")
	for i, p := range parts {
		parts[i] = "sudo " + p
	}
	return strings.Join(parts, " && ")
}

// NixOS configures the system declaratively via configuration.nix + nixos-rebuild,
// not the imperative /etc/sysctl.d, /etc/ssh/sshd_config, and apt/dnf/zypper
// commands the generic fix hints assume. The patterns below are anchored so
// they only rewrite the intended hints; everything else passes through.
var (
	reNixSysctlPersist = regexp.MustCompile(`^to persist: echo '([^'=]+)=(.+)' >> /etc/sysctl\.d/99-dsd\.conf$`)
	reNixSSHDSet       = regexp.MustCompile(`^to fix: set (\S+) (.+) in /etc/ssh/sshd_config$`)
	reNixSSHDEchoSet   = regexp.MustCompile(`^to fix:\s+echo '(\S+) (.+)' >> /etc/ssh/sshd_config && systemctl restart sshd$`)
	reNixSSHRestart    = regexp.MustCompile(`^to fix: systemctl restart sshd$`)
	reNixSSHProtocol   = regexp.MustCompile(`^to fix: remove or comment out 'Protocol' line in /etc/ssh/sshd_config$`)
	reNixRsyslog       = regexp.MustCompile(`^to fix: apt install rsyslog\s+OR\s+dnf install rsyslog\s+OR\s+zypper install rsyslog$`)
	reNixJournald      = regexp.MustCompile(`^to (?:fix|persist):\s+echo '([^']+)' >> /etc/systemd/journald\.conf(?: && systemctl restart systemd-journald)?$`)
)

// hostIsNixOS reports whether the running host is NixOS, per /etc/os-release.
func hostIsNixOS() bool {
	return strings.Contains(strings.ToLower(cvedata.DetectDistroID()), "nixos")
}

// nixosifyHints rewrites every insight's fix hints into their configuration.nix
// equivalents. Hints that match no known pattern are left untouched.
func nixosifyHints(insights []models.Insight) []models.Insight {
	for i := range insights {
		if len(insights[i].Hints) == 0 {
			continue
		}
		rewritten := make([]string, 0, len(insights[i].Hints))
		for _, h := range insights[i].Hints {
			if nh, drop := nixosFixHint(h); !drop {
				rewritten = append(rewritten, nh)
			}
		}
		insights[i].Hints = rewritten
	}
	return insights
}

// nixosFixHint rewrites a single generic fix hint to its NixOS form. The bool
// return is true when the hint should be dropped on NixOS (a standalone sshd
// restart that the rebuild already covers); otherwise it returns the rewritten
// hint, or the hint unchanged when no NixOS rewrite applies.
func nixosFixHint(hint string) (string, bool) {
	if m := reNixSysctlPersist.FindStringSubmatch(hint); m != nil {
		return fmt.Sprintf("to persist (NixOS): boot.kernel.sysctl = { %q = %s; }; in configuration.nix, then nixos-rebuild switch", m[1], m[2]), false
	}
	if m := reNixSSHDSet.FindStringSubmatch(hint); m != nil {
		return fmt.Sprintf("to fix (NixOS): services.openssh.settings.%s = %q; in configuration.nix, then nixos-rebuild switch", m[1], m[2]), false
	}
	if m := reNixSSHDEchoSet.FindStringSubmatch(hint); m != nil {
		return fmt.Sprintf("to fix (NixOS): services.openssh.settings.%s = %q; in configuration.nix, then nixos-rebuild switch", m[1], m[2]), false
	}
	if reNixSSHRestart.MatchString(hint) {
		return "", true // configuration.nix rebuild already restarts sshd
	}
	if reNixSSHProtocol.MatchString(hint) {
		return "to fix (NixOS): remove any 'Protocol' line from services.openssh.extraConfig, then nixos-rebuild switch", false
	}
	if reNixRsyslog.MatchString(hint) {
		return "to fix (NixOS): services.rsyslogd.enable = true; in configuration.nix, then nixos-rebuild switch", false
	}
	if m := reNixJournald.FindStringSubmatch(hint); m != nil {
		return fmt.Sprintf("to fix (NixOS): services.journald.extraConfig = %q; in configuration.nix, then nixos-rebuild switch", m[1]), false
	}
	return hint, false
}

//nolint:cyclop // type dispatch — each case is trivial
func applyOne(data interface{}, thresh Thresholds, ctrCtx platform.ContainerContext) []models.Insight {
	switch d := data.(type) {
	case models.CPUInfo:
		return checkCPU(d, thresh)
	case *models.CPUInfo:
		return checkCPU(*d, thresh)
	case models.MemoryInfo:
		return checkMemory(d, thresh, ctrCtx)
	case *models.MemoryInfo:
		return checkMemory(*d, thresh, ctrCtx)
	case models.DiskInfo:
		return checkDisk(d, thresh)
	case *models.DiskInfo:
		return checkDisk(*d, thresh)
	case models.SwapInfo:
		return checkSwap(d, thresh)
	case *models.SwapInfo:
		return checkSwap(*d, thresh)
	case models.IOInfo:
		return checkIO(d, thresh)
	case *models.IOInfo:
		return checkIO(*d, thresh)
	case models.NetworkInfo:
		return checkNetwork(d)
	case *models.NetworkInfo:
		return checkNetwork(*d)
	case models.NFSInfo:
		return checkNFS(d)
	case *models.NFSInfo:
		return checkNFS(*d)
	case models.BINDInfo:
		return checkBIND(d)
	case *models.BINDInfo:
		return checkBIND(*d)
	case models.ClockInfo:
		return checkClock(d, thresh)
	case *models.ClockInfo:
		if d != nil {
			return checkClock(*d, thresh)
		}
	}
	return applyOneExtended(data, thresh)
}

//nolint:cyclop // type dispatch — each case is trivial
func applyOneExtended(data interface{}, thresh Thresholds) []models.Insight { //nolint:funlen // flat type switch — splitting would harm readability
	switch d := data.(type) {
	case models.FDInfo:
		return checkFD(d, thresh)
	case *models.FDInfo:
		return checkFD(*d, thresh)
	case models.SystemdInfo:
		return checkSystemd(d)
	case *models.SystemdInfo:
		return checkSystemd(*d)
	case models.SysctlInfo:
		return checkSysctl(d)
	case *models.SysctlInfo:
		return checkSysctl(*d)
	case models.KernelSecurityInfo:
		return checkKernelSecurity(d, thresh)
	case *models.KernelSecurityInfo:
		return checkKernelSecurity(*d, thresh)
	case models.LogsInfo:
		return checkLogs(d, thresh)
	case *models.LogsInfo:
		return checkLogs(*d, thresh)
	case models.EntropyInfo:
		return checkEntropy(d)
	case *models.EntropyInfo:
		if d != nil {
			return checkEntropy(*d)
		}
	case models.PackagesInfo:
		return checkPackages(d)
	case *models.PackagesInfo:
		if d != nil {
			return checkPackages(*d)
		}
	case models.CVEAllResult:
		return checkCVEHealth(d)
	case *models.CVEAllResult:
		if d != nil {
			return checkCVEHealth(*d)
		}
	case models.NVMeInfo:
		return checkNVMe(d)
	case *models.NVMeInfo:
		if d != nil {
			return checkNVMe(*d)
		}
	case models.RAIDInfo:
		return checkRAID(d)
	case *models.RAIDInfo:
		if d != nil {
			return checkRAID(*d)
		}
	case models.ZFSInfo:
		return checkZFS(d)
	case *models.ZFSInfo:
		if d != nil {
			return checkZFS(*d)
		}
	case models.LVMInfo:
		return checkLVM(d)
	case *models.LVMInfo:
		if d != nil {
			return checkLVM(*d)
		}
	case models.DRBDInfo:
		return checkDRBD(d)
	case *models.DRBDInfo:
		if d != nil {
			return checkDRBD(*d)
		}
	case models.PVEInfo:
		return checkPVE(d)
	case *models.PVEInfo:
		if d != nil {
			return checkPVE(*d)
		}
	case models.BatteryInfo:
		return checkBattery(d)
	case *models.BatteryInfo:
		if d != nil {
			return checkBattery(*d)
		}
	case models.ThermalInfo:
		return checkThermal(d, thresh)
	case *models.ThermalInfo:
		if d != nil {
			return checkThermal(*d, thresh)
		}
	case models.HealthDeepInfo:
		return checkHealthDeep(d)
	case *models.HealthDeepInfo:
		return checkHealthDeep(*d)
	case models.FirmwareInfo:
		return checkFirmware(d)
	case *models.FirmwareInfo:
		return checkFirmware(*d)
	case models.DockerInfo:
		return checkDocker(d)
	case *models.DockerInfo:
		return checkDocker(*d)
	case models.ContainerdInfo:
		return checkContainerd(d)
	case *models.ContainerdInfo:
		return checkContainerd(*d)
	case models.PostgresInfo:
		return checkPostgres(d)
	case *models.PostgresInfo:
		return checkPostgres(*d)
	case models.MySQLInfo:
		return checkMySQL(d)
	case *models.MySQLInfo:
		return checkMySQL(*d)
	case models.RedisInfo:
		return checkRedis(d)
	case *models.RedisInfo:
		return checkRedis(*d)
	case models.MemcachedInfo:
		return checkMemcached(d)
	case *models.MemcachedInfo:
		return checkMemcached(*d)
	case models.NginxInfo:
		return checkNginx(d)
	case *models.NginxInfo:
		return checkNginx(*d)
	case models.ApacheInfo:
		return checkApache(d)
	case *models.ApacheInfo:
		return checkApache(*d)
	case models.HAProxyInfo:
		return checkHAProxy(d)
	case *models.HAProxyInfo:
		return checkHAProxy(*d)
	case models.RabbitMQInfo:
		return checkRabbitMQ(d)
	case *models.RabbitMQInfo:
		return checkRabbitMQ(*d)
	case models.ElasticsearchInfo:
		return checkElasticsearch(d)
	case *models.ElasticsearchInfo:
		return checkElasticsearch(*d)
	case models.K8sInfo:
		return checkK8s(d)
	case *models.K8sInfo:
		return checkK8s(*d)
	case models.KVMInfo:
		return checkKVM(d)
	case *models.KVMInfo:
		return checkKVM(*d)
	case models.SteamOSInfo:
		return checkSteamOS(d)
	case *models.SteamOSInfo:
		return checkSteamOS(*d)
	case models.TLSInfo:
		return checkTLS(d)
	case *models.TLSInfo:
		return checkTLS(*d)
	case models.GPUInfo:
		return checkGPU(d)
	case *models.GPUInfo:
		if d != nil {
			return checkGPU(*d)
		}
	case models.SecurityInfo:
		return checkSecurity(d)
	case *models.SecurityInfo:
		if d != nil {
			return checkSecurity(*d)
		}
	case models.ProcessInfo:
		return checkProcesses(d, thresh)
	case *models.ProcessInfo:
		return checkProcesses(*d, thresh)
	case models.SnapperInfo:
		return checkSnapper(d)
	case *models.SnapperInfo:
		if d != nil {
			return checkSnapper(*d)
		}
	case models.SUSEConnectInfo:
		return checkSUSEConnect(d)
	case *models.SUSEConnectInfo:
		if d != nil {
			return checkSUSEConnect(*d)
		}
	case models.HardwareInfo:
		return checkHardware(d)
	case *models.HardwareInfo:
		if d != nil {
			return checkHardware(*d)
		}
	case models.BondingInfo:
		return checkBonding(d)
	case *models.BondingInfo:
		if d != nil {
			return checkBonding(*d)
		}
	case models.IPMIInfo:
		return checkIPMI(d)
	case *models.IPMIInfo:
		if d != nil {
			return checkIPMI(*d)
		}
	case models.OOMInfo:
		return checkOOM(d)
	case *models.OOMInfo:
		if d != nil {
			return checkOOM(*d)
		}
	case models.HBAInfo:
		return checkHBA(d)
	case *models.HBAInfo:
		if d != nil {
			return checkHBA(*d)
		}
	case models.PressureInfo:
		return checkPressure(d)
	case *models.PressureInfo:
		if d != nil {
			return checkPressure(*d)
		}
	case models.MultipathInfo:
		return checkMultipath(d)
	case *models.MultipathInfo:
		if d != nil {
			return checkMultipath(*d)
		}
	case models.CephInfo:
		return checkCeph(d)
	case *models.CephInfo:
		if d != nil {
			return checkCeph(*d)
		}
	case models.FirewallInfo:
		return checkFirewall(d)
	case *models.FirewallInfo:
		if d != nil {
			return checkFirewall(*d)
		}
	case models.AuthInfo:
		return checkAuth(d)
	case *models.AuthInfo:
		if d != nil {
			return checkAuth(*d)
		}
	case models.CloudInfo:
		return checkCloudMeta(d)
	case *models.CloudInfo:
		if d != nil {
			return checkCloudMeta(*d)
		}
	case models.CloudInitInfo:
		return checkCloudInit(d)
	case *models.CloudInitInfo:
		if d != nil {
			return checkCloudInit(*d)
		}
	case models.VMwareInfo:
		return checkVMware(d)
	case *models.VMwareInfo:
		if d != nil {
			return checkVMware(*d)
		}
	case models.AuditInfo:
		return checkAuditd(d)
	case *models.AuditInfo:
		if d != nil {
			return checkAuditd(*d)
		}
	case models.NUMAInfo:
		return checkNUMA(d)
	case *models.NUMAInfo:
		if d != nil {
			return checkNUMA(*d)
		}
	case models.VLANInfo:
		return checkVLAN(d)
	case *models.VLANInfo:
		if d != nil {
			return checkVLAN(*d)
		}
	case models.ISCSIInfo:
		return checkISCSI(d)
	case *models.ISCSIInfo:
		if d != nil {
			return checkISCSI(*d)
		}
	case models.InfiniBandInfo:
		return checkInfiniBand(d)
	case *models.InfiniBandInfo:
		if d != nil {
			return checkInfiniBand(*d)
		}
	case models.SRIOVInfo:
		return checkSRIOV(d)
	case *models.SRIOVInfo:
		if d != nil {
			return checkSRIOV(*d)
		}
	case models.NspawnInfo:
		return checkNspawn(d)
	case *models.NspawnInfo:
		if d != nil {
			return checkNspawn(*d)
		}
	case models.HugePagesInfo:
		return checkHugePages(d)
	case *models.HugePagesInfo:
		if d != nil {
			return checkHugePages(*d)
		}
	case models.CPUFreqInfo:
		return checkCPUFreq(d)
	case *models.CPUFreqInfo:
		if d != nil {
			return checkCPUFreq(*d)
		}
	case models.LaunchdInfo:
		return checkLaunchd(d)
	case *models.LaunchdInfo:
		if d != nil {
			return checkLaunchd(*d)
		}
	case models.DBusInfo:
		return checkDBus(d)
	case *models.DBusInfo:
		if d != nil {
			return checkDBus(*d)
		}
	case models.SessionsInfo:
		return checkSessions(d)
	case *models.SessionsInfo:
		if d != nil {
			return checkSessions(*d)
		}
	case models.CronInfo:
		return checkCron(d)
	case *models.CronInfo:
		if d != nil {
			return checkCron(*d)
		}
	case models.DNSResolverInfo:
		return checkDNS(d)
	case *models.DNSResolverInfo:
		if d != nil {
			return checkDNS(*d)
		}
	}
	return nil
}

func levelPct(val, warn, crit float64) string {
	if val >= crit {
		return "CRIT"
	}
	if val >= warn {
		return "WARN"
	}
	return ""
}

func insight(level, check, message string, hints []string) models.Insight {
	return models.Insight{Level: level, Check: check, Message: message, Hints: hints}
}

func checkCPU(cpu models.CPUInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight

	// Choose the right metric for the threshold:
	// - UsagePct (real user+sys%) is accurate on Linux (/proc/stat) and macOS (top).
	//   Use it when available — it matches what htop/Activity Monitor show.
	// - LoadPct (load_avg_1 / num_cpus) is a proxy. On macOS it fires false alarms
	//   because many tiny short-lived threads inflate the queue without consuming CPU.
	checkPct := cpu.LoadPct
	usingInstantaneous := false
	if cpu.UsagePct > 0 {
		checkPct = cpu.UsagePct
		usingInstantaneous = true
	}

	// Instantaneous /proc/stat metrics (user+sys% and run-queue depth) are
	// contaminated by dsd's own parallel collection on small-core hosts: while
	// the CPU collector sleeps between its two samples, sibling collectors spawn
	// ss/journalctl/smartctl/… that briefly saturate the box. The 1-minute load
	// average predates this run and is immune, so require it to corroborate.
	// Genuine CPU pressure always shows in the load average — a sustained
	// run-queue cannot coexist with a near-zero load — whereas dsd's own spike
	// does not. Anything below the warn floor (including a legitimately idle
	// load of 0.00, where the collector still returns valid load data) is
	// treated as measurement noise. The load-ratio verdict is itself the
	// sustained signal, so only the instantaneous paths are gated.
	loadPct := cpu.LoadPct
	if loadPct == 0 && cpu.LoadAvg1 > 0 && cpu.NumCPU > 0 {
		loadPct = cpu.LoadAvg1 / float64(cpu.NumCPU) * 100
	}
	loadCorroborated := loadPct >= thresh.CPULoadWarnMultiplier*100

	if l := levelPct(checkPct, thresh.CPULoadWarnMultiplier*100, thresh.CPULoadCritMultiplier*100); l != "" && (!usingInstantaneous || loadCorroborated) {
		msg := fmt.Sprintf("%.0f%% CPU (user+sys)", cpu.UsagePct)
		if cpu.LoadAvg1 > 0 {
			msg += fmt.Sprintf(" — load avg %.2f across %d CPUs", cpu.LoadAvg1, cpu.NumCPU)
		}
		out = append(out, insight(l, "CPU Load",
			msg,
			[]string{"to inspect: uptime", "to inspect: ps aux --sort=-%cpu | head -10", "to inspect: top -b -n1 | head -25"},
		))
	}

	// CPU steal — hypervisor is withholding CPU from this VM.
	// Only meaningful on virtual machines (bare metal always shows 0).
	// > 10%: host is over-provisioned — neighbours are competing for physical CPUs.
	// > 20%: severe — application latency will be unpredictable.
	if cpu.StealPct >= 20 {
		out = append(out, insight("CRIT", "CPU Load/Steal",
			fmt.Sprintf("CPU steal at %.1f%% — hypervisor is withholding CPU time from this VM", cpu.StealPct),
			[]string{
				"to inspect: top -b -n1 | grep Cpu",
				"to inspect: vmstat 1 5  (look at the 'st' column)",
				"note: steal > 20%% means the host is severely over-provisioned",
				"note: escalate to your cloud provider or migrate to a less-loaded host",
			},
		))
	} else if cpu.StealPct >= 10 {
		out = append(out, insight("WARN", "CPU Load/Steal",
			fmt.Sprintf("CPU steal at %.1f%% — VM is not getting all requested CPU cycles", cpu.StealPct),
			[]string{
				"to inspect: top -b -n1 | grep Cpu  (look for 'st' column)",
				"to inspect: vmstat 1 5",
				"note: steal time indicates host over-provisioning — consider VM migration",
			},
		))
	}

	// CPU iowait — CPU is idle but blocked waiting for I/O.
	// High iowait with normal/low CPU usage means load is I/O-driven, not compute-driven.
	// This is the canonical "high load average but CPU is not busy" pattern.
	if cpu.IOwaitPct >= 40 {
		out = append(out, insight("CRIT", "CPU Load/IOWait",
			fmt.Sprintf("I/O wait at %.1f%% — CPU is stalled waiting for disk or network I/O", cpu.IOwaitPct),
			[]string{
				"to inspect: iostat -x 1 5",
				"to inspect: iotop -ao",
				"to inspect: ps aux | grep ' D '  (D-state processes blocked on I/O)",
				"note: high iowait with normal CPU usage = disk bottleneck, not CPU",
			},
		))
	} else if cpu.IOwaitPct >= 20 {
		out = append(out, insight("WARN", "CPU Load/IOWait",
			fmt.Sprintf("I/O wait at %.1f%% — load may be I/O-driven rather than CPU-bound", cpu.IOwaitPct),
			[]string{
				"to inspect: iostat -x 1 5",
				"to inspect: ps aux | grep ' D '",
			},
		))
	}

	// Run-queue saturation — more runnable tasks than the CPU can execute at once.
	// procs_running counts processes ready to run (including those on-CPU); sustained
	// values above the core count mean tasks are queued for CPU time. This is distinct
	// from CPU% (how busy cores are) and load avg (which also counts D-state tasks).
	// Context-switch rate is shown as supporting context — reliable spike detection
	// needs the history-aware engine (v2), so it is not thresholded on its own.
	if loadCorroborated && cpu.NumCPU > 0 && cpu.RunQueue > 0 {
		cpuLabel := pluralize(cpu.NumCPU, "CPU", "CPUs")
		switch {
		case cpu.RunQueue >= 4*cpu.NumCPU:
			out = append(out, insight("CRIT", "CPU Load/RunQueue",
				fmt.Sprintf("%d runnable tasks on %s — run queue is ~%d× saturated, tasks are waiting for CPU",
					cpu.RunQueue, cpuLabel, cpu.RunQueue/cpu.NumCPU),
				runQueueHints(cpu),
			))
		case cpu.RunQueue >= 2*cpu.NumCPU:
			out = append(out, insight("WARN", "CPU Load/RunQueue",
				fmt.Sprintf("%d runnable tasks on %s — more tasks ready to run than cores available",
					cpu.RunQueue, cpuLabel),
				runQueueHints(cpu),
			))
		}
	}

	return out
}

// pluralize returns "<n> <singular>" when n == 1, otherwise "<n> <plural>".
func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}

// runQueueHints builds the inspection hints for a run-queue saturation insight,
// folding in context-switch rate and blocked-task count when present.
func runQueueHints(cpu models.CPUInfo) []string {
	hints := []string{
		"to inspect: vmstat 1 5  (the 'r' column is the run queue length)",
		"to inspect: top -H -b -n1 | head -20  (per-thread, find the busy threads)",
	}
	if cpu.ContextSwitchRate > 0 {
		hints = append(hints, fmt.Sprintf("context: ~%.0f context switches/s during sampling", cpu.ContextSwitchRate))
	}
	if cpu.ProcsBlocked > 0 {
		hints = append(hints, fmt.Sprintf("context: %d task(s) blocked on I/O (D state) — see CPU/IOWait", cpu.ProcsBlocked))
	}
	hints = append(hints, "note: persistent run-queue saturation = under-provisioned CPU or a runaway thread spawner")
	return hints
}

// checkDBus surfaces D-Bus health. D-Bus is treated as a Tier-0 dependency —
// its failure cascades to all services that communicate via IPC.
func checkDBus(d models.DBusInfo) []models.Insight {
	if d.Status == "n/a" || d.Active {
		return nil // healthy or not applicable (non-Linux)
	}
	hints := []string{
		"to inspect: systemctl status dbus.service",
		"to inspect: journalctl -u dbus.service -n 20",
		"note: D-Bus failure cascades — NetworkManager, systemd-logind, and other services will also fail",
		"note: check SELinux policy type: cat /etc/selinux/config | grep SELINUXTYPE",
	}
	if d.LastError != "" {
		hints = append([]string{"last error: " + d.LastError}, hints...)
	}
	return []models.Insight{insight("CRIT", "DBus",
		"D-Bus system message bus has failed — all IPC-dependent services are affected",
		hints,
	)}
}

func checkMemory(mem models.MemoryInfo, thresh Thresholds, ctrCtx platform.ContainerContext) []models.Insight {
	var out []models.Insight
	if l := levelPct(mem.UsedPct, thresh.RAMWarnPct, thresh.RAMCritPct); l != "" {
		var memHints []string
		if runtime.GOOS == "darwin" {
			memHints = []string{"to inspect: vm_stat", "to inspect: top -l 1 | grep PhysMem", "to inspect: ps aux -m | head -10"}
		} else {
			memHints = []string{"to inspect: free -h", "to inspect: ps aux --sort=-%mem | head -10"}
		}
		out = append(out, insight(l, "Memory",
			fmt.Sprintf("RAM usage at %.0f%% (%.1f GB free of %.1f GB total)", mem.UsedPct, mem.FreeGB, mem.TotalGB),
			memHints,
		))
	}
	// CommitLimit is only ENFORCED in strict-accounting mode (vm.overcommit_memory=2).
	// In the default heuristic mode (0) and always-overcommit mode (1), Committed_AS
	// routinely exceeds CommitLimit on a perfectly healthy box — flagging it there is
	// a false positive. Only mode 2 makes the over-commit an actual allocation/OOM risk.
	if mem.OverCommitted && mem.OvercommitMode == 2 {
		out = append(out, insight("CRIT", "Memory",
			"memory overcommitted under strict accounting (vm.overcommit_memory=2) — new allocations will be refused",
			[]string{"to inspect: cat /proc/meminfo | grep -E 'CommitLimit|Committed_AS'", "to inspect: sysctl vm.overcommit_memory"},
		))
	}
	slabPct := 0.0
	if mem.TotalGB > 0 {
		slabPct = (mem.SlabMB / 1024) / mem.TotalGB * 100
	}
	// Suppress slab check inside containers — /proc/meminfo Slab is a host-level
	// value but mem.TotalGB reflects the cgroup memory limit, not host RAM.
	// Comparing host slab against container ceiling always produces false WARNs.
	if slabPct >= thresh.SlabWarnPct && !ctrCtx.InContainer {
		out = append(out, insight("WARN", "Memory/Slab",
			fmt.Sprintf("kernel slab cache is %.0f%% of total RAM (%.0f MB)", slabPct, mem.SlabMB),
			[]string{"to inspect: cat /proc/slabinfo | sort -k3 -rn | head -20", "to inspect: slabtop -o | head -20"},
		))
	}
	// ECC memory errors (physical hosts). Now collected in the fast health path,
	// so a failing DIMM surfaces in routine `dsd health`, not only `dsd hardware`.
	if mem.EDACAvailable {
		out = append(out, eccInsights(mem.CorrectedErrors, mem.UncorrectedErrors, "Memory")...)
	}
	return out
}

// eccInsights turns EDAC corrected/uncorrected counts into insights. Shared by
// the health Memory check and the hardware check so their thresholds and wording
// can't drift. Uncorrected errors are an active RAM fault (CRIT); corrected
// errors above a small floor mean a DIMM is degrading (WARN).
func eccInsights(corrected, uncorrected int64, check string) []models.Insight {
	switch {
	case uncorrected > 0:
		return []models.Insight{insight("CRIT", check,
			fmt.Sprintf("%d uncorrected ECC memory error(s) — hardware RAM fault", uncorrected),
			[]string{"to inspect: edac-util -s 4", "to diagnose: run memtest86+ and check which DIMM"})}
	case corrected > 100:
		return []models.Insight{insight("WARN", check,
			fmt.Sprintf("%d corrected ECC memory error(s) — RAM degrading", corrected),
			[]string{"to inspect: edac-util -s 4", "note: rising corrected-error counts often precede an uncorrectable fault"})}
	}
	return nil
}

func checkDisk(disk models.DiskInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	for _, fs := range disk.Filesystems {
		if l := levelPct(fs.UsedPct, thresh.DiskWarnPct, thresh.DiskCritPct); l != "" {
			hints := []string{"to inspect: df -h", fmt.Sprintf("to inspect: du -sh %s/* 2>/dev/null | sort -h | tail -20", fs.Mount)}
			// /boot filling up is almost always old kernel images after upgrades.
			// Show distro-specific cleanup command based on detected package manager.
			if fs.Mount == "/boot" {
				bootHints := []string{
					"to inspect: df -h /boot",
					"to inspect: ls -lh /boot/vmlinuz* /boot/initramfs* /boot/initrd*",
				}
				switch thresh.PackageManager {
				case "dnf":
					bootHints = append(bootHints,
						"to inspect: rpm -q kernel",
						"to fix:     dnf remove --oldinstallonly --setopt installonly_limit=2",
					)
				case "apt":
					bootHints = append(bootHints,
						"to fix: apt autoremove --purge",
					)
				case "zypper":
					bootHints = append(bootHints,
						"to fix: zypper packages --orphaned | grep kernel",
					)
				case "pacman":
					bootHints = append(bootHints,
						"to inspect: pacman -Q linux",
						"to fix:     pacman -R <old-kernel-packages>",
					)
				default:
					// Unknown package manager — show all options
					bootHints = append(bootHints,
						"to fix (dnf):    dnf remove --oldinstallonly --setopt installonly_limit=2",
						"to fix (apt):    apt autoremove --purge",
						"to fix (zypper): zypper packages --orphaned | grep kernel",
						"to fix (pacman): pacman -Q linux  # then pacman -R <old-kernels>",
					)
				}
				hints = bootHints
			}
			out = append(out, insight(l, "Disk",
				fmt.Sprintf("disk usage at %.0f%% on %s (%s)", fs.UsedPct, fs.Mount, fs.Device),
				hints,
			))
		}
		if l := levelPct(fs.InodesUsedPct, thresh.DiskWarnPct, thresh.DiskCritPct); l != "" {
			out = append(out, insight(l, "Disk",
				fmt.Sprintf("inode usage at %.0f%% on %s", fs.InodesUsedPct, fs.Mount),
				[]string{"to inspect: df -i", fmt.Sprintf("to inspect: find %s -xdev -printf '%%h\\n' | sort | uniq -c | sort -rn | head -20", fs.Mount)},
			))
		}
		// A writable on-disk filesystem mounted read-only is almost always an
		// error remount: the kernel hit I/O or metadata errors and dropped the fs
		// to ro to prevent further damage, so apps silently fail to write. dsd
		// captured this but never surfaced it (a serious missed condition). The
		// on-disk-fstype allowlist avoids flagging inherently/intentionally ro
		// mounts (squashfs, iso9660, overlay, ro bind mounts).
		if fs.ReadOnly && isWritableOnDiskFS(fs.FSType) {
			out = append(out, insight("WARN", "Disk",
				fmt.Sprintf("filesystem %s (%s on %s) is mounted READ-ONLY — if it should be writable, the kernel likely remounted it after an I/O error", fs.Mount, fs.FSType, fs.Device),
				[]string{
					"to inspect: dmesg | grep -iE 'remount|i/o error|ext4-fs error|xfs.*(error|corrupt)|btrfs.*error'",
					fmt.Sprintf("to inspect: mount | grep ' %s '", fs.Mount),
					fmt.Sprintf("after fixing the cause: mount -o remount,rw %s", fs.Mount),
					"note: intentionally read-only mounts (immutable OS, ro bind mounts) can ignore this",
				},
			))
		}
	}
	out = append(out, checkDiskExtras(disk)...)
	return out
}

// isWritableOnDiskFS reports whether a filesystem type is a normal read-write
// on-disk filesystem (so being mounted read-only is suspicious). Allowlist, not
// denylist, so squashfs/iso9660/overlay/tmpfs/etc. never trip the ro check.
func isWritableOnDiskFS(fsType string) bool {
	switch fsType {
	case "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs":
		return true
	}
	return false
}

// checkBtrfsVolume turns one btrfs volume's health into insights: missing devices
// are a DEGRADED CRIT; read/write I/O errors are a failing-device CRIT (not
// scrub-correctable); corruption/checksum errors alone are a WARN (often
// scrub-correctable).
func checkBtrfsVolume(v models.BtrfsVolume) []models.Insight {
	if v.MissingDevs > 0 {
		return []models.Insight{insight("CRIT", "Disk",
			fmt.Sprintf("btrfs %s is DEGRADED — %d missing device(s), data at risk", v.MountPoint, v.MissingDevs),
			[]string{
				fmt.Sprintf("to inspect: btrfs filesystem show %s", v.MountPoint),
				fmt.Sprintf("to inspect: btrfs device stats %s", v.MountPoint),
				"to fix:     reattach missing device and run: btrfs device scan",
			},
		)}
	}
	if v.Status != "errors" {
		return nil
	}

	var ioErrs, corruptErrs int64
	for _, d := range v.Devices {
		ioErrs += d.ReadErrs + d.WriteErrs
		corruptErrs += d.CorruptErrs
	}
	if ioErrs > 0 {
		// Read/write I/O errors mean the underlying device is failing (bad blocks,
		// cabling, controller) — not scrub-correctable. CRIT.
		return []models.Insight{insight("CRIT", "Disk",
			fmt.Sprintf("btrfs %s has %d device I/O error(s) — failing storage or cabling", v.MountPoint, ioErrs),
			[]string{
				fmt.Sprintf("to inspect: btrfs device stats %s", v.MountPoint),
				"to inspect: dmesg | grep -i 'btrfs\\|i/o error'",
				"note: back up data now — I/O errors are not scrub-correctable",
			},
		)}
	}
	// Corruption/checksum errors only — often correctable via scrub. WARN.
	return []models.Insight{insight("WARN", "Disk",
		fmt.Sprintf("btrfs %s has %d checksum/corruption error(s) — may be scrub-correctable", v.MountPoint, corruptErrs),
		[]string{
			fmt.Sprintf("to inspect: btrfs device stats %s", v.MountPoint),
			fmt.Sprintf("to fix:     btrfs scrub start %s  (check for correctable errors)", v.MountPoint),
		},
	)}
}

func checkDiskExtras(disk models.DiskInfo) []models.Insight {
	var out []models.Insight
	if disk.SteamOS != nil {
		out = append(out, checkSteamOSDisk(disk.SteamOS)...)
	}
	// SMART health
	for _, d := range disk.Drives {
		if d.SMART == nil || d.SMART.Error != "" {
			continue
		}
		if !d.SMART.Healthy {
			out = append(out, insight("CRIT", "Disk",
				fmt.Sprintf("%s SMART health FAILED — drive may be failing, back up immediately", d.Name),
				[]string{
					fmt.Sprintf("to inspect: smartctl -a /dev/%s", d.Name),
					"to inspect: dmesg | grep -i 'error\\|failed\\|reset'",
				},
			))
		} else if d.SMART.PercentUsed >= 90 {
			out = append(out, insight("WARN", "Disk",
				fmt.Sprintf("%s NVMe wear at %d%% — drive approaching end of life", d.Name, d.SMART.PercentUsed),
				[]string{fmt.Sprintf("to inspect: smartctl -A /dev/%s", d.Name)},
			))
		} else if d.SMART.MediaErrors > 0 {
			out = append(out, insight("WARN", "Disk",
				fmt.Sprintf("%s has %d media error(s) — monitor closely", d.Name, d.SMART.MediaErrors),
				[]string{fmt.Sprintf("to inspect: smartctl -a /dev/%s", d.Name)},
			))
		}
	}
	// btrfs volume health — missing devices are a silent CRIT
	for _, v := range disk.BtrfsVolumes {
		out = append(out, checkBtrfsVolume(v)...)
	}
	// ZFS pool health
	for _, p := range disk.ZFSPools {
		switch p.State {
		case "DEGRADED":
			out = append(out, insight("CRIT", "Disk",
				fmt.Sprintf("ZFS pool %s is DEGRADED — data protection compromised", p.Name),
				[]string{
					fmt.Sprintf("to inspect: zpool status %s", p.Name),
					fmt.Sprintf("to fix:     zpool online %s <device>  (if device is available)", p.Name),
				},
			))
		case "FAULTED", "OFFLINE":
			out = append(out, insight("CRIT", "Disk",
				fmt.Sprintf("ZFS pool %s is %s — pool may be inaccessible", p.Name, p.State),
				[]string{fmt.Sprintf("to inspect: zpool status %s", p.Name)},
			))
		}
		if ins, ok := zfsVdevErrorInsight(p, "Disk"); ok {
			out = append(out, ins)
		}
		if p.ScrubAgeDays < 0 {
			out = append(out, insight("INFO", "Disk",
				fmt.Sprintf("ZFS pool %s has never been scrubbed — schedule regular scrubs", p.Name),
				[]string{fmt.Sprintf("to fix: zpool scrub %s", p.Name)},
			))
		} else if p.ScrubAgeDays > 30 {
			out = append(out, insight("INFO", "Disk",
				fmt.Sprintf("ZFS pool %s last scrubbed %d days ago — consider running scrub", p.Name, p.ScrubAgeDays),
				[]string{fmt.Sprintf("to fix: zpool scrub %s", p.Name)},
			))
		}
	}
	return out
}

func checkSwap(swap models.SwapInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	if swap.MemPressureLevel > 0 {
		if swap.MemPressureLevel > 1 {
			if l := levelPct(swap.UsedPct, 75, 90); l != "" {
				out = append(out, insight(l, "Swap",
					fmt.Sprintf("swap usage at %.0f%% with elevated memory pressure (level %d)", swap.UsedPct, swap.MemPressureLevel),
					[]string{"to inspect: vm_stat | grep swap", "to inspect: sysctl vm.swapusage", "to inspect: top -l 1 | grep PhysMem"},
				))
			}
		}
		return out
	}
	if l := levelPct(swap.UsedPct, thresh.SwapWarnPct, thresh.SwapCritPct); l != "" {
		out = append(out, insight(l, "Swap",
			fmt.Sprintf("swap usage at %.0f%% (%.1f GB used)", swap.UsedPct, swap.UsedGB),
			[]string{"to inspect: free -h", "to inspect: vmstat 1 5"},
		))
	}
	actIn, actOut := swap.PagesInPerSec, swap.PagesOutPerSec
	maxAct := actIn
	if actOut > maxAct {
		maxAct = actOut
	}
	switch {
	case maxAct > thresh.SwapActivityCrit:
		// Heavy sustained paging warrants a CRIT even on zram: at this rate the
		// (de)compression CPU cost and the memory shortfall it implies both bite.
		out = append(out, insight("CRIT", "Swap",
			fmt.Sprintf("heavy swap activity: %.0f pages/s in, %.0f pages/s out", actIn, actOut),
			[]string{"to inspect: vmstat 1 5", "to inspect: sar -W 1 5", "to inspect: ps aux --sort=-%mem | head -10"},
		))
	case maxAct > thresh.SwapActivityWarn && swap.ZramDevices > 0:
		// zram-backed swap is compressed RAM, not disk. Moderate paging is normal
		// on zram-by-default distros (Fedora/Ubuntu/Pop!_OS/SteamOS) and is not the
		// latency cliff a disk-swap WARN implies — report it as context, not a fault.
		out = append(out, insight("INFO", "Swap",
			fmt.Sprintf("swap activity: %.0f pages/s in, %.0f pages/s out — zram-backed (compressed RAM, not disk thrash)", actIn, actOut),
			[]string{"to inspect: zramctl", "to inspect: vmstat 1 5"},
		))
	case maxAct > thresh.SwapActivityWarn:
		out = append(out, insight("WARN", "Swap",
			fmt.Sprintf("swap activity detected: %.0f pages/s in, %.0f pages/s out", actIn, actOut),
			[]string{"to inspect: vmstat 1 5", "to inspect: free -h"},
		))
	}
	return out
}

func checkIO(io models.IOInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	saturatedCount := 0
	for _, dev := range io.Devices {
		warnUtil, critUtil := ioUtilThresholds(dev.DriveType, thresh)
		warnAwait, critAwait := ioAwaitThresholds(dev.DriveType, thresh)

		if l := levelPct(dev.UtilPct, warnUtil, critUtil); l != "" {
			hints := []string{"to inspect: iostat -x 1 5", "to inspect: iotop -ao"}
			// Item 6: 100% util with btrfs-cleaner note
			if dev.UtilPct >= 99 {
				hints = append(hints,
					"note: 100% utilization on NVMe/SSD is abnormal — check for runaway process",
					"note: if filesystem is BTRFS, btrfs-cleaner may be the cause",
					"to check: ps aux | grep btrfs",
					"to pause btrfs maintenance: btrfs balance cancel / && btrfs scrub cancel /",
				)
				saturatedCount++
			}
			out = append(out, insight(l, "IO",
				fmt.Sprintf("disk %s utilization at %.0f%%", dev.Name, dev.UtilPct),
				hints,
			))
		}
		if l := levelPct(dev.AwaitMs, warnAwait, critAwait); l != "" {
			out = append(out, insight(l, "IO",
				fmt.Sprintf("disk %s await latency %.1f ms", dev.Name, dev.AwaitMs),
				[]string{"to inspect: iostat -x 1 5", "to inspect: iotop -ao"},
			))
		}
	}

	// Item 5: multiple drives showing errors → shared component hint.
	// Research: "4 disks with identical errors — unlikely all DOA, check the HBA"
	// When 3+ drives are saturated simultaneously, the common failure point is the
	// controller, backplane, or cable — not the drives themselves.
	if saturatedCount >= 3 {
		out = append(out, insight("WARN", "IO",
			fmt.Sprintf("%d drives at 100%% utilization simultaneously — may indicate shared component fault", saturatedCount),
			[]string{
				"note: multiple drives failing together often points to HBA, backplane, or cable",
				"to inspect: lspci | grep -i storage",
				"to inspect: dmesg | grep -E 'ata[0-9]+|scsi|hba'",
				"to inspect: check backplane power and data cables",
				"to inspect: smartctl -a /dev/<each drive>  (check if errors are identical)",
			},
		))
	}

	return out
}

// ioAwaitThresholds returns WARN and CRIT await thresholds based on drive type.
// ioUtilThresholds returns the %util WARN/CRIT thresholds for a drive type.
// %util is the fraction of time the device had ≥1 request in flight — for a
// spinning HDD that sits at 80–100% during any normal sequential workload
// (backups, large copies) because an HDD serialises requests. So util-based
// alerting is a false positive on HDDs; their saturation is caught by AWAIT
// (latency) instead, which ioAwaitThresholds scales correctly. Returning
// thresholds above 100 disables util alerting for HDDs while leaving the
// await check to do the real work. SSD/NVMe keep the SSD thresholds (100%
// util genuinely is abnormal there).
func ioUtilThresholds(driveType string, thresh Thresholds) (warn, crit float64) {
	if driveType == "hdd" {
		return 101, 101 // never fires — await is the HDD saturation signal
	}
	return thresh.IOUtilWarnPctSSD, thresh.IOUtilCritPctSSD
}

func ioAwaitThresholds(driveType string, thresh Thresholds) (warn, crit float64) {
	switch driveType {
	case "nvme":
		return 5.0, 15.0
	case "hdd":
		return 50.0, 100.0
	default: // ssd, unknown
		return thresh.IOAwaitWarnMsSSD, thresh.IOAwaitCritMsSSD
	}
}

// IsPVEServicePort reports whether a port is a mandatory Proxmox VE service
// port: 8006 (web UI), 3128 (spiceproxy), or 111 (rpcbind/portmapper).
// Exported as the single source of truth — cmd/security.go consumes it so the
// {8006, 3128, 111} set is not duplicated across packages.
func IsPVEServicePort(port int) bool {
	switch port {
	case 8006, 3128, 111:
		return true
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// cpuDeepSaturationLoadFloorPct mirrors the default CPU load warn multiplier
// (0.7): below this load-average ratio the box is not under sustained pressure,
// so a per-core "all saturated" reading is dsd's own collection overhead.
const cpuDeepSaturationLoadFloorPct = 70.0

// healthDeepLoadCorroborates reports whether the 1-minute load average confirms
// the per-core saturation reading. A genuinely idle box reads load 0.00, which
// is valid data (not "unavailable"), so it correctly returns false — there is
// no sustained saturation to lose.
func healthDeepLoadCorroborates(d models.HealthDeepInfo) bool {
	if d.NumCPU <= 0 {
		return false
	}
	return (d.LoadAvg1/float64(d.NumCPU))*100 >= cpuDeepSaturationLoadFloorPct
}

func checkHealthDeep(d models.HealthDeepInfo) []models.Insight {
	var out []models.Insight

	// Core imbalance — one thread bottleneck
	if d.CoreImbalance >= 80 && len(d.Cores) > 1 {
		// Find the hot core
		hotCore := 0
		for _, c := range d.Cores {
			if c.UsagePct == d.MaxCorePct {
				hotCore = c.Core
				break
			}
		}
		out = append(out, insight("WARN", "CPUDeep",
			fmt.Sprintf("CPU core imbalance: core%d at %.0f%% while others average %.0f%% — single-threaded bottleneck",
				hotCore, d.MaxCorePct, d.MinCorePct),
			[]string{
				"to inspect: mpstat -P ALL 1 3",
				"to inspect: ps aux --sort=-%cpu | head -10",
			},
		))
	} else if d.MaxCorePct >= 95 && len(d.Cores) > 1 && healthDeepLoadCorroborates(d) {
		// All cores pegged. Per-core %s are sampled while dsd's own deep
		// collection runs, which can peg every core on a small host and read a
		// false 100%. The 1-minute load average predates this run and is immune,
		// so only fire when it confirms sustained saturation. (The imbalance
		// branch above needs no such guard: dsd's load spreads across cores, so
		// it produces low imbalance, not a hot single core.)
		out = append(out, insight("WARN", "CPUDeep",
			fmt.Sprintf("all CPU cores near saturation (max: %.0f%%, min: %.0f%%)", d.MaxCorePct, d.MinCorePct),
			[]string{"to inspect: mpstat -P ALL 1 3"},
		))
	}

	// Dirty pages — large write backlog risks data loss on crash
	if d.DirtyMB >= 500 {
		out = append(out, insight("WARN", "CPUDeep",
			fmt.Sprintf("%.0f MB of dirty pages pending write-back — data loss risk on crash", d.DirtyMB),
			[]string{
				"to inspect: cat /proc/meminfo | grep Dirty",
				"to inspect: iostat -x 1 5",
			},
		))
	}

	// cgroup v2 slice health
	if d.Cgroup != nil {
		out = append(out, checkCgroupV2(*d.Cgroup)...)
	}

	return out
}

// checkHardware evaluates physical hardware health from SMART, hwmon, and EDAC.
func checkHardware(h models.HardwareInfo) []models.Insight { //nolint:cyclop,funlen // flat independent hardware checks — splitting would harm readability
	var out []models.Insight

	// ── Drive health ──────────────────────────────────────────────────────────
	for _, d := range h.Drives {
		if !d.SmartctlAvailable {
			out = append(out, insight("INFO", "Hardware",
				"smartctl not installed — drive health unavailable",
				[]string{"to fix: install smartmontools (apt/dnf/zypper install smartmontools)"},
			))
			continue // skip this drive only — EDAC/ECC checks below are independent of smartctl
		}
		if d.Error != "" {
			out = append(out, insight("WARN", "Hardware",
				fmt.Sprintf("%s: %s", d.Device, d.Error),
				nil,
			))
			continue
		}

		prefix := d.Device
		if d.Model != "" {
			prefix = fmt.Sprintf("%s (%s)", d.Device, d.Model)
		}

		// SMART overall. Only a drive that actually reported a verdict can FAIL it;
		// a detected-but-unread drive (controller/USB bridge/virtual disk emits
		// JSON with no smart_status) must not be called failing — that was a false
		// CRIT ("back up immediately") on healthy drives.
		switch {
		case !d.SmartRead:
			out = append(out, insight("INFO", "Hardware",
				fmt.Sprintf("%s — SMART health not reported (behind a RAID/HBA controller or USB bridge, or a virtual disk)", prefix),
				[]string{"to inspect: smartctl -a " + d.Device + "  (try -d sat / -d cciss,N)"},
			))
		case !d.SmartOK:
			out = append(out, insight("CRIT", "Hardware",
				fmt.Sprintf("%s — SMART FAILED: drive may fail imminently, back up immediately", prefix),
				[]string{
					"to inspect: smartctl -a " + d.Device,
					"to run self-test: smartctl -t short " + d.Device,
				},
			))
		}

		// Drive temperature
		switch {
		case d.Type == "nvme" && d.TempC >= 80:
			out = append(out, insight("CRIT", "Hardware",
				fmt.Sprintf("%s temperature %d°C — NVMe critical thermal threshold", prefix, d.TempC),
				[]string{"to inspect: smartctl -a " + d.Device},
			))
		case d.Type == "nvme" && d.TempC >= 70:
			out = append(out, insight("WARN", "Hardware",
				fmt.Sprintf("%s temperature %d°C — NVMe running hot", prefix, d.TempC),
				[]string{"to inspect: smartctl -a " + d.Device},
			))
		case d.Type != "nvme" && d.TempC >= 60:
			out = append(out, insight("CRIT", "Hardware",
				fmt.Sprintf("%s temperature %d°C — HDD critical thermal threshold", prefix, d.TempC),
				[]string{"to inspect: smartctl -a " + d.Device},
			))
		case d.Type != "nvme" && d.TempC >= 50:
			out = append(out, insight("WARN", "Hardware",
				fmt.Sprintf("%s temperature %d°C — HDD running hot", prefix, d.TempC),
				[]string{"to inspect: smartctl -a " + d.Device},
			))
		}

		// Wear / endurance
		switch {
		case d.WearPct >= 95:
			out = append(out, insight("CRIT", "Hardware",
				fmt.Sprintf("%s wear at %d%% — drive near end of rated life, replace soon", prefix, d.WearPct),
				[]string{"to plan: schedule drive replacement"},
			))
		case d.WearPct >= 80:
			out = append(out, insight("WARN", "Hardware",
				fmt.Sprintf("%s wear at %d%% — approaching end of rated endurance", prefix, d.WearPct),
				[]string{"to plan: schedule drive replacement"},
			))
		}

		// SATA bad sectors
		if d.ReallocatedSectors > 0 {
			level := "WARN"
			if d.ReallocatedSectors >= 10 {
				level = "CRIT"
			}
			out = append(out, insight(level, "Hardware",
				fmt.Sprintf("%s: %d reallocated sector(s) — drive remapping failed reads", prefix, d.ReallocatedSectors),
				[]string{
					"to inspect: smartctl -a " + d.Device,
					"to test: smartctl -t long " + d.Device,
				},
			))
		}
		if d.PendingSectors > 0 {
			level := "WARN"
			if d.PendingSectors >= 5 {
				level = "CRIT"
			}
			out = append(out, insight(level, "Hardware",
				fmt.Sprintf("%s: %d pending sector(s) — unreadable sectors awaiting remap", prefix, d.PendingSectors),
				[]string{"to inspect: smartctl -a " + d.Device},
			))
		}
		if d.UncorrectableErrors > 0 {
			out = append(out, insight("CRIT", "Hardware",
				fmt.Sprintf("%s: %d offline uncorrectable sector(s) — data loss risk", prefix, d.UncorrectableErrors),
				[]string{
					"to inspect: smartctl -a " + d.Device,
					"to rescue: back up immediately",
				},
			))
		}

		// NVMe media errors
		if d.MediaErrors > 0 {
			level := "WARN"
			if d.MediaErrors >= 10 {
				level = "CRIT"
			}
			out = append(out, insight(level, "Hardware",
				fmt.Sprintf("%s: %d media error(s) — NVMe data integrity events", prefix, d.MediaErrors),
				[]string{"to inspect: smartctl -a " + d.Device},
			))
		}

		// Healthy drive — emit OK so it shows in output
		healthy := len(out) == 0 || func() bool {
			for _, i := range out {
				if i.Check == "Hardware" && strings.HasPrefix(i.Message, prefix) {
					return false
				}
			}
			return true
		}()
		if healthy {
			msg := fmt.Sprintf("%s — SMART OK", prefix)
			if d.TempC > 0 {
				msg += fmt.Sprintf(", %d°C", d.TempC)
			}
			if d.PowerOnH > 0 {
				msg += fmt.Sprintf(", %d h", d.PowerOnH)
			}
			if d.WearPct > 0 {
				msg += fmt.Sprintf(", %d%% worn", d.WearPct)
			}
			out = append(out, insight("OK", "Hardware", msg, nil))
		}
	}

	// ── EDAC memory ───────────────────────────────────────────────────────────
	if h.Memory.EDACAvailable {
		out = append(out, eccInsights(h.Memory.CorrectedErrors, h.Memory.UncorrectedErrors, "Hardware")...)
	}

	return out
}

// containsStr returns true if s is in the slice ss.
func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// ── New heuristics: Bonding, IPMI, OOM, HBA, Pressure, Multipath ──────────

func checkBonding(b models.BondingInfo) []models.Insight {
	if len(b.Bonds) == 0 {
		return nil
	}
	var out []models.Insight
	for _, bond := range b.Bonds {
		// Single-slave bond — no redundancy
		if len(bond.Slaves) < 2 {
			out = append(out, insight("WARN", "Bonding",
				fmt.Sprintf("%s has only 1 slave — no redundancy (second NIC missing or disconnected)", bond.Name),
				[]string{
					fmt.Sprintf("to inspect: cat /proc/net/bonding/%s", bond.Name),
					"to inspect: ip link show",
					"note:       bonding provides no benefit with a single slave",
				},
			))
		}
		if bond.DownSlaves == 0 {
			// Healthy — check for USB slaves as a reliability advisory
			for _, s := range bond.Slaves {
				if isUSBNetworkInterface(s.Name) {
					out = append(out, insight("INFO", "Bonding",
						fmt.Sprintf("%s: slave %s is a USB NIC — USB adapters are less reliable than PCIe NICs for production bonding (can be unplugged, USB bus is a single point of failure)",
							bond.Name, s.Name),
						[]string{
							"note: consider replacing with a PCIe or onboard NIC for production HA",
							fmt.Sprintf("to inspect: readlink /sys/class/net/%s/device/subsystem", s.Name),
						},
					))
				}
			}
			continue
		}
		if bond.DownSlaves == len(bond.Slaves) {
			out = append(out, insight("CRIT", "Bonding",
				fmt.Sprintf("%s: all %d slaves down — bond is completely failed", bond.Name, bond.DownSlaves),
				[]string{
					fmt.Sprintf("to inspect: cat /proc/net/bonding/%s", bond.Name),
					"to inspect: ip link show",
				},
			))
		} else {
			out = append(out, insight("WARN", "Bonding",
				fmt.Sprintf("%s: %d/%d slave(s) down (%s mode) — running degraded",
					bond.Name, bond.DownSlaves, len(bond.Slaves), bond.ModeShort),
				[]string{
					fmt.Sprintf("to inspect: cat /proc/net/bonding/%s", bond.Name),
					"to inspect: ip link show",
					"to inspect: ethtool <slave-interface>",
				},
			))
		}
		// Surface individual down slaves
		for _, s := range bond.Slaves {
			if s.State == "down" {
				out = append(out, insight("INFO", "Bonding",
					fmt.Sprintf("%s: slave %s is down (MII: %s)", bond.Name, s.Name, s.MIIStatus),
					[]string{
						fmt.Sprintf("to inspect: ethtool %s", s.Name),
						fmt.Sprintf("to inspect: ip link show %s", s.Name),
					},
				))
			}
		}
		// High link failures on any slave
		for _, s := range bond.Slaves {
			if s.LinkFails > 10 {
				out = append(out, insight("WARN", "Bonding",
					fmt.Sprintf("%s: slave %s has %d link failures — check cable or switch port",
						bond.Name, s.Name, s.LinkFails),
					[]string{fmt.Sprintf("to inspect: ethtool %s", s.Name)},
				))
			}
		}
	}
	return out
}

// isUSBNetworkInterface returns true if the network interface is USB-based.
// Checks /sys/class/net/<iface>/device/subsystem symlink for "usb".
func isUSBNetworkInterface(iface string) bool {
	subsystem, err := os.Readlink(fmt.Sprintf("/sys/class/net/%s/device/subsystem", iface))
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(subsystem), "usb")
}

func checkIPMI(ipmi models.IPMIInfo) []models.Insight {
	// IPMI hardware is present (the collector is gated on /dev/ipmi*) but the
	// sensor read failed — surface it rather than stay silent. The collector sets
	// Status="error" with Available=false here; returning nil on !Available alone
	// hid a BMC/sensor read failure on a server that has IPMI.
	if ipmi.Status == "error" {
		reason := ipmi.StatusReason
		if reason == "" {
			reason = "IPMI sensor read failed"
		}
		return []models.Insight{insight("WARN", "IPMI", reason,
			[]string{
				"to inspect: ipmitool sdr",
				"to inspect: ipmitool sel list | tail -20",
				"note: check BMC access — kernel module ipmi_devintf and /dev/ipmi0 permissions",
			})}
	}
	if !ipmi.Available {
		return nil
	}
	var out []models.Insight
	if ipmi.PSUFailed > 0 {
		out = append(out, insight("CRIT", "IPMI",
			fmt.Sprintf("%d PSU(s) in fault state — risk of host going offline", ipmi.PSUFailed),
			[]string{
				"to inspect: ipmitool sdr type 'Power Supply'",
				"to inspect: ipmitool sel list | tail -20",
				"note: replace failed PSU before removing redundant one",
			},
		))
	}
	if ipmi.FanFailed > 0 {
		out = append(out, insight("WARN", "IPMI",
			fmt.Sprintf("%d fan(s) in fault state — thermal risk", ipmi.FanFailed),
			[]string{
				"to inspect: ipmitool sdr type Fan",
				"to inspect: ipmitool sel list | tail -20",
			},
		))
	}
	if ipmi.TempCritical > 0 {
		out = append(out, insight("CRIT", "IPMI",
			fmt.Sprintf("%d temperature sensor(s) in critical state", ipmi.TempCritical),
			[]string{
				"to inspect: ipmitool sdr type Temperature",
				"to inspect: check airflow and fan operation",
			},
		))
	}
	return out
}

func checkOOM(oom models.OOMInfo) []models.Insight {
	if oom.EventsLast24h == 0 {
		return nil
	}
	var victims []string
	seen := map[string]bool{}
	for _, ev := range oom.RecentEvents {
		if !seen[ev.Process] {
			seen[ev.Process] = true
			victims = append(victims, ev.Process)
		}
	}
	msg := fmt.Sprintf("%d OOM kill event(s) in the last 24h", oom.EventsLast24h)
	if len(victims) > 0 {
		msg += fmt.Sprintf(" — killed: %s", strings.Join(victims, ", "))
	}
	// CRIT, not WARN: an OOM kill is a real failure (a process was killed). The
	// logs path already CRITs on OOM kills in the last hour; this 24h-window path
	// must agree, else a kill 60+ min ago would only WARN and exit 1 not 2.
	return []models.Insight{insight("CRIT", "OOM",
		msg,
		[]string{
			"to inspect: journalctl -k | grep -i 'oom\\|killed process'",
			"to inspect: dmesg | grep -i 'out of memory'",
			"to inspect: free -h",
			"to inspect: ps aux --sort=-%mem | head -10",
			"note: OOM kills are silent — services may restart without apparent cause",
		},
	)}
}

func checkHBA(hba models.HBAInfo) []models.Insight {
	if len(hba.Ports) == 0 {
		return nil
	}
	var out []models.Insight
	for _, p := range hba.Ports {
		state := strings.ToLower(p.PortState)
		switch {
		case state == "":
			// port_state was unreadable (sysfs read failed). Don't whitelist it as
			// healthy — the inline renderer already counts it as not-online, so a
			// silent OK here was a sibling-divergence false-OK. Surface it as unknown.
			out = append(out, insight("WARN", "HBA",
				fmt.Sprintf("FC port %s state could not be read — storage path health unknown", p.Name),
				[]string{
					"to inspect: cat /sys/class/fc_host/" + p.Name + "/port_state",
					"to inspect: systool -c fc_host -v",
				},
			))
		case state != "online" && state != "linkup":
			out = append(out, insight("CRIT", "HBA",
				fmt.Sprintf("FC port %s is %s — storage path lost", p.Name, p.PortState),
				[]string{
					"to inspect: cat /sys/class/fc_host/" + p.Name + "/port_state",
					"to inspect: systool -c fc_host -v",
					"note: check SFP cable, switch zoning, and target port",
				},
			))
		}
		if p.LinkFailures > 0 || p.LossOfSync > 100 {
			out = append(out, insight("WARN", "HBA",
				fmt.Sprintf("FC port %s: %d link failures, %d loss-of-sync — check fibre and SFP",
					p.Name, p.LinkFailures, p.LossOfSync),
				[]string{
					"to inspect: cat /sys/class/fc_host/" + p.Name + "/statistics/link_failure_count",
					"to inspect: check SFP module and fibre cable",
				},
			))
		}
	}
	return out
}

func checkPressure(p models.PressureInfo) []models.Insight {
	if !p.Available {
		return nil
	}
	var out []models.Insight
	// Memory full stall > 10% in last 60s is severe
	if p.MemoryFull.Avg60 >= 10 {
		out = append(out, insight("CRIT", "Pressure",
			fmt.Sprintf("memory full stall %.1f%% avg60 — tasks blocked waiting for memory", p.MemoryFull.Avg60),
			[]string{
				"to inspect: cat /proc/pressure/memory",
				"to inspect: free -h",
				"to inspect: ps aux --sort=-%mem | head -10",
				"note: OOM kill may be imminent — act now",
			},
		))
	} else if p.MemorySome.Avg60 >= 20 {
		out = append(out, insight("WARN", "Pressure",
			fmt.Sprintf("memory pressure %.1f%% avg60 — some tasks delayed waiting for memory", p.MemorySome.Avg60),
			[]string{
				"to inspect: cat /proc/pressure/memory",
				"to inspect: free -h",
			},
		))
	}
	// IO full stall > 5% in last 60s
	if p.IOFull.Avg60 >= 5 {
		out = append(out, insight("WARN", "Pressure",
			fmt.Sprintf("IO full stall %.1f%% avg60 — all tasks blocked on disk IO", p.IOFull.Avg60),
			[]string{
				"to inspect: cat /proc/pressure/io",
				"to inspect: iostat -x 1 5",
				"to inspect: iotop -ao",
			},
		))
	}
	// CPU stall > 30% in last 60s (some stall, not full — CPU is never "full" stalled)
	if p.CPUSome.Avg60 >= 30 {
		out = append(out, insight("WARN", "Pressure",
			fmt.Sprintf("CPU pressure %.1f%% avg60 — tasks waiting for CPU time", p.CPUSome.Avg60),
			[]string{
				"to inspect: cat /proc/pressure/cpu",
				"to inspect: uptime",
				"to inspect: ps aux --sort=-%cpu | head -10",
			},
		))
	}
	return out
}

func checkMultipath(m models.MultipathInfo) []models.Insight {
	if !m.Available || len(m.Devices) == 0 {
		return nil
	}
	var out []models.Insight
	for _, dev := range m.Devices {
		if dev.FailedPaths == 0 {
			continue
		}
		if dev.ActivePaths == 0 {
			out = append(out, insight("CRIT", "Multipath",
				fmt.Sprintf("%s (%s): all paths failed — device unavailable", dev.Name, dev.DM),
				[]string{
					"to inspect: multipathd show paths",
					"to inspect: multipath -l",
					"to inspect: check SAN fabric and HBA",
				},
			))
		} else {
			out = append(out, insight("WARN", "Multipath",
				fmt.Sprintf("%s (%s): %d/%d paths failed — running degraded",
					dev.Name, dev.DM, dev.FailedPaths, dev.TotalPaths),
				[]string{
					"to inspect: multipathd show paths",
					"to inspect: multipath -l",
					fmt.Sprintf("to inspect: cat /sys/block/%s/dm/state", dev.DM),
					"note: replace failed path before removing redundant one",
				},
			))
		}
	}
	return out
}

// ── Medium priority: Ceph, Firewall, Auth, CloudMeta, Auditd ──────────────
// ── Low priority: NUMA, VLAN, iSCSI, InfiniBand, SR-IOV, Nspawn ──────────

func checkCeph(c models.CephInfo) []models.Insight {
	if !c.Available {
		// Configured for a cluster but `ceph health` failed → the cluster is
		// unreachable from a node that's part of it. That's a real outage and must
		// surface, not be silently gated off like a bare client binary.
		if c.Configured {
			return []models.Insight{insight("CRIT", "Ceph",
				"Ceph cluster unreachable — node is configured for a cluster but `ceph health` failed",
				[]string{
					"to inspect: ceph -s   (or: ceph health detail)",
					"to check mons: systemctl status ceph-mon.target",
					"note: a stuck/unreachable mon quorum freezes all RBD/CephFS I/O",
				})}
		}
		return nil
	}
	switch c.Health {
	case "HEALTH_ERR":
		msg := "Ceph cluster health is ERROR"
		if len(c.Summary) > 0 {
			msg = "Ceph: " + c.Summary[0]
		}
		return []models.Insight{insight("CRIT", "Ceph", msg,
			[]string{"to inspect: ceph health detail", "to inspect: ceph osd tree"})}
	case "HEALTH_WARN":
		msg := "Ceph cluster health is WARN"
		if len(c.Summary) > 0 {
			msg = "Ceph: " + c.Summary[0]
		}
		return []models.Insight{insight("WARN", "Ceph", msg,
			[]string{"to inspect: ceph health detail", "to inspect: ceph osd stat"})}
	case "HEALTH_UNKNOWN":
		// `ceph health detail` ran but returned no parseable status — surface that
		// rather than letting an empty Health read as a healthy cluster.
		return []models.Insight{insight("WARN", "Ceph",
			"Ceph cluster health could not be read — `ceph health detail` returned no parseable status",
			[]string{"to inspect: ceph health detail", "to inspect: ceph -s"})}
	}
	downOSDs := c.OSDTotal - c.OSDUp
	if downOSDs > 0 {
		return []models.Insight{insight("WARN", "Ceph",
			fmt.Sprintf("%d OSD(s) down (%d/%d up)", downOSDs, c.OSDUp, c.OSDTotal),
			[]string{"to inspect: ceph osd tree", "to inspect: ceph osd stat"})}
	}
	return nil
}

func checkFirewall(f models.FirewallInfo) []models.Insight {
	if !f.Available {
		return nil
	}
	if !f.Active || f.TotalRules == 0 {
		// On Proxmox VE, pve-firewall manages the host firewall and loads its
		// rules dynamically — an empty base ruleset is expected (see BUG-017).
		if f.PVEFirewallActive {
			return []models.Insight{insight("INFO", "Firewall",
				"PVE firewall active (pve-firewall) — host firewall managed by Proxmox",
				[]string{"to inspect: pve-firewall status", "to inspect: cat /etc/pve/firewall/cluster.fw"},
			)}
		}
		return []models.Insight{insight("WARN", "Firewall",
			fmt.Sprintf("%s is installed but no rules are active — host is unprotected", f.Backend),
			[]string{
				"to inspect: iptables -L -n",
				"to inspect: nft list ruleset",
				"note: consider enabling ufw, firewalld, or writing iptables/nft rules",
			})}
	}
	return nil
}

func checkAuth(a models.AuthInfo) []models.Insight {
	if !a.Available {
		return nil // sshd not installed — row hidden
	}
	// The auth source could not be read (typically a non-root run where the
	// journal and /var/log/auth.log are both inaccessible). Surface that honestly
	// as INFO instead of letting FailedLast24h==0 read as a clean "no failures" —
	// a check that silently reads OK when it never ran is a false sense of security.
	if !a.Checked {
		msg := a.StatusReason
		if msg == "" {
			msg = "SSH auth log could not be read — failed-login detection skipped"
		}
		return []models.Insight{insight("INFO", "Auth", msg,
			[]string{"run as root (sudo) to verify SSH authentication failures"})}
	}
	if a.FailedLast24h == 0 {
		return nil
	}
	var out []models.Insight
	if a.FailedLast24h > 1000 {
		hints := []string{
			"to inspect: journalctl _COMM=sshd --since '24 hours ago' | grep 'Failed password'",
			"to inspect: lastb | head -20",
			"to fix:     consider fail2ban or sshguard",
		}
		if len(a.TopSources) > 0 {
			hints = append(hints, fmt.Sprintf("top attacker: %s (%d attempts)",
				a.TopSources[0].Source, a.TopSources[0].Count))
		}
		out = append(out, insight("WARN", "Auth",
			fmt.Sprintf("%d failed SSH login attempts in 24h — brute force likely", a.FailedLast24h),
			hints))
	} else if a.FailedLast24h > 100 {
		out = append(out, insight("INFO", "Auth",
			fmt.Sprintf("%d failed SSH login attempts in 24h", a.FailedLast24h),
			[]string{"to inspect: journalctl _COMM=sshd --since '24 hours ago' | grep Failed"}))
	}
	if a.RootAttempts > 0 {
		out = append(out, insight("WARN", "Auth",
			fmt.Sprintf("%d root login attempt(s) — ensure PermitRootLogin no in sshd_config", a.RootAttempts),
			[]string{
				"to inspect: grep PermitRootLogin /etc/ssh/sshd_config",
				"to fix:     echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && systemctl restart sshd",
			}))
	}
	return out
}

func checkCloudMeta(c models.CloudInfo) []models.Insight {
	if !c.Available {
		return nil
	}
	var out []models.Insight
	if c.SpotTermination {
		out = append(out, insight("CRIT", "CloudMeta",
			fmt.Sprintf("%s spot/preemptible instance scheduled for termination — save state now", c.Provider),
			[]string{
				"note: instance will be terminated imminently",
				"to inspect: check instance metadata for exact termination time",
			}))
	}
	if c.MaintenanceEvent {
		out = append(out, insight("WARN", "CloudMeta",
			fmt.Sprintf("%s maintenance event pending: %s", c.Provider, c.MaintenanceDetails),
			[]string{"to inspect: check cloud provider console for details"}))
	}
	return out
}

// checkCloudInit flags instances that booted but never finished configuring.
// Generic to every cloud-init platform (not provider-specific). Silent when
// cloud-init completed cleanly, is disabled, or never ran.
func checkCloudInit(c models.CloudInitInfo) []models.Insight {
	if !c.Available {
		return nil
	}
	ds := c.Datasource
	if ds == "" {
		ds = "unknown"
	}
	var out []models.Insight

	switch {
	case c.Status == "error" || len(c.Errors) > 0:
		hints := []string{}
		for i, e := range c.Errors {
			if i >= 3 {
				break
			}
			hints = append(hints, "error: "+e)
		}
		hints = append(hints,
			"to inspect: cloud-init status --long",
			"logs: /var/log/cloud-init.log, /var/log/cloud-init-output.log")
		out = append(out, insight("CRIT", "CloudInit",
			fmt.Sprintf("cloud-init failed — instance configuration incomplete (datasource: %s)", ds),
			hints))

	case strings.Contains(c.ExtendedStatus, "degraded") || len(c.RecoverableErrors) > 0:
		hints := []string{}
		for i, e := range c.RecoverableErrors {
			if i >= 3 {
				break
			}
			hints = append(hints, e)
		}
		hints = append(hints, "to inspect: cloud-init status --long")
		out = append(out, insight("WARN", "CloudInit",
			"cloud-init completed with recoverable errors — some configuration may be missing",
			hints))

	case c.Status == "running":
		out = append(out, insight("INFO", "CloudInit",
			"cloud-init still running — instance configuration in progress",
			[]string{"note: provisioning not yet complete; re-check after boot settles"}))
	}
	return out
}

func checkAuditd(a models.AuditInfo) []models.Insight {
	if !a.Available {
		return nil
	}
	var out []models.Insight
	if !a.Running {
		out = append(out, insight("WARN", "Auditd",
			"auditd is installed but not running — compliance logging inactive",
			[]string{
				"to fix: systemctl enable --now auditd",
				"note: required for CIS/STIG compliance",
			}))
	}
	if a.AuditLogSizeGB > 10 {
		out = append(out, insight("WARN", "Auditd",
			fmt.Sprintf("audit log is %.1f GB — consider log rotation", a.AuditLogSizeGB),
			[]string{
				"to inspect: ls -lh /var/log/audit/",
				"to fix:     auditctl -e 0 && truncate -s 0 /var/log/audit/audit.log && auditctl -e 1",
			}))
	}
	return out
}

func checkNUMA(n models.NUMAInfo) []models.Insight {
	if !n.Available {
		return nil
	}
	if n.Imbalanced {
		return []models.Insight{insight("WARN", "NUMA",
			fmt.Sprintf("%d NUMA nodes with unbalanced memory — may cause performance issues", n.NodeCount),
			[]string{
				"to inspect: numactl --hardware",
				"to inspect: numastat -m",
				"note: consider NUMA-aware memory allocation for latency-sensitive workloads",
			})}
	}
	return nil
}

func checkVLAN(v models.VLANInfo) []models.Insight {
	if len(v.Interfaces) == 0 {
		return nil
	}
	var down []string
	for _, iface := range v.Interfaces {
		if !iface.Up {
			down = append(down, fmt.Sprintf("%s (VLAN %d)", iface.Name, iface.VLANID))
		}
	}
	if len(down) == 0 {
		return nil
	}
	return []models.Insight{insight("WARN", "VLAN",
		fmt.Sprintf("%d VLAN interface(s) down: %s", len(down), strings.Join(down, ", ")),
		[]string{
			"to inspect: ip link show",
			"to inspect: cat /proc/net/vlan/config",
		})}
}

func checkISCSI(i models.ISCSIInfo) []models.Insight {
	if !i.Available || len(i.Sessions) == 0 {
		return nil
	}
	if i.FailedCount == 0 {
		return nil
	}
	return []models.Insight{insight("CRIT", "iSCSI",
		fmt.Sprintf("%d iSCSI session(s) not logged in — storage path lost", i.FailedCount),
		[]string{
			"to inspect: iscsiadm -m session",
			"to fix:     iscsiadm -m node --loginall=all",
			"to inspect: check network connectivity to iSCSI portal",
		})}
}

func checkInfiniBand(ib models.InfiniBandInfo) []models.Insight {
	if len(ib.Ports) == 0 {
		return nil
	}
	var down []string
	for _, p := range ib.Ports {
		state := strings.ToUpper(p.State)
		// An unreadable state ("") is NOT treated as active — the inline renderer
		// already counts it as not-active, so whitelisting it here was a divergence
		// false-OK. Surface it as unreadable.
		if state != "ACTIVE" {
			label := p.State
			if label == "" {
				label = "unreadable"
			}
			down = append(down, fmt.Sprintf("%s port %d (%s)", p.Device, p.Port, label))
		}
	}
	if len(down) == 0 {
		return nil
	}
	return []models.Insight{insight("WARN", "InfiniBand",
		fmt.Sprintf("%d IB port(s) not active: %s", len(down), strings.Join(down, ", ")),
		[]string{
			"to inspect: ibstat",
			"to inspect: cat /sys/class/infiniband/*/ports/*/state",
			"note: check cable and switch port",
		})}
}

func checkSRIOV(s models.SRIOVInfo) []models.Insight {
	// SR-IOV doesn't have a clear failure state — surface INFO if VFs are enabled
	if len(s.Devices) == 0 {
		return nil
	}
	total := 0
	for _, d := range s.Devices {
		total += d.NumVFs
	}
	if total == 0 {
		return nil // capable but no VFs active — expected
	}
	return nil // VFs active — healthy, shown in inline
}

func checkNspawn(n models.NspawnInfo) []models.Insight {
	if !n.Available || len(n.Containers) == 0 {
		return nil
	}
	if n.FailedCount == 0 {
		return nil
	}
	return []models.Insight{insight("WARN", "Nspawn",
		fmt.Sprintf("%d systemd-nspawn container(s) in failed/degraded state", n.FailedCount),
		[]string{
			"to inspect: machinectl list",
			"to inspect: machinectl status <name>",
		})}
}

// ── HugePages and CPUFreq heuristics ────────────────────────────────────────

func checkHugePages(h models.HugePagesInfo) []models.Insight {
	if h.Configured == 0 && !h.THPEnabled {
		return nil // not configured, not relevant
	}
	var out []models.Insight

	// Static huge pages configured but mostly unused — wasted locked RAM
	if h.Configured > 0 {
		usedPct := float64(h.Used) / float64(h.Configured) * 100
		if usedPct < 20 && h.ReservedGB >= 1 {
			out = append(out, insight("WARN", "HugePages",
				fmt.Sprintf("%.0f%% of huge pages unused — %.1f GB locked and wasted (used %d/%d pages)",
					100-usedPct, h.ReservedGB, h.Used, h.Configured),
				[]string{
					"to inspect: grep Huge /proc/meminfo",
					"note: static huge pages lock RAM at boot — free unused pages or reduce HugePages_Total",
					"to fix: echo 0 > /proc/sys/vm/nr_hugepages  (releases all — requires workload restart)",
				},
			))
		}
		// All huge pages used — may want more
		if usedPct >= 100 && h.Configured > 0 {
			out = append(out, insight("INFO", "HugePages",
				fmt.Sprintf("all %d huge pages in use (%.1f GB) — consider increasing if workload allows",
					h.Configured, h.ReservedGB),
				[]string{
					"to inspect: grep Huge /proc/meminfo",
					"to add more: sysctl -w vm.nr_hugepages=<N>",
				},
			))
		}
	}

	// THP set to "always" on a database server — causes latency spikes
	// THP is great for general workloads but known to cause pauses in:
	// MySQL, PostgreSQL, Redis, MongoDB, Oracle
	if h.THPMode == "always" {
		out = append(out, insight("INFO", "HugePages",
			"transparent huge pages mode is 'always' — may cause latency spikes for database workloads",
			[]string{
				"to inspect: cat /sys/kernel/mm/transparent_hugepage/enabled",
				"to check:   if running MySQL/PostgreSQL/Redis/MongoDB, set to 'madvise' or 'never'",
				"to fix:     echo madvise > /sys/kernel/mm/transparent_hugepage/enabled",
				"to persist: add to /etc/rc.local or a systemd service",
			},
		))
	}

	return out
}

func checkCPUFreq(f models.CPUFreqInfo) []models.Insight {
	if f.Governor == "" {
		return nil // cpufreq not available
	}
	var out []models.Insight

	// powersave governor on a server — leaves performance on the table
	// schedutil/ondemand are fine (responsive). powersave caps at min freq.
	if f.Governor == "powersave" {
		out = append(out, insight("WARN", "CPUFreq",
			fmt.Sprintf("CPU governor is 'powersave' — CPU running at %d MHz (max %d MHz), performance limited",
				f.CurrentMHz, f.MaxMHz),
			[]string{
				"to inspect: cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor",
				"to fix: cpupower frequency-set -g performance",
				"to fix (manual): echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor",
				"to persist: add to /etc/rc.local or use tuned profile 'throughput-performance'",
				"note: 'schedutil' or 'ondemand' are also acceptable for variable workloads",
			},
		))
	}

	// Heavy throttling — current frequency well below max despite not being powersave
	// Usually caused by thermal throttling or power limit
	if f.Governor != "powersave" && f.ThrottledPct >= 40 && f.MaxMHz > 0 {
		out = append(out, insight("WARN", "CPUFreq",
			fmt.Sprintf("CPU running at %d MHz (%d%% below max %d MHz) — possible thermal or power throttle",
				f.CurrentMHz, int(f.ThrottledPct), f.MaxMHz),
			[]string{
				"to inspect: cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
				"to inspect: sensors  (check CPU temperature)",
				"to inspect: dmesg | grep -i 'throttl\\|thermal\\|power limit'",
				"to inspect: turbostat --quiet --show Busy%,Avg_MHz,Bzy_MHz,PkgWatt 2>/dev/null | head -5",
			},
		))
	}

	return out
}

func checkLaunchd(l models.LaunchdInfo) []models.Insight {
	if len(l.Failed) == 0 {
		return nil
	}
	var names []string
	for _, svc := range l.Failed {
		names = append(names, svc.Label)
	}
	// Show at most 3 names inline to keep message readable
	shown := names
	suffix := ""
	if len(shown) > 3 {
		shown = shown[:3]
		suffix = fmt.Sprintf(" (+%d more)", len(names)-3)
	}
	return []models.Insight{insight("WARN", "Launchd",
		fmt.Sprintf("%d launchd service(s) failed: %s%s",
			len(l.Failed), strings.Join(shown, ", "), suffix),
		[]string{
			"to inspect: launchctl list | awk '$2 != 0 && $2 != \"-\"'",
			"to inspect: log show --predicate 'subsystem == \"com.apple.launchd\"' --last 1h",
			"to fix:     launchctl kickstart system/<label>",
		},
	)}
}

// checkSessions surfaces active session anomalies (Spec H1):
// root login via SSH, sessions idle > 8h, unusual concurrent session count.
// Silent when only the current user is logged in normally.
func checkSessions(s models.SessionsInfo) []models.Insight {
	if s.TotalCount == 0 {
		return nil // w not available or no sessions — skip silently
	}
	var out []models.Insight

	// Root logged in via SSH. On Proxmox VE root SSH is required for cluster
	// management, so flagging it CRIT (as checkSecurity already declines to do for
	// PermitRootLogin on PVE) would fire on the operator's own management session.
	// Surface it as INFO there instead of a false CRIT.
	if s.RootSSH {
		if s.IsPVE {
			out = append(out, insight("INFO", "Sessions",
				"root is logged in via SSH — expected on Proxmox VE (cluster management requires it)",
				[]string{"to inspect: w"},
			))
		} else {
			out = append(out, insight("CRIT", "Sessions",
				"root is logged in via SSH — direct root SSH access is a security risk",
				[]string{
					"to inspect: w",
					"to fix: set PermitRootLogin no in /etc/ssh/sshd_config",
					"to fix: use sudo or su instead of direct root SSH",
				},
			))
		}
	}

	// Sessions idle > 8 hours — unattended terminals
	if len(s.LongIdle) > 0 {
		users := strings.Join(unique(s.LongIdle), ", ")
		out = append(out, insight("WARN", "Sessions",
			fmt.Sprintf("%d session(s) idle > 8h: %s — unattended terminal risk",
				len(s.LongIdle), users),
			[]string{
				"to inspect: w",
				"to fix: set ClientAliveInterval 300 in /etc/ssh/sshd_config to auto-disconnect",
			},
		))
	}

	// Unusual number of concurrent sessions (> 5 is worth noting on a typical server)
	if s.TotalCount > 5 {
		out = append(out, insight("WARN", "Sessions",
			fmt.Sprintf("%d concurrent sessions active — unusually high for a single server",
				s.TotalCount),
			[]string{"to inspect: w", "to inspect: last | head -20"},
		))
	}

	// Informational: unique remote IPs when > 1 different source
	if len(s.UniqueIPs) > 1 {
		out = append(out, insight("INFO", "Sessions",
			fmt.Sprintf("%d session(s) from %d unique IP(s): %s",
				s.RemoteCount, len(s.UniqueIPs),
				strings.Join(s.UniqueIPs, ", ")),
			[]string{"to inspect: w"},
		))
	}

	return out
}

// unique returns a deduplicated copy of a string slice, preserving order.
func unique(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// firstN returns at most the first n elements of ss.
func firstN(ss []string, n int) []string {
	if len(ss) <= n {
		return ss
	}
	return ss[:n]
}

// ── SSH weak algorithm checks (Spec 13) ──────────────────────────────────────

// ── cgroup v2 heuristics ─────────────────────────────────────────────────────
// Integrated into checkHealthDeep (HealthDeepInfo) below.

func checkCgroupV2(cg models.CgroupV2Info) []models.Insight {
	if !cg.Available {
		return nil
	}
	var out []models.Insight

	// OOM kills at root scope. memory.events oom_kill is a CUMULATIVE counter since
	// boot — it can't tell a kill from 5 minutes ago from one at boot weeks back, so
	// firing CRIT on >0 was a recency-gate (a single boot-time OOM = permanent CRIT).
	// Recency is owned by the timestamped Logs/OOM check (windowed to 24h); here we
	// surface the lifetime counter as INFO context, not a live alarm.
	if cg.OOMKills > 0 {
		out = append(out, insight("INFO", "Cgroup",
			fmt.Sprintf("cgroup OOM kill counter = %d since boot (lifetime total, not necessarily recent)",
				cg.OOMKills),
			[]string{
				"recency: see the Logs/OOM check — it windows OOM events to the last 24h",
				"to inspect: cat /sys/fs/cgroup/memory.events",
				"to identify: dmesg | grep -i 'oom_kill\\|out of memory'",
			},
		))
	}

	// CPU throttled slices. ThrottledPct is throttled_usec/usage_usec — both
	// cumulative since the slice was created, so this is a LIFETIME ratio, not the
	// current rate (a slice hammered at boot but idle now still reads high). The
	// wording reflects that; a high lifetime ratio is still a real "this slice is
	// chronically cpu-constrained" signal.
	for _, s := range cg.Slices {
		if s.ThrottledPct > 20 {
			out = append(out, insight("CRIT", "Cgroup",
				fmt.Sprintf("%s CPU throttled %.0f%% of its run time (since boot) — chronically hitting cpu.max",
					s.Name, s.ThrottledPct),
				[]string{
					fmt.Sprintf("to inspect: cat /sys/fs/cgroup/%s/cpu.stat", s.Name),
					fmt.Sprintf("to fix: increase or remove cpu.max in /sys/fs/cgroup/%s/cpu.max", s.Name),
					"note: lifetime ratio — throttling causes latency spikes even when overall CPU is idle",
				},
			))
		} else if s.ThrottledPct > 5 {
			out = append(out, insight("WARN", "Cgroup",
				fmt.Sprintf("%s CPU throttled %.0f%% of its run time (since boot)",
					s.Name, s.ThrottledPct),
				[]string{
					fmt.Sprintf("to inspect: cat /sys/fs/cgroup/%s/cpu.stat", s.Name),
				},
			))
		}

		// Memory usage near limit
		if s.HasMemLimit && s.MemUsedPct > 90 {
			out = append(out, insight("CRIT", "Cgroup",
				fmt.Sprintf("%s memory %.0f%% of limit (%.0f/%.0f MB)",
					s.Name, s.MemUsedPct, s.MemCurrentMB, s.MemLimitMB),
				[]string{
					fmt.Sprintf("to inspect: cat /sys/fs/cgroup/%s/memory.current", s.Name),
					fmt.Sprintf("to inspect: cat /sys/fs/cgroup/%s/memory.events", s.Name),
					"note: at 100% the kernel will OOM-kill processes in this slice",
				},
			))
		} else if s.HasMemLimit && s.MemUsedPct > 75 {
			out = append(out, insight("WARN", "Cgroup",
				fmt.Sprintf("%s memory at %.0f%% of limit",
					s.Name, s.MemUsedPct),
				[]string{
					fmt.Sprintf("to inspect: cat /sys/fs/cgroup/%s/memory.current", s.Name),
				},
			))
		}
	}

	return out
}

// truncateSELinux truncates a string for inline hint display.
func truncateSELinux(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
