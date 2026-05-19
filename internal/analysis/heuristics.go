package analysis

import (
	"fmt"
	"math"
	"runtime"
	"strings"

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
	return insights
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
	case models.K8sInfo:
		return checkK8s(d)
	case *models.K8sInfo:
		return checkK8s(*d)
	case models.KVMInfo:
		return checkKVM(d)
	case *models.KVMInfo:
		return checkKVM(*d)
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
		return checkProcesses(d)
	case *models.ProcessInfo:
		return checkProcesses(*d)
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
	if cpu.UsagePct > 0 {
		checkPct = cpu.UsagePct
	}

	if l := levelPct(checkPct, thresh.CPULoadWarnMultiplier*100, thresh.CPULoadCritMultiplier*100); l != "" {
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
		out = append(out, insight("CRIT", "CPU/Steal",
			fmt.Sprintf("CPU steal at %.1f%% — hypervisor is withholding CPU time from this VM", cpu.StealPct),
			[]string{
				"to inspect: top -b -n1 | grep Cpu",
				"to inspect: vmstat 1 5  (look at the 'st' column)",
				"note: steal > 20%% means the host is severely over-provisioned",
				"note: escalate to your cloud provider or migrate to a less-loaded host",
			},
		))
	} else if cpu.StealPct >= 10 {
		out = append(out, insight("WARN", "CPU/Steal",
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
		out = append(out, insight("CRIT", "CPU/IOWait",
			fmt.Sprintf("I/O wait at %.1f%% — CPU is stalled waiting for disk or network I/O", cpu.IOwaitPct),
			[]string{
				"to inspect: iostat -x 1 5",
				"to inspect: iotop -ao",
				"to inspect: ps aux | grep ' D '  (D-state processes blocked on I/O)",
				"note: high iowait with normal CPU usage = disk bottleneck, not CPU",
			},
		))
	} else if cpu.IOwaitPct >= 20 {
		out = append(out, insight("WARN", "CPU/IOWait",
			fmt.Sprintf("I/O wait at %.1f%% — load may be I/O-driven rather than CPU-bound", cpu.IOwaitPct),
			[]string{
				"to inspect: iostat -x 1 5",
				"to inspect: ps aux | grep ' D '",
			},
		))
	}

	return out
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
	if mem.OverCommitted {
		out = append(out, insight("CRIT", "Memory",
			"memory overcommitted — OOM kill risk",
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
	return out
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
	}
	out = append(out, checkDiskExtras(disk)...)
	return out
}

func checkDiskExtras(disk models.DiskInfo) []models.Insight {
	var out []models.Insight
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
		if p.ReadErrors+p.WriteErrors+p.CksumErrors > 0 {
			out = append(out, insight("WARN", "Disk",
				fmt.Sprintf("ZFS pool %s has vdev errors (R:%d W:%d C:%d) — run scrub",
					p.Name, p.ReadErrors, p.WriteErrors, p.CksumErrors),
				[]string{fmt.Sprintf("to fix: zpool scrub %s", p.Name)},
			))
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
	if maxAct > thresh.SwapActivityCrit {
		out = append(out, insight("CRIT", "Swap",
			fmt.Sprintf("heavy swap activity: %.0f pages/s in, %.0f pages/s out", actIn, actOut),
			[]string{"to inspect: vmstat 1 5", "to inspect: sar -W 1 5", "to inspect: ps aux --sort=-%mem | head -10"},
		))
	} else if maxAct > thresh.SwapActivityWarn {
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
		warnUtil, critUtil := thresh.IOUtilWarnPctSSD, thresh.IOUtilCritPctSSD
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

func checkNFS(nfs models.NFSInfo) []models.Insight {
	var out []models.Insight
	for _, m := range nfs.Mounts {
		if m.Stale {
			hints := []string{
				fmt.Sprintf("to unmount (safe): umount -l %s", m.Mount),
				fmt.Sprintf("to remount after recovery: mount -o remount %s", m.Mount),
			}
			if !m.ServerReachable {
				hints = append(hints,
					fmt.Sprintf("server %s unreachable — check network/firewall", m.Server))
			}
			out = append(out, insight("CRIT", "NFS",
				fmt.Sprintf("mount %s is STALE — processes accessing it will hang in D-state", m.Mount),
				hints))
		}
		for _, warn := range m.OptionsWarnings {
			out = append(out, insight("WARN", "NFS",
				fmt.Sprintf("%s: %s", m.Mount, warn),
				[]string{"to fix: remount with correct options in /etc/fstab"},
			))
		}
	}
	if nfs.StaleMounts == 0 && nfs.RetransPerMin > 100 {
		out = append(out, insight("WARN", "NFS",
			fmt.Sprintf("elevated NFS retransmissions (%.0f) — NFS transport may be unreliable", nfs.RetransPerMin),
			[]string{
				"to inspect: nfsstat -rc",
				"to inspect: cat /proc/net/rpc/nfs",
			},
		))
	}
	if !nfs.RpcbindActive && len(nfs.Mounts) > 0 {
		out = append(out, insight("WARN", "NFS",
			"rpcbind inactive with NFS mounts present — NFS client operations may fail",
			[]string{
				"to fix: systemctl enable --now rpcbind",
			},
		))
	}
	return out
}

func checkNetwork(net models.NetworkInfo) []models.Insight { //nolint:funlen,cyclop // network checks are a flat list; splitting would hurt readability
	var out []models.Insight

	// Link speed check — 100Mbps on a server primary interface suggests wrong
	// cable (Cat5 instead of Cat5e/Cat6) or switch port misconfiguration.
	for _, iface := range net.Interfaces {
		if iface.Name == net.PrimaryInterface && iface.SpeedMbps > 0 && iface.SpeedMbps < 1000 {
			out = append(out, insight("WARN", "Network",
				fmt.Sprintf("primary interface %s linked at %d Mbps — expected 1000+ Mbps (check cable or switch port)", iface.Name, iface.SpeedMbps),
				[]string{
					"to inspect: ethtool " + iface.Name,
					"to inspect: cat /sys/class/net/" + iface.Name + "/speed",
				},
			))
		}
		// USB-attached NIC as primary interface
		if iface.Name == net.PrimaryInterface && iface.IsUSB {
			driver := iface.Driver
			if driver == "" {
				driver = "USB NIC"
			}
			speedInfo := ""
			if iface.SpeedMbps >= 1000 {
				speedInfo = fmt.Sprintf(" @ %dGbps", iface.SpeedMbps/1000)
			} else if iface.SpeedMbps > 0 {
				speedInfo = fmt.Sprintf(" @ %dMbps", iface.SpeedMbps)
			}
			out = append(out, insight("WARN", "Network",
				fmt.Sprintf("primary interface %s is USB-attached (%s%s) — susceptible to disconnect/reset, not recommended for production", iface.Name, driver, speedInfo),
				[]string{
					"to inspect: dmesg | grep -i usb",
					"to inspect: lsusb",
				},
			))
		}
		// Hardware NIC errors (CRC, frame, overrun) — distinct from drops
		if iface.RxErrors > 100 || iface.TxErrors > 100 {
			out = append(out, insight("WARN", "Network",
				fmt.Sprintf("%s has hardware errors: rx:%d tx:%d — may indicate bad cable, NIC, or switch port", iface.Name, iface.RxErrors, iface.TxErrors),
				[]string{
					"to inspect: ethtool -S " + iface.Name,
					"to inspect: ip -s link show " + iface.Name,
				},
			))
		}
	}

	if net.PrimaryInterfaceDown {
		out = append(out, insight("CRIT", "Network",
			fmt.Sprintf("primary interface %s is DOWN", net.PrimaryInterface),
			[]string{"to inspect: ip link show", "to inspect: ip route", fmt.Sprintf("to fix: ip link set %s up", net.PrimaryInterface)},
		))
	} else if net.GatewayPingMs < 0 && net.InternetPingMs < 0 {
		out = append(out, insight("CRIT", "Network",
			"gateway and internet unreachable — host appears offline",
			[]string{"to inspect: ip route", "to inspect: ip link show", "to inspect: ping -c3 $(ip route | awk '/default/{print $3}')"},
		))
	} else if net.GatewayPingMs < 0 && net.InternetPingMs >= 0 {
		out = append(out, insight("INFO", "Network",
			"gateway not responding to probes — internet traffic is flowing",
			[]string{"to inspect: traceroute 8.8.8.8", "to inspect: ping -c3 $(ip route | awk '/default/{print $3}')"},
		))
	} else if net.GatewayPingMs > 200 {
		out = append(out, insight("CRIT", "Network",
			fmt.Sprintf("gateway ping is %.0f ms — severe latency", net.GatewayPingMs),
			[]string{"to inspect: ping -c5 $(ip route | awk '/default/{print $3}')", "to inspect: ip route"},
		))
	} else if net.GatewayPingMs > 50 {
		out = append(out, insight("WARN", "Network",
			fmt.Sprintf("gateway ping is %.0f ms — elevated latency", net.GatewayPingMs),
			[]string{"to inspect: ping -c5 $(ip route | awk '/default/{print $3}')"},
		))
	}
	if !net.PrimaryInterfaceDown && net.GatewayPingMs >= 0 {
		if net.GatewayPacketLossPct >= 50 {
			out = append(out, insight("CRIT", "Network",
				fmt.Sprintf("gateway packet loss %.0f%%", net.GatewayPacketLossPct),
				[]string{"to inspect: ping -c20 $(ip route | awk '/default/{print $3}')", "to inspect: ip link show"},
			))
		} else if net.GatewayPacketLossPct >= 10 {
			out = append(out, insight("WARN", "Network",
				fmt.Sprintf("gateway packet loss %.0f%%", net.GatewayPacketLossPct),
				[]string{"to inspect: ping -c20 $(ip route | awk '/default/{print $3}')"},
			))
		}
	}
	if net.DNSFailed {
		out = append(out, insight("CRIT", "Network/DNS",
			"DNS resolution failed — cannot resolve hostnames",
			[]string{"to inspect: dig @8.8.8.8 google.com", "to inspect: cat /etc/resolv.conf", "to inspect: systemctl status systemd-resolved"},
		))
	} else if net.DNSResolvesMs > 1000 {
		out = append(out, insight("CRIT", "Network/DNS",
			fmt.Sprintf("DNS resolution took %.0f ms", net.DNSResolvesMs),
			[]string{"to inspect: dig @8.8.8.8 google.com", "to inspect: cat /etc/resolv.conf", "to inspect: systemctl status systemd-resolved"},
		))
	} else if net.DNSResolvesMs > 200 {
		out = append(out, insight("WARN", "Network/DNS",
			fmt.Sprintf("DNS resolution took %.0f ms", net.DNSResolvesMs),
			[]string{"to inspect: dig @8.8.8.8 google.com", "to inspect: cat /etc/resolv.conf"},
		))
	}
	if net.CloseWaitCount > 500 {
		out = append(out, insight("CRIT", "Network",
			fmt.Sprintf("%d CLOSE_WAIT connections — likely connection leak", net.CloseWaitCount),
			[]string{"to inspect: ss -s", "to inspect: ss -tan state close-wait | head -20"},
		))
	} else if net.CloseWaitCount > 100 {
		out = append(out, insight("WARN", "Network",
			fmt.Sprintf("%d CLOSE_WAIT connections", net.CloseWaitCount),
			[]string{"to inspect: ss -s", "to inspect: netstat -an | grep CLOSE_WAIT | wc -l"},
		))
	}

	// Deep TCP metrics — only populated when NetworkDeepCollector is used
	if net.TimeWaitCount > 1000 {
		out = append(out, insight("WARN", "Network",
			fmt.Sprintf("%d TIME_WAIT sockets — high connection churn or missing tcp_tw_reuse", net.TimeWaitCount),
			[]string{"to inspect: ss -tan | grep TIME-WAIT | wc -l", "to inspect: ss -tan state time-wait | head -10", "to fix: sysctl -w net.ipv4.tcp_tw_reuse=1"},
		))
	}
	if net.SynRetransCount > 100 {
		out = append(out, insight("WARN", "Network",
			fmt.Sprintf("%d SYN retransmissions — packet loss or server overload", net.SynRetransCount),
			[]string{"to inspect: cat /proc/net/netstat | grep TCPSynRetrans", "to inspect: ss -tan state syn-sent"},
		))
	}
	if net.ListenOverflows > 0 {
		out = append(out, insight("CRIT", "Network",
			fmt.Sprintf("%d listen queue overflow(s) — SYN backlog saturated, connections being dropped", net.ListenOverflows),
			[]string{"to inspect: sysctl net.core.somaxconn", "to fix: sysctl -w net.core.somaxconn=4096", "to fix: sysctl -w net.ipv4.tcp_max_syn_backlog=4096"},
		))
	}
	if net.RetransFailCount > 10 {
		out = append(out, insight("WARN", "Network",
			fmt.Sprintf("%d TCP retransmit failures — persistent connectivity problems", net.RetransFailCount),
			[]string{"to inspect: cat /proc/net/netstat | grep TCPRetransFail", "to inspect: ss -ti"},
		))
	}
	if net.ConntrackUsedPct >= 80 {
		out = append(out, insight("CRIT", "Network",
			fmt.Sprintf("conntrack table %.0f%% full — new connections will be dropped when full", net.ConntrackUsedPct),
			[]string{"to inspect: conntrack -C", "to inspect: cat /proc/sys/net/netfilter/nf_conntrack_count", "to fix: sysctl -w net.netfilter.nf_conntrack_max=262144"},
		))
	} else if net.ConntrackUsedPct >= 60 {
		out = append(out, insight("WARN", "Network",
			fmt.Sprintf("conntrack table %.0f%% full", net.ConntrackUsedPct),
			[]string{"to inspect: conntrack -C", "to inspect: cat /proc/sys/net/netfilter/nf_conntrack_count"},
		))
	}
	return out
}

func checkClock(clock models.ClockInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	if !clock.Synced {
		// RTCInLocalTZ alone doesn't mean NTP is truly broken — the kernel
		// reports unsynchronized when RTC is in local time (dual-boot Windows),
		// but NTP may be actively syncing. Downgrade to WARN in this case.
		level := "CRIT"
		if clock.RTCInLocalTZ {
			level = "WARN"
		}
		msg := "NTP is not synchronized"
		hints := []string{
			"to inspect: timedatectl status",
			"to inspect: chronyc tracking",
			"to inspect: systemctl status chronyd ntpd",
		}
		if clock.RTCInLocalTZ {
			msg = "RTC is in local timezone — NTP reports unsync (common on dual-boot with Windows)"
			hints = append(hints, "to fix: timedatectl set-local-rtc 0 (switches RTC to UTC, resolves the false CRIT)")
		}
		out = append(out, insight(level, "Clock", msg, hints))
	}
	if clock.OffsetMs != -1 {
		abs := math.Abs(clock.OffsetMs)
		if l := levelPct(abs, thresh.NTPOffsetWarnMs, thresh.NTPOffsetCritMs); l != "" {
			out = append(out, insight(l, "Clock",
				fmt.Sprintf("NTP offset is %.1f ms (source: %s)", clock.OffsetMs, clock.Source),
				[]string{"to inspect: chronyc tracking", "to inspect: ntpq -p", "to inspect: timedatectl status"},
			))
		}
	}
	return out
}

func checkFD(fd models.FDInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	if l := levelPct(fd.UsedPct, thresh.FDSystemWarnPct, thresh.FDSystemCritPct); l != "" {
		out = append(out, insight(l, "FDLimits",
			fmt.Sprintf("system FD usage at %.0f%% (%d / %d open)", fd.UsedPct, fd.OpenCount, fd.MaxCount),
			[]string{"to inspect: cat /proc/sys/fs/file-nr", "to inspect: lsof | wc -l"},
		))
	}
	for _, proc := range fd.HotProcesses {
		if proc.UsedPct >= thresh.FDProcWarnPct {
			out = append(out, insight("WARN", "FDLimits",
				fmt.Sprintf("process %s (PID %d) has %d/%d FDs open (%.0f%%)",
					proc.Name, proc.PID, proc.OpenFDs, proc.SoftLimit, proc.UsedPct),
				[]string{
					fmt.Sprintf("to inspect: ls /proc/%d/fd | wc -l", proc.PID),
					fmt.Sprintf("to inspect: lsof -p %d | tail -20", proc.PID),
				},
			))
		}
	}
	if fd.DeletedOpenSizeGB >= 1 {
		out = append(out, insight("WARN", "FDLimits",
			fmt.Sprintf("%.1f GB held by deleted-but-open files", fd.DeletedOpenSizeGB),
			[]string{"to inspect: lsof | grep deleted | head -20", "to inspect: lsof | grep deleted | awk '{sum+=$7} END{print sum/1024/1024/1024\" GB\"}'"},
		))
	}
	return out
}
func checkSystemd(sys models.SystemdInfo) []models.Insight {
	if !sys.Available {
		return nil // not present on this platform — hide the row entirely
	}
	out := make([]models.Insight, 0, len(sys.FailedUnits))
	selinuxEnforcing := sys.SELinuxEnforcing // set by ApplyThresholds pre-scan
	for _, unit := range sys.FailedUnits {
		hints := []string{
			fmt.Sprintf("to inspect: systemctl status %s", unit),
			fmt.Sprintf("to inspect: journalctl -u %s -n 50", unit),
		}
		// SELinux double-layer hint — the most common invisible failure cause.
		// Permission errors from SELinux produce no output in journalctl -u;
		// admins check standard permissions and config and find nothing wrong.
		if selinuxEnforcing {
			hints = append(hints,
				"note: SELinux is enforcing — check AVC denials if permissions look correct",
				fmt.Sprintf("to check SELinux: ausearch -m avc -ts recent -c %s", unitBaseName(unit)),
			)
		}
		out = append(out, insight("CRIT", "Systemd",
			fmt.Sprintf("unit %s has failed", unit),
			hints,
		))
	}

	// Boot slowness — surface top slow units from systemd-analyze blame.
	// Threshold: WARN if any unit > 10s, INFO if total boot > 30s.
	// Research: "systemd-analyze blame tells you which is slow — not why"
	// dsd surfaces the slow units with the next diagnostic step.
	for _, u := range sys.SlowUnits {
		if u.Duration >= 10 {
			hints := make([]string, 0, 6)
			hints = append(hints,
				fmt.Sprintf("to inspect: systemctl status %s", u.Name),
				fmt.Sprintf("to inspect: journalctl -u %s -b", u.Name),
				"to analyse:  systemd-analyze blame",
				"to plot:     systemd-analyze plot > boot.svg",
			)
			// Service-specific fix hints for known slow-boot offenders
			hints = append(hints, slowBootFix(u.Name)...)
			out = append(out, insight("WARN", "Systemd",
				fmt.Sprintf("slow boot unit: %s took %.1fs", u.Name, u.Duration),
				hints,
			))
		}
	}
	if sys.TotalBootSec > 30 && len(sys.SlowUnits) == 0 {
		out = append(out, insight("INFO", "Systemd",
			fmt.Sprintf("total boot time %.0fs — run systemd-analyze blame to find slow units", sys.TotalBootSec),
			[]string{
				"to analyse: systemd-analyze blame",
				"to plot:    systemd-analyze plot > boot.svg",
			},
		))
	}

	return out
}

func checkSysctl(sysctl models.SysctlInfo) []models.Insight { //nolint:cyclop,funlen // workload-profile switch — each case is a distinct set of checks, splitting would harm readability
	var out []models.Insight

	// somaxconn — always checked
	if sysctl.NetSomaxconn != 0 && sysctl.NetSomaxconn < 512 {
		out = append(out, insight("CRIT", "Sysctl",
			fmt.Sprintf("net.core.somaxconn=%d is critically low (< 512)", sysctl.NetSomaxconn),
			[]string{"to inspect: sysctl net.core.somaxconn", "to fix: sysctl -w net.core.somaxconn=4096", "to persist: echo 'net.core.somaxconn=4096' >> /etc/sysctl.d/99-dsd.conf"},
		))
	} else if sysctl.NetSomaxconn != 0 && sysctl.NetSomaxconn < 1024 {
		out = append(out, insight("WARN", "Sysctl",
			fmt.Sprintf("net.core.somaxconn=%d is low (< 1024)", sysctl.NetSomaxconn),
			[]string{"to inspect: sysctl net.core.somaxconn", "to fix: sysctl -w net.core.somaxconn=4096", "to persist: echo 'net.core.somaxconn=4096' >> /etc/sysctl.d/99-dsd.conf"},
		))
	}

	// PID table usage — always checked
	if sysctl.KernelPIDMax > 0 {
		pidPct := float64(sysctl.PIDCount) / float64(sysctl.KernelPIDMax) * 100
		if l := levelPct(pidPct, 80, 90); l != "" {
			out = append(out, insight(l, "Sysctl",
				fmt.Sprintf("PID table at %.0f%% (%d / %d)", pidPct, sysctl.PIDCount, sysctl.KernelPIDMax),
				[]string{"to inspect: cat /proc/sys/kernel/pid_max", "to inspect: ps aux | wc -l"},
			))
		}
	}

	// Workload-aware tuning recommendations.
	// Each case adds "to persist:" hints so engineers know the fix survives reboot.
	switch sysctl.Workload {
	case "k8s":
		if sysctl.VMMaxMapCount > 0 && sysctl.VMMaxMapCount < 262144 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("vm.max_map_count=%d is low for k8s/Elasticsearch (recommended: 262144)", sysctl.VMMaxMapCount),
				[]string{"to inspect: sysctl vm.max_map_count", "to fix: sysctl -w vm.max_map_count=262144", "to persist: echo 'vm.max_map_count=262144' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
		if sysctl.FSInotifyWatches > 0 && sysctl.FSInotifyWatches < 524288 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("fs.inotify.max_user_watches=%d is low for k8s (recommended: 524288)", sysctl.FSInotifyWatches),
				[]string{"to inspect: sysctl fs.inotify.max_user_watches", "to fix: sysctl -w fs.inotify.max_user_watches=524288", "to persist: echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
		if sysctl.VMSwappiness > 10 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("vm.swappiness=%d is high for k8s node (recommended: \u2264 10)", sysctl.VMSwappiness),
				[]string{"to inspect: sysctl vm.swappiness", "to fix: sysctl -w vm.swappiness=10", "to persist: echo 'vm.swappiness=10' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}

	case "webserver":
		if sysctl.TCPTWReuse == 0 {
			out = append(out, insight("WARN", "Sysctl",
				"net.ipv4.tcp_tw_reuse=0 \u2014 enabling helps high-traffic web servers reuse TIME_WAIT sockets",
				[]string{"to fix: sysctl -w net.ipv4.tcp_tw_reuse=1", "to persist: echo 'net.ipv4.tcp_tw_reuse=1' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
		if sysctl.NetRmemMax > 0 && sysctl.NetRmemMax < 16777216 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("net.core.rmem_max=%d is low for high-throughput web server (recommended: 16MB)", sysctl.NetRmemMax),
				[]string{"to inspect: sysctl net.core.rmem_max", "to fix: sysctl -w net.core.rmem_max=16777216", "to persist: echo 'net.core.rmem_max=16777216' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}

	case "database":
		if sysctl.VMSwappiness > 10 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("vm.swappiness=%d is high for database workload (recommended: \u2264 10)", sysctl.VMSwappiness),
				[]string{"to inspect: sysctl vm.swappiness", "to fix: sysctl -w vm.swappiness=10", "to persist: echo 'vm.swappiness=10' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
		if sysctl.VMDirtyRatio > 10 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("vm.dirty_ratio=%d is high for database (recommended: \u2264 10 to reduce write latency spikes)", sysctl.VMDirtyRatio),
				[]string{"to inspect: sysctl vm.dirty_ratio", "to fix: sysctl -w vm.dirty_ratio=10", "to fix: sysctl -w vm.dirty_background_ratio=3", "to persist: echo 'vm.dirty_ratio=10' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}

	case "elasticsearch":
		if sysctl.VMMaxMapCount > 0 && sysctl.VMMaxMapCount < 262144 {
			out = append(out, insight("CRIT", "Sysctl",
				fmt.Sprintf("vm.max_map_count=%d \u2014 Elasticsearch requires \u2265 262144 or it will refuse to start", sysctl.VMMaxMapCount),
				[]string{"to inspect: sysctl vm.max_map_count", "to fix: sysctl -w vm.max_map_count=262144", "to persist: echo 'vm.max_map_count=262144' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
		if sysctl.VMSwappiness > 1 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("vm.swappiness=%d \u2014 Elasticsearch recommends 1 to minimise GC pauses from swapping", sysctl.VMSwappiness),
				[]string{"to inspect: sysctl vm.swappiness", "to fix: sysctl -w vm.swappiness=1", "to persist: echo 'vm.swappiness=1' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}

	case "container":
		if sysctl.VMMaxMapCount > 0 && sysctl.VMMaxMapCount < 262144 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("vm.max_map_count=%d is low for container host running JVM workloads (recommended: 262144)", sysctl.VMMaxMapCount),
				[]string{"to inspect: sysctl vm.max_map_count", "to fix: sysctl -w vm.max_map_count=262144", "to persist: echo 'vm.max_map_count=262144' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
		if sysctl.FSInotifyWatches > 0 && sysctl.FSInotifyWatches < 131072 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("fs.inotify.max_user_watches=%d is low for container host (recommended: 131072+)", sysctl.FSInotifyWatches),
				[]string{"to inspect: sysctl fs.inotify.max_user_watches", "to fix: sysctl -w fs.inotify.max_user_watches=131072", "to persist: echo 'fs.inotify.max_user_watches=131072' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}

	default: // general production server \u2014 flag values clearly suboptimal for any server role
		if sysctl.VMSwappiness > 30 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("vm.swappiness=%d is high for a server (recommended: \u2264 30; production servers typically use 10)", sysctl.VMSwappiness),
				[]string{"to inspect: cat /proc/sys/vm/swappiness", "to fix: sysctl -w vm.swappiness=10", "to persist: echo 'vm.swappiness=10' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
		if sysctl.NetRmemMax > 0 && sysctl.NetRmemMax < 4194304 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("net.core.rmem_max=%d is low (recommended: \u2265 4MB for modern network throughput)", sysctl.NetRmemMax),
				[]string{"to inspect: sysctl net.core.rmem_max", "to fix: sysctl -w net.core.rmem_max=4194304", "to persist: echo 'net.core.rmem_max=4194304' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
	}

	return out
}

// slowBootFix returns service-specific fix hints for known slow-boot offenders.
// These are services that are commonly slow and have a well-understood cause + fix.
func slowBootFix(unit string) []string {
	switch unit {
	case "gpu-manager.service":
		// Ubuntu/Mint GPU switching service. Slow on hybrid GPU laptops (AMD+NVIDIA)
		// especially when the iGPU is disabled in BIOS (nothing to switch between).
		return []string{
			"note: gpu-manager detects GPUs for PRIME switching — slow on Optimus laptops",
			"to fix (if not using GPU switching): systemctl disable --now gpu-manager.service",
			"note: safe to disable if you use NVIDIA-only mode or have one GPU",
		}
	case "NetworkManager-wait-online.service":
		// Waits for a network connection before continuing boot.
		// Often blocks boot on servers where network comes up slowly.
		return []string{
			"note: waits for network before continuing boot — often unnecessary on servers",
			"to fix: systemctl disable NetworkManager-wait-online.service",
			"note: safe if nothing critical depends on network at boot time",
		}
	case "plymouth-quit-wait.service":
		// Plymouth boot splash screen — slow when display detection is delayed.
		return []string{
			"note: plymouth boot splash — can be slow on headless or hybrid GPU systems",
			"to fix (headless): systemctl disable plymouth-quit-wait.service",
		}
	case "fwupd-refresh.service":
		// Firmware update metadata refresh — hits the network on boot.
		return []string{
			"note: checks for firmware updates on boot — hits the network",
			"to fix: systemctl disable fwupd-refresh.service  (updates still work manually)",
			"to run manually: fwupdmgr refresh",
		}
	case "snapd.service", "snapd.seeded.service":
		// Snap daemon — slow initialisation especially on first boot or after updates.
		return []string{
			"note: snap daemon initialisation — slow on first boot or after updates",
			"to fix (if not using snaps): systemctl disable --now snapd.service snapd.socket",
			"note: only disable if you have no snap packages installed",
		}
	case "apt-daily.service", "apt-daily-upgrade.service":
		return []string{
			"note: apt background updates running at boot — competes with boot I/O",
			"to fix: systemctl disable apt-daily.service apt-daily-upgrade.service",
			"note: updates will still run from cron/timer — boot impact removed",
		}
	default:
		return nil
	}
}

// unitBaseName extracts the base name from a systemd unit for use in ausearch -c.
// e.g. "nginx.service" → "nginx", "my-app@1.service" → "my-app"
func unitBaseName(unit string) string {
	// Strip extension
	if dot := strings.LastIndex(unit, "."); dot > 0 {
		unit = unit[:dot]
	}
	// Strip instance from template units
	if at := strings.LastIndex(unit, "@"); at > 0 {
		unit = unit[:at]
	}
	return unit
}

// extractAVCProcessNames parses comm= fields from SELinux AVC log lines.
// Returns unique process names so we can suggest targeted boolean searches.
// Example: type=AVC ... comm="httpd" ... → ["httpd"]
func extractAVCProcessNames(samples []string) []string {
	seen := map[string]bool{}
	var procs []string
	for _, line := range samples {
		idx := strings.Index(line, `comm="`)
		if idx < 0 {
			continue
		}
		rest := line[idx+6:]
		end := strings.IndexByte(rest, '"')
		if end <= 0 {
			continue
		}
		proc := rest[:end]
		if !seen[proc] {
			seen[proc] = true
			procs = append(procs, proc)
		}
	}
	return procs
}

func checkKernelSecurity(mac models.KernelSecurityInfo, thresh Thresholds) []models.Insight {
	seActive := mac.SELinuxPresent && mac.SELinuxMode != "disabled"
	aaActive := mac.AppArmorPresent && mac.AppArmorMode != "disabled" && mac.AppArmorMode != "unknown"
	aaIndeterminate := mac.AppArmorPresent && mac.AppArmorMode == "unknown"

	var out []models.Insight

	// SELinux policy type validation — surface BEFORE any denial checks.
	// A bad SELINUXTYPE= is the root cause of cascading service failures at boot.
	// This check fires even when SELinux mode is "permissive" because the policy
	// directory / package mismatch still prevents dbus from loading its context file.
	if mac.SELinuxPresent && mac.SELinuxType != "" {
		if !mac.SELinuxTypeValid {
			out = append(out, insight("CRIT", "KernelSec",
				fmt.Sprintf("SELinux SELINUXTYPE=%q is not a valid policy type (must be: targeted, minimum, mls)", mac.SELinuxType),
				[]string{
					"to inspect: cat /etc/selinux/config",
					"to fix:     set SELINUXTYPE=targeted in /etc/selinux/config",
					"to fix:     touch /.autorelabel && reboot",
					"note: invalid SELINUXTYPE causes dbus to fail, cascading to NetworkManager and systemd-logind",
				},
			))
		} else if !mac.SELinuxPolicyDirOK {
			out = append(out, insight("CRIT", "KernelSec",
				fmt.Sprintf("SELinux SELINUXTYPE=%q policy directory /etc/selinux/%s/ does not exist", mac.SELinuxType, mac.SELinuxType),
				[]string{
					fmt.Sprintf("to fix:     dnf install selinux-policy-%s", mac.SELinuxType),
					"to fix:     touch /.autorelabel && reboot",
					"note: missing policy directory causes dbus to fail at boot",
				},
			))
		} else if !mac.SELinuxPolicyPkgOK {
			out = append(out, insight("CRIT", "KernelSec",
				fmt.Sprintf("SELinux policy package selinux-policy-%s is not installed", mac.SELinuxType),
				[]string{
					fmt.Sprintf("to fix:     dnf install selinux-policy-%s", mac.SELinuxType),
					"to fix:     touch /.autorelabel && reboot",
				},
			))
		}
		if mac.SELinuxRelabelPending {
			out = append(out, insight("WARN", "KernelSec",
				"SELinux filesystem relabel is pending — reboot required to complete relabeling",
				[]string{
					"note: /.autorelabel exists — system will relabel on next boot",
					"to apply: reboot",
				},
			))
		}
	}

	if !seActive && !aaActive {
		if aaIndeterminate {
			return append(out, insight("INFO", "KernelSec",
				"AppArmor present but mode unreadable — re-run as root",
				nil,
			))
		}
		// On non-Linux platforms (macOS, etc.) neither SELinux nor AppArmor
		// is applicable — hide the row rather than showing a misleading INFO.
		if runtime.GOOS != "linux" {
			return nil
		}
		if len(out) == 0 {
			return []models.Insight{insight("INFO", "KernelSec",
				"kernel security module not enforced",
				nil,
			)}
		}
		return out
	}

	// AppArmor-specific checks
	if aaActive {
		// Profiles in complain mode mean enforcement is bypassed
		if mac.AppArmorComplain > 0 {
			out = append(out, insight("WARN", "KernelSec",
				fmt.Sprintf("%d AppArmor profile(s) in complain mode — not enforcing", mac.AppArmorComplain),
				[]string{
					"to inspect: aa-status",
					"to enforce: aa-enforce /etc/apparmor.d/*",
				},
			))
		}
		// Denials in last hour
		if mac.AppArmorDenials > 0 {
			out = append(out, insight("WARN", "KernelSec",
				fmt.Sprintf("%d AppArmor denial(s) in the last hour", mac.AppArmorDenials),
				[]string{
					"to inspect: dmesg | grep -i apparmor",
					"to inspect: journalctl -k | grep apparmor",
				},
			))
		}
	}
	if !mac.SELinuxPresent {
		return out
	}
	out = append(out, checkSELinuxDenials(mac, thresh)...)
	return out
}

// checkSELinuxDenials handles SELinux AVC denial insights and dontaudit suppression warning.
// Extracted from checkKernelSecurity to keep function length within linter limits.
func checkSELinuxDenials(mac models.KernelSecurityInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	if l := func() string {
		if mac.SELinuxDenials < 0 {
			return ""
		}
		if mac.SELinuxDenials >= thresh.SELinuxDenialsCritPerHr {
			return "CRIT"
		}
		if mac.SELinuxDenials >= thresh.SELinuxDenialsWarnPerHr {
			return "WARN"
		}
		return ""
	}(); l != "" {
		hints := []string{
			"to inspect: ausearch -m avc -ts recent",
			"to inspect: sealert -a /var/log/audit/audit.log",
		}
		if len(mac.SELinuxAVCSamples) > 0 {
			procs := extractAVCProcessNames(mac.SELinuxAVCSamples)
			for _, proc := range procs {
				hints = append(hints, fmt.Sprintf("to check booleans: getsebool -a | grep %s", proc))
			}
		} else {
			hints = append(hints, "to check booleans: getsebool -a | grep <process-name>")
		}
		hints = append(hints,
			"to generate fix: ausearch -m avc -ts recent | audit2allow -M mypolicy",
			"to apply fix:    semodule -i mypolicy.pp",
			"note: check booleans and file contexts BEFORE using audit2allow",
			"note: audit2allow may grant broader access than needed — review .te file first",
		)
		for _, avc := range mac.SELinuxAVCSamples {
			hints = append(hints, "sample AVC: "+avc)
		}
		out = append(out, insight(l, "KernelSec",
			fmt.Sprintf("%d SELinux denial(s) in the last hour (mode: %s)", mac.SELinuxDenials, mac.SELinuxMode),
			hints,
		))
	}
	// dontaudit suppression warning — zero denials does not mean clean.
	// dontaudit rules silently suppress certain denials — the "invisible SELinux" problem.
	if mac.SELinuxMode == "enforcing" && mac.SELinuxDenials == 0 {
		out = append(out, insight("INFO", "KernelSec",
			"SELinux enforcing — if services fail unexpectedly, dontaudit rules may suppress denials silently",
			[]string{
				"to expose hidden denials: semodule -DB  (disables dontaudit rules)",
				"to re-enable dontaudit:   semodule -B   (run after debugging)",
				"to check for suppressed:  ausearch -m avc -ts recent --raw | wc -l",
			},
		))
	}
	return out
}

func checkLogs(logs models.LogsInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	if logs.NeedsRoot {
		out = append(out, insight("INFO", "Logs",
			"some checks limited — run as root for OOM/segfault detection via /dev/kmsg and auth log analysis",
			nil,
		))
	}
	if l := levelPct(logs.JournalSizeGB, thresh.JournalSizeWarnGB, thresh.JournalSizeCritGB); l != "" {
		out = append(out, insight(l, "Logs",
			fmt.Sprintf("journal is %.1f GB", logs.JournalSizeGB),
			[]string{"to inspect: journalctl --disk-usage", "to fix: journalctl --vacuum-size=1G", "to fix: journalctl --vacuum-time=7d"},
		))
	}
	if logs.OOMKills > 0 {
		procs := strings.Join(logs.OOMProcesses, ", ")
		out = append(out, insight("CRIT", "Logs",
			fmt.Sprintf("%d OOM kill(s) in the last hour — processes killed: %s", logs.OOMKills, procs),
			[]string{"to inspect: dmesg | grep -i 'out of memory'", "to inspect: free -h"},
		))
	}
	if logs.Segfaults > 0 {
		procs := strings.Join(logs.SegfaultProcs, ", ")
		out = append(out, insight("WARN", "Logs",
			fmt.Sprintf("%d segfault(s) in the last hour — processes: %s", logs.Segfaults, procs),
			[]string{"to inspect: dmesg | grep segfault", "to inspect: journalctl -p err -n 50"},
		))
	}
	for _, unit := range logs.CrashLoops {
		out = append(out, insight("CRIT", "Logs",
			fmt.Sprintf("crash loop detected: %s", unit),
			[]string{fmt.Sprintf("to inspect: journalctl -u %s -n 50", strings.Fields(unit)[0])},
		))
	}

	// Kernel instability signals — always CRIT, any count is too many
	if logs.SoftLockups > 0 {
		out = append(out, insight("CRIT", "Logs",
			fmt.Sprintf("%d soft lockup(s) detected — CPU stuck in kernel context", logs.SoftLockups),
			[]string{"to inspect: dmesg | grep -i 'soft lockup'", "to inspect: check for runaway kernel threads or NFS hangs"},
		))
	}
	if logs.HardLockups > 0 {
		out = append(out, insight("CRIT", "Logs",
			fmt.Sprintf("%d hard lockup(s) detected — CPU unresponsive, NMI watchdog fired", logs.HardLockups),
			[]string{"to inspect: dmesg | grep -i 'hard lockup'", "to inspect: likely hardware issue — check memory and CPU"},
		))
	}
	if logs.KernelPanics > 0 {
		out = append(out, insight("CRIT", "Logs",
			fmt.Sprintf("%d kernel panic record(s) found — system crashed previously", logs.KernelPanics),
			[]string{"to inspect: ls /sys/fs/pstore/", "to inspect: dmesg | grep -i panic", "to inspect: check /var/crash if kdump is enabled"},
		))
	}

	// NVMe timeout and controller reset events — the leading cause of system freezes
	// on NVMe hardware. Any count is worth surfacing — these don't happen normally.
	if logs.NVMeTimeouts > 0 {
		out = append(out, insight("WARN", "Logs",
			fmt.Sprintf("%d NVMe I/O timeout event(s) in the last hour — drive may be failing or entering bad power state", logs.NVMeTimeouts),
			[]string{
				"to inspect: dmesg | grep -i 'nvme.*timeout'",
				"to inspect: smartctl -a /dev/nvme0  (or nvme smart-log /dev/nvme0)",
				"to mitigate: echo 'options nvme_core default_ps_max_latency_us=0' >> /etc/modprobe.d/nvme.conf",
				"note: NVMe timeouts can freeze the entire I/O stack — monitor closely",
			},
		))
	}
	if logs.NVMeResets > 0 {
		out = append(out, insight("CRIT", "Logs",
			fmt.Sprintf("%d NVMe controller reset/down event(s) — drive or PCIe link is unstable", logs.NVMeResets),
			[]string{
				"to inspect: dmesg | grep -i 'nvme.*reset\\|controller is down\\|CSTS'",
				"to inspect: nvme smart-log /dev/nvme0  (if nvme-cli installed)",
				"to mitigate: echo 'options nvme_core default_ps_max_latency_us=0' >> /etc/modprobe.d/nvme.conf",
				"to mitigate: add 'pcie_aspm=off' to kernel cmdline if power-state related",
				"note: controller resets can cause mdadm/BTRFS/ZFS to go read-only",
			},
		))
	}

	// Journal health — silent log loss is worse than noisy logs
	out = append(out, checkJournalHealthInsights(logs)...)

	return out
}

func checkJournalHealthInsights(logs models.LogsInfo) []models.Insight {
	out := checkJournalConfig(logs)
	out = append(out, checkJournalActivity(logs)...)
	return out
}

func checkJournalConfig(logs models.LogsInfo) []models.Insight {
	var out []models.Insight
	if logs.JournalCorrupt {
		out = append(out, insight("CRIT", "Logs",
			"journald journal corruption detected — some logs may be unreadable or missing",
			[]string{
				"to inspect: journalctl --verify",
				"to fix:     journalctl --rotate && journalctl --vacuum-time=1s",
				"to fix:     rm /var/log/journal/*/*.journal~ (corrupted files)",
			},
		))
	}
	if logs.JournalVolatile {
		out = append(out, insight("WARN", "Logs",
			"journald logs are volatile — all logs lost on reboot (no /var/log/journal/)",
			[]string{
				"to fix:     mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal",
				"to persist: echo 'Storage=persistent' >> /etc/systemd/journald.conf && systemctl restart systemd-journald",
			},
		))
	}
	if logs.JournalRateLimited {
		out = append(out, insight("WARN", "Logs",
			"journald RateLimitBurst is very low — logs may be silently dropped under load",
			[]string{
				"to inspect: grep RateLimit /etc/systemd/journald.conf",
				"to fix:     echo 'RateLimitBurst=10000' >> /etc/systemd/journald.conf",
				"to fix:     systemctl restart systemd-journald",
			},
		))
	}
	if logs.JournalNoTextFallback {
		out = append(out, insight("INFO", "Logs",
			"no text log fallback detected (rsyslog/syslog-ng not running) — logs require journalctl to read",
			[]string{
				"to fix: apt install rsyslog  OR  dnf install rsyslog",
				"note:   without a text fallback, logs are unreadable if journald corrupts or system partially fails",
				"note:   standard Unix tools (grep, tail, less) cannot read binary journal files",
			},
		))
	}
	if logs.JournalUnbounded {
		out = append(out, insight("WARN", "Logs",
			fmt.Sprintf("journald has no SystemMaxUse cap — journal is %.1f GB and growing unbounded", logs.JournalSizeGB),
			[]string{
				"to fix: echo 'SystemMaxUse=2G' >> /etc/systemd/journald.conf",
				"to fix: systemctl restart systemd-journald",
				"to fix: journalctl --vacuum-size=2G  (immediate cleanup)",
			},
		))
	}
	if logs.JournalSyncRisk {
		out = append(out, insight("INFO", "Logs",
			"journald SyncIntervalSec is high (default 5min) — final log lines from a crashing process may be lost",
			[]string{
				"to fix: echo 'SyncIntervalSec=30s' >> /etc/systemd/journald.conf",
				"to fix: systemctl restart systemd-journald",
				"note:   lower sync interval increases disk I/O but ensures crash logs are preserved",
			},
		))
	}
	if logs.LogDiskUsedPct >= 90 {
		out = append(out, insight("CRIT", "Logs",
			fmt.Sprintf("log volume %s is %.0f%% full — journald may stop writing logs",
				logs.LogDiskMount, logs.LogDiskUsedPct),
			[]string{
				"to inspect: df -h " + logs.LogDiskMount,
				"to inspect: journalctl --disk-usage",
				"to fix:     journalctl --vacuum-size=500M",
				"to fix:     journalctl --vacuum-time=7d",
			},
		))
	} else if logs.LogDiskUsedPct >= 80 {
		out = append(out, insight("WARN", "Logs",
			fmt.Sprintf("log volume %s is %.0f%% full — monitor to prevent log loss",
				logs.LogDiskMount, logs.LogDiskUsedPct),
			[]string{
				"to inspect: df -h " + logs.LogDiskMount,
				"to inspect: journalctl --disk-usage",
				"to fix:     journalctl --vacuum-size=1G",
			},
		))
	}
	return out
}

func checkJournalActivity(logs models.LogsInfo) []models.Insight {
	var out []models.Insight
	if logs.CoreDumpCount > 0 {
		paths := make([]string, 0, len(logs.CrashFiles))
		for _, cf := range logs.CrashFiles {
			paths = append(paths, fmt.Sprintf("%s (%.1fMB, %dd ago)", cf.Path, cf.SizeMB, cf.AgeDays))
		}
		out = append(out, insight("WARN", "Logs",
			fmt.Sprintf("%d crash dump(s)/panic record(s) found in the last 30 days", logs.CoreDumpCount),
			append([]string{
				"to inspect: ls -lh /var/crash/ /var/lib/systemd/coredump/ /sys/fs/pstore/",
				"to analyse: journalctl -k -b -1 | tail -50  (previous boot kernel log)",
			}, paths...),
		))
	}
	if logs.ErrorCount > 50 {
		hints := make([]string, 0, 1+len(logs.TopErrors))
		hints = append(hints, "to inspect: journalctl -p err --since '1 hour ago' --no-pager | tail -30")
		hints = append(hints, logs.TopErrors...)
		out = append(out, insight("WARN", "Logs",
			fmt.Sprintf("%d error(s) logged in the last hour", logs.ErrorCount), hints))
	} else if logs.ErrorCount > 10 {
		out = append(out, insight("INFO", "Logs",
			fmt.Sprintf("%d error(s) logged in the last hour — check if expected", logs.ErrorCount),
			[]string{"to inspect: journalctl -p err --since '1 hour ago' --no-pager"},
		))
	}
	return out
}

func checkEntropy(e models.EntropyInfo) []models.Insight {
	if !e.Available {
		return nil // not measured on this platform
	}
	if e.EntropyBits < 64 {
		return []models.Insight{insight("CRIT", "Entropy",
			fmt.Sprintf("entropy pool critically low (%d bits) — crypto operations may block or fail", e.EntropyBits),
			[]string{"to inspect: cat /proc/sys/kernel/random/entropy_avail", "to fix: install haveged or rng-tools"},
		)}
	}
	if e.EntropyBits < 256 {
		return []models.Insight{insight("WARN", "Entropy",
			fmt.Sprintf("entropy pool low (%d bits) — TLS and key generation may slow down", e.EntropyBits),
			[]string{"to inspect: cat /proc/sys/kernel/random/entropy_avail", "to fix: install haveged or rng-tools"},
		)}
	}
	return nil
}

func checkProcesses(proc models.ProcessInfo) []models.Insight {
	var out []models.Insight
	if proc.ZombieCount >= 10 {
		out = append(out, insight("CRIT", "Processes",
			fmt.Sprintf("%d zombie processes detected", proc.ZombieCount),
			[]string{"to inspect: ps aux | grep Z", "to inspect: cat /proc/*/status | grep -E '^Name|^State' | paste - -"},
		))
	} else if proc.ZombieCount > 0 {
		out = append(out, insight("WARN", "Processes",
			fmt.Sprintf("%d zombie process(es) detected", proc.ZombieCount),
			[]string{"to inspect: ps aux | grep Z"},
		))
	}
	if proc.HungCount >= 5 {
		out = append(out, insight("CRIT", "Processes",
			fmt.Sprintf("%d hung (uninterruptible) processes", proc.HungCount),
			[]string{"to inspect: ps aux | grep ' D '", "to inspect: for pid in $(ps -eo pid,stat | awk '$2~/D/{print $1}'); do cat /proc/$pid/wchan 2>/dev/null; done"},
		))
	} else if proc.HungCount > 0 {
		out = append(out, insight("WARN", "Processes",
			fmt.Sprintf("%d hung (uninterruptible) process(es)", proc.HungCount),
			[]string{"to inspect: ps aux | grep ' D '"},
		))
	}
	return out
}

func checkNVMe(n models.NVMeInfo) []models.Insight { //nolint:funlen // NVMe + SATA/SAS checks — each drive type is a distinct section
	var out []models.Insight

	// NVMe drives
	for _, dev := range n.Devices {
		if dev.CriticalWarning > 0 {
			out = append(out, insight("CRIT", "Drives",
				fmt.Sprintf("%s critical warning flag set (0x%02x) — drive may be failing", dev.Name, dev.CriticalWarning),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
		if dev.MediaErrors > 0 {
			out = append(out, insight("CRIT", "Drives",
				fmt.Sprintf("%s has %d media error(s) — data integrity risk", dev.Name, dev.MediaErrors),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
		if dev.AvailableSparePct > 0 && dev.AvailableSparePct <= dev.SpareThresholdPct {
			out = append(out, insight("CRIT", "Drives",
				fmt.Sprintf("%s spare capacity at %d%% (threshold: %d%%) — drive near end of life", dev.Name, dev.AvailableSparePct, dev.SpareThresholdPct),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		} else if dev.AvailableSparePct > 0 && dev.AvailableSparePct < 20 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s spare capacity low at %d%%", dev.Name, dev.AvailableSparePct),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
		if dev.PercentageUsed >= 90 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s wear at %d%% — consider replacement planning", dev.Name, dev.PercentageUsed),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
		if dev.TempC >= 70 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s temperature %g°C — elevated for NVMe", dev.Name, dev.TempC),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
		if dev.UnsafeShutdowns > 100 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s has %d unsafe shutdown(s) — power cuts risk filesystem corruption", dev.Name, dev.UnsafeShutdowns),
				[]string{"to inspect: nvme smart-log " + dev.Name, "to inspect: nvme list", "to fix: ensure clean shutdowns, check UPS"},
			))
		}
		if dev.PowerOnHours > 35000 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s has %d power-on hours (~%.1f years) — beyond typical consumer NVMe lifespan", dev.Name, dev.PowerOnHours, float64(dev.PowerOnHours)/8760),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
	}

	// SATA/SAS drives
	for _, dev := range n.SATADevices {
		if dev.Error != "" {
			continue
		}
		if !dev.SmartOK {
			out = append(out, insight("CRIT", "Drives",
				fmt.Sprintf("%s (%s) SMART check FAILED — drive may be failing", dev.Name, dev.Type),
				[]string{"to inspect: smartctl -a " + dev.Name},
			))
		}
		if dev.ReallocatedSectors > 0 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s has %d reallocated sector(s) — early sign of drive failure", dev.Name, dev.ReallocatedSectors),
				[]string{"to inspect: smartctl -a " + dev.Name},
			))
		}
		if dev.PendingSectors > 0 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s has %d pending sector(s) — unreadable sectors awaiting reallocation", dev.Name, dev.PendingSectors),
				[]string{"to inspect: smartctl -a " + dev.Name},
			))
		}
		if dev.UncorrectableErrors > 0 {
			out = append(out, insight("CRIT", "Drives",
				fmt.Sprintf("%s has %d uncorrectable error(s) — data loss risk", dev.Name, dev.UncorrectableErrors),
				[]string{"to inspect: smartctl -a " + dev.Name},
			))
		}
		if dev.TempC >= 55 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s (%s) temperature %d°C — elevated for SATA drive", dev.Name, dev.Type, dev.TempC),
				[]string{"to inspect: smartctl -a " + dev.Name},
			))
		}
		if dev.PowerOnHours > 43800 {
			out = append(out, insight("WARN", "Drives",
				fmt.Sprintf("%s (%s) has %d power-on hours (~%.1f years) — beyond typical HDD lifespan", dev.Name, dev.Type, dev.PowerOnHours, float64(dev.PowerOnHours)/8760),
				[]string{"to inspect: smartctl -a " + dev.Name},
			))
		}
	}

	return out
}

// checkZFS surfaces ZFS pool health issues: degraded state, capacity, errors, scrub age.
// ZFS is used heavily by Proxmox, TrueNAS-derived systems, and enterprise Linux.
func checkZFS(z models.ZFSInfo) []models.Insight {
	out := make([]models.Insight, 0, len(z.Pools))
	for _, pool := range z.Pools {
		out = append(out, checkZFSPool(pool)...)
	}
	return out
}

// checkZFSPool checks a single ZFS pool — extracted to keep funlen within linter limits.
func checkZFSPool(pool models.ZFSPool) []models.Insight { //nolint:funlen // flat list of independent pool checks
	var out []models.Insight

	// Pool state — anything other than ONLINE is a problem
	switch pool.State {
	case "DEGRADED":
		msg := fmt.Sprintf("ZFS pool %s is DEGRADED", pool.Name)
		if pool.StatusMsg != "" {
			msg += " — " + pool.StatusMsg
		}
		out = append(out, insight("CRIT", "ZFS", msg,
			[]string{
				fmt.Sprintf("to inspect: zpool status %s", pool.Name),
				fmt.Sprintf("to inspect: zpool events %s", pool.Name),
				"note: replace failed vdev and run: zpool replace <pool> <old> <new>",
				"note: data is at risk — restore redundancy immediately",
			},
		))
	case "FAULTED":
		out = append(out, insight("CRIT", "ZFS",
			fmt.Sprintf("ZFS pool %s is FAULTED — pool may be unrecoverable", pool.Name),
			[]string{
				fmt.Sprintf("to inspect: zpool status -v %s", pool.Name),
				"note: FAULTED means pool was taken offline due to unrecoverable error",
				"note: import with: zpool import -F <pool>  (force recovery, may lose data)",
			},
		))
	case "REMOVED", "UNAVAIL", "OFFLINE":
		out = append(out, insight("CRIT", "ZFS",
			fmt.Sprintf("ZFS pool %s state: %s", pool.Name, pool.State),
			[]string{
				fmt.Sprintf("to inspect: zpool status -v %s", pool.Name),
				fmt.Sprintf("to inspect: zpool events %s", pool.Name),
			},
		))
	}

	// Capacity — ZFS copy-on-write degrades badly above 80%, writes fail above 90%
	if l := levelPct(pool.UsedPct, 80, 90); l != "" {
		out = append(out, insight(l, "ZFS",
			fmt.Sprintf("ZFS pool %s is %.0f%% full (%.1f GB free of %.1f GB)",
				pool.Name, pool.UsedPct, pool.FreeGB, pool.SizeGB),
			[]string{
				fmt.Sprintf("to inspect: zfs list -r %s", pool.Name),
				"note: ZFS performance degrades significantly above 80% capacity",
				"note: above 90%, writes may fail — free space or expand pool",
				"to free space: zfs destroy <snapshot>  (remove old snapshots)",
			},
		))
	}

	// Fragmentation
	if pool.FragPct >= 70 {
		out = append(out, insight("WARN", "ZFS",
			fmt.Sprintf("ZFS pool %s fragmentation at %d%% — read/write amplification likely", pool.Name, pool.FragPct),
			[]string{
				fmt.Sprintf("to inspect: zpool list %s", pool.Name),
				"note: fragmentation above 70% causes significant performance degradation",
			},
		))
	} else if pool.FragPct >= 50 {
		out = append(out, insight("INFO", "ZFS",
			fmt.Sprintf("ZFS pool %s fragmentation at %d%%", pool.Name, pool.FragPct),
			[]string{fmt.Sprintf("to inspect: zpool list %s", pool.Name)},
		))
	}

	// Errors — any count is worth surfacing
	if total := pool.ReadErrors + pool.WriteErrors + pool.CksumErrors; total > 0 {
		out = append(out, insight("CRIT", "ZFS",
			fmt.Sprintf("ZFS pool %s has errors: %d read, %d write, %d checksum",
				pool.Name, pool.ReadErrors, pool.WriteErrors, pool.CksumErrors),
			[]string{
				fmt.Sprintf("to inspect: zpool status -v %s", pool.Name),
				"note: checksum errors indicate data corruption or bad hardware",
				"to clear counters: zpool clear <pool>  (only after fixing root cause)",
				"to run scrub: zpool scrub <pool>",
			},
		))
	}

	// Scrub age — periodic scrubs detect silent corruption
	switch {
	case pool.ScrubAgeDays < 0:
		out = append(out, insight("WARN", "ZFS",
			fmt.Sprintf("ZFS pool %s has never been scrubbed — silent corruption risk", pool.Name),
			[]string{
				fmt.Sprintf("to run scrub: zpool scrub %s", pool.Name),
				"note: monthly scrubs are recommended for all ZFS pools",
				"to automate: systemctl enable zfs-scrub.timer  (if available)",
			},
		))
	case pool.ScrubAgeDays > 30:
		out = append(out, insight("INFO", "ZFS",
			fmt.Sprintf("ZFS pool %s last scrubbed %d days ago (recommended: monthly)", pool.Name, pool.ScrubAgeDays),
			[]string{fmt.Sprintf("to run scrub: zpool scrub %s", pool.Name)},
		))
	}

	return out
}

// checkLVM surfaces LVM health issues: thin pool exhaustion, VG free space,
// snapshot overflow, and missing PVs. Thin pool exhaustion is the #1 silent
// failure in Proxmox/KVM environments — VMs freeze with no warning.
func checkLVM(l models.LVMInfo) []models.Insight {
	var out []models.Insight

	// Thin pool data and metadata usage — CRIT thresholds are tight because
	// exhaustion happens fast and recovery requires unmounting everything.
	for _, pool := range l.ThinPools {
		// Data exhaustion: 80% WARN, 90% CRIT
		if lv := levelPct(pool.DataPct, 80, 90); lv != "" {
			out = append(out, insight(lv, "LVM",
				fmt.Sprintf("thin pool %s/%s data at %.0f%% (%.1f GB total)",
					pool.VG, pool.Name, pool.DataPct, pool.SizeGB),
				[]string{
					fmt.Sprintf("to inspect: lvs %s/%s", pool.VG, pool.Name),
					fmt.Sprintf("to extend:  lvextend -l +50%%FREE %s/%s", pool.VG, pool.Name),
					"note: thin pool exhaustion silently freezes all VMs writing to it",
					"note: set lvm.conf thin_pool_autoextend_threshold=80 to auto-extend",
				},
			))
		}
		// Metadata exhaustion: 50% WARN, 75% CRIT (much more dangerous than data)
		// Metadata exhaustion cannot be easily recovered and requires pool deactivation.
		if lv := levelPct(pool.MetaPct, 50, 75); lv != "" {
			out = append(out, insight(lv, "LVM",
				fmt.Sprintf("thin pool %s/%s metadata at %.0f%% — metadata exhaustion is unrecoverable without deactivation",
					pool.VG, pool.Name, pool.MetaPct),
				[]string{
					fmt.Sprintf("to inspect: lvs %s/%s", pool.VG, pool.Name),
					fmt.Sprintf("to extend:  lvextend --poolmetadatasize +1G %s/%s", pool.VG, pool.Name),
					"note: metadata exhaustion is worse than data exhaustion — act immediately",
				},
			))
		}
	}

	// VG free space — skip inactive VGs (no mounted LVs = leftover OS partition)
	for _, vg := range l.VGs {
		if !vg.HasMountedLV {
			out = append(out, insight("INFO", "LVM",
				fmt.Sprintf("inactive volume group %s is %.0f%% full — no LVs mounted (old OS partition?)",
					vg.Name, 100-vg.FreePct),
				[]string{
					fmt.Sprintf("to inspect: vgs %s", vg.Name),
					fmt.Sprintf("to inspect: lvs | grep %s", vg.Name),
					"note: this VG has no mounted LVs on this OS — likely a leftover from a previous install",
				},
			))
			continue
		}
		if lv := levelPct(100-vg.FreePct, 90, 98); lv != "" {
			out = append(out, insight(lv, "LVM",
				fmt.Sprintf("volume group %s is %.0f%% full (%.1f GB free of %.1f GB)",
					vg.Name, 100-vg.FreePct, vg.FreeGB, vg.SizeGB),
				[]string{
					fmt.Sprintf("to inspect: vgs %s", vg.Name),
					fmt.Sprintf("to inspect: pvs | grep %s", vg.Name),
					"to add PV:  pvcreate /dev/<new-disk> && vgextend <vg> /dev/<new-disk>",
				},
			))
		}
		// Missing PVs — a PV has been removed or failed
		if vg.MissingPVs > 0 {
			out = append(out, insight("CRIT", "LVM",
				fmt.Sprintf("volume group %s has %d missing PV(s) — data at risk",
					vg.Name, vg.MissingPVs),
				[]string{
					fmt.Sprintf("to inspect: pvs | grep %s", vg.Name),
					fmt.Sprintf("to inspect: vgreduce --removemissing %s  (removes missing PVs)", vg.Name),
					"note: missing PVs mean LVs on that device are inaccessible",
				},
			))
		}
	}

	// Snapshots — COW table overflow corrupts the snapshot
	for _, snap := range l.Snapshots {
		if lv := levelPct(snap.DataPct, 80, 95); lv != "" {
			out = append(out, insight(lv, "LVM",
				fmt.Sprintf("snapshot %s/%s is %.0f%% full — overflow will corrupt the snapshot",
					snap.VG, snap.Name, snap.DataPct),
				[]string{
					fmt.Sprintf("to inspect: lvs %s/%s", snap.VG, snap.Name),
					fmt.Sprintf("to extend:  lvextend -L +1G %s/%s", snap.VG, snap.Name),
					fmt.Sprintf("to remove:  lvremove %s/%s  (if snapshot is no longer needed)", snap.VG, snap.Name),
				},
			))
		}
	}

	return out
}

// checkDRBD surfaces DRBD replication issues: disconnection, split brain,
// disk state degradation, and sync progress. DRBD is used in Pacemaker/
// Corosync clusters — a split brain or disconnection means the HA layer
// is no longer protecting against node failure.
// checkDRBD surfaces DRBD resource health issues: split-brain, disconnected
// peer, inconsistent disk, and sync progress.
// DRBD is commonly used in Pacemaker/Corosync clusters for block device HA.
// checkPVE surfaces Proxmox VE host health issues.
// Silent no-op on non-Proxmox hosts.
func checkPVE(p models.PVEInfo) []models.Insight {
	if !p.IsPVE {
		return nil
	}
	if p.NeedsRoot {
		return []models.Insight{insight("INFO", "PVE",
			"Proxmox VE detected — run as root for full cluster/storage/backup checks",
			[]string{"to run: sudo dsd health"},
		)}
	}
	out := make([]models.Insight, 0, 8)
	out = append(out, checkPVESubscription(p)...)
	out = append(out, checkPVECluster(p)...)
	out = append(out, checkPVEStorage(p)...)
	out = append(out, checkPVEBackups(p)...)
	return out
}

func checkPVESubscription(p models.PVEInfo) []models.Insight {
	switch p.Subscription.Status {
	case "notfound", "":
		return []models.Insight{insight("WARN", "PVE",
			"no Proxmox VE subscription — security updates require an active subscription",
			[]string{
				"note: without a subscription, security patches lag behind the enterprise repo",
				"to subscribe: https://www.proxmox.com/en/proxmox-ve/pricing",
			},
		)}
	case "expired":
		return []models.Insight{insight("CRIT", "PVE",
			"Proxmox VE subscription has EXPIRED — no access to security updates",
			[]string{
				"to renew: https://www.proxmox.com/en/proxmox-ve/pricing",
				"to inspect: pvesh get /nodes/localhost/subscription",
			},
		)}
	}
	return nil
}

func checkPVECluster(p models.PVEInfo) []models.Insight {
	out := make([]models.Insight, 0, 4)

	if !p.QuorumOK {
		out = append(out, insight("CRIT", "PVE",
			"cluster quorum LOST — VMs cannot start or migrate until quorum is restored",
			[]string{
				"to inspect: pvecm status",
				"to inspect: systemctl status corosync pve-cluster",
				"note: do not force quorum unless certain of network partition vs node failure",
			},
		))
	}

	if !p.HAFencingOK {
		out = append(out, insight("CRIT", "PVE",
			"HA fencing device unreachable — "+p.HAFencingMsg,
			[]string{
				"to inspect: pvecm status",
				"to inspect: ha-manager status",
				"note: without fencing, HA cannot safely restart VMs from a failed node",
			},
		))
	}

	if len(p.Nodes) > 1 {
		versions := map[string]bool{}
		for _, n := range p.Nodes {
			if n.Version != "" {
				versions[n.Version] = true
			}
		}
		if len(versions) > 1 {
			out = append(out, insight("WARN", "PVE",
				fmt.Sprintf("cluster has mixed PVE versions across %d nodes — live migration may fail", len(p.Nodes)),
				[]string{
					"to inspect: pvecm status",
					"to fix: apt update && apt full-upgrade  (on each node, one at a time)",
				},
			))
		}
		for _, n := range p.Nodes {
			if !n.Online {
				out = append(out, insight("CRIT", "PVE",
					fmt.Sprintf("cluster node %s is OFFLINE", n.Name),
					[]string{
						"to inspect: pvecm status",
						fmt.Sprintf("to inspect: ssh root@%s 'systemctl status pve-cluster corosync'", n.Name),
					},
				))
			}
		}
	}
	return out
}

func checkPVEStorage(p models.PVEInfo) []models.Insight {
	var out []models.Insight
	for _, s := range p.Storages {
		if !s.Active {
			out = append(out, insight("CRIT", "PVE",
				fmt.Sprintf("storage %s (%s) is INACTIVE", s.Name, s.Type),
				[]string{
					"to inspect: pvesm status",
					fmt.Sprintf("to inspect: pvesh get /nodes/localhost/storage/%s/status", s.Name),
				},
			))
			continue
		}
		if l := levelPct(s.UsedPct, 80, 90); l != "" {
			out = append(out, insight(l, "PVE",
				fmt.Sprintf("storage %s (%s) is %.0f%% full (%.1f GB free of %.1f GB)",
					s.Name, s.Type, s.UsedPct, s.TotalGB-s.UsedGB, s.TotalGB),
				[]string{
					"to inspect: pvesm status",
					"note: full storage prevents VM disk writes and snapshot creation",
					"to free: remove old backups, snapshots, or ISO images",
				},
			))
		}
	}
	return out
}

func checkPVEBackups(p models.PVEInfo) []models.Insight {
	var out []models.Insight
	switch {
	case p.BackupAgeDays < 0:
		out = append(out, insight("WARN", "PVE",
			"no successful backup found — VMs have no recovery point",
			[]string{
				"to inspect: pvesh get /nodes/localhost/tasks --typefilter vzdump",
				"to schedule: Datacenter → Backup → Add",
			},
		))
	case p.BackupAgeDays > 7:
		out = append(out, insight("WARN", "PVE",
			fmt.Sprintf("last successful backup was %d days ago", p.BackupAgeDays),
			[]string{
				"to inspect: pvesh get /nodes/localhost/tasks --typefilter vzdump",
				"to run now: vzdump --all --compress zstd --storage local",
			},
		))
	}
	failed := 0
	for _, t := range p.RecentBackups {
		if t.Status != "OK" {
			failed++
		}
	}
	if failed > 0 {
		out = append(out, insight("WARN", "PVE",
			fmt.Sprintf("%d backup task(s) failed in the last 7 days", failed),
			[]string{
				"to inspect: pvesh get /nodes/localhost/tasks --typefilter vzdump",
				"to inspect: ls /var/log/vzdump/",
			},
		))
	}
	return out
}

func checkDRBD(d models.DRBDInfo) []models.Insight {
	out := make([]models.Insight, 0, len(d.Resources))
	for _, res := range d.Resources {
		out = append(out, checkDRBDResource(res)...)
	}
	return out
}

// checkDRBDResource checks a single DRBD resource.
func checkDRBDResource(res models.DRBDResource) []models.Insight { //nolint:funlen // flat list of independent DRBD state checks
	var out []models.Insight
	name := fmt.Sprintf("drbd%d", res.Minor)

	// Connection state — the most critical signal
	switch res.ConnState {
	case "SplitBrain":
		// Split-brain: both nodes diverged and have different data.
		// This requires manual resolution — data loss is possible.
		out = append(out, insight("CRIT", "DRBD",
			fmt.Sprintf("%s: SPLIT-BRAIN detected — both nodes have diverged, manual resolution required", name),
			[]string{
				"note: split-brain means both nodes accepted conflicting writes",
				"to resolve (discard secondary): drbdadm secondary <resource>",
				"to resolve (discard secondary): drbdadm disconnect <resource>",
				"to resolve (discard secondary): drbdadm -- --discard-my-data connect <resource>",
				"to resolve (on primary):         drbdadm connect <resource>",
				"warning: always decide which node has authoritative data first",
			},
		))
	case "StandAlone":
		// StandAlone: not connected to peer, operating without replication.
		out = append(out, insight("CRIT", "DRBD",
			fmt.Sprintf("%s: STANDALONE — not connected to peer, no replication active", name),
			[]string{
				"to inspect: cat /proc/drbd",
				fmt.Sprintf("to reconnect: drbdadm connect %s", name),
				"note: data is not being replicated — single point of failure",
			},
		))
	case "WFConnection":
		// Waiting for connection — peer may be down or network issue
		out = append(out, insight("WARN", "DRBD",
			fmt.Sprintf("%s: waiting for peer connection (WFConnection) — peer may be down", name),
			[]string{
				fmt.Sprintf("to inspect: drbdadm status %s", name),
				"to inspect: ping <peer-ip>",
				"to inspect: dmesg | grep -i drbd",
			},
		))
	case "Disconnecting":
		out = append(out, insight("WARN", "DRBD",
			fmt.Sprintf("%s: disconnecting from peer", name),
			[]string{fmt.Sprintf("to inspect: drbdadm status %s", name)},
		))
	case "SyncSource", "SyncTarget":
		// Syncing — degraded but recoverable. Show progress.
		msg := fmt.Sprintf("%s: syncing (%.1f%% complete", name, res.SyncPct)
		if res.SyncKBLeft > 0 {
			msg += fmt.Sprintf(", %d MB remaining", res.SyncKBLeft/1024)
		}
		msg += ")"
		out = append(out, insight("INFO", "DRBD", msg,
			[]string{
				"to monitor: watch -n2 cat /proc/drbd",
				"note: do not restart the cluster until sync completes",
			},
		))
	}

	// Disk state — local disk health
	switch res.LocalDisk {
	case "Failed":
		out = append(out, insight("CRIT", "DRBD",
			fmt.Sprintf("%s: local disk state FAILED — underlying device has errors", name),
			[]string{
				fmt.Sprintf("to inspect: drbdadm status %s", name),
				"to inspect: dmesg | grep -E 'drbd|sda|sdb|nvme'",
				"to inspect: smartctl -a /dev/<underlying-device>",
			},
		))
	case "Detached":
		out = append(out, insight("CRIT", "DRBD",
			fmt.Sprintf("%s: local disk DETACHED — DRBD is not connected to underlying block device", name),
			[]string{
				fmt.Sprintf("to reattach: drbdadm attach %s", name),
				fmt.Sprintf("to inspect:  drbdadm status %s", name),
			},
		))
	case "Inconsistent":
		// Inconsistent during sync is normal — flag only if not syncing
		if res.ConnState != "SyncSource" && res.ConnState != "SyncTarget" {
			out = append(out, insight("CRIT", "DRBD",
				fmt.Sprintf("%s: local disk INCONSISTENT and not syncing", name),
				[]string{
					fmt.Sprintf("to inspect: drbdadm status %s", name),
					fmt.Sprintf("to force sync: drbdadm -- --overwrite-data-of-peer primary %s", name),
					"warning: only use --overwrite-data-of-peer if you are certain this node has correct data",
				},
			))
		}
	case "Outdated":
		out = append(out, insight("WARN", "DRBD",
			fmt.Sprintf("%s: local disk OUTDATED — peer has newer data", name),
			[]string{
				fmt.Sprintf("to inspect: drbdadm status %s", name),
				"note: disk will sync automatically when peer connection is restored",
			},
		))
	}

	return out
}

// checkRAID surfaces degraded or failed mdadm RAID arrays from /proc/mdstat.
// A degraded array has lost redundancy — one more drive failure means data loss.
func checkRAID(r models.RAIDInfo) []models.Insight {
	var out []models.Insight
	for _, arr := range r.Arrays {
		switch arr.State {
		case "degraded":
			out = append(out, insight("CRIT", "RAID",
				fmt.Sprintf("%s (%s) is DEGRADED — %d/%d drives active, failed: %s",
					arr.Name, arr.Level, arr.Active, arr.Total, strings.Join(arr.Failed, ", ")),
				[]string{
					"to inspect: cat /proc/mdstat",
					fmt.Sprintf("to inspect: mdadm --detail /dev/%s", arr.Name),
					"note: replace the failed drive and run: mdadm --add /dev/<array> /dev/<new-drive>",
					"note: data is at risk until redundancy is restored",
				},
			))
		case "recovering":
			out = append(out, insight("WARN", "RAID",
				fmt.Sprintf("%s (%s) is REBUILDING — %.1f%% complete",
					arr.Name, arr.Level, arr.RebuildPct),
				[]string{
					"to inspect: cat /proc/mdstat",
					"note: array is degraded during rebuild — avoid further drive failures",
					"note: rebuild progress updates every ~30s in /proc/mdstat",
				},
			))
		case "failed":
			out = append(out, insight("CRIT", "RAID",
				fmt.Sprintf("%s is FAILED — array is not operational", arr.Name),
				[]string{
					fmt.Sprintf("to inspect: mdadm --detail /dev/%s", arr.Name),
					"to inspect: dmesg | grep -i mdadm",
					"note: data may be lost — check individual drive health with smartctl",
				},
			))
		}
	}
	return out
}

func checkBattery(b models.BatteryInfo) []models.Insight {
	if !b.Present {
		return nil // desktop or no battery
	}
	var out []models.Insight

	// Battery wear
	if b.HealthPct > 0 {
		if b.HealthPct < 60 {
			out = append(out, insight("CRIT", "Battery",
				fmt.Sprintf("battery health at %.0f%% — replacement recommended", b.HealthPct),
				[]string{"to inspect: cat /sys/class/power_supply/BAT0/energy_full_design"},
			))
		} else if b.HealthPct < 80 {
			out = append(out, insight("WARN", "Battery",
				fmt.Sprintf("battery health at %.0f%% (%.0f cycle(s)) — degraded", b.HealthPct, float64(b.CycleCounts)),
				[]string{"to inspect: cat /sys/class/power_supply/BAT0/energy_full"},
			))
		}
	}

	// Low charge while discharging
	if b.Status == "Discharging" && b.CapacityPct <= 10 {
		out = append(out, insight("CRIT", "Battery",
			fmt.Sprintf("battery at %d%% and discharging — connect power", b.CapacityPct),
			nil,
		))
	} else if b.Status == "Discharging" && b.CapacityPct <= 20 {
		out = append(out, insight("WARN", "Battery",
			fmt.Sprintf("battery at %d%% and discharging", b.CapacityPct),
			nil,
		))
	}

	return out
}

func checkThermal(t models.ThermalInfo, thresh Thresholds) []models.Insight {
	if t.CPUTempC == 0 || t.Source == "" {
		return nil // no thermal data available on this platform
	}
	hints := []string{
		"to inspect: cat /sys/class/hwmon/hwmon*/temp*_input",
		"to inspect: check cooling and airflow",
	}
	if t.CPUTempC >= 95 {
		return []models.Insight{insight("CRIT", "CPU Thermal",
			fmt.Sprintf("CPU temperature %g°C — thermal throttling active", t.CPUTempC),
			hints,
		)}
	}
	if t.CPUTempC >= 85 {
		return []models.Insight{insight("WARN", "CPU Thermal",
			fmt.Sprintf("CPU temperature %g°C — elevated (source: %s)", t.CPUTempC, t.Source),
			hints,
		)}
	}
	// Load-aware idle thermal check:
	// High temp at low CPU load suggests poor cooling (dried paste, blocked vents)
	// rather than normal workload heat. Only warn if we actually have load data.
	// Threshold: >60°C when CPU is under 20% load.
	if thresh.CPULoadPct > 0 && t.CPUTempC >= 60 && thresh.CPULoadPct < 20 {
		return []models.Insight{insight("WARN", "CPU Thermal",
			fmt.Sprintf("CPU temperature %g°C at %.0f%% load — elevated for low CPU activity, possible cooling issue",
				t.CPUTempC, thresh.CPULoadPct),
			[]string{
				"to inspect: cat /sys/class/hwmon/hwmon*/temp*_input",
				"to inspect: check for dust buildup and blocked vents",
				"to inspect: consider reseating thermal paste on older hardware",
			},
		)}
	}
	return nil
}

func checkGPU(gpu models.GPUInfo) []models.Insight {
	if len(gpu.Devices) == 0 && gpu.Status == "" {
		return nil // no GPU or driver not loaded — skip silently
	}
	var out []models.Insight

	// NVIDIA detected but driver/nvidia-smi not available
	if gpu.Status == "nvidia-no-driver" {
		out = append(out, insight("INFO", "GPU",
			"NVIDIA GPU detected — install driver for GPU health monitoring",
			[]string{
				"to fix (Ubuntu/Mint): apt-get install nvidia-driver-535",
				"to fix (RHEL/Fedora): dnf install akmod-nvidia",
				"to inspect: lspci | grep -i nvidia",
				"note: reboot required after driver install",
			},
		))
	}

	for _, dev := range gpu.Devices {
		prefix := dev.Name
		if len(gpu.Devices) > 1 {
			prefix = fmt.Sprintf("GPU%d (%s)", dev.Index, dev.Name)
		}
		if dev.TempC >= 90 {
			out = append(out, insight("CRIT", "GPU",
				fmt.Sprintf("%s temperature %d°C — thermal throttling likely", prefix, dev.TempC),
				[]string{"to inspect: nvidia-smi", "to inspect: check cooling and airflow"},
			))
		} else if dev.TempC >= 80 {
			out = append(out, insight("WARN", "GPU",
				fmt.Sprintf("%s temperature %d°C — elevated", prefix, dev.TempC),
				[]string{"to inspect: nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader"},
			))
		}
		if l := levelPct(dev.MemUsedPct, 85, 95); l != "" {
			out = append(out, insight(l, "GPU",
				fmt.Sprintf("%s VRAM usage at %.0f%% (%d/%d MB)", prefix, dev.MemUsedPct, dev.MemUsedMB, dev.MemTotalMB),
				[]string{"to inspect: nvidia-smi --query-gpu=memory.used,memory.total --format=csv"},
			))
		}
		if dev.XidErrors > 0 {
			out = append(out, insight("CRIT", "GPU",
				fmt.Sprintf("%s %d Xid error(s) in the last hour — hardware fault detected", prefix, dev.XidErrors),
				[]string{"to inspect: dmesg | grep 'NVRM: Xid'", "to inspect: nvidia-smi -q | grep -A2 'Xid'"},
			))
		}
		// Sustained compute load — INFO signal for correlation engine.
		// Not a fault on its own, but provides context when combined with
		// thermal or memory pressure signals.
		if dev.UtilPct >= 80 && dev.PowerDrawW >= 80 {
			out = append(out, insight("INFO", "GPU",
				fmt.Sprintf("%s sustained compute load — util %d%%, %.0fW", prefix, dev.UtilPct, dev.PowerDrawW),
				nil,
			))
		}
	}
	return out
}

func checkSecurity(sec models.SecurityInfo) []models.Insight { //nolint:funlen,cyclop // security checks are a flat list of independent conditions; splitting would harm readability
	var out []models.Insight

	if sec.NeedsRoot {
		out = append(out, insight("INFO", "Hardening",
			"some checks limited — run as root for port process names, failed logins, and SELinux audit log",
			nil,
		))
	}

	// SSH misconfigurations
	if sec.SSHPermitRoot {
		// On offensive/pentest distros (Kali, Parrot), root SSH is intentional.
		// Downgrade to INFO with a note rather than CRIT.
		if sec.IsOffensiveDistro {
			out = append(out, insight("INFO", "Hardening",
				"SSH root login enabled — expected on offensive security distro (Kali/Parrot)",
				nil,
			))
		} else {
			out = append(out, insight("CRIT", "Hardening",
				"SSH permits root login",
				[]string{"to fix: set PermitRootLogin no in /etc/ssh/sshd_config", "to fix: systemctl restart sshd"},
			))
		}
	}
	if sec.SSHPasswordAuth {
		if sec.IsOffensiveDistro {
			out = append(out, insight("INFO", "Hardening",
				"SSH password auth enabled — expected on offensive security distro (Kali/Parrot)",
				nil,
			))
		} else {
			out = append(out, insight("WARN", "Hardening",
				"SSH allows password authentication — key-based auth recommended",
				[]string{"to fix: set PasswordAuthentication no in /etc/ssh/sshd_config"},
			))
		}
	}

	// ── SSH config audit — additional CIS checks ──────────────────────────

	// Protocol 1 is cryptographically broken (DES, 1990s-era)
	if sec.SSHProtocol1 {
		out = append(out, insight("CRIT", "Hardening",
			"SSH Protocol 1 is enabled — cryptographically broken, remove from sshd_config",
			[]string{
				"to fix: remove or comment out 'Protocol' line in /etc/ssh/sshd_config",
				"note: modern OpenSSH only supports Protocol 2 — this line has no effect unless very old",
			},
		))
	}

	// PermitEmptyPasswords — allows login with no password at all
	if sec.SSHPermitEmptyPwd {
		out = append(out, insight("CRIT", "Hardening",
			"SSH allows empty passwords — any account with no password is remotely accessible",
			[]string{
				"to fix: set PermitEmptyPasswords no in /etc/ssh/sshd_config",
				"to fix: systemctl restart sshd",
				"to audit: awk -F: '($2==\"\"){print $1}' /etc/shadow",
			},
		))
	}

	// StrictModes disabled — sshd won't check file permissions on ~/.ssh
	// This allows world-writable authorized_keys to be used (privilege escalation vector)
	if !sec.SSHStrictModes {
		out = append(out, insight("WARN", "Hardening",
			"SSH StrictModes disabled — sshd will not check ~/.ssh file permissions",
			[]string{
				"to fix: set StrictModes yes in /etc/ssh/sshd_config",
				"note: without StrictModes, world-writable authorized_keys files are accepted",
			},
		))
	}

	// MaxAuthTries > 6 — too many attempts before disconnect (brute force risk)
	// CIS benchmark recommends ≤ 4; we warn at > 6 to avoid noise on defaults
	if sec.SSHMaxAuthTries > 6 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("SSH MaxAuthTries is %d — reduce to 4 or fewer to limit brute force attempts", sec.SSHMaxAuthTries),
			[]string{
				"to fix: set MaxAuthTries 4 in /etc/ssh/sshd_config",
				"to fix: systemctl restart sshd",
			},
		))
	}

	// LoginGraceTime > 60s — long window for unauthenticated connections (DoS risk)
	// Default is 120s in older OpenSSH; CIS recommends ≤ 60s
	if sec.SSHLoginGraceTime > 60 {
		out = append(out, insight("INFO", "Hardening",
			fmt.Sprintf("SSH LoginGraceTime is %ds — recommend ≤60s to limit unauthenticated connection window",
				sec.SSHLoginGraceTime),
			[]string{
				"to fix: set LoginGraceTime 60 in /etc/ssh/sshd_config",
				"to fix: systemctl restart sshd",
			},
		))
	}

	// X11Forwarding — attack surface on servers, should be off
	if sec.SSHX11Forwarding && !sec.IsOffensiveDistro {
		out = append(out, insight("INFO", "Hardening",
			"SSH X11Forwarding enabled — unnecessary on servers, increases attack surface",
			[]string{
				"to fix: set X11Forwarding no in /etc/ssh/sshd_config",
				"note: only needed if users require GUI applications over SSH",
			},
		))
	}

	// AgentForwarding — allows attackers with root on a jump host to use your keys
	if sec.SSHAgentForwarding && !sec.IsOffensiveDistro {
		out = append(out, insight("INFO", "Hardening",
			"SSH AgentForwarding enabled — if this server is compromised, agent keys on your laptop can be stolen",
			[]string{
				"to fix: set AllowAgentForwarding no in /etc/ssh/sshd_config",
				"note: use ssh -A explicitly when you need forwarding, rather than leaving it on globally",
			},
		))
	}

	// ClientAliveInterval = 0 — no idle timeout; sessions left open indefinitely
	if sec.SSHClientAliveInterval == 0 && !sec.IsOffensiveDistro {
		out = append(out, insight("INFO", "Hardening",
			"SSH idle timeout not set — sessions stay open indefinitely (set ClientAliveInterval)",
			[]string{
				"to fix: set ClientAliveInterval 300 in /etc/ssh/sshd_config",
				"to fix: set ClientAliveCountMax 3 in /etc/ssh/sshd_config",
				"note: this disconnects idle sessions after 300s × 3 = 15 minutes",
			},
		))
	}

	// AllowUsers / AllowGroups — informational: good hygiene if configured
	// No WARN — absence isn't a misconfiguration, just an opportunity to note best practice
	// (already surfaced via password auth and root login checks)

	// ── Weak SSH algorithms (sshd -T or file parse) ───────────────────────────
	// Check only when we have algorithm data (non-empty strings from sshd -T or config).
	out = append(out, checkSSHWeakCiphers(sec)...)
	out = append(out, checkSSHWeakMACs(sec)...)
	out = append(out, checkSSHWeakKEX(sec)...)

	// Failed logins
	if sec.FailedLogins >= 20 {
		msg := fmt.Sprintf("%d failed login attempts in the last hour", sec.FailedLogins)
		if len(sec.FailedLoginIPs) > 0 {
			msg += fmt.Sprintf(" — top sources: %s", strings.Join(sec.FailedLoginIPs[:min(3, len(sec.FailedLoginIPs))], ", "))
		}
		out = append(out, insight("CRIT", "Hardening", msg,
			[]string{"to inspect: journalctl _COMM=sshd | grep -E 'Failed|penalty' | tail -20", "to inspect: last -f /var/log/wtmp | head -20", "to fix: consider fail2ban or firewall rules"},
		))
	} else if sec.FailedLogins >= 5 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d failed login attempts in the last hour", sec.FailedLogins),
			[]string{"to inspect: journalctl _COMM=sshd | grep -E 'Failed|penalty' | tail -20"},
		))
	}

	// Unexpected listening ports — split into known services (INFO) vs truly unexpected (WARN)
	// Known service processes are auto-detected and downgraded to INFO with context.
	knownServiceProcesses := map[string]string{
		// Kubernetes / k8s distributions
		"kubelite":        "k8s/microk8s",
		"kubelet":         "k8s",
		"kube-apiserver":  "k8s",
		"kube-scheduler":  "k8s",
		"kube-controller": "k8s",
		"cluster-agent":   "k8s/microk8s",
		"containerd":      "container-runtime",
		"dockerd":         "docker",
		// Observability
		"prometheus":    "prometheus",
		"node_exporter": "prometheus",
		"grafana":       "grafana",
		"alertmanager":  "prometheus",
		// Databases
		"mysqld":       "mysql",
		"postgres":     "postgresql",
		"mongod":       "mongodb",
		"redis-server": "redis",
		// Web/proxy
		"nginx":   "nginx",
		"apache2": "apache",
		"httpd":   "apache",
		"traefik": "traefik",
		"haproxy": "haproxy",
	}

	var unexpectedPorts []string
	var knownPorts []string
	var knownServices []string
	var portHints []string
	portHints = append(portHints, "to inspect: ss -tlnp")

	for _, p := range sec.ListeningPorts {
		if p.Expected {
			continue
		}
		portStr := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		// Check if process is a known service
		serviceName := ""
		for proc, svc := range knownServiceProcesses {
			if strings.Contains(strings.ToLower(p.Process), proc) {
				serviceName = svc
				break
			}
		}
		if serviceName != "" {
			knownPorts = append(knownPorts, portStr)
			if !containsStr(knownServices, serviceName) {
				knownServices = append(knownServices, serviceName)
			}
		} else {
			unexpectedPorts = append(unexpectedPorts, portStr)
			portHints = append(portHints, fmt.Sprintf("to inspect: ss -tlnp | grep :%d", p.Port))
		}
	}

	// Known services — downgrade to INFO
	if len(knownPorts) > 0 {
		out = append(out, insight("INFO", "Hardening",
			fmt.Sprintf("%d port(s) from known service(s) (%s) listening on all interfaces — consider binding to specific interfaces in production",
				len(knownPorts), strings.Join(knownServices, ", ")),
			[]string{
				"to inspect: ss -tlnp",
				"to restrict: bind service to specific interface/IP instead of 0.0.0.0",
			},
		))
	}
	// Truly unexpected ports — keep as WARN
	if len(unexpectedPorts) > 0 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d unexpected port(s) listening on all interfaces: %s",
				len(unexpectedPorts), strings.Join(unexpectedPorts, ", ")),
			portHints,
		))
	}

	// Cockpit (port 9090) — informational: management UI exposed
	for _, p := range sec.ListeningPorts {
		if p.Port == 9090 {
			out = append(out, insight("INFO", "Hardening",
				"Cockpit management UI listening on port 9090 — ensure it is not exposed to the internet",
				[]string{
					"to inspect: systemctl status cockpit",
					"to restrict: configure AllowUnencrypted=false in /etc/cockpit/cockpit.conf",
					"to restrict: limit access with firewall-cmd --add-rich-rule",
				},
			))
			break
		}
	}

	// Firewall
	if sec.FirewallActive && !sec.SSHAllowed {
		out = append(out, insight("CRIT", "Hardening",
			fmt.Sprintf("firewall (%s) active but SSH (port 22) not in allowed services — you may lose remote access after reconnect", sec.FirewallType),
			[]string{
				"to fix (firewalld): firewall-cmd --add-service=ssh --permanent && firewall-cmd --reload",
				"to fix (ufw): ufw allow ssh",
			},
		))
	}

	// Sudo NOPASSWD
	if len(sec.SudoNopasswd) > 0 {
		// On offensive distros (Kali, Parrot), NOPASSWD groups like %kali-trusted
		// and service accounts like _gvm are intentional defaults — downgrade to INFO.
		if sec.IsOffensiveDistro {
			out = append(out, insight("INFO", "Hardening",
				fmt.Sprintf("NOPASSWD sudo for: %s — expected on offensive security distro", strings.Join(sec.SudoNopasswd, ", ")),
				nil,
			))
		} else {
			out = append(out, insight("WARN", "Hardening",
				fmt.Sprintf("NOPASSWD sudo for: %s", strings.Join(sec.SudoNopasswd, ", ")),
				[]string{"to inspect: sudo -l", "to inspect: cat /etc/sudoers"},
			))
		}
	}

	// Unexpected SUID binaries
	if len(sec.SUIDBinaries) > 0 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d unexpected SUID binary(ies): %s", len(sec.SUIDBinaries),
				strings.Join(sec.SUIDBinaries[:min(3, len(sec.SUIDBinaries))], ", ")),
			[]string{"to inspect: find / -perm -4000 -type f 2>/dev/null"},
		))
	}

	// Non-root users with UID 0 — always CRIT
	if len(sec.UID0Users) > 0 {
		out = append(out, insight("CRIT", "Hardening",
			fmt.Sprintf("non-root user(s) with UID 0: %s", strings.Join(sec.UID0Users, ", ")),
			[]string{"to inspect: awk -F: '$3==0' /etc/passwd", "to inspect: getent passwd | awk -F: '$3==0'", "to fix: remove or reassign UID for affected accounts"},
		))
	}

	// Suspect cron entries
	if len(sec.SuspectCrons) > 0 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d suspect cron entry(ies) — pipes to shell or writes to sensitive paths", len(sec.SuspectCrons)),
			[]string{"to inspect: cat /etc/cron.d/* /var/spool/cron/crontabs/*", "to inspect: review entries piping to bash or wget/curl"},
		))
	}

	// SELinux denials — skip sentinel value (-1 = data unavailable)
	if sec.SELinuxDenials >= 10 {
		msg := fmt.Sprintf("%d SELinux denials in the last hour (mode: %s)", sec.SELinuxDenials, sec.SELinuxMode)
		hints := []string{
			"to inspect: ausearch -m avc -ts recent",
			"to inspect: sealert -a /var/log/audit/audit.log",
		}
		// Surface grouped AVC findings with fix commands
		for _, g := range sec.SELinuxAVCGroups {
			if g.Count < 3 {
				continue // skip rare one-offs
			}
			summary := fmt.Sprintf("  %s → %s [%s] ×%d", g.Scontext, g.Tcontext, g.Tclass, g.Count)
			if g.BooleanFix != "" {
				summary += fmt.Sprintf("  fix: setsebool -P %s on", g.BooleanFix)
			} else if g.FixCmd != "" {
				summary += fmt.Sprintf("  fix: %s", truncateSELinux(g.FixCmd, 80))
			}
			hints = append(hints, summary)
		}
		out = append(out, insight("WARN", "Hardening", msg, hints))
	}

	// RHEL/Rocky: crypto-policies — LEGACY is a security risk
	if sec.CryptoPolicy == "LEGACY" {
		out = append(out, insight("WARN", "Hardening",
			"system-wide crypto policy is LEGACY — weak algorithms (MD5, SHA-1, DH<1024) are permitted",
			[]string{
				"to inspect: update-crypto-policies --show",
				"to fix: update-crypto-policies --set DEFAULT",
			},
		))
	}

	// RHEL/Rocky: auditd running but no rules — security theater
	if sec.AuditRules == 0 && sec.SELinuxMode != "" {
		out = append(out, insight("WARN", "Hardening",
			"auditd is running but has no active rules — system calls and file access are not being audited",
			[]string{
				"to inspect: auditctl -l",
				"to fix: augenrules --load or add rules to /etc/audit/rules.d/",
			},
		))
	}

	// RHEL/Rocky: AIDE installed but database never initialised
	if sec.AIDEInstalled && !sec.AIDEDBExists {
		out = append(out, insight("WARN", "Hardening",
			"AIDE is installed but database has never been initialised — file integrity monitoring is inactive",
			[]string{
				"to fix: aide --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db",
			},
		))
	}

	// RHEL/Rocky: AIDE database stale (> 7 days)
	if sec.AIDEInstalled && sec.AIDEDBExists && sec.AIDELastRunDays > 7 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("AIDE file integrity database is %d day(s) old — run a fresh check", sec.AIDELastRunDays),
			[]string{
				"to fix: aide --check",
				"to automate: add 'aide --check' to cron or systemd timer",
			},
		))
	}

	// SUSE supportconfig — stale or never run
	if sec.SupportconfigAvailable {
		switch {
		case sec.SupportconfigLastRunDays == -1:
			out = append(out, insight("INFO", "Hardening",
				"supportconfig available but never run — collect before opening SUSE support ticket",
				[]string{"to run: supportconfig", "archives saved to /var/log/scc_*.txz"},
			))
		case sec.SupportconfigLastRunDays > 30:
			out = append(out, insight("INFO", "Hardening",
				fmt.Sprintf("supportconfig last run %d day(s) ago — consider refreshing before a support call", sec.SupportconfigLastRunDays),
				[]string{"to run: supportconfig"},
			))
		}
	}

	// SUSEConnect subscription expiry
	if sec.SUSEConnectRegistered {
		switch {
		case sec.SUSEConnectExpiresDays == 0:
			out = append(out, insight("CRIT", "Hardening",
				"SUSEConnect subscription EXPIRED — security patches no longer available",
				[]string{"to fix: renew subscription at https://scc.suse.com"},
			))
		case sec.SUSEConnectExpiresDays > 0 && sec.SUSEConnectExpiresDays <= 14:
			out = append(out, insight("CRIT", "Hardening",
				fmt.Sprintf("SUSEConnect subscription expires in %d day(s) — renew immediately", sec.SUSEConnectExpiresDays),
				[]string{"to fix: renew subscription at https://scc.suse.com"},
			))
		case sec.SUSEConnectExpiresDays > 14 && sec.SUSEConnectExpiresDays <= 30:
			out = append(out, insight("WARN", "Hardening",
				fmt.Sprintf("SUSEConnect subscription expires in %d day(s)", sec.SUSEConnectExpiresDays),
				[]string{"to fix: renew subscription at https://scc.suse.com"},
			))
		}
	}

	// User account hardening (Spec 14)
	out = append(out, checkEmptyPasswords(sec)...)
	out = append(out, checkStalePasswords(sec)...)
	out = append(out, checkWorldWritable(sec)...)

	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func checkPackages(pkg models.PackagesInfo) []models.Insight {
	var out []models.Insight

	// No security repo configured — warn explicitly rather than showing zero.
	if pkg.Status == "no-security-repo" {
		return []models.Insight{insight("WARN", "Packages",
			"no security repository configured — security updates cannot be detected",
			[]string{
				"to fix (Debian): add 'deb http://security.debian.org/debian-security <suite>-security main' to /etc/apt/sources.list",
				"to fix (Ubuntu): add 'deb http://security.ubuntu.com/ubuntu <suite>-security main' to /etc/apt/sources.list",
			},
		)}
	}

	if pkg.SecurityUpdates == 0 {
		// Check for ESM-only updates even when no standard security updates exist
		if pkg.ESMUpdates > 0 {
			return []models.Insight{insight("WARN", "Packages",
				fmt.Sprintf("%d security update(s) require Ubuntu Pro (ESM) — not visible without subscription", pkg.ESMUpdates),
				[]string{
					"to inspect: pro security-status",
					"to fix:     ubuntu.com/pro (free for up to 5 machines)",
				},
			)}
		}
		return nil
	}

	// distro-correct fix commands
	fixCmd := "apt-get upgrade"
	inspectCmd := "apt list --upgradable 2>/dev/null | grep -i security"
	switch pkg.PackageManager {
	case "brew":
		fixCmd = "brew upgrade"
		inspectCmd = "brew outdated"
	case "dnf":
		fixCmd = "dnf upgrade --security"
		inspectCmd = "dnf updateinfo list security"
	case "zypper":
		fixCmd = "zypper patch --category security"
		inspectCmd = "zypper list-patches --category security"
	case "pacman":
		fixCmd = "pacman -Syu"
		inspectCmd = "checkupdates"
	case "yum":
		fixCmd = "yum update --security"
		inspectCmd = "yum updateinfo list security"
	}

	if pkg.CriticalUpdates > 0 {
		out = append(out, insight("CRIT", "Packages",
			fmt.Sprintf("%d critical security update(s) available (%s)", pkg.CriticalUpdates, pkg.PackageManager),
			[]string{
				fmt.Sprintf("to inspect: %s", inspectCmd),
				fmt.Sprintf("to fix: %s", fixCmd),
			},
		))
	} else if pkg.ImportantUpdates > 0 {
		out = append(out, insight("WARN", "Packages",
			fmt.Sprintf("%d important security update(s) available (%s)", pkg.ImportantUpdates, pkg.PackageManager),
			[]string{fmt.Sprintf("to fix: %s", fixCmd)},
		))
	} else {
		out = append(out, insight("WARN", "Packages",
			fmt.Sprintf("%d security update(s) available (%s)", pkg.SecurityUpdates, pkg.PackageManager),
			[]string{fmt.Sprintf("to fix: %s", fixCmd)},
		))
	}

	// Ubuntu ESM: surface Pro-gated security updates as INFO so the admin
	// knows real CVEs exist even without a Pro subscription.
	if pkg.ESMUpdates > 0 {
		out = append(out, insight("WARN", "Packages",
			fmt.Sprintf("%d security update(s) require Ubuntu Pro (ESM) — not applied without subscription", pkg.ESMUpdates),
			[]string{
				"to inspect: pro security-status",
				"to fix:     ubuntu.com/pro (free for up to 5 machines)",
			},
		))
	}

	// Package integrity (deep mode only — populated by PackagesDeepCollector)
	if pkg.Integrity != nil {
		out = append(out, checkPackageIntegrity(*pkg.Integrity)...)
	}

	out = append(out, checkPackageExtras(pkg)...)
	return out
}

func checkPackageExtras(pkg models.PackagesInfo) []models.Insight {
	out := make([]models.Insight, 0, len(pkg.SUSEMigrationRisks))
	// SUSE pre-migration: warn about boot-breaking package risks before zypper migration.
	// Research finding: admins regularly brick systems during SLES service pack migration
	// because grub2-x86_64-efi is not locked, system is unregistered, or kernel not rebooted.
	for _, risk := range pkg.SUSEMigrationRisks {
		out = append(out, insight("WARN", "Packages",
			"SUSE migration risk: "+risk,
			[]string{
				"to lock grub:   zypper addlock grub2-x86_64-efi",
				"to check locks: zypper locks",
				"to register:    SUSEConnect -r <registration-code>",
				"note: resolve before running zypper migration to avoid boot failure",
			},
		))
	}
	return out
}

func checkPackageIntegrity(pi models.PackageIntegrity) []models.Insight {
	var out []models.Insight

	if len(pi.BrokenPackages) > 0 {
		out = append(out, insight("CRIT", "Packages",
			fmt.Sprintf("%d broken/inconsistent package(s) detected", len(pi.BrokenPackages)),
			append([]string{
				"to inspect (dnf):  dnf check",
				"to inspect (dpkg): dpkg --audit",
				"to fix (dnf):      dnf distro-sync",
				"to fix (apt):      apt --fix-broken install",
			}, pi.BrokenPackages[:min(3, len(pi.BrokenPackages))]...),
		))
	}

	if len(pi.UnmetDeps) > 0 {
		out = append(out, insight("CRIT", "Packages",
			fmt.Sprintf("%d unmet dependency/dependencies detected", len(pi.UnmetDeps)),
			append([]string{"to fix: apt --fix-broken install"}, pi.UnmetDeps...),
		))
	}

	if len(pi.RPMVerifyFailed) > 0 {
		out = append(out, insight("WARN", "Packages",
			fmt.Sprintf("%d system file(s) modified from package baseline (rpm --verify)", len(pi.RPMVerifyFailed)),
			append([]string{
				"to inspect: rpm --verify --all | grep -v '^..........  c '",
				"note:       modifications to non-config files may indicate tampering or a broken update",
			}, pi.RPMVerifyFailed[:min(3, len(pi.RPMVerifyFailed))]...),
		))
	}

	if pi.VerifyTimedOut {
		out = append(out, insight("WARN", "Packages",
			"rpm --verify timed out — system may be under heavy load or have many packages",
			[]string{"to run manually: rpm --verify --all 2>/dev/null | grep -v '^..........  c '"},
		))
	}

	if len(pi.MissingLibs) > 0 {
		out = append(out, insight("CRIT", "Packages",
			fmt.Sprintf("%d missing shared library/libraries detected", len(pi.MissingLibs)),
			append([]string{
				"to inspect: ldd /bin/ls /usr/bin/ssh /usr/bin/python3",
				"to fix:     reinstall the package providing the missing .so file",
			}, pi.MissingLibs...),
		))
	}

	if !pi.LdconfigOK {
		out = append(out, insight("WARN", "Packages",
			"ldconfig failed — shared library cache may be stale or corrupted",
			[]string{"to fix: sudo ldconfig", "to inspect: ldconfig -p | head -20"},
		))
	}

	return out
}

func checkTLS(tls models.TLSInfo) []models.Insight {
	if len(tls.Certs) == 0 {
		return nil // no certs found — don't fire
	}
	var out []models.Insight

	// Expired certs — always CRIT
	for _, cert := range tls.Certs {
		if cert.ExpiresIn < 0 {
			out = append(out, insight("CRIT", "TLS",
				fmt.Sprintf("certificate expired %d day(s) ago: %s (%s)", -cert.ExpiresIn, cert.Subject, cert.Path),
				[]string{
					fmt.Sprintf("to inspect: openssl x509 -in %s -noout -dates", cert.Path),
					"to fix: renew certificate (certbot renew or manual replacement)",
				},
			))
		}
	}

	// Expiring within 7 days — CRIT
	for _, cert := range tls.Certs {
		if cert.ExpiresIn >= 0 && cert.ExpiresIn <= 7 {
			out = append(out, insight("CRIT", "TLS",
				fmt.Sprintf("certificate expires in %d day(s): %s (%s)", cert.ExpiresIn, cert.Subject, cert.Path),
				[]string{
					fmt.Sprintf("to inspect: openssl x509 -in %s -noout -dates", cert.Path),
					"to fix: renew now — certbot renew or manual replacement",
				},
			))
		}
	}

	// Expiring within 30 days — WARN
	for _, cert := range tls.Certs {
		if cert.ExpiresIn > 7 && cert.ExpiresIn <= 30 {
			out = append(out, insight("WARN", "TLS",
				fmt.Sprintf("certificate expires in %d day(s): %s (%s)", cert.ExpiresIn, cert.Subject, cert.Path),
				[]string{
					fmt.Sprintf("to inspect: openssl x509 -in %s -noout -dates", cert.Path),
					"to fix: renew soon — certbot renew or manual replacement",
				},
			))
		}
	}

	return out
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
	} else if d.MaxCorePct >= 95 && len(d.Cores) > 1 {
		// All cores pegged
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

func checkKVM(kvm models.KVMInfo) []models.Insight {
	var out []models.Insight
	if !kvm.Detected {
		return out
	}
	// Crashed VMs — always CRIT
	for _, vm := range kvm.VMs {
		if vm.State == models.KVMCrashed {
			hints := []string{
				fmt.Sprintf("to inspect: virsh console %s", vm.Name),
				fmt.Sprintf("to inspect: cat /var/log/libvirt/qemu/%s.log | tail -50", vm.Name),
				fmt.Sprintf("to restart: virsh start %s", vm.Name),
			}
			if vm.LastLogError != "" {
				hints = append([]string{"last log: " + vm.LastLogError}, hints...)
			}
			out = append(out, insight("CRIT", "KVM",
				fmt.Sprintf("VM %s is in CRASHED state", vm.Name), hints))
		}
	}
	// Paused VMs — WARN
	if kvm.VMsPaused > 0 {
		out = append(out, insight("WARN", "KVM",
			fmt.Sprintf("%d VM(s) paused — may indicate a problem or forgotten snapshot", kvm.VMsPaused),
			[]string{
				"to inspect: virsh list --all | grep paused",
				"to resume:  virsh resume <name>",
			},
		))
	}
	// Shut-off VMs with autostart=yes — WARN
	if kvm.VMsDownAutostart > 0 {
		var names []string
		for _, vm := range kvm.VMs {
			if (vm.State == models.KVMShutOff || vm.State == models.KVMShutDown) && vm.AutoStart {
				names = append(names, vm.Name)
			}
		}
		out = append(out, insight("WARN", "KVM",
			fmt.Sprintf("%d VM(s) shut off with autostart=yes: %s",
				kvm.VMsDownAutostart, strings.Join(firstN(names, 3), ", ")),
			[]string{
				"to start:   virsh start <name>",
				"to inspect: virsh dominfo <name>",
			},
		))
	}
	// Disk I/O errors — CRIT
	if kvm.DiskIOErrors > 0 {
		out = append(out, insight("CRIT", "KVM",
			fmt.Sprintf("%d VM(s) have recorded disk I/O errors", kvm.DiskIOErrors),
			[]string{
				"to inspect: virsh domblkerror <name>",
				"to inspect: dmesg | grep -i 'error\\|failed'",
				"note:       disk I/O errors persist across VM reboots until cleared",
			},
		))
	}
	// Inactive networks — WARN
	if kvm.NetworksInactive > 0 {
		out = append(out, insight("WARN", "KVM",
			fmt.Sprintf("%d virtual network(s) inactive — VMs may lose connectivity", kvm.NetworksInactive),
			[]string{
				"to inspect: virsh net-list --all",
				"to start:   virsh net-start <name>",
				"to autostart: virsh net-autostart <name>",
			},
		))
	}
	// Inactive storage pools — WARN
	if kvm.PoolsInactive > 0 {
		out = append(out, insight("WARN", "KVM",
			fmt.Sprintf("%d storage pool(s) inactive — disk images may be inaccessible", kvm.PoolsInactive),
			[]string{
				"to inspect: virsh pool-list --all",
				"to start:   virsh pool-start <name>",
			},
		))
	}
	// Full storage pools — WARN/CRIT
	if kvm.PoolsNearFull > 0 {
		out = append(out, insight("WARN", "KVM",
			fmt.Sprintf("%d storage pool(s) >85%% full — VMs may fail to write disk", kvm.PoolsNearFull),
			[]string{
				"to inspect: virsh pool-info <name>",
				"to inspect: du -sh /var/lib/libvirt/images/*",
			},
		))
	}
	return out
}

func checkDocker(d models.DockerInfo) []models.Insight {
	var out []models.Insight

	if !d.Available {
		if d.StatusReason != "" {
			out = append(out, insight("WARN", "Docker",
				d.StatusReason,
				[]string{"to inspect: systemctl status docker"},
			))
		}
		return out
	}

	// Crash looping containers — always CRIT
	for _, name := range d.CrashLooping {
		out = append(out, insight("CRIT", "Docker",
			fmt.Sprintf("container %q is crash looping (restarted >5 times)", name),
			[]string{
				fmt.Sprintf("to inspect: docker logs %s --tail 50", name),
				fmt.Sprintf("to inspect: docker inspect %s | grep -A5 RestartCount", name),
			},
		))
	}

	// Unhealthy containers
	for _, name := range d.Unhealthy {
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("container %q health check failing", name),
			[]string{
				fmt.Sprintf("to inspect: docker inspect %s | grep -A10 Health", name),
				fmt.Sprintf("to inspect: docker logs %s --tail 20", name),
			},
		))
	}

	// Stopped containers — informational, not always bad
	if d.Stopped > 5 {
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("%d stopped containers accumulating — consider pruning", d.Stopped),
			[]string{"to fix: docker container prune"},
		))
	}

	// Dangling images eating disk
	if d.DanglingImagesMB >= 1024 {
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("%d dangling images using %.1f GB — run docker image prune", d.DanglingImages, d.DanglingImagesMB/1024),
			[]string{"to fix: docker image prune", "to fix: docker system prune"},
		))
	} else if d.DanglingImages > 0 {
		out = append(out, insight("INFO", "Docker",
			fmt.Sprintf("%d dangling image(s) using %.0f MB", d.DanglingImages, d.DanglingImagesMB),
			[]string{"to fix: docker image prune"},
		))
	}

	// Orphaned volumes
	if d.OrphanedVolumes > 3 {
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("%d orphaned volumes not attached to any container", d.OrphanedVolumes),
			[]string{"to fix: docker volume prune"},
		))
	}

	// MTU mismatch — container MTU > host MTU causes silent fragmentation
	if d.MTUMismatch {
		out = append(out, insight("WARN", "Docker",
			fmt.Sprintf("container network MTU (%d) > host interface MTU (%d) — silent packet fragmentation",
				d.ContainerMTU, d.HostMTU),
			[]string{
				fmt.Sprintf("to fix: set MTU %d in container network config to match host", d.HostMTU),
				"to inspect (docker): docker network inspect bridge | grep mtu",
				"to inspect (podman): podman network inspect podman | grep mtu",
				"note: MTU mismatch causes connection timeouts for large payloads (HTTP, TLS handshakes)",
			},
		))
	}

	return out
}

func checkK8s(k models.K8sInfo) []models.Insight {
	var out []models.Insight

	if !k.Detected {
		return out
	}

	out = append(out, checkK8sNodes(k)...)
	out = append(out, checkK8sPodHealth(k)...)
	out = append(out, checkK8sWorkloadsAndEvents(k)...)

	if k.OSLayer != nil {
		out = append(out, checkK8sOSLayer(*k.OSLayer)...)
	}

	return out
}

func checkK8sNodes(k models.K8sInfo) []models.Insight {
	var out []models.Insight
	if k.NodesNotReady > 0 {
		out = append(out, insight("CRIT", "K8s",
			fmt.Sprintf("%d node(s) not Ready — cluster may be degraded", k.NodesNotReady),
			[]string{
				"to inspect: kubectl get nodes -o wide",
				"to inspect: kubectl describe node <name>",
			},
		))
	}
	for _, node := range k.Nodes {
		for cond, status := range node.Conditions {
			if cond == "Ready" || status != "True" {
				continue
			}
			out = append(out, insight("CRIT", "K8s",
				fmt.Sprintf("node %s: %s condition True — workloads may be evicted", node.Name, cond),
				[]string{
					fmt.Sprintf("to inspect: kubectl describe node %s | grep -A5 Conditions", node.Name),
				},
			))
		}
	}
	return out
}

func checkK8sPodHealth(k models.K8sInfo) []models.Insight {
	var out []models.Insight
	if k.CrashLooping > 0 {
		hints := []string{"to inspect: kubectl get pods -A | grep -v Running"}
		for _, p := range k.Pods {
			if strings.Contains(p.Status, "CrashLoop") && p.PreviousLogs != "" {
				hints = append(hints, fmt.Sprintf("  %s/%s last log: %s",
					p.Namespace, p.Name, k8sFirstLine(p.PreviousLogs)))
			}
			if p.TerminationMsg != "" {
				hints = append(hints, fmt.Sprintf("  %s/%s exit msg: %s",
					p.Namespace, p.Name, k8sFirstLine(p.TerminationMsg)))
			}
		}
		out = append(out, insight("CRIT", "K8s",
			fmt.Sprintf("%d pod(s) crash looping", k.CrashLooping), hints))
	}
	if k.PodsNotReady > 0 {
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("%d pod(s) running but containers not ready", k.PodsNotReady),
			[]string{
				"to inspect: kubectl get pods -A | grep '0/'",
				"to inspect: kubectl describe pod <name> -n <ns>",
			},
		))
	}
	if k.Pending > 0 {
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("%d pod(s) stuck in Pending — check node resources or PVC availability",
				k.Pending),
			[]string{
				"to inspect: kubectl get pods -A | grep Pending",
				"to inspect: kubectl describe pod <name> -n <ns> | grep -A5 Events",
			},
		))
	}
	if k.HighRestarts > 0 {
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("%d pod(s) with ≥10 restarts — instability detected", k.HighRestarts),
			[]string{
				"to inspect: kubectl get pods -A --sort-by='.status.containerStatuses[0].restartCount'",
				"to inspect: kubectl logs <pod> -n <ns> --previous",
			},
		))
	}
	if k.Terminating > 0 {
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("%d pod(s) stuck Terminating — finalizer or webhook blocking deletion",
				k.Terminating),
			[]string{
				"to inspect: kubectl get pods -A | grep Terminating",
				"to force: kubectl delete pod <name> -n <ns> --grace-period=0 --force",
			},
		))
	}
	return out
}

func checkK8sWorkloadsAndEvents(k models.K8sInfo) []models.Insight {
	var out []models.Insight
	if k.PVCsNotBound > 0 {
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("%d PVC(s) not Bound — pods waiting for storage may stay Pending",
				k.PVCsNotBound),
			[]string{
				"to inspect: kubectl get pvc -A | grep -v Bound",
				"to inspect: kubectl describe pvc <name> -n <ns>",
			},
		))
	}
	if k.WorkloadsDown > 0 {
		var names []string
		for _, w := range k.Workloads {
			if w.Ready < w.Desired {
				names = append(names, fmt.Sprintf("%s/%s (%d/%d)",
					w.Namespace, w.Name, w.Ready, w.Desired))
			}
		}
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("%d workload(s) degraded: %s",
				k.WorkloadsDown, strings.Join(firstN(names, 3), ", ")),
			[]string{
				"to inspect: kubectl get deploy,statefulset -A | grep -v '1/1'",
				"to inspect: kubectl rollout status deployment/<name> -n <ns>",
			},
		))
	}
	if len(k.Events) > 0 {
		reasons := map[string]int{}
		for _, e := range k.Events {
			reasons[e.Reason]++
		}
		var summary []string
		for reason, count := range reasons {
			summary = append(summary, fmt.Sprintf("%s×%d", reason, count))
			if len(summary) >= 4 {
				break
			}
		}
		hints := []string{"to inspect: kubectl get events -A --field-selector type=Warning"}
		for _, e := range k.Events {
			if strings.Contains(e.Message, "subnet.env") {
				hints = append(hints,
					"CRIT: flannel subnet.env missing — CNI network plugin not ready",
					"to fix: sudo systemctl restart k3s  (regenerates subnet.env)")
				break
			}
		}
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("%d Warning event(s): %s", len(k.Events), strings.Join(summary, ", ")),
			hints))
	}
	return out
}

// checkK8sOSLayer emits insights for OS-level k8s node health.
func checkK8sOSLayer(l models.K8sOSLayer) []models.Insight {
	var out []models.Insight

	if !l.IPForwardEnabled {
		out = append(out, insight("CRIT", "K8s",
			"IP forwarding disabled — pod-to-pod networking will fail",
			[]string{
				"to fix (persistent): echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/99-k8s.conf && sysctl -p",
				"to fix (immediate): sysctl -w net.ipv4.ip_forward=1",
			},
		))
	}

	if !l.FlannelSubnetOK {
		out = append(out, insight("CRIT", "K8s",
			"/run/flannel/subnet.env missing — CNI network plugin cannot configure pod networking",
			[]string{
				"to fix (k3s): sudo systemctl restart k3s",
				"to inspect: sudo journalctl -u k3s -n 50 | grep -i flannel",
			},
		))
	}

	if !l.CNIBinsOK {
		out = append(out, insight("CRIT", "K8s",
			"/opt/cni/bin/ is empty — CNI plugins not installed, networking will fail",
			[]string{
				"to fix (k3s): sudo systemctl restart k3s",
				"to fix (kubeadm): reinstall kubeadm network plugin",
			},
		))
	}

	if !l.KubeForwardChain {
		out = append(out, insight("WARN", "K8s",
			"KUBE-FORWARD chain not found in iptables/nftables — kube-proxy may not be running",
			[]string{
				"to inspect: sudo iptables -L KUBE-FORWARD -n 2>/dev/null || sudo nft list tables",
				"to inspect: kubectl get pods -n kube-system | grep kube-proxy",
			},
		))
	}

	if len(l.CertExpiredNames) > 0 {
		out = append(out, insight("CRIT", "K8s",
			fmt.Sprintf("k8s certificate(s) EXPIRED: %s — API server will reject requests",
				strings.Join(l.CertExpiredNames, ", ")),
			[]string{
				"to fix (kubeadm): kubeadm certs renew all",
				"to fix (k3s): sudo systemctl restart k3s  (auto-renews certs)",
			},
		))
	} else if l.CertExpirySoonDays > 0 {
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("k8s certificate(s) expire in %d day(s) — renew before expiry",
				l.CertExpirySoonDays),
			[]string{
				"to fix (kubeadm): kubeadm certs renew all",
				"to fix (k3s): sudo systemctl restart k3s",
			},
		))
	}

	if len(l.KubeletErrors) > 0 {
		out = append(out, insight("WARN", "K8s",
			fmt.Sprintf("kubelet errors in journal: %s", l.KubeletErrors[0]),
			append([]string{"to inspect: journalctl -u kubelet -u k3s -n 50 --no-pager"},
				l.KubeletErrors[1:]...),
		))
	}

	return out
}

// k8sFirstLine returns the first non-empty line of a multi-line string.
func k8sFirstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return s
}

func checkFirmware(f models.FirmwareInfo) []models.Insight {
	var out []models.Insight

	if !f.Available || f.UpgradeCount == 0 {
		return out
	}

	// Security-critical firmware (dbx, BIOS security patches)
	if f.SecurityCount > 0 {
		var names []string
		for _, u := range f.Upgrades {
			if u.SecurityFix {
				names = append(names, u.Name)
			}
		}
		out = append(out, insight("WARN", "Firmware",
			fmt.Sprintf("%d security-relevant firmware upgrade(s) pending: %s",
				f.SecurityCount, strings.Join(names, ", ")),
			[]string{
				"to inspect: fwupdmgr get-upgrades",
				"to apply:   fwupdmgr update",
				"note: most firmware updates require a reboot",
			},
		))
	}

	// Non-security firmware upgrades
	nonSec := f.UpgradeCount - f.SecurityCount
	if nonSec > 0 {
		out = append(out, insight("INFO", "Firmware",
			fmt.Sprintf("%d non-security firmware upgrade(s) available", nonSec),
			[]string{"to inspect: fwupdmgr get-upgrades"},
		))
	}

	return out
}

// checkSnapper evaluates Btrfs/Snapper snapshot health.
// Thresholds:
//
//	WARN  — no snapshot in >24h (rollback safety window exceeded)
//	WARN  — total snapshot space >20GB (may indicate cleanup needed)
//	CRIT  — no snapshot in >72h (3 days without a rollback point)
//	INFO  — snapper available but no snapshots exist yet
func checkSnapper(s models.SnapperInfo) []models.Insight {
	if !s.Available {
		return nil // snapper not installed — not an error, just skip
	}

	var out []models.Insight

	if s.Error != "" {
		// "run as root" is an expected non-root limitation — INFO not WARN
		level := "WARN"
		if strings.Contains(s.Error, "run as root") {
			level = "INFO"
		}
		out = append(out, insight(level, "Snapshots",
			fmt.Sprintf("snapper: %s", s.Error),
			nil,
		))
		return out
	}

	// No snapshots at all
	if s.SnapshotCount == 0 {
		out = append(out, insight("WARN", "Snapshots",
			"snapper is installed but no snapshots exist — system has no rollback points",
			[]string{
				"to fix: snapper create --description 'initial'",
				"to enable automatic snapshots: snapper set-config TIMELINE_CREATE=yes",
			},
		))
		return out
	}

	// Staleness — how long since last snapshot
	switch {
	case s.LastSnapshotH < 0:
		// Could not determine last snapshot time — treat as stale
		out = append(out, insight("WARN", "Snapshots",
			fmt.Sprintf("%d snapshot(s) found but last snapshot time could not be determined", s.SnapshotCount),
			[]string{"to check: sudo snapper list"},
		))
	case s.LastSnapshotH >= 72:
		out = append(out, insight("CRIT", "Snapshots",
			fmt.Sprintf("no Btrfs snapshot in %dh — system has no recent rollback point", s.LastSnapshotH),
			[]string{
				"to fix: snapper create --description 'manual'",
				"to enable timeline: snapper set-config TIMELINE_CREATE=yes",
			},
		))
	case s.LastSnapshotH >= 24:
		out = append(out, insight("WARN", "Snapshots",
			fmt.Sprintf("last Btrfs snapshot was %dh ago — rollback window may be stale", s.LastSnapshotH),
			[]string{
				"to fix: snapper create --description 'manual'",
				"to check schedule: snapper get-config | grep TIMELINE",
			},
		))
	}

	// Space usage
	switch {
	case s.TotalSpaceGB >= 50:
		out = append(out, insight("CRIT", "Snapshots",
			fmt.Sprintf("Btrfs snapshots consuming %.1f GB — filesystem space at risk", s.TotalSpaceGB),
			[]string{
				"to clean up: snapper delete --sync <number>",
				"to list by size: sudo snapper list",
				"to limit retention: snapper set-config NUMBER_LIMIT=10",
			},
		))
	case s.TotalSpaceGB >= 20:
		out = append(out, insight("WARN", "Snapshots",
			fmt.Sprintf("Btrfs snapshots consuming %.1f GB — consider pruning old snapshots", s.TotalSpaceGB),
			[]string{
				"to clean up: snapper delete --sync <number>",
				"to limit retention: snapper set-config NUMBER_LIMIT=10",
			},
		))
	}

	// Healthy state — emit INFO so the check is visible in output
	if len(out) == 0 {
		msg := fmt.Sprintf("%d Btrfs snapshot(s)", s.SnapshotCount)
		if s.LastSnapshotH >= 0 {
			msg += fmt.Sprintf(" — last < %dh ago", s.LastSnapshotH+1)
		}
		if s.TotalSpaceGB > 0 {
			msg += fmt.Sprintf(", %.1f GB used", s.TotalSpaceGB)
		}
		out = append(out, insight("OK", "Snapshots", msg, nil))
	}

	return out
}

// checkSUSEConnect surfaces SUSEConnect subscription status in dsd health.
// CRIT if expired or expires <=14d, WARN if <=30d, OK otherwise.
// Silent (no insight) when SUSEConnect is not registered — non-SLES systems.
func checkSUSEConnect(s models.SUSEConnectInfo) []models.Insight {
	switch s.Platform {
	case "rhel":
		return checkRHELSubscription(s)
	case "ubuntu-pro":
		return checkUbuntuPro(s)
	default: // "suse" or legacy (empty platform field)
		return checkSUSESubscription(s)
	}
}

func checkSUSESubscription(s models.SUSEConnectInfo) []models.Insight {
	if !s.Registered {
		return []models.Insight{insight("WARN", "Subscription",
			"SUSE system is not registered — security patches unavailable without SUSEConnect",
			[]string{
				"to fix: SUSEConnect -r <REGCODE>",
				"to register: https://scc.suse.com",
			},
		)}
	}
	switch {
	case s.ExpiresDays == 0:
		return []models.Insight{insight("CRIT", "Subscription",
			"SUSE subscription EXPIRED — security patches unavailable",
			[]string{"to fix: renew at https://scc.suse.com"},
		)}
	case s.ExpiresDays > 0 && s.ExpiresDays <= 14:
		return []models.Insight{insight("CRIT", "Subscription",
			fmt.Sprintf("SUSE subscription expires in %d day(s) — renew immediately", s.ExpiresDays),
			[]string{"to fix: renew at https://scc.suse.com"},
		)}
	case s.ExpiresDays > 14 && s.ExpiresDays <= 30:
		return []models.Insight{insight("WARN", "Subscription",
			fmt.Sprintf("SUSE subscription expires in %d day(s)", s.ExpiresDays),
			[]string{"to fix: renew at https://scc.suse.com"},
		)}
	default:
		return nil // OK — no insight needed
	}
}

func checkRHELSubscription(s models.SUSEConnectInfo) []models.Insight {
	switch s.Status {
	case "unregistered":
		return []models.Insight{insight("WARN", "Subscription",
			"RHEL/Oracle system is not registered — security updates may be unavailable",
			[]string{
				"to fix: subscription-manager register --auto-attach",
				"to inspect: subscription-manager status",
				"note: Rocky/AlmaLinux do not require registration",
			},
		)}
	case "expired":
		return []models.Insight{insight("CRIT", "Subscription",
			"Red Hat subscription EXPIRED — security patches unavailable",
			[]string{
				"to fix: renew at https://access.redhat.com",
				"to inspect: subscription-manager list --consumed",
			},
		)}
	default:
		return nil // current — no insight needed
	}
}

func checkUbuntuPro(s models.SUSEConnectInfo) []models.Insight {
	if s.Status == "detached" {
		// Ubuntu Pro is optional — INFO not WARN (Ubuntu still works without it)
		return []models.Insight{insight("INFO", "Subscription",
			"Ubuntu Pro not attached — ESM security patches and Livepatch unavailable",
			[]string{
				"to attach: pro attach <token>  (free for up to 5 personal machines)",
				"to get token: ubuntu.com/pro",
				"to inspect: pro status",
			},
		)}
	}
	return nil // attached — no insight needed
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
			return out
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

		// SMART overall
		if !d.SmartOK {
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
		switch {
		case h.Memory.UncorrectedErrors > 0:
			out = append(out, insight("CRIT", "Hardware",
				fmt.Sprintf("EDAC: %d uncorrected memory error(s) — hardware RAM fault", h.Memory.UncorrectedErrors),
				[]string{
					"to inspect: edac-util -s 4",
					"to diagnose: run memtest86+",
				},
			))
		case h.Memory.CorrectedErrors > 100:
			out = append(out, insight("WARN", "Hardware",
				fmt.Sprintf("EDAC: %d corrected memory error(s) — RAM degrading", h.Memory.CorrectedErrors),
				[]string{"to inspect: edac-util -s 4"},
			))
		}
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
		if bond.DownSlaves == 0 {
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

func checkIPMI(ipmi models.IPMIInfo) []models.Insight {
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
	return []models.Insight{insight("WARN", "OOM",
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
		if state != "online" && state != "linkup" && state != "" {
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
		if state != "ACTIVE" && state != "" {
			down = append(down, fmt.Sprintf("%s port %d (%s)", p.Device, p.Port, p.State))
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

	// Root logged in via SSH — always CRIT
	if s.RootSSH {
		out = append(out, insight("CRIT", "Sessions",
			"root is logged in via SSH — direct root SSH access is a security risk",
			[]string{
				"to inspect: w",
				"to fix: set PermitRootLogin no in /etc/ssh/sshd_config",
				"to fix: use sudo or su instead of direct root SSH",
			},
		))
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

// checkSSHWeakCiphers flags CBC-mode and arcfour ciphers.
// CBC-mode ciphers are vulnerable to BEAST and Lucky13 attacks.
// Data source: sshd -T (preferred, root) or sshd_config file parse.
func checkSSHWeakCiphers(sec models.SecurityInfo) []models.Insight {
	if sec.SSHCiphers == "" {
		return nil
	}
	weakPatterns := []string{"cbc", "arcfour", "3des-cbc", "blowfish-cbc", "cast128-cbc"}
	var found []string
	for _, c := range strings.Split(sec.SSHCiphers, ",") {
		c = strings.TrimSpace(strings.ToLower(c))
		for _, weak := range weakPatterns {
			if strings.Contains(c, weak) {
				found = append(found, c)
				break
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	source := "sshd_config"
	if sec.SSHAuditSource == "sshd -T" {
		source = "sshd -T (effective config)"
	}
	return []models.Insight{insight("WARN", "Hardening",
		fmt.Sprintf("SSH weak cipher(s) enabled (%s): %s", source, strings.Join(found, ", ")),
		[]string{
			"to fix: set Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr in /etc/ssh/sshd_config",
			"note: CBC-mode ciphers are vulnerable to BEAST/Lucky13",
			"to verify: sshd -T | grep ciphers",
		},
	)}
}

// checkSSHWeakMACs flags legacy MAC algorithms.
// hmac-sha1 and hmac-md5 use broken hash functions. umac-64 has insufficient tag length.
// The *-etm variants of hmac-sha1 are marginally safer but still not recommended.
func checkSSHWeakMACs(sec models.SecurityInfo) []models.Insight {
	if sec.SSHMACs == "" {
		return nil
	}
	// Flag non-ETM weak MACs; ETM variants are accepted as borderline acceptable
	strictWeak := []string{"hmac-md5", "hmac-sha1,", "hmac-sha1 ", "umac-64@", "hmac-ripemd160"}
	// hmac-sha1 (non-ETM) — check as standalone token
	var found []string
	for _, m := range strings.Split(sec.SSHMACs, ",") {
		m = strings.TrimSpace(strings.ToLower(m))
		for _, weak := range strictWeak {
			// Match exact token or token followed by nothing (avoid matching hmac-sha1-etm)
			if m == strings.TrimRight(weak, ", ") ||
				strings.HasPrefix(m, "hmac-md5") ||
				strings.HasPrefix(m, "hmac-ripemd160") ||
				(strings.HasPrefix(m, "umac-64@") && !strings.Contains(m, "etm")) ||
				m == "hmac-sha1" {
				found = append(found, m)
				break
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	source := "sshd_config"
	if sec.SSHAuditSource == "sshd -T" {
		source = "sshd -T (effective config)"
	}
	return []models.Insight{insight("WARN", "Hardening",
		fmt.Sprintf("SSH weak MAC(s) enabled (%s): %s", source, strings.Join(found, ", ")),
		[]string{
			"to fix: set MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com in /etc/ssh/sshd_config",
			"note: hmac-sha1 uses SHA-1 which is cryptographically broken",
			"to verify: sshd -T | grep '^macs'",
		},
	)}
}

// checkSSHWeakKEX flags broken Diffie-Hellman key exchange algorithms.
// group1-sha1 uses 1024-bit DH (Logjam attack). group14-sha1 uses SHA-1.
func checkSSHWeakKEX(sec models.SecurityInfo) []models.Insight {
	if sec.SSHKexAlgorithms == "" {
		return nil
	}
	weakKEX := []string{
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group-exchange-sha1",
	}
	var found []string
	for _, k := range strings.Split(sec.SSHKexAlgorithms, ",") {
		k = strings.TrimSpace(strings.ToLower(k))
		for _, weak := range weakKEX {
			if k == weak {
				found = append(found, k)
				break
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	source := "sshd_config"
	if sec.SSHAuditSource == "sshd -T" {
		source = "sshd -T (effective config)"
	}
	return []models.Insight{insight("WARN", "Hardening",
		fmt.Sprintf("SSH weak KEX algorithm(s) enabled (%s): %s", source, strings.Join(found, ", ")),
		[]string{
			"to fix: set KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256 in /etc/ssh/sshd_config",
			"note: diffie-hellman-group1-sha1 is vulnerable to the Logjam attack (1024-bit DH)",
			"to verify: sshd -T | grep kexalgorithms",
		},
	)}
}

// ── User account hardening checks (Spec 14) ──────────────────────────────────

// These checks are appended to checkSecurity via calls inside that function.
// Keeping them as standalone functions makes them independently testable.

func checkEmptyPasswords(sec models.SecurityInfo) []models.Insight {
	if len(sec.EmptyPasswordAccounts) == 0 {
		return nil
	}
	return []models.Insight{insight("CRIT", "Hardening",
		fmt.Sprintf("account(s) with no password set: %s — any user can log in without a password",
			strings.Join(sec.EmptyPasswordAccounts, ", ")),
		[]string{
			"to inspect: sudo awk -F: '($2==\"\"){print $1}' /etc/shadow",
			"to fix:     passwd <username>  (set a password)",
			"to lock:    passwd -l <username>  (lock until password is set)",
		},
	)}
}

func checkStalePasswords(sec models.SecurityInfo) []models.Insight {
	if len(sec.StalePasswordAccounts) == 0 {
		return nil
	}
	shown := sec.StalePasswordAccounts
	suffix := ""
	if len(shown) > 3 {
		shown = shown[:3]
		suffix = fmt.Sprintf(" (+%d more)", len(sec.StalePasswordAccounts)-3)
	}
	return []models.Insight{insight("WARN", "Hardening",
		fmt.Sprintf("password never expires for human account(s): %s%s",
			strings.Join(shown, ", "), suffix),
		[]string{
			"to inspect: sudo chage -l <username>",
			"to fix:     chage -M 90 <username>  (expire after 90 days)",
			"to fix all: awk -F: '($3>=1000 && $3<65534){print $1}' /etc/passwd | xargs -I{} chage -M 90 {}",
			"note: CIS benchmark recommends maximum password age ≤ 365 days",
		},
	)}
}

func checkWorldWritable(sec models.SecurityInfo) []models.Insight {
	if len(sec.WorldWritableDirs) == 0 {
		return nil
	}
	return []models.Insight{insight("CRIT", "Hardening",
		fmt.Sprintf("world-writable director(y/ies) missing sticky bit: %s — any user can delete others' files",
			strings.Join(sec.WorldWritableDirs, ", ")),
		[]string{
			"to fix: chmod +t /tmp /var/tmp /dev/shm",
			"to verify: ls -ld /tmp /var/tmp /dev/shm",
			"note: sticky bit (t) prevents users from deleting files they don't own",
		},
	)}
}

// ── Cron heuristics (Spec 9) ─────────────────────────────────────────────────

func checkCron(c models.CronInfo) []models.Insight {
	var out []models.Insight

	if !c.DaemonActive && c.AnacronPresent {
		out = append(out, insight("INFO", "Cron",
			"no persistent cron daemon — anacron only (jobs run when machine is up, not on exact schedule)",
			[]string{
				"to install persistent cron: dnf install cronie  (RHEL/Fedora)",
				"to install persistent cron: apt install cron    (Debian/Ubuntu)",
			},
		))
	} else if !c.DaemonActive && !c.AnacronPresent {
		if c.SystemdTimers > 0 {
			out = append(out, insight("INFO", "Cron",
				fmt.Sprintf("no cron daemon installed — %d systemd timer(s) active instead", c.SystemdTimers),
				[]string{"to inspect: systemctl list-timers"},
			))
		} else {
			out = append(out, insight("WARN", "Cron",
				"no cron daemon and no anacron — scheduled jobs will not run",
				[]string{
					"to install: dnf install cronie  (RHEL/Fedora)",
					"to install: apt install cron    (Debian/Ubuntu)",
				},
			))
		}
		return out
	}

	if len(c.Failures) > 0 {
		names := make([]string, 0, len(c.Failures))
		for _, f := range c.Failures {
			names = append(names, f.Job)
		}
		out = append(out, insight("WARN", "Cron",
			fmt.Sprintf("%d cron job failure(s) in the last 24h: %s",
				len(c.Failures), strings.Join(firstN(names, 3), ", ")),
			[]string{
				"to inspect: journalctl -u crond --since '24 hours ago' | grep -i failed",
				"to inspect: grep FAILED /var/log/cron",
			},
		))
	}

	out = append(out, checkCronQuality(c.QualityIssues)...)
	out = append(out, checkAnacronSchedules(c.AnacronJobs)...)

	return out
}

func checkCronQuality(issues []models.CronJob) []models.Insight {
	if len(issues) == 0 {
		return nil
	}
	var out []models.Insight
	var missingCmds, noPATH []string
	for _, j := range issues {
		for _, issue := range j.Issues {
			if strings.Contains(issue, "not found") {
				missingCmds = append(missingCmds, j.Source)
			} else if strings.Contains(issue, "PATH") {
				noPATH = append(noPATH, j.Source)
			}
		}
	}
	if len(missingCmds) > 0 {
		out = append(out, insight("WARN", "Cron",
			fmt.Sprintf("crontab references missing command(s) in: %s",
				strings.Join(firstN(missingCmds, 3), ", ")),
			[]string{
				"to inspect: grep -n '' /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null",
				"note: missing binaries cause silent failures — cron sends no warning",
			},
		))
	}
	if len(noPATH) > 0 {
		out = append(out, insight("INFO", "Cron",
			fmt.Sprintf("%d crontab file(s) use relative paths without PATH= set — jobs may fail with 'command not found'",
				len(noPATH)),
			[]string{
				"to fix: add PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin at the top of the crontab",
			},
		))
	}
	return out
}

func checkAnacronSchedules(jobs []models.AnacronJob) []models.Insight {
	var out []models.Insight
	for _, j := range jobs {
		if j.LastRunH < 0 {
			out = append(out, insight("INFO", "Cron",
				fmt.Sprintf("anacron cron.%s has never run — machine may not have been on at scheduled time", j.Name),
				[]string{fmt.Sprintf("to run now: anacron -f -n cron.%s", j.Name)},
			))
		} else if j.OverdueH > 0 {
			out = append(out, insight("WARN", "Cron",
				fmt.Sprintf("anacron cron.%s is %dh overdue (last run: %dh ago)", j.Name, j.OverdueH, j.LastRunH),
				[]string{
					fmt.Sprintf("to run now: anacron -f -n cron.%s", j.Name),
					"note: machine was likely off during scheduled window",
				},
			))
		}
	}
	return out
}

// ── DNS resolver heuristics (Spec 15) ────────────────────────────────────────

func checkDNS(d models.DNSResolverInfo) []models.Insight {
	var out []models.Insight

	if !d.ExternalResolvesOK && d.Manager != "none" {
		msg := "DNS resolution failing — cannot resolve external hostnames"
		if d.ResolvTestError != "" {
			msg += ": " + d.ResolvTestError
		}
		out = append(out, insight("CRIT", "DNS", msg,
			[]string{
				"to inspect: cat /etc/resolv.conf",
				"to inspect: dig google.com",
				"to inspect: systemctl status NetworkManager systemd-resolved",
			},
		))
		return out
	}

	out = append(out, checkDNSQuality(d)...)

	if d.ExternalResolvesOK && d.ExternalLatencyMs > 500 {
		out = append(out, insight("WARN", "DNS",
			fmt.Sprintf("DNS resolution is slow (%dms) — may affect application startup and health checks",
				d.ExternalLatencyMs),
			[]string{
				"to inspect: dig +stats google.com",
				"to fix: consider a local caching resolver (systemd-resolved, unbound)",
				fmt.Sprintf("current nameservers: %s", strings.Join(d.Nameservers, ", ")),
			},
		))
	} else if d.ExternalResolvesOK && d.ExternalLatencyMs > 200 {
		out = append(out, insight("INFO", "DNS",
			fmt.Sprintf("DNS latency %dms — acceptable but consider local caching", d.ExternalLatencyMs),
			[]string{"to inspect: dig +stats google.com"},
		))
	}

	if d.PublicFallback {
		out = append(out, insight("INFO", "DNS",
			"public DNS resolver (8.8.8.8/1.1.1.1) configured — DNS queries leave your network",
			[]string{
				"note: on servers this may expose internal hostname lookups to public resolvers",
				"to fix: use your organisation's internal DNS resolver instead",
			},
		))
	}

	return out
}

func checkDNSQuality(d models.DNSResolverInfo) []models.Insight {
	var out []models.Insight

	if d.TooManyNameservers {
		out = append(out, insight("WARN", "DNS",
			fmt.Sprintf("/etc/resolv.conf has %d nameservers — libc silently ignores all beyond 3",
				len(d.Nameservers)),
			[]string{
				"to fix: remove extra nameservers from /etc/resolv.conf",
				"note: if managed by NetworkManager, adjust connection DNS settings",
			},
		))
	}
	if d.HasLoopback {
		out = append(out, insight("WARN", "DNS",
			"loopback nameserver (127.x.x.x) in /etc/resolv.conf but systemd-resolved is not active — DNS may fail",
			[]string{
				"to fix: sudo systemctl enable --now systemd-resolved",
				"to fix: or replace 127.0.0.1 with a real nameserver IP",
			},
		))
	}
	if d.NdotsHigh > 3 {
		out = append(out, insight("WARN", "DNS",
			fmt.Sprintf("ndots:%d set — every short hostname is tried as FQDN first, causing %d extra DNS lookups per query",
				d.NdotsHigh, d.NdotsHigh),
			[]string{
				"note: ndots >3 is set by Kubernetes (ndots:5) and may leak internal hostnames",
				"to inspect: grep ndots /etc/resolv.conf",
				"to fix: reduce to ndots:2 unless Kubernetes service discovery requires it",
			},
		))
	}
	if d.IPv6Only {
		out = append(out, insight("WARN", "DNS",
			"all configured nameservers are IPv6 — applications without IPv6 support may fail to resolve",
			[]string{
				"to fix: add at least one IPv4 nameserver to /etc/resolv.conf",
				fmt.Sprintf("current: %s", strings.Join(d.Nameservers, ", ")),
			},
		))
	}
	if len(d.DuplicateNameserver) > 0 {
		out = append(out, insight("INFO", "DNS",
			fmt.Sprintf("duplicate nameserver entries: %s", strings.Join(d.DuplicateNameserver, ", ")),
			[]string{"to fix: remove duplicate entries from /etc/resolv.conf"},
		))
	}
	return out
}

// ── cgroup v2 heuristics ─────────────────────────────────────────────────────
// Integrated into checkHealthDeep (HealthDeepInfo) below.

func checkCgroupV2(cg models.CgroupV2Info) []models.Insight {
	if !cg.Available {
		return nil
	}
	var out []models.Insight

	// OOM kills at root scope
	if cg.OOMKills > 0 {
		out = append(out, insight("CRIT", "Cgroup",
			fmt.Sprintf("cgroup OOM kill counter = %d — processes are being killed due to memory limits",
				cg.OOMKills),
			[]string{
				"to inspect: cat /sys/fs/cgroup/memory.events",
				"to inspect: journalctl -k | grep -i oom",
				"to identify: dmesg | grep -i 'oom_kill\\|out of memory'",
			},
		))
	}

	// CPU throttled slices
	for _, s := range cg.Slices {
		if s.ThrottledPct > 20 {
			out = append(out, insight("CRIT", "Cgroup",
				fmt.Sprintf("%s CPU throttled %.0f%% — workloads are hitting cpu.max limits",
					s.Name, s.ThrottledPct),
				[]string{
					fmt.Sprintf("to inspect: cat /sys/fs/cgroup/%s/cpu.stat", s.Name),
					fmt.Sprintf("to fix: increase or remove cpu.max in /sys/fs/cgroup/%s/cpu.max", s.Name),
					"note: throttling causes latency spikes even when overall CPU is idle",
				},
			))
		} else if s.ThrottledPct > 5 {
			out = append(out, insight("WARN", "Cgroup",
				fmt.Sprintf("%s CPU throttled %.0f%%",
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
