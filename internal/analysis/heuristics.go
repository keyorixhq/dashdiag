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
func applyOneExtended(data interface{}, thresh Thresholds) []models.Insight {
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
	case models.BatteryInfo:
		return checkBattery(d)
	case *models.BatteryInfo:
		if d != nil {
			return checkBattery(*d)
		}
	case models.ThermalInfo:
		return checkThermal(d)
	case *models.ThermalInfo:
		if d != nil {
			return checkThermal(*d)
		}
	case models.HealthDeepInfo:
		return checkHealthDeep(d)
	case *models.HealthDeepInfo:
		return checkHealthDeep(*d)
	case models.DockerInfo:
		return checkDocker(d)
	case *models.DockerInfo:
		return checkDocker(*d)
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
	l := levelPct(cpu.LoadPct, thresh.CPULoadWarnMultiplier*100, thresh.CPULoadCritMultiplier*100)
	if l == "" {
		return nil
	}
	return []models.Insight{insight(l, "CPU",
		fmt.Sprintf("load average at %.0f%% of capacity (%.2f / %d CPUs)", cpu.LoadPct, cpu.LoadAvg1, cpu.NumCPU),
		[]string{"to inspect: uptime", "to inspect: ps aux --sort=-%cpu | head -10", "to inspect: top -b -n1 | head -25"},
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
			out = append(out, insight(l, "Disk",
				fmt.Sprintf("disk usage at %.0f%% on %s (%s)", fs.UsedPct, fs.Mount, fs.Device),
				[]string{"to inspect: df -h", fmt.Sprintf("to inspect: du -sh %s/* 2>/dev/null | sort -h | tail -20", fs.Mount)},
			))
		}
		if l := levelPct(fs.InodesUsedPct, thresh.DiskWarnPct, thresh.DiskCritPct); l != "" {
			out = append(out, insight(l, "Disk",
				fmt.Sprintf("inode usage at %.0f%% on %s", fs.InodesUsedPct, fs.Mount),
				[]string{"to inspect: df -i", fmt.Sprintf("to inspect: find %s -xdev -printf '%%h\\n' | sort | uniq -c | sort -rn | head -20", fs.Mount)},
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
	for _, dev := range io.Devices {
		warnUtil, critUtil := thresh.IOUtilWarnPctSSD, thresh.IOUtilCritPctSSD
		warnAwait, critAwait := ioAwaitThresholds(dev.DriveType, thresh)

		if l := levelPct(dev.UtilPct, warnUtil, critUtil); l != "" {
			out = append(out, insight(l, "IO",
				fmt.Sprintf("disk %s utilization at %.0f%%", dev.Name, dev.UtilPct),
				[]string{"to inspect: iostat -x 1 5", "to inspect: iotop -ao"},
			))
		}
		if l := levelPct(dev.AwaitMs, warnAwait, critAwait); l != "" {
			out = append(out, insight(l, "IO",
				fmt.Sprintf("disk %s await latency %.1f ms", dev.Name, dev.AwaitMs),
				[]string{"to inspect: iostat -x 1 5", "to inspect: iotop -ao"},
			))
		}
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
func checkNetwork(net models.NetworkInfo) []models.Insight { //nolint:funlen // network checks are a flat list; splitting would hurt readability
	var out []models.Insight
	if net.PrimaryInterfaceDown {
		out = append(out, insight("CRIT", "Network",
			fmt.Sprintf("primary interface %s is DOWN", net.PrimaryInterface),
			[]string{fmt.Sprintf("to fix: ip link set %s up", net.PrimaryInterface), "to inspect: ip link show", "to inspect: ip route"},
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
			[]string{"to inspect: ss -tan | grep TIME-WAIT | wc -l", "to fix: sysctl -w net.ipv4.tcp_tw_reuse=1"},
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
			[]string{"to fix: sysctl -w net.core.somaxconn=4096", "to fix: sysctl -w net.ipv4.tcp_max_syn_backlog=4096"},
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
			[]string{"to inspect: conntrack -C", "to fix: sysctl -w net.netfilter.nf_conntrack_max=262144"},
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
		out = append(out, insight("CRIT", "Clock",
			"NTP is not synchronized",
			[]string{"to inspect: timedatectl status", "to inspect: chronyc tracking", "to inspect: systemctl status chronyd ntpd"},
		))
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
		return []models.Insight{insight("INFO", "Systemd",
			"systemd not present",
			nil,
		)}
	}
	out := make([]models.Insight, 0, len(sys.FailedUnits))
	for _, unit := range sys.FailedUnits {
		out = append(out, insight("CRIT", "Systemd",
			fmt.Sprintf("unit %s has failed", unit),
			[]string{fmt.Sprintf("to inspect: systemctl status %s", unit), fmt.Sprintf("to inspect: journalctl -u %s -n 50", unit)},
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
			[]string{"to inspect: sysctl net.core.somaxconn", "to fix: sysctl -w net.core.somaxconn=4096"},
		))
	} else if sysctl.NetSomaxconn != 0 && sysctl.NetSomaxconn < 1024 {
		out = append(out, insight("WARN", "Sysctl",
			fmt.Sprintf("net.core.somaxconn=%d is low (< 1024)", sysctl.NetSomaxconn),
			[]string{"to inspect: sysctl net.core.somaxconn", "to fix: sysctl -w net.core.somaxconn=4096"},
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
				[]string{"to fix: sysctl -w vm.max_map_count=262144", "to persist: echo 'vm.max_map_count=262144' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
		if sysctl.FSInotifyWatches > 0 && sysctl.FSInotifyWatches < 524288 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("fs.inotify.max_user_watches=%d is low for k8s (recommended: 524288)", sysctl.FSInotifyWatches),
				[]string{"to fix: sysctl -w fs.inotify.max_user_watches=524288", "to persist: echo 'fs.inotify.max_user_watches=524288' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
		if sysctl.VMSwappiness > 10 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("vm.swappiness=%d is high for k8s node (recommended: \u2264 10)", sysctl.VMSwappiness),
				[]string{"to fix: sysctl -w vm.swappiness=10", "to persist: echo 'vm.swappiness=10' >> /etc/sysctl.d/99-dsd.conf"},
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
				[]string{"to fix: sysctl -w net.core.rmem_max=16777216", "to persist: echo 'net.core.rmem_max=16777216' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}

	case "database":
		if sysctl.VMSwappiness > 10 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("vm.swappiness=%d is high for database workload (recommended: \u2264 10)", sysctl.VMSwappiness),
				[]string{"to fix: sysctl -w vm.swappiness=10", "to persist: echo 'vm.swappiness=10' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
		if sysctl.VMDirtyRatio > 10 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("vm.dirty_ratio=%d is high for database (recommended: \u2264 10 to reduce write latency spikes)", sysctl.VMDirtyRatio),
				[]string{"to fix: sysctl -w vm.dirty_ratio=10", "to fix: sysctl -w vm.dirty_background_ratio=3", "to persist: echo 'vm.dirty_ratio=10' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}

	case "elasticsearch":
		if sysctl.VMMaxMapCount > 0 && sysctl.VMMaxMapCount < 262144 {
			out = append(out, insight("CRIT", "Sysctl",
				fmt.Sprintf("vm.max_map_count=%d \u2014 Elasticsearch requires \u2265 262144 or it will refuse to start", sysctl.VMMaxMapCount),
				[]string{"to fix: sysctl -w vm.max_map_count=262144", "to persist: echo 'vm.max_map_count=262144' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
		if sysctl.VMSwappiness > 1 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("vm.swappiness=%d \u2014 Elasticsearch recommends 1 to minimise GC pauses from swapping", sysctl.VMSwappiness),
				[]string{"to fix: sysctl -w vm.swappiness=1", "to persist: echo 'vm.swappiness=1' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}

	case "container":
		if sysctl.VMMaxMapCount > 0 && sysctl.VMMaxMapCount < 262144 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("vm.max_map_count=%d is low for container host running JVM workloads (recommended: 262144)", sysctl.VMMaxMapCount),
				[]string{"to fix: sysctl -w vm.max_map_count=262144", "to persist: echo 'vm.max_map_count=262144' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
		if sysctl.FSInotifyWatches > 0 && sysctl.FSInotifyWatches < 131072 {
			out = append(out, insight("WARN", "Sysctl",
				fmt.Sprintf("fs.inotify.max_user_watches=%d is low for container host (recommended: 131072+)", sysctl.FSInotifyWatches),
				[]string{"to fix: sysctl -w fs.inotify.max_user_watches=131072", "to persist: echo 'fs.inotify.max_user_watches=131072' >> /etc/sysctl.d/99-dsd.conf"},
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
				[]string{"to fix: sysctl -w net.core.rmem_max=4194304", "to persist: echo 'net.core.rmem_max=4194304' >> /etc/sysctl.d/99-dsd.conf"},
			))
		}
	}

	return out
}

func checkKernelSecurity(mac models.KernelSecurityInfo, thresh Thresholds) []models.Insight {
	seActive := mac.SELinuxPresent && mac.SELinuxMode != "disabled"
	aaActive := mac.AppArmorPresent && mac.AppArmorMode != "disabled" && mac.AppArmorMode != "unknown"
	aaIndeterminate := mac.AppArmorPresent && mac.AppArmorMode == "unknown"
	if !seActive && !aaActive {
		if aaIndeterminate {
			return []models.Insight{insight("INFO", "KernelSec",
				"AppArmor present but mode unreadable — re-run as root",
				nil,
			)}
		}
		return []models.Insight{insight("INFO", "KernelSec",
			"kernel security module not enforced",
			nil,
		)}
	}
	if !mac.SELinuxPresent {
		return nil
	}
	if l := func() string {
		if mac.SELinuxDenials >= thresh.SELinuxDenialsCritPerHr {
			return "CRIT"
		}
		if mac.SELinuxDenials >= thresh.SELinuxDenialsWarnPerHr {
			return "WARN"
		}
		return ""
	}(); l != "" {
		return []models.Insight{insight(l, "KernelSec",
			fmt.Sprintf("%d SELinux denials (mode: %s)", mac.SELinuxDenials, mac.SELinuxMode),
			[]string{"to inspect: ausearch -m avc -ts recent", "to inspect: sealert -a /var/log/audit/audit.log"},
		)}
	}
	return nil
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
			[]string{"to inspect: journalctl --disk-usage", "to fix: journalctl --vacuum-size=1G"},
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
	return out
}

func checkEntropy(e models.EntropyInfo) []models.Insight {
	if e.Available < 0 {
		return nil // not available on this platform
	}
	if e.Available < 64 {
		return []models.Insight{insight("CRIT", "Entropy",
			fmt.Sprintf("entropy pool critically low (%d bits) — crypto operations may block or fail", e.Available),
			[]string{"to inspect: cat /proc/sys/kernel/random/entropy_avail", "to fix: install haveged or rng-tools"},
		)}
	}
	if e.Available < 256 {
		return []models.Insight{insight("WARN", "Entropy",
			fmt.Sprintf("entropy pool low (%d bits) — TLS and key generation may slow down", e.Available),
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

func checkNVMe(n models.NVMeInfo) []models.Insight {
	if len(n.Devices) == 0 {
		return nil
	}
	var out []models.Insight
	for _, dev := range n.Devices {
		if dev.CriticalWarning > 0 {
			out = append(out, insight("CRIT", "NVMe",
				fmt.Sprintf("%s critical warning flag set (0x%02x) — drive may be failing", dev.Name, dev.CriticalWarning),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
		if dev.MediaErrors > 0 {
			out = append(out, insight("CRIT", "NVMe",
				fmt.Sprintf("%s has %d media error(s) — data integrity risk", dev.Name, dev.MediaErrors),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
		if dev.AvailableSparePct > 0 && dev.AvailableSparePct <= dev.SpareThresholdPct {
			out = append(out, insight("CRIT", "NVMe",
				fmt.Sprintf("%s spare capacity at %d%% (threshold: %d%%) — drive near end of life", dev.Name, dev.AvailableSparePct, dev.SpareThresholdPct),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		} else if dev.AvailableSparePct > 0 && dev.AvailableSparePct < 20 {
			out = append(out, insight("WARN", "NVMe",
				fmt.Sprintf("%s spare capacity low at %d%%", dev.Name, dev.AvailableSparePct),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
		if dev.PercentageUsed >= 90 {
			out = append(out, insight("WARN", "NVMe",
				fmt.Sprintf("%s wear at %d%% — consider replacement planning", dev.Name, dev.PercentageUsed),
				[]string{"to inspect: nvme smart-log " + dev.Name},
			))
		}
		if dev.TempC >= 70 {
			out = append(out, insight("WARN", "NVMe",
				fmt.Sprintf("%s temperature %g°C — elevated for NVMe", dev.Name, dev.TempC),
				[]string{"to inspect: nvme smart-log " + dev.Name},
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

func checkThermal(t models.ThermalInfo) []models.Insight {
	if t.CPUTempC == 0 || t.Source == "" {
		return nil // no thermal data available on this platform
	}
	if t.CPUTempC >= 95 {
		return []models.Insight{insight("CRIT", "Thermal",
			fmt.Sprintf("CPU temperature %g°C — thermal throttling active", t.CPUTempC),
			[]string{"to inspect: cat /sys/class/hwmon/hwmon*/temp*_input", "to inspect: check cooling and airflow"},
		)}
	}
	if t.CPUTempC >= 85 {
		return []models.Insight{insight("WARN", "Thermal",
			fmt.Sprintf("CPU temperature %g°C — elevated (source: %s)", t.CPUTempC, t.Source),
			[]string{"to inspect: cat /sys/class/hwmon/hwmon*/temp*_input"},
		)}
	}
	return nil
}

func checkGPU(gpu models.GPUInfo) []models.Insight {
	if len(gpu.Devices) == 0 {
		return nil // no GPU or driver not loaded — skip silently
	}
	var out []models.Insight
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

func checkSecurity(sec models.SecurityInfo) []models.Insight { //nolint:funlen // security checks are a flat list of independent conditions; splitting would harm readability
	var out []models.Insight

	if sec.NeedsRoot {
		out = append(out, insight("INFO", "Hardening",
			"some checks limited — run as root for port process names, failed logins, and SELinux audit log",
			nil,
		))
	}

	// SSH misconfigurations
	if sec.SSHPermitRoot {
		out = append(out, insight("CRIT", "Hardening",
			"SSH permits root login",
			[]string{"to fix: set PermitRootLogin no in /etc/ssh/sshd_config", "to fix: systemctl restart sshd"},
		))
	}
	if sec.SSHPasswordAuth {
		out = append(out, insight("WARN", "Hardening",
			"SSH allows password authentication — key-based auth recommended",
			[]string{"to fix: set PasswordAuthentication no in /etc/ssh/sshd_config"},
		))
	}

	// Failed logins
	if sec.FailedLogins >= 20 {
		msg := fmt.Sprintf("%d failed login attempts in the last hour", sec.FailedLogins)
		if len(sec.FailedLoginIPs) > 0 {
			msg += fmt.Sprintf(" — top sources: %s", strings.Join(sec.FailedLoginIPs[:min(3, len(sec.FailedLoginIPs))], ", "))
		}
		out = append(out, insight("CRIT", "Hardening", msg,
			[]string{"to inspect: journalctl _COMM=sshd | grep -E 'Failed|penalty' | tail -20", "to fix: consider fail2ban or firewall rules"},
		))
	} else if sec.FailedLogins >= 5 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d failed login attempts in the last hour", sec.FailedLogins),
			[]string{"to inspect: journalctl _COMM=sshd | grep -E 'Failed|penalty' | tail -20"},
		))
	}

	// Unexpected listening ports — group all into one insight
	var unexpectedPorts []string
	var portHints []string
	portHints = append(portHints, "to inspect: ss -tlnp")
	for _, p := range sec.ListeningPorts {
		if !p.Expected {
			unexpectedPorts = append(unexpectedPorts,
				fmt.Sprintf("%d/%s", p.Port, p.Protocol))
			portHints = append(portHints,
				fmt.Sprintf("to inspect: ss -tlnp | grep :%d", p.Port))
		}
	}
	if len(unexpectedPorts) > 0 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d unexpected port(s) listening on all interfaces: %s",
				len(unexpectedPorts), strings.Join(unexpectedPorts, ", ")),
			portHints,
		))
	}

	// Sudo NOPASSWD
	if len(sec.SudoNopasswd) > 0 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("NOPASSWD sudo for: %s", strings.Join(sec.SudoNopasswd, ", ")),
			[]string{"to inspect: sudo -l", "to inspect: cat /etc/sudoers"},
		))
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
			[]string{"to inspect: awk -F: '$3==0' /etc/passwd", "to fix: remove or reassign UID for affected accounts"},
		))
	}

	// Suspect cron entries
	if len(sec.SuspectCrons) > 0 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d suspect cron entry(ies) — pipes to shell or writes to sensitive paths", len(sec.SuspectCrons)),
			[]string{"to inspect: cat /etc/cron.d/* /var/spool/cron/crontabs/*", "to inspect: review entries piping to bash or wget/curl"},
		))
	}

	// SELinux denials
	if sec.SELinuxDenials >= 10 {
		out = append(out, insight("WARN", "Hardening",
			fmt.Sprintf("%d SELinux denials in the last hour (mode: %s)", sec.SELinuxDenials, sec.SELinuxMode),
			[]string{"to inspect: ausearch -m avc -ts recent", "to inspect: sealert -a /var/log/audit/audit.log"},
		))
	}

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
		return nil
	}

	// distro-correct fix commands
	fixCmd := "apt-get upgrade"
	inspectCmd := "apt list --upgradable 2>/dev/null | grep -i security"
	if pkg.PackageManager == "dnf" {
		fixCmd = "dnf upgrade --security"
		inspectCmd = "dnf updateinfo list security"
	}

	if pkg.CriticalUpdates > 0 {
		out = append(out, insight("CRIT", "Packages",
			fmt.Sprintf("%d critical security update(s) available (%s)", pkg.CriticalUpdates, pkg.PackageManager),
			[]string{
				fmt.Sprintf("to fix: %s", fixCmd),
				fmt.Sprintf("to inspect: %s", inspectCmd),
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

	return out
}
