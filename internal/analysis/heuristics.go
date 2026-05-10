package analysis

import (
	"fmt"
	"math"
	"runtime"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func ApplyThresholds(results []runner.Result, thresh Thresholds, env platform.CloudEnvironment) []models.Insight {
	var insights []models.Insight
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		switch data := r.Data.(type) {
		case models.CPUInfo:
			insights = append(insights, checkCPU(data, thresh)...)
		case *models.CPUInfo:
			insights = append(insights, checkCPU(*data, thresh)...)
		case models.MemoryInfo:
			insights = append(insights, checkMemory(data, thresh)...)
		case *models.MemoryInfo:
			insights = append(insights, checkMemory(*data, thresh)...)
		case models.DiskInfo:
			insights = append(insights, checkDisk(data, thresh)...)
		case *models.DiskInfo:
			insights = append(insights, checkDisk(*data, thresh)...)
		case models.SwapInfo:
			insights = append(insights, checkSwap(data, thresh)...)
		case *models.SwapInfo:
			insights = append(insights, checkSwap(*data, thresh)...)
		case models.IOInfo:
			insights = append(insights, checkIO(data, thresh)...)
		case *models.IOInfo:
			insights = append(insights, checkIO(*data, thresh)...)
		case models.NetworkInfo:
			insights = append(insights, checkNetwork(data)...)
		case *models.NetworkInfo:
			insights = append(insights, checkNetwork(*data)...)
		case models.ClockInfo:
			insights = append(insights, checkClock(data, thresh)...)
		case *models.ClockInfo:
			if data != nil {
				insights = append(insights, checkClock(*data, thresh)...)
			}
		case models.FDInfo:
			insights = append(insights, checkFD(data, thresh)...)
		case *models.FDInfo:
			insights = append(insights, checkFD(*data, thresh)...)
		case models.SystemdInfo:
			insights = append(insights, checkSystemd(data)...)
		case *models.SystemdInfo:
			insights = append(insights, checkSystemd(*data)...)
		case models.SysctlInfo:
			insights = append(insights, checkSysctl(data)...)
		case *models.SysctlInfo:
			insights = append(insights, checkSysctl(*data)...)
		case models.KernelSecurityInfo:
			insights = append(insights, checkKernelSecurity(data, thresh)...)
		case *models.KernelSecurityInfo:
			insights = append(insights, checkKernelSecurity(*data, thresh)...)
		case models.LogsInfo:
			insights = append(insights, checkLogs(data, thresh)...)
		case *models.LogsInfo:
			insights = append(insights, checkLogs(*data, thresh)...)
		case models.ProcessInfo:
			insights = append(insights, checkProcesses(data)...)
		case *models.ProcessInfo:
			insights = append(insights, checkProcesses(*data)...)
		}
	}
	return insights
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
		[]string{"uptime", "ps aux --sort=-%cpu | head -10", "top -b -n1 | head -25"},
	)}
}

func checkMemory(mem models.MemoryInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	if l := levelPct(mem.UsedPct, thresh.RAMWarnPct, thresh.RAMCritPct); l != "" {
		var memHints []string
		if runtime.GOOS == "darwin" {
			memHints = []string{"vm_stat", "top -l 1 | grep PhysMem", "ps aux -m | head -10"}
		} else {
			memHints = []string{"free -h", "ps aux --sort=-%mem | head -10"}
		}
		out = append(out, insight(l, "Memory",
			fmt.Sprintf("RAM usage at %.0f%% (%.1f GB free of %.1f GB total)", mem.UsedPct, mem.FreeGB, mem.TotalGB),
			memHints,
		))
	}
	if mem.OverCommitted {
		out = append(out, insight("CRIT", "Memory",
			"memory overcommitted — OOM kill risk",
			[]string{"cat /proc/meminfo | grep -E 'CommitLimit|Committed_AS'", "sysctl vm.overcommit_memory"},
		))
	}
	slabPct := 0.0
	if mem.TotalGB > 0 {
		slabPct = (mem.SlabMB / 1024) / mem.TotalGB * 100
	}
	if slabPct >= thresh.SlabWarnPct {
		out = append(out, insight("WARN", "Memory/Slab",
			fmt.Sprintf("kernel slab cache is %.0f%% of total RAM (%.0f MB)", slabPct, mem.SlabMB),
			[]string{"cat /proc/slabinfo | sort -k3 -rn | head -20", "slabtop -o | head -20"},
		))
	}
	return out
}

func checkDisk(disk models.DiskInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	for _, fs := range disk.Filesystems {
		// Use collector name "Disk" so insightForResult("Disk", insights) finds this insight.
		// Mount path is preserved in the message.
		if l := levelPct(fs.UsedPct, thresh.DiskWarnPct, thresh.DiskCritPct); l != "" {
			out = append(out, insight(l, "Disk",
				fmt.Sprintf("disk usage at %.0f%% on %s (%s)", fs.UsedPct, fs.Mount, fs.Device),
				[]string{"df -h", fmt.Sprintf("du -sh %s/* 2>/dev/null | sort -h | tail -20", fs.Mount)},
			))
		}
		if l := levelPct(fs.InodesUsedPct, thresh.DiskWarnPct, thresh.DiskCritPct); l != "" {
			out = append(out, insight(l, "Disk",
				fmt.Sprintf("inode usage at %.0f%% on %s", fs.InodesUsedPct, fs.Mount),
				[]string{"df -i", fmt.Sprintf("find %s -xdev -printf '%%h\\n' | sort | uniq -c | sort -rn | head -20", fs.Mount)},
			))
		}
	}
	return out
}

func checkSwap(swap models.SwapInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight

	// macOS path: MemPressureLevel > 0 is the Darwin sentinel (always set by collectDarwin).
	// macOS uses swap proactively even without memory pressure, so threshold-based alerts
	// without a pressure gate produce constant false WARNs on healthy machines.
	if swap.MemPressureLevel > 0 {
		if swap.MemPressureLevel > 1 {
			if l := levelPct(swap.UsedPct, 75, 90); l != "" {
				out = append(out, insight(l, "Swap",
					fmt.Sprintf("swap usage at %.0f%% with elevated memory pressure (level %d)", swap.UsedPct, swap.MemPressureLevel),
					[]string{"vm_stat | grep swap", "sysctl vm.swapusage", "top -l 1 | grep PhysMem"},
				))
			}
		}
		return out
	}

	// Linux path: threshold-based.
	if l := levelPct(swap.UsedPct, thresh.SwapWarnPct, thresh.SwapCritPct); l != "" {
		out = append(out, insight(l, "Swap",
			fmt.Sprintf("swap usage at %.0f%% (%.1f GB used)", swap.UsedPct, swap.UsedGB),
			[]string{"free -h", "vmstat 1 5"},
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
			[]string{"vmstat 1 5", "sar -W 1 5", "ps aux --sort=-%mem | head -10"},
		))
	} else if maxAct > thresh.SwapActivityWarn {
		out = append(out, insight("WARN", "Swap",
			fmt.Sprintf("swap activity detected: %.0f pages/s in, %.0f pages/s out", actIn, actOut),
			[]string{"vmstat 1 5", "free -h"},
		))
	}
	return out
}

func checkIO(io models.IOInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	for _, dev := range io.Devices {
		// Use collector name "IO" so insightForResult("IO", insights) finds this insight.
		// Device name is preserved in the message.
		if l := levelPct(dev.UtilPct, thresh.IOUtilWarnPctSSD, thresh.IOUtilCritPctSSD); l != "" {
			out = append(out, insight(l, "IO",
				fmt.Sprintf("disk %s utilization at %.0f%%", dev.Name, dev.UtilPct),
				[]string{"iostat -x 1 5", "iotop -ao"},
			))
		}
		if l := levelPct(dev.AwaitMs, thresh.IOAwaitWarnMsSSD, thresh.IOAwaitCritMsSSD); l != "" {
			out = append(out, insight(l, "IO",
				fmt.Sprintf("disk %s await latency %.1f ms", dev.Name, dev.AwaitMs),
				[]string{"iostat -x 1 5", "iotop -ao"},
			))
		}
	}
	return out
}

func checkNetwork(net models.NetworkInfo) []models.Insight {
	var out []models.Insight
	if net.PrimaryInterfaceDown {
		out = append(out, insight("CRIT", "Network",
			fmt.Sprintf("primary interface %s is DOWN", net.PrimaryInterface),
			[]string{fmt.Sprintf("ip link set %s up", net.PrimaryInterface), "ip link show", "ip route"},
		))
	} else if net.GatewayPingMs < 0 && net.InternetPingMs < 0 {
		// Both gateway and internet unreachable — truly disconnected.
		out = append(out, insight("CRIT", "Network",
			"gateway and internet unreachable — host appears offline",
			[]string{"ip route", "ip link show", "ping -c3 $(ip route | awk '/default/{print $3}')"},
		))
	} else if net.GatewayPingMs < 0 && net.InternetPingMs >= 0 {
		// Gateway not responding to probes but internet traffic is flowing.
		// Common with routers (e.g. Zyxel Keenetic) that drop ICMP/TCP probes
		// on the LAN interface while still forwarding traffic.
		out = append(out, insight("INFO", "Network",
			"gateway not responding to probes — internet traffic is flowing",
			[]string{"traceroute 8.8.8.8", "ping -c3 $(ip route | awk '/default/{print $3}')"},
		))
	} else if net.GatewayPingMs > 200 {
		out = append(out, insight("CRIT", "Network",
			fmt.Sprintf("gateway ping is %.0f ms — severe latency", net.GatewayPingMs),
			[]string{"ping -c5 $(ip route | awk '/default/{print $3}')", "ip route"},
		))
	} else if net.GatewayPingMs > 50 {
		out = append(out, insight("WARN", "Network",
			fmt.Sprintf("gateway ping is %.0f ms — elevated latency", net.GatewayPingMs),
			[]string{"ping -c5 $(ip route | awk '/default/{print $3}')"},
		))
	}
	if !net.PrimaryInterfaceDown && net.GatewayPingMs >= 0 {
		if net.GatewayPacketLossPct >= 50 {
			out = append(out, insight("CRIT", "Network",
				fmt.Sprintf("gateway packet loss %.0f%%", net.GatewayPacketLossPct),
				[]string{"ping -c20 $(ip route | awk '/default/{print $3}')", "ip link show"},
			))
		} else if net.GatewayPacketLossPct >= 10 {
			out = append(out, insight("WARN", "Network",
				fmt.Sprintf("gateway packet loss %.0f%%", net.GatewayPacketLossPct),
				[]string{"ping -c20 $(ip route | awk '/default/{print $3}')"},
			))
		}
	}
	if net.DNSFailed {
		out = append(out, insight("CRIT", "Network/DNS",
			"DNS resolution failed — cannot resolve hostnames",
			[]string{"dig @8.8.8.8 google.com", "cat /etc/resolv.conf", "systemctl status systemd-resolved"},
		))
	} else if net.DNSResolvesMs > 1000 {
		out = append(out, insight("CRIT", "Network/DNS",
			fmt.Sprintf("DNS resolution took %.0f ms", net.DNSResolvesMs),
			[]string{"dig @8.8.8.8 google.com", "cat /etc/resolv.conf", "systemctl status systemd-resolved"},
		))
	} else if net.DNSResolvesMs > 200 {
		out = append(out, insight("WARN", "Network/DNS",
			fmt.Sprintf("DNS resolution took %.0f ms", net.DNSResolvesMs),
			[]string{"dig @8.8.8.8 google.com", "cat /etc/resolv.conf"},
		))
	}
	if net.CloseWaitCount > 500 {
		out = append(out, insight("CRIT", "Network",
			fmt.Sprintf("%d CLOSE_WAIT connections — likely connection leak", net.CloseWaitCount),
			[]string{"ss -s", "ss -tan state close-wait | head -20"},
		))
	} else if net.CloseWaitCount > 100 {
		out = append(out, insight("WARN", "Network",
			fmt.Sprintf("%d CLOSE_WAIT connections", net.CloseWaitCount),
			[]string{"ss -s", "netstat -an | grep CLOSE_WAIT | wc -l"},
		))
	}
	return out
}

func checkClock(clock models.ClockInfo, thresh Thresholds) []models.Insight {
	var out []models.Insight
	if !clock.Synced {
		out = append(out, insight("CRIT", "Clock",
			"NTP is not synchronized",
			[]string{"timedatectl status", "chronyc tracking", "systemctl status chronyd ntpd"},
		))
	}
	if clock.OffsetMs != -1 {
		abs := math.Abs(clock.OffsetMs)
		if l := levelPct(abs, thresh.NTPOffsetWarnMs, thresh.NTPOffsetCritMs); l != "" {
			out = append(out, insight(l, "Clock",
				fmt.Sprintf("NTP offset is %.1f ms (source: %s)", clock.OffsetMs, clock.Source),
				[]string{"chronyc tracking", "ntpq -p", "timedatectl status"},
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
			[]string{"cat /proc/sys/fs/file-nr", "lsof | wc -l"},
		))
	}
	for _, proc := range fd.HotProcesses {
		if proc.UsedPct >= thresh.FDProcWarnPct {
			out = append(out, insight("WARN", "FDLimits",
				fmt.Sprintf("process %s (PID %d) has %d/%d FDs open (%.0f%%)",
					proc.Name, proc.PID, proc.OpenFDs, proc.SoftLimit, proc.UsedPct),
				[]string{
					fmt.Sprintf("ls /proc/%d/fd | wc -l", proc.PID),
					fmt.Sprintf("lsof -p %d | tail -20", proc.PID),
				},
			))
		}
	}
	if fd.DeletedOpenSizeGB >= 1 {
		out = append(out, insight("WARN", "FDLimits",
			fmt.Sprintf("%.1f GB held by deleted-but-open files", fd.DeletedOpenSizeGB),
			[]string{"lsof | grep deleted | head -20", "lsof | grep deleted | awk '{sum+=$7} END{print sum/1024/1024/1024\" GB\"}'"},
		))
	}
	return out
}

func checkSystemd(sys models.SystemdInfo) []models.Insight {
	if !sys.Available {
		return []models.Insight{insight("INFO", "Systemd",
			"systemd not present on this system",
			nil,
		)}
	}
	out := make([]models.Insight, 0, len(sys.FailedUnits))
	for _, unit := range sys.FailedUnits {
		out = append(out, insight("CRIT", "Systemd",
			fmt.Sprintf("unit %s has failed", unit),
			[]string{fmt.Sprintf("systemctl status %s", unit), fmt.Sprintf("journalctl -u %s -n 50", unit)},
		))
	}
	return out
}

func checkSysctl(sysctl models.SysctlInfo) []models.Insight {
	var out []models.Insight
	if sysctl.NetSomaxconn != 0 && sysctl.NetSomaxconn < 512 {
		out = append(out, insight("CRIT", "Sysctl",
			fmt.Sprintf("net.core.somaxconn=%d is critically low (< 512)", sysctl.NetSomaxconn),
			[]string{"sysctl net.core.somaxconn", "sysctl -w net.core.somaxconn=4096"},
		))
	} else if sysctl.NetSomaxconn != 0 && sysctl.NetSomaxconn < 1024 {
		out = append(out, insight("WARN", "Sysctl",
			fmt.Sprintf("net.core.somaxconn=%d is low (< 1024)", sysctl.NetSomaxconn),
			[]string{"sysctl net.core.somaxconn", "sysctl -w net.core.somaxconn=4096"},
		))
	}
	if sysctl.KernelPIDMax > 0 {
		pidPct := float64(sysctl.PIDCount) / float64(sysctl.KernelPIDMax) * 100
		if l := levelPct(pidPct, 80, 90); l != "" {
			out = append(out, insight(l, "Sysctl",
				fmt.Sprintf("PID table at %.0f%% (%d / %d)", pidPct, sysctl.PIDCount, sysctl.KernelPIDMax),
				[]string{"cat /proc/sys/kernel/pid_max", "ps aux | wc -l"},
			))
		}
	}
	return out
}

func checkKernelSecurity(mac models.KernelSecurityInfo, thresh Thresholds) []models.Insight {
	// "Active" means the module is present AND actually applying policies.
	// AppArmor in "disabled" mode counts as not active — common in containers
	// where /sys reports the host's AppArmor state but no profiles apply.
	seActive := mac.SELinuxPresent && mac.SELinuxMode != "disabled"
	aaActive := mac.AppArmorPresent && mac.AppArmorMode != "disabled"
	if !seActive && !aaActive {
		return []models.Insight{insight("INFO", "KernelSecurity",
			"no kernel security module enforcing on this system",
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
		return []models.Insight{insight(l, "KernelSecurity",
			fmt.Sprintf("%d SELinux denials (mode: %s)", mac.SELinuxDenials, mac.SELinuxMode),
			[]string{"ausearch -m avc -ts recent", "sealert -a /var/log/audit/audit.log"},
		)}
	}
	return nil
}

func checkLogs(logs models.LogsInfo, thresh Thresholds) []models.Insight {
	if l := levelPct(logs.JournalSizeGB, thresh.JournalSizeWarnGB, thresh.JournalSizeCritGB); l != "" {
		return []models.Insight{insight(l, "Logs",
			fmt.Sprintf("journal is %.1f GB", logs.JournalSizeGB),
			[]string{"journalctl --disk-usage", "journalctl --vacuum-size=1G"},
		)}
	}
	return nil
}

func checkProcesses(proc models.ProcessInfo) []models.Insight {
	var out []models.Insight
	if proc.ZombieCount >= 10 {
		out = append(out, insight("CRIT", "Processes",
			fmt.Sprintf("%d zombie processes detected", proc.ZombieCount),
			[]string{"ps aux | grep Z", "cat /proc/*/status | grep -E '^Name|^State' | paste - -"},
		))
	} else if proc.ZombieCount > 0 {
		out = append(out, insight("WARN", "Processes",
			fmt.Sprintf("%d zombie process(es) detected", proc.ZombieCount),
			[]string{"ps aux | grep Z"},
		))
	}
	if proc.HungCount >= 5 {
		out = append(out, insight("CRIT", "Processes",
			fmt.Sprintf("%d hung (uninterruptible) processes", proc.HungCount),
			[]string{"ps aux | grep ' D '", "for pid in $(ps -eo pid,stat | awk '$2~/D/{print $1}'); do cat /proc/$pid/wchan 2>/dev/null; done"},
		))
	} else if proc.HungCount > 0 {
		out = append(out, insight("WARN", "Processes",
			fmt.Sprintf("%d hung (uninterruptible) process(es)", proc.HungCount),
			[]string{"ps aux | grep ' D '"},
		))
	}
	return out
}
