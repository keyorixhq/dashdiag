package analysis

import (
	"fmt"
	"runtime"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

const (
	inspectVMStat    = "to inspect: vmstat 1 5"
	inspectIOStat    = "to inspect: iostat -x 1 5"
	inspectPsMemHead = "to inspect: ps aux --sort=-%mem | head -10"
	inspectIotop     = "to inspect: iotop -ao"
)

func checkCPU(cpu models.CPUInfo, thresh Thresholds, ctrCtx platform.ContainerContext) []models.Insight {
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
		out = append(out, insight(l, corrCatCPULoad,
			msg,
			[]string{"to inspect: uptime", "to inspect: ps aux --sort=-%cpu | head -10", "to inspect: top -b -n1 | head -25"},
		))
	}

	// CPU steal — hypervisor is withholding CPU from this VM.
	// Only meaningful on virtual machines (bare metal always shows 0).
	// > 10%: host is over-provisioned — neighbours are competing for physical CPUs.
	// > 20%: severe — application latency will be unpredictable.
	// When a host CPU limit is known (VMware stat channel, threaded in by the
	// pre-scan), the steal is attributed to that configured cap instead — the
	// remediation is to remove the limit in vSphere, NOT migrate the VM (§N.4).
	if ins, ok := cpuStealInsight(cpu.StealPct, cpu.HostCPULimitMHz); ok {
		out = append(out, ins)
	}

	// Allocated-but-offline vCPUs — a hot-added vCPU the guest never onlined.
	// Skipped in a container: lxcfs/cgroup present a cpuset-limited core count as
	// "online" against the host's full "present" set, so a correctly-allocated
	// container (e.g. cores=2 on an 8-core host) looks like 6 offline vCPUs. The
	// container can't online host CPUs anyway, so the WARN and its remediation are
	// both wrong inside one.
	if !ctrCtx.InContainer {
		if ins, ok := cpuOfflineInsight(cpu); ok {
			out = append(out, ins)
		}
	}

	// CPU iowait — CPU is idle but blocked waiting for I/O.
	// High iowait with normal/low CPU usage means load is I/O-driven, not compute-driven.
	// This is the canonical "high load average but CPU is not busy" pattern.
	if cpu.IOwaitPct >= 40 {
		out = append(out, insight("CRIT", corrCatCPUIOwait,
			fmt.Sprintf("I/O wait at %.1f%% — CPU is stalled waiting for disk or network I/O", cpu.IOwaitPct),
			[]string{
				inspectIOStat,
				inspectIotop,
				"to inspect: ps aux | grep ' D '  (D-state processes blocked on I/O)",
				"note: high iowait with normal CPU usage = disk bottleneck, not CPU",
			},
		))
	} else if cpu.IOwaitPct >= 20 {
		out = append(out, insight("WARN", corrCatCPUIOwait,
			fmt.Sprintf("I/O wait at %.1f%% — load may be I/O-driven rather than CPU-bound", cpu.IOwaitPct),
			[]string{
				inspectIOStat,
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
	// RunQueue (procs_running) is a single instantaneous /proc/stat sample, inflated
	// by dsd's own parallel collectors on small-core hosts — so the 1-min load average
	// (immune; predates this run) must corroborate the saturation at the SAME tier, not
	// merely clear the warn floor. A genuine 4× run queue pins load avg well above the
	// core count; a momentary procs_running spike on a 1-vCPU box does not. Without the
	// tier-matched gate, that spike false-CRIT'd an otherwise-idle VM (load ~1.0).
	if cpu.NumCPU > 0 && cpu.RunQueue > 0 {
		cpuLabel := pluralize(cpu.NumCPU, "CPU", "CPUs")
		switch {
		case cpu.RunQueue >= 4*cpu.NumCPU && loadPct >= 200:
			out = append(out, insight("CRIT", "CPU Load/RunQueue",
				fmt.Sprintf("%d runnable tasks on %s — run queue is ~%d× saturated, tasks are waiting for CPU",
					cpu.RunQueue, cpuLabel, cpu.RunQueue/cpu.NumCPU),
				runQueueHints(cpu),
			))
		case cpu.RunQueue >= 2*cpu.NumCPU && loadPct >= 100:
			out = append(out, insight("WARN", "CPU Load/RunQueue",
				fmt.Sprintf("%d runnable tasks on %s — more tasks ready to run than cores available",
					cpu.RunQueue, cpuLabel),
				runQueueHints(cpu),
			))
		}
	}

	return out
}

func checkMemory(mem models.MemoryInfo, thresh Thresholds, ctrCtx platform.ContainerContext) []models.Insight {
	var out []models.Insight
	// Inside a memory-limited container whose cgroup usage wasn't measurable,
	// UsedPct/FreeGB are still derived from host-wide /proc/meminfo while TotalGB is
	// the container's cgroup ceiling — scoring one against the other would compare
	// two different things (host pressure vs. a container limit) and produce a
	// false-OK (idle container, busy host masks nothing) or false-WARN (busy host,
	// idle container) in either direction. Skip rather than guess.
	ramUnmeasurable := ctrCtx.InContainer && ctrCtx.MemLimitMB > 0 && !mem.CgroupMemMeasured
	if ramUnmeasurable {
		out = append(out, unverifiedInsight("INFO", "Memory",
			"RAM usage check skipped — cgroup memory usage could not be read in this container, so host /proc/meminfo can't be validly scored against the container's memory limit",
			[]string{"note: needs the memory controller mounted and readable (memory.current on cgroup v2, memory.usage_in_bytes on v1)"}))
	} else if l := levelPct(mem.UsedPct, thresh.RAMWarnPct, thresh.RAMCritPct); l != "" {
		var memHints []string
		if runtime.GOOS == "darwin" {
			memHints = []string{"to inspect: vm_stat", "to inspect: top -l 1 | grep PhysMem", "to inspect: ps aux -m | head -10"}
		} else {
			memHints = []string{inspectFreeH, inspectPsMemHead}
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
	out = append(out, memHotplugInsights(mem)...)
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
	actIn, actOut := swap.PagesInPerSec, swap.PagesOutPerSec
	maxAct := actIn
	if actOut > maxAct {
		maxAct = actOut
	}
	// Static swap OCCUPANCY. A near-full swap is a genuine OOM-headroom risk even when
	// the box isn't paging right now (when swap fills, the OOM killer starts), so CRIT
	// at the crit threshold unconditionally. Mid-range occupancy, though, is only
	// meaningful when the box is ACTUALLY paging: under the default swappiness the
	// kernel proactively parks idle anon pages in swap, so a healthy long-running
	// server routinely sits at 20-40% swap used with zero memory pressure (handled
	// above) and zero paging activity — WARNing on that occupancy alone was a false
	// alarm. So gate the mid-range WARN on light paging, and leave heavy paging to the
	// rate branch below (the `<= SwapActivityWarn` guard keeps the two from doubling).
	switch {
	case swap.UsedPct >= thresh.SwapCritPct:
		out = append(out, insight("CRIT", "Swap",
			fmt.Sprintf("swap %.0f%% full (%.1f GB used) — near exhaustion; the OOM killer starts when swap fills", swap.UsedPct, swap.UsedGB),
			[]string{inspectFreeH, inspectPsMemHead, inspectVMStat},
		))
	case swap.UsedPct >= thresh.SwapWarnPct && maxAct > 0 && maxAct <= thresh.SwapActivityWarn:
		out = append(out, insight("WARN", "Swap",
			fmt.Sprintf("swap %.0f%% used (%.1f GB) and paging — memory may be under real pressure", swap.UsedPct, swap.UsedGB),
			[]string{inspectFreeH, inspectVMStat},
		))
	}
	switch {
	case maxAct > thresh.SwapActivityCrit:
		// Heavy sustained paging warrants a CRIT even on zram: at this rate the
		// (de)compression CPU cost and the memory shortfall it implies both bite.
		out = append(out, insight("CRIT", "Swap",
			fmt.Sprintf("heavy swap activity: %.0f pages/s in, %.0f pages/s out", actIn, actOut),
			[]string{inspectVMStat, "to inspect: sar -W 1 5", inspectPsMemHead},
		))
	case maxAct > thresh.SwapActivityWarn && swap.ZramDevices > 0:
		// zram-backed swap is compressed RAM, not disk. Moderate paging is normal
		// on zram-by-default distros (Fedora/Ubuntu/Pop!_OS/SteamOS) and is not the
		// latency cliff a disk-swap WARN implies — report it as context, not a fault.
		out = append(out, insight("INFO", "Swap",
			fmt.Sprintf("swap activity: %.0f pages/s in, %.0f pages/s out — zram-backed (compressed RAM, not disk thrash)", actIn, actOut),
			[]string{"to inspect: zramctl", inspectVMStat},
		))
	case maxAct > thresh.SwapActivityWarn:
		out = append(out, insight("WARN", "Swap",
			fmt.Sprintf("swap activity detected: %.0f pages/s in, %.0f pages/s out", actIn, actOut),
			[]string{inspectVMStat, inspectFreeH},
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
			hints := []string{inspectIOStat, inspectIotop}
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
				[]string{inspectIOStat, inspectIotop},
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

func checkHealthDeep(d models.HealthDeepInfo) []models.Insight {
	var out []models.Insight

	// Core imbalance — one thread bottleneck. Gate on a SUSTAINED single-thread
	// load: one hot core on an otherwise-idle box (e.g. loadavg 0.25 on 12 cores)
	// is just normal foreground work with spare capacity, NOT a bottleneck —
	// flagging it WARN was a false alarm (seen on a real AMD/12-core host). A genuine
	// single-threaded bottleneck keeps a thread continuously runnable, so loadavg1
	// is at least ~1.0; the 1-min average also predates (and is immune to) dsd's own
	// per-core sampling spike.
	if d.CoreImbalance >= 80 && len(d.Cores) > 1 && d.LoadAvg1 >= 1.0 {
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
				inspectIOStat,
			},
		))
	}

	// cgroup v2 slice health
	if d.Cgroup != nil {
		out = append(out, checkCgroupV2(*d.Cgroup)...)
	}

	return out
}

// cpuStealInsight builds the CPU-steal insight for a given steal percentage,
// returning ok=false below the WARN floor (10%). When hostCPULimitMHz > 0 a host
// CPU cap is known to be configured on this VM (e.g. a VMware vSphere limit read
// via open-vm-tools), so the steal is attributed to that cap — the guest is being
// throttled to its limit, which presents in the guest as steal time. That changes
// the remediation from the generic "migrate to a less-loaded host" (which does NOT
// help against a configured limit) to "remove the limit in vSphere" (§N.4). The
// severity still tracks the steal magnitude (≥20% CRIT, ≥10% WARN).
func cpuStealInsight(stealPct float64, hostCPULimitMHz int) (models.Insight, bool) {
	level := ""
	switch {
	case stealPct >= 20:
		level = "CRIT"
	case stealPct >= 10:
		level = "WARN"
	default:
		return models.Insight{}, false
	}

	if hostCPULimitMHz > 0 {
		return insight(level, corrCatCPUSteal,
			fmt.Sprintf("CPU steal at %.1f%% with a host CPU limit of %d MHz configured on this VM — the guest is being throttled to its configured cap, not losing CPU to noisy neighbours",
				stealPct, hostCPULimitMHz),
			[]string{
				"to fix: remove or raise the VM's CPU limit in vSphere (Edit Settings → CPU → Limit = Unlimited)",
				"to inspect: vmware-toolbox-cmd stat cpulimit",
				"note: migrating the VM will NOT help — this is a configured cap, not host contention",
			},
		), true
	}

	if level == "CRIT" {
		return insight("CRIT", corrCatCPUSteal,
			fmt.Sprintf("CPU steal at %.1f%% — hypervisor is withholding CPU time from this VM", stealPct),
			[]string{
				"to inspect: top -b -n1 | grep Cpu",
				"to inspect: vmstat 1 5  (look at the 'st' column)",
				"note: steal > 20%% means the host is severely over-provisioned",
				"note: escalate to your cloud provider or migrate to a less-loaded host",
			},
		), true
	}
	return insight("WARN", corrCatCPUSteal,
		fmt.Sprintf("CPU steal at %.1f%% — VM is not getting all requested CPU cycles", stealPct),
		[]string{
			"to inspect: top -b -n1 | grep Cpu  (look for 'st' column)",
			inspectVMStat,
			"note: steal time indicates host over-provisioning — consider VM migration",
		},
	), true
}

// cpuOfflineInsight flags allocated-but-offline vCPUs: present > online. The common
// cause is a VMware/cloud CPU hot-add the guest never onlined — Debian/Ubuntu lack
// the auto-online udev rule RHEL ships, so the VM runs on a fraction of its
// allocation with no other signal (found live: a 14-vCPU VMware guest running on 2).
// Gated against the two intentional causes so it doesn't false-WARN: SMT
// force-disabled (sibling threads parked for a security mitigation) and
// isolcpus/nohz_full (cores deliberately isolated) → INFO, not WARN. ok=false when
// availability wasn't read (non-Linux) or all present CPUs are online.
func cpuOfflineInsight(cpu models.CPUInfo) (models.Insight, bool) {
	if cpu.PresentCPUs <= 0 || cpu.OnlineCPUs <= 0 || cpu.PresentCPUs <= cpu.OnlineCPUs {
		return models.Insight{}, false
	}
	offline := cpu.PresentCPUs - cpu.OnlineCPUs
	switch {
	case cpu.SMTControl == "off" || cpu.SMTControl == "forceoff":
		return insight("INFO", corrCatCPULoad,
			fmt.Sprintf("%d of %d CPUs are offline because SMT is disabled — the hyperthread siblings are parked (a security mitigation, expected)", offline, cpu.PresentCPUs),
			[]string{"to inspect: cat /sys/devices/system/cpu/smt/control"},
		), true
	case cpu.CPUsIsolated:
		return insight("INFO", corrCatCPULoad,
			fmt.Sprintf("%d of %d CPUs are offline/isolated — isolcpus or nohz_full is set on the kernel cmdline (intentional)", offline, cpu.PresentCPUs),
			[]string{"to inspect: cat /proc/cmdline"},
		), true
	default:
		return insight("WARN", corrCatCPULoad,
			fmt.Sprintf("%d of %d allocated vCPUs are offline — the guest is using only %d; a hot-added vCPU the OS never onlined (some distros lack the auto-online udev rule RHEL ships), so the VM runs on a fraction of its allocation", offline, cpu.PresentCPUs, cpu.OnlineCPUs),
			[]string{
				"to online now: for c in /sys/devices/system/cpu/cpu[0-9]*/online; do echo 1 > $c; done   (as root)",
				`to persist: a udev rule — SUBSYSTEM=="cpu", ACTION=="add", TEST=="online", ATTR{online}=="0", ATTR{online}="1"`,
				"note: if the offline CPUs are intentional (isolcpus / SMT off), this can be ignored",
			},
		), true
	}
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

// memHotplugInsights flags hot-added RAM the guest isn't using: memory blocks
// left offline while auto-onlining is disabled. This is the cross-platform
// "I grew the VM to 16 GB but it still shows 8" bug (VMware hot-add, KVM
// virtio-mem, Hyper-V Dynamic Memory, cloud vertical scaling). Gated on
// auto-online being OFF as well, so it does NOT fire on memory a balloon /
// virtio-mem driver intentionally offlined (where auto-online is irrelevant) —
// keeping it to the high-confidence misconfiguration.
func memHotplugInsights(mem models.MemoryInfo) []models.Insight {
	if !mem.MemHotplugChecked || mem.OfflineMemoryBlocks == 0 || mem.AutoOnlineBlocks {
		return nil
	}
	amount := fmt.Sprintf("%d memory block(s)", mem.OfflineMemoryBlocks)
	if mem.OfflineMemoryMB > 0 {
		amount = fmt.Sprintf("%.1f GB (%d block(s))", float64(mem.OfflineMemoryMB)/1024, mem.OfflineMemoryBlocks)
	}
	return []models.Insight{insight("WARN", "Memory",
		fmt.Sprintf("%s of RAM is offline and auto-onlining is disabled — hot-added memory the guest sees but is not using", amount),
		[]string{
			"to use it now: for f in /sys/devices/system/memory/memory*/state; do echo online > $f; done",
			"to persist: echo online > /sys/devices/system/memory/auto_online_blocks (or kernel arg memhp_default_state=online)",
			"note: common after growing a VM's RAM (VMware hot-add / cloud vertical scaling) without onlining the new blocks",
		})}
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
