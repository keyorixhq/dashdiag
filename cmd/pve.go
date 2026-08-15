package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	pveCmd.Flags().Bool("deep", false, "deep mode: run pveperf storage benchmark (~15s)")
	rootCmd.AddCommand(pveCmd)
}

var pveCmd = &cobra.Command{
	Use:   "pve",
	Short: "Proxmox VE health — VMs, containers, storage, cluster, backups",
	RunE:  runPVE,
}

func runPVE(cmd *cobra.Command, _ []string) error {
	deep, _ := cmd.Flags().GetBool("deep")
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	if !collectors.IsPVEHost() {
		fmt.Println(asciiOr("info", iconInfoSp, mode) + " Not a Proxmox VE node — dsd pve requires a Proxmox host")
		return nil
	}

	timeout := 18 * time.Second
	if deep {
		timeout = 40 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	col := collectors.NewPVECollector()
	cols := []runner.Collector{col}
	p := output.NewCommandProgress("PVE health", col.Timeout(), mode, len(cols))
	p.Start()

	var info *models.PVEInfo
	for r := range runner.RunAll(ctx, cols) {
		p.Step("")
		if v, ok := r.Data.(*models.PVEInfo); ok {
			info = v
		}
	}
	p.Done()
	elapsed := p.Elapsed()

	if info == nil {
		return nil
	}

	if mode == output.ModeJSON {
		if deep {
			perfCtx, perfCancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer perfCancel()
			info.Perf = collectors.CollectPVEPerf(perfCtx, "/var/lib/vz")
		}
		return printPVEJSON(info)
	}

	printPVEReport(info, deep, elapsed, mode)
	return nil
}

// printPVEJSON marshals the full PVE report as indented JSON to stdout.
func printPVEJSON(info *models.PVEInfo) error {
	return outputJSON(os.Stdout, info)
}

func printPVEReport(info *models.PVEInfo, deep bool, elapsed time.Duration, mode output.OutputMode) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	fmt.Println()
	fmt.Println(sep)

	// pvesh API unreachable (root path): everything below is empty/unverified.
	// Surface it up front so the report isn't read as a clean health check.
	if info.IsPVE && !info.NeedsRoot && !info.APIReachable {
		fmt.Println(render.StyleWarn.Render(asciiOr("warn", iconWarnSp, mode) +
			" Proxmox API (pvesh) not responding — health below could NOT be verified"))
		fmt.Println("    → to inspect: systemctl status pve-cluster corosync pvedaemon")
	}

	// Node overview
	printPVENode(info, mode)

	// VMs and containers
	printPVEGuests(info, mode)

	// Storage
	printPVEStorage(info, mode)

	// Task errors
	printPVETaskErrors(info, mode)

	// Cluster
	printPVECluster(info, mode)

	// Network bridges
	printPVEBridges(info, mode)

	// Backup
	printPVEBackup(info, mode)

	// Performance (deep)
	if deep {
		perfCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		info.Perf = collectors.CollectPVEPerf(perfCtx, "/var/lib/vz")
		printPVEPerf(info.Perf, mode)
	}

	// Summary
	fmt.Println()
	fmt.Println(sep)
	issues := countPVEIssues(info)
	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("%s Proxmox VE healthy. Checks passed%s", asciiOr("ok", iconOK, mode), timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("%s %d concern(s) found%s", asciiOr("warn", iconWarnSp, mode), issues, timing)))
	}
}

func printPVENode(info *models.PVEInfo, mode output.OutputMode) {
	fmt.Printf("\n[Proxmox Node]\n")

	// Host line: hostname + PVE version / kernel
	if info.PVEVersion != "" || info.KernelVersion != "" {
		host, _ := os.Hostname()
		verStr := ""
		if info.PVEVersion != "" {
			verStr = "PVE " + info.PVEVersion
		}
		if info.KernelVersion != "" {
			if verStr != "" {
				verStr += " / "
			}
			verStr += "kernel " + info.KernelVersion
		}
		fmt.Printf("  Host:     %-12s %s\n", host, verStr)
	}

	// CPU usage % — shown whenever node status was fetched (UptimeSec>0),
	// since an idle node legitimately reports 0% CPU.
	if info.UptimeSec > 0 {
		coresStr := ""
		if info.PhysicalCores > 0 {
			coresStr = fmt.Sprintf(" (%d cores)", info.PhysicalCores)
		}
		fmt.Printf("  CPU:      %.0f%% used%s\n", info.CPUPct, coresStr)
	}

	if info.PhysicalCores > 0 {
		fmt.Printf("  Cores:    %d physical\n", info.PhysicalCores)
	}
	if info.HostMemGB > 0 {
		fmt.Printf("  Memory:   %.1f GB\n", info.HostMemGB)
	}
	if info.UptimeSec > 0 {
		fmt.Printf("  Uptime:   %s\n", formatPVEUptime(info.UptimeSec))
	}
	// Subscription
	sub := info.Subscription
	subIcon := asciiOr("ok", iconOK, mode)
	subDetail := sub.Status
	switch strings.ToLower(sub.Status) {
	case "active":
		subDetail = "active"
		if sub.Product != "" {
			subDetail += " (" + sub.Product + ")"
		}
	case "notfound", "":
		subIcon = asciiOr("info", iconInfoSp, mode)
		subDetail = "no subscription (community edition)"
	case "expired":
		subIcon = asciiOr("warn", iconWarnSp, mode)
		subDetail = "subscription expired"
	case "unverified":
		subIcon = asciiOr("info", iconInfoSp, mode)
		subDetail = "configured, live status not verified (pvesh failed)"
	}
	fmt.Printf("  License:  %s %s\n", subIcon, subDetail)
}

func printPVEGuests(info *models.PVEInfo, mode output.OutputMode) {
	total := info.RunningCount + info.StoppedCount + info.PausedCount
	if total == 0 {
		if !info.GuestsVerified {
			// internal-models-11-02: a total count of 0 with GuestsVerified
			// false means guest enumeration itself failed (pvesh qemu/lxc
			// query error or unparseable JSON), not that the node genuinely
			// has no VMs/CTs. Say so instead of the same "none" a real
			// guest-less node gets.
			fmt.Printf("\n[VMs & Containers]  NOT verified — guest enumeration failed\n")
			fmt.Printf("  %s  to inspect: pvesh get /nodes/localhost/qemu\n", asciiOr(secLvlInfo, secIconInfo, mode))
			fmt.Printf("  %s  to inspect: pvesh get /nodes/localhost/lxc\n", asciiOr(secLvlInfo, secIconInfo, mode))
			return
		}
		fmt.Printf("\n[VMs & Containers]  none\n")
		return
	}
	fmt.Printf("\n[VMs & Containers]  (%d total: %d running, %d stopped",
		total, info.RunningCount, info.StoppedCount)
	if info.PausedCount > 0 {
		fmt.Printf(", %d paused", info.PausedCount)
	}
	fmt.Println(")")

	for _, g := range info.Guests {
		icon := asciiOr("ok", iconOK, mode)
		note := ""
		switch g.Status {
		case "paused":
			icon = asciiOr("warn", iconWarnSp, mode)
			note = "  [unexpected pause — migration hung?]"
		case "stopped":
			if g.OnBoot {
				icon = asciiOr("warn", iconWarnSp, mode)
				note = "  [autostart ON — should be running]"
			} else {
				icon = asciiOr("info", iconInfoSp, mode)
				note = "  [autostart OFF]"
			}
		}
		typeStr := "VM"
		if g.Type == "lxc" {
			typeStr = "CT"
		}
		fmt.Printf("  %s  %s  %-4d  %-20s  %s%s\n",
			icon, typeStr, g.VMID, output.SanitizeControl(g.Name), g.Status, note)
	}

	// Resource overcommit check
	if info.PhysicalCores > 0 && info.TotalVCPUs > 0 {
		ratio := float64(info.TotalVCPUs) / float64(info.PhysicalCores)
		icon := asciiOr("ok", iconOK, mode)
		if ratio > 8 {
			icon = asciiOr("fail", iconFail, mode)
		} else if ratio > 4 {
			icon = asciiOr("warn", iconWarnSp, mode)
		}
		fmt.Printf("\n  %s  vCPU ratio: %d vCPUs / %d cores (%.1f:1)\n",
			icon, info.TotalVCPUs, info.PhysicalCores, ratio)
	}
	if info.HostMemGB > 0 && info.TotalMemGB > 0 {
		pct := info.TotalMemGB / info.HostMemGB * 100
		icon := asciiOr("ok", iconOK, mode)
		if pct > 150 {
			icon = asciiOr("fail", iconFail, mode)
		} else if pct > 100 {
			icon = asciiOr("warn", iconWarnSp, mode)
		}
		fmt.Printf("  %s  Memory assigned: %.1f GB / %.1f GB RAM (%.0f%%)\n",
			icon, info.TotalMemGB, info.HostMemGB, pct)
	}
}

func printPVEStorage(info *models.PVEInfo, mode output.OutputMode) {
	if len(info.Storages) == 0 {
		return
	}
	fmt.Printf("\n[Storage]\n")
	for _, s := range info.Storages {
		icon := asciiOr("ok", iconOK, mode)
		note := ""
		if !s.Active {
			icon = asciiOr("fail", iconFail, mode)
			note = "  UNAVAILABLE"
		} else {
			// Classify identically to dsd health (analysis.PVEStorageLevel) so the
			// two commands never disagree on the same storage (BUG-050 class).
			switch analysis.PVEStorageLevel(s.UsedPct) {
			case "CRIT":
				icon = asciiOr("fail", iconFail, mode)
				note = fmt.Sprintf("  CRIT: %.0f%% full", s.UsedPct)
			case "WARN":
				icon = asciiOr("warn", iconWarnSp, mode)
				note = fmt.Sprintf("  %.0f%% full", s.UsedPct)
			}
		}
		sizeStr := ""
		if s.TotalGB > 0 {
			sizeStr = fmt.Sprintf("  %.0f / %.0f GB  (%.0f%%)",
				s.UsedGB, s.TotalGB, s.UsedPct)
		}
		fmt.Printf("  %s  %-16s %-10s%s%s\n",
			icon, output.SanitizeControl(s.Name), s.Type, sizeStr, note)
	}
}

func printPVETaskErrors(info *models.PVEInfo, mode output.OutputMode) {
	fmt.Printf("\n[Recent Tasks]  (last 24h)\n")
	if len(info.TaskErrors) == 0 {
		fmt.Println("  " + asciiOr("ok", iconOK, mode) + "  No task errors")
		return
	}

	// Types with 3+ errors are CRIT.
	critTypes := pveTaskErrorCritTypes(info.TaskErrors)

	for _, e := range info.TaskErrors {
		icon := asciiOr("warn", iconWarnSp, mode)
		if critTypes[e.Type] {
			icon = asciiOr("fail", iconFail, mode)
		}
		// cmd-11-05: truncate by rune, not byte — a multi-byte UTF-8 character
		// sitting across the byte-77 cut would otherwise produce invalid UTF-8
		// written to stdout. Mirrors truncateProcStr (cmd/proc.go).
		msg := output.SanitizeControl(e.Msg)
		if r := []rune(msg); len(r) > 80 {
			msg = string(r[:77]) + "..."
		}
		vmid := e.VMID
		if vmid == "" {
			vmid = "-"
		}
		fmt.Printf("  %s  %-10s %-6s %s  \"%s\"\n",
			icon, output.SanitizeControl(e.Type), output.SanitizeControl(vmid), output.SanitizeControl(e.StartAt), msg)
	}
}

func printPVECluster(info *models.PVEInfo, mode output.OutputMode) {
	if info.ClusterName == "" && len(info.Nodes) == 0 {
		return // single-node, no cluster
	}
	fmt.Printf("\n[Cluster]  %s\n", output.SanitizeControl(info.ClusterName))
	if info.QuorumOK {
		fmt.Println("  " + asciiOr("ok", iconOK, mode) + "  Quorate: yes")
	} else {
		fmt.Println("  " + asciiOr("fail", iconFail, mode) + "  Quorate: NO — split-brain risk")
	}
	for _, n := range info.Nodes {
		icon := asciiOr("ok", iconOK, mode)
		if !n.Online {
			icon = asciiOr("warn", iconWarnSp, mode)
		}
		status := "online"
		if !n.Online {
			status = "OFFLINE"
		}
		fmt.Printf("  %s  %s  %s\n", icon, output.SanitizeControl(n.Name), status)
	}
}

func printPVEBackup(info *models.PVEInfo, mode output.OutputMode) {
	fmt.Printf("\n[Backups]\n")

	// Per-VM/CT audit when available (templates already excluded by the collector).
	if len(info.BackupStatuses) > 0 {
		for _, b := range info.BackupStatuses {
			icon, ageStr := pveBackupIconAge(b.LastBackupDays, mode)
			fmt.Printf("  %s  %-5d %-20s last backup: %s\n", icon, b.VMID, b.Name, ageStr)
		}
		return
	}

	switch {
	case info.BackupAgeDays < 0:
		fmt.Println("  " + asciiOr("fail", iconFail, mode) + "  No successful backup found")
	case info.BackupAgeDays == 0:
		fmt.Println("  " + asciiOr("ok", iconOK, mode) + "  Last successful backup: today")
	case info.BackupAgeDays == 1:
		fmt.Println("  " + asciiOr("ok", iconOK, mode) + "  Last successful backup: yesterday")
	case info.BackupAgeDays <= 7:
		fmt.Printf("  %s  Last successful backup: %d days ago\n", asciiOr("ok", iconOK, mode), info.BackupAgeDays)
	case info.BackupAgeDays <= 30:
		fmt.Printf("  %s  Last successful backup: %d days ago\n", asciiOr("warn", iconWarnSp, mode), info.BackupAgeDays)
	default:
		fmt.Printf("  %s  Last successful backup: %d days ago\n", asciiOr("fail", iconFail, mode), info.BackupAgeDays)
	}
}

// pveBackupIconAge maps backup age (days; -1 = never) to an icon and label.
// > 30 days or never → CRIT, > 7 days → WARN, otherwise OK.
func pveBackupIconAge(days int, mode output.OutputMode) (icon, ageStr string) {
	switch {
	case days < 0:
		return asciiOr("fail", iconFail, mode), "never"
	case days == 0:
		return asciiOr("ok", iconOK, mode), "today"
	case days == 1:
		return asciiOr("ok", iconOK, mode), "1 day ago"
	case days <= 7:
		return asciiOr("ok", iconOK, mode), fmt.Sprintf("%d days ago", days)
	case days <= 30:
		return asciiOr("warn", iconWarnSp, mode), fmt.Sprintf("%d days ago", days)
	default:
		return asciiOr("fail", iconFail, mode), fmt.Sprintf("%d days ago", days)
	}
}

func printPVEPerf(perf *models.PVEPerf, mode output.OutputMode) {
	if perf == nil {
		return
	}
	fmt.Printf("\n[Storage Performance (pveperf %s)]\n", perf.Path)
	if !perf.Available {
		fmt.Println("  " + asciiOr("info", iconInfoSp, mode) + "  pveperf not found — install proxmox-ve package")
		return
	}
	if perf.BufferedReadMB > 0 {
		icon := asciiOr("ok", iconOK, mode)
		if perf.BufferedReadMB < 50 {
			icon = asciiOr("fail", iconFail, mode)
		} else if perf.BufferedReadMB < 200 {
			icon = asciiOr("warn", iconWarnSp, mode)
		}
		fmt.Printf("  %s  Buffered reads:  %.0f MB/s\n", icon, perf.BufferedReadMB)
	}
	if perf.FsyncsPerSec > 0 {
		icon := asciiOr("ok", iconOK, mode)
		if perf.FsyncsPerSec < 100 {
			icon = asciiOr("fail", iconFail, mode)
		} else if perf.FsyncsPerSec < 500 {
			icon = asciiOr("warn", iconWarnSp, mode)
		}
		fmt.Printf("  %s  Fsyncs/sec:      %.0f  (expected: > 500 for good VM stability)\n",
			icon, perf.FsyncsPerSec)
	}
	if perf.AvgSeekMs > 0 {
		icon := asciiOr("ok", iconOK, mode)
		if perf.AvgSeekMs > 10 {
			icon = asciiOr("fail", iconFail, mode)
		} else if perf.AvgSeekMs > 2 {
			icon = asciiOr("warn", iconWarnSp, mode)
		}
		fmt.Printf("  %s  Avg seek time:   %.2f ms\n", icon, perf.AvgSeekMs)
	}
	if perf.CPUBogomips > 0 {
		fmt.Printf("  %s  CPU bogomips:    %.0f\n", asciiOr("ok", iconOK, mode), perf.CPUBogomips)
	}
	if perf.DNSExtMs > 0 {
		icon := asciiOr("ok", iconOK, mode)
		if perf.DNSExtMs > 500 {
			icon = asciiOr("warn", iconWarnSp, mode)
		}
		fmt.Printf("  %s  DNS ext:         %.0f ms\n", icon, perf.DNSExtMs)
	}
}

func printPVEBridges(info *models.PVEInfo, mode output.OutputMode) {
	if len(info.Bridges) == 0 {
		if !info.BridgesVerified {
			// internal-models-11-03: every real PVE node has at least one
			// bridge (vmbr0) — an empty Bridges slice with BridgesVerified
			// false means the pvesh network query itself failed, not that
			// the node genuinely has no bridges. Say so instead of printing
			// nothing, which reads identically to "network section skipped,
			// nothing to report" for a node that may have a DOWN bridge.
			fmt.Printf("\n[Network]\n")
			fmt.Printf("  %s  bridge configuration NOT verified — pvesh network query failed\n",
				asciiOr(secLvlInfo, secIconInfo, mode))
			fmt.Println("       to inspect: pvesh get /nodes/localhost/network")
		}
		return
	}
	fmt.Printf("\n[Network]\n")
	for _, b := range info.Bridges {
		name := output.SanitizeControl(b.Name)
		switch {
		case !b.Active:
			fmt.Printf("  %s  %-8s DOWN  — VMs on this bridge lose network\n", asciiOr("fail", iconFail, mode), name)
			continue
		case !b.HasUplink:
			fmt.Printf("  %s  %-8s UP   ← no uplink interface attached\n", asciiOr("warn", iconWarnSp, mode), name)
			fmt.Println("       This bridge has no physical NIC — VMs on it are isolated.")
			continue
		}

		stp := "off"
		if b.STPEnabled {
			stp = "ON"
		}
		icon := asciiOr("ok", iconOK, mode)
		if b.STPEnabled {
			icon = asciiOr("warn", iconWarnSp, mode)
		}
		fmt.Printf("  %s  %-8s UP   ← %s  STP: %s", icon, name, output.SanitizeControl(b.Ports), stp)
		if b.STPEnabled {
			fmt.Print("  (may cause ~30s boot delay)")
		}
		fmt.Println()
		if b.STPEnabled {
			fmt.Printf("       → nmcli connection modify %s bridge.stp no\n", name)
		}
	}
}

// pveTaskErrorCritTypes returns the set of task types with 3+ errors (CRIT).
func pveTaskErrorCritTypes(errs []models.PVETaskError) map[string]bool {
	byType := make(map[string]int)
	for _, e := range errs {
		byType[e.Type]++
	}
	crit := make(map[string]bool)
	for typ, n := range byType {
		if n >= 3 {
			crit[typ] = true
		}
	}
	return crit
}

// formatPVEUptime renders a node uptime (seconds) as days/hours/minutes.
func formatPVEUptime(sec int64) string {
	switch {
	case sec >= 86400:
		return fmt.Sprintf("%d days", sec/86400)
	case sec >= 3600:
		return fmt.Sprintf("%d hours", sec/3600)
	default:
		return fmt.Sprintf("%d minutes", sec/60)
	}
}

func countPVEIssues(info *models.PVEInfo) int {
	// pvesh API unreachable (root path) — nothing below was actually verified, so
	// the unreachable API is the one real concern; everything else is empty by
	// failure, not by health. Don't add spurious "backup never" etc. on top.
	if info.IsPVE && !info.NeedsRoot && !info.APIReachable {
		return 1
	}
	n := 0
	for _, s := range info.Storages {
		// Classify identically to dsd health (analysis.PVEStorageLevel: 80 WARN /
		// 90 CRIT) so the `dsd pve` concern count agrees with the health verdict.
		// The old hardcoded 85/95 under-counted pools in the 80–84% band — `dsd pve`
		// read "healthy" while `dsd health` flagged the same pool WARN.
		if !s.Active || analysis.PVEStorageLevel(s.UsedPct) != "" {
			n++
		}
	}
	for _, g := range info.Guests {
		if g.Status == "paused" || (g.Status == "stopped" && g.OnBoot) {
			n++
		}
	}
	if !info.QuorumOK && info.ClusterName != "" {
		n++
	}
	// Backups: prefer the per-VM audit when present, else the global age.
	if len(info.BackupStatuses) > 0 {
		for _, b := range info.BackupStatuses {
			if b.LastBackupDays > 7 || b.LastBackupDays < 0 {
				n++
			}
		}
	} else if info.BackupAgeDays > 7 || info.BackupAgeDays < 0 {
		n++
	}
	n += len(info.TaskErrors)
	if info.PhysicalCores > 0 && float64(info.TotalVCPUs)/float64(info.PhysicalCores) > 4 {
		n++
	}
	if info.HostMemGB > 0 && info.TotalMemGB/info.HostMemGB > 1.0 {
		n++
	}
	// Network bridges: down, no uplink, or STP enabled.
	for _, b := range info.Bridges {
		if !b.Active || !b.HasUplink || b.STPEnabled {
			n++
		}
	}
	return n
}
