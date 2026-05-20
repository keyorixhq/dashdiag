package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

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
	if !collectors.IsPVEHost() {
		fmt.Println("ℹ️  Not a Proxmox VE node — dsd pve requires a Proxmox host")
		return nil
	}

	deep, _ := cmd.Flags().GetBool("deep")
	plain, _ := cmd.Flags().GetBool("plain")
	mode := output.DetectMode(plain, false, "")

	timeout := 10 * time.Second
	if deep {
		timeout = 30 * time.Second
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
		return outputJSON(os.Stdout, info)
	}

	printPVEReport(info, deep, elapsed)
	return nil
}

func printPVEReport(info *models.PVEInfo, deep bool, elapsed time.Duration) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	fmt.Println()
	fmt.Println(sep)

	// Node overview
	printPVENode(info)

	// VMs and containers
	printPVEGuests(info)

	// Storage
	printPVEStorage(info)

	// Task errors
	printPVETaskErrors(info)

	// Cluster
	printPVECluster(info)

	// Backup
	printPVEBackup(info)

	// Performance (deep)
	if deep {
		perfCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		info.Perf = collectors.CollectPVEPerf(perfCtx, "/var/lib/vz")
		printPVEPerf(info.Perf)
	}

	// Summary
	fmt.Println()
	fmt.Println(sep)
	issues := countPVEIssues(info)
	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("✅ Proxmox VE healthy. Checks passed%s", timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("⚠️  %d concern(s) found%s", issues, timing)))
	}
}

func printPVENode(info *models.PVEInfo) {
	fmt.Printf("\n[Proxmox Node]\n")
	if info.PhysicalCores > 0 {
		fmt.Printf("  Cores:    %d physical\n", info.PhysicalCores)
	}
	if info.HostMemGB > 0 {
		fmt.Printf("  Memory:   %.1f GB\n", info.HostMemGB)
	}
	// Subscription
	sub := info.Subscription
	subIcon := "✅"
	subDetail := sub.Status
	switch strings.ToLower(sub.Status) {
	case "active":
		subDetail = "active"
		if sub.Product != "" {
			subDetail += " (" + sub.Product + ")"
		}
	case "notfound", "":
		subIcon = "ℹ️ "
		subDetail = "no subscription (community edition)"
	case "expired":
		subIcon = "⚠️ "
		subDetail = "subscription expired"
	}
	fmt.Printf("  License:  %s %s\n", subIcon, subDetail)
}

func printPVEGuests(info *models.PVEInfo) {
	total := info.RunningCount + info.StoppedCount + info.PausedCount
	if total == 0 {
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
		icon := "✅"
		note := ""
		switch g.Status {
		case "paused":
			icon = "⚠️ "
			note = "  [unexpected pause — migration hung?]"
		case "stopped":
			if g.OnBoot {
				icon = "⚠️ "
				note = "  [autostart ON — should be running]"
			} else {
				icon = "ℹ️ "
				note = "  [autostart OFF]"
			}
		}
		typeStr := "VM"
		if g.Type == "lxc" {
			typeStr = "CT"
		}
		fmt.Printf("  %s  %s  %-4d  %-20s  %s%s\n",
			icon, typeStr, g.VMID, g.Name, g.Status, note)
	}

	// Resource overcommit check
	if info.PhysicalCores > 0 && info.TotalVCPUs > 0 {
		ratio := float64(info.TotalVCPUs) / float64(info.PhysicalCores)
		icon := "✅"
		if ratio > 8 {
			icon = "❌"
		} else if ratio > 4 {
			icon = "⚠️ "
		}
		fmt.Printf("\n  %s  vCPU ratio: %d vCPUs / %d cores (%.1f:1)\n",
			icon, info.TotalVCPUs, info.PhysicalCores, ratio)
	}
	if info.HostMemGB > 0 && info.TotalMemGB > 0 {
		pct := info.TotalMemGB / info.HostMemGB * 100
		icon := "✅"
		if pct > 150 {
			icon = "❌"
		} else if pct > 100 {
			icon = "⚠️ "
		}
		fmt.Printf("  %s  Memory assigned: %.1f GB / %.1f GB RAM (%.0f%%)\n",
			icon, info.TotalMemGB, info.HostMemGB, pct)
	}
}

func printPVEStorage(info *models.PVEInfo) {
	if len(info.Storages) == 0 {
		return
	}
	fmt.Printf("\n[Storage]\n")
	for _, s := range info.Storages {
		icon := "✅"
		note := ""
		if !s.Active {
			icon = "❌"
			note = "  UNAVAILABLE"
		} else if s.UsedPct >= 95 {
			icon = "❌"
			note = fmt.Sprintf("  CRIT: %.0f%% full", s.UsedPct)
		} else if s.UsedPct >= 85 {
			icon = "⚠️ "
			note = fmt.Sprintf("  %.0f%% full", s.UsedPct)
		}
		sizeStr := ""
		if s.TotalGB > 0 {
			sizeStr = fmt.Sprintf("  %.0f / %.0f GB  (%.0f%%)",
				s.UsedGB, s.TotalGB, s.UsedPct)
		}
		fmt.Printf("  %s  %-16s %-10s%s%s\n",
			icon, s.Name, s.Type, sizeStr, note)
	}
}

func printPVETaskErrors(info *models.PVEInfo) {
	if len(info.TaskErrors) == 0 {
		return
	}
	fmt.Printf("\n[Recent Task Errors — last 24h]\n")
	for _, e := range info.TaskErrors {
		msg := e.Msg
		if len(msg) > 60 {
			msg = msg[:57] + "..."
		}
		fmt.Printf("  ⚠️   %-12s  %s  %s  %s\n", e.Type, e.StartAt, e.VMID, msg)
	}
}

func printPVECluster(info *models.PVEInfo) {
	if info.ClusterName == "" && len(info.Nodes) == 0 {
		return // single-node, no cluster
	}
	fmt.Printf("\n[Cluster]  %s\n", info.ClusterName)
	if info.QuorumOK {
		fmt.Println("  ✅  Quorate: yes")
	} else {
		fmt.Println("  ❌  Quorate: NO — split-brain risk")
	}
	for _, n := range info.Nodes {
		icon := "✅"
		if !n.Online {
			icon = "⚠️ "
		}
		status := "online"
		if !n.Online {
			status = "OFFLINE"
		}
		fmt.Printf("  %s  %s  %s\n", icon, n.Name, status)
	}
}

func printPVEBackup(info *models.PVEInfo) {
	fmt.Printf("\n[Backups]\n")
	switch {
	case info.BackupAgeDays < 0:
		fmt.Println("  ❌  No successful backup found")
	case info.BackupAgeDays == 0:
		fmt.Println("  ✅  Last successful backup: today")
	case info.BackupAgeDays == 1:
		fmt.Println("  ✅  Last successful backup: yesterday")
	case info.BackupAgeDays <= 7:
		fmt.Printf("  ✅  Last successful backup: %d days ago\n", info.BackupAgeDays)
	case info.BackupAgeDays <= 30:
		fmt.Printf("  ⚠️   Last successful backup: %d days ago\n", info.BackupAgeDays)
	default:
		fmt.Printf("  ❌  Last successful backup: %d days ago\n", info.BackupAgeDays)
	}
}

func printPVEPerf(perf *models.PVEPerf) {
	if perf == nil {
		return
	}
	fmt.Printf("\n[Storage Performance (pveperf %s)]\n", perf.Path)
	if !perf.Available {
		fmt.Println("  ℹ️   pveperf not found — install proxmox-ve package")
		return
	}
	if perf.BufferedReadMB > 0 {
		icon := "✅"
		if perf.BufferedReadMB < 50 {
			icon = "❌"
		} else if perf.BufferedReadMB < 200 {
			icon = "⚠️ "
		}
		fmt.Printf("  %s  Buffered reads:  %.0f MB/s\n", icon, perf.BufferedReadMB)
	}
	if perf.FsyncsPerSec > 0 {
		icon := "✅"
		if perf.FsyncsPerSec < 100 {
			icon = "❌"
		} else if perf.FsyncsPerSec < 500 {
			icon = "⚠️ "
		}
		fmt.Printf("  %s  Fsyncs/sec:      %.0f  (expected: > 500 for good VM stability)\n",
			icon, perf.FsyncsPerSec)
	}
	if perf.AvgSeekMs > 0 {
		icon := "✅"
		if perf.AvgSeekMs > 10 {
			icon = "❌"
		} else if perf.AvgSeekMs > 2 {
			icon = "⚠️ "
		}
		fmt.Printf("  %s  Avg seek time:   %.2f ms\n", icon, perf.AvgSeekMs)
	}
	if perf.CPUBogomips > 0 {
		fmt.Printf("  ✅  CPU bogomips:    %.0f\n", perf.CPUBogomips)
	}
	if perf.DNSExtMs > 0 {
		icon := "✅"
		if perf.DNSExtMs > 500 {
			icon = "⚠️ "
		}
		fmt.Printf("  %s  DNS ext:         %.0f ms\n", icon, perf.DNSExtMs)
	}
}

func countPVEIssues(info *models.PVEInfo) int {
	n := 0
	for _, s := range info.Storages {
		if !s.Active || s.UsedPct >= 95 {
			n++
		} else if s.UsedPct >= 85 {
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
	if info.BackupAgeDays > 7 || info.BackupAgeDays < 0 {
		n++
	}
	n += len(info.TaskErrors)
	if info.PhysicalCores > 0 && float64(info.TotalVCPUs)/float64(info.PhysicalCores) > 4 {
		n++
	}
	if info.HostMemGB > 0 && info.TotalMemGB/info.HostMemGB > 1.0 {
		n++
	}
	return n
}
