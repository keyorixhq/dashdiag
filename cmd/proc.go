package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(procCmd)
}

var procCmd = &cobra.Command{
	Use:   "proc [PID]",
	Short: "Process inspector — memory map, open files, connections, D-state diagnosis",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runProc,
}

func runProc(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	pid := 0
	if len(args) == 1 {
		var err error
		pid, err = strconv.Atoi(args[0])
		if err != nil || pid <= 0 {
			return fmt.Errorf("invalid PID: %s", args[0])
		}
	}

	p := output.NewCommandProgress("Process inspector", 5*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewProcCollector(pid)}) {
		p.Step(r.Name)
		result = r
	}

	info, ok := result.Data.(*models.ProcInfo)
	if !ok || info == nil {
		return result.Err
	}

	if mode == output.ModeJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(info)
		return nil
	}

	if pid == 0 {
		printProcTopList(info, mode)
		return nil
	}
	printProcDetail(info, mode)
	return nil
}

// ── top list ──────────────────────────────────────────────────────────────────

func printProcTopList(info *models.ProcInfo, mode output.OutputMode) {
	human := mode == output.ModeHuman
	if human {
		fmt.Fprintln(os.Stdout, "\n🔍  Top processes by RSS")
		fmt.Printf("  %-8s %-20s %8s %6s\n", "PID", "NAME", "RSS", "MEM%")
		fmt.Println("  " + strings.Repeat("─", 46))
	}
	for _, p := range info.TopProcs {
		fmt.Printf("  %-8d %-20s %7.1fMB %5.1f%%\n",
			p.PID, truncateProcStr(p.Name, 20), p.RSSMB, p.MemPct)
	}
	if human {
		fmt.Printf("\n  Run `dsd proc <PID>` for detailed analysis of any process above.\n")
	}
}

// ── detail view ───────────────────────────────────────────────────────────────

func printProcDetail(info *models.ProcInfo, mode output.OutputMode) {
	human := mode == output.ModeHuman
	if human {
		fmt.Fprintf(os.Stdout, "\n🔍  Process %d — %s\n\n", info.PID, info.Name)
	}
	printProcIdentity(info, mode)
	printProcState(info, mode)
	printProcResources(info, mode)
	printProcFiles(info, mode, human)
	printProcConnections(info, mode, human)
	if info.DState && human {
		printDStateGuide(info.WChan, info.PID)
	}
}

func printProcIdentity(info *models.ProcInfo, mode output.OutputMode) {
	human := mode == output.ModeHuman
	if human {
		fmt.Fprintln(os.Stdout, "[Identity]")
	}
	printProcLine(mode, "PID", fmt.Sprintf("%d", info.PID))
	if info.PPID > 0 {
		parent := fmt.Sprintf("%d", info.PPID)
		if info.ParentName != "" {
			parent += " (" + info.ParentName + ")"
		}
		printProcLine(mode, "Parent", parent)
	}
	if info.User != "" {
		printProcLine(mode, "User", info.User)
	}
	if info.CgroupName != "" {
		printProcLine(mode, "Cgroup", info.CgroupName)
	}
	printProcLine(mode, "Cmdline", truncateProcStr(info.Cmdline, 120))
	printProcLine(mode, "Uptime", fmtDuration(info.UptimeSec))
}

func printProcState(info *models.ProcInfo, mode output.OutputMode) {
	human := mode == output.ModeHuman
	if human {
		fmt.Fprintln(os.Stdout, "\n[State]")
	}
	stateLabel := info.State
	if info.DState {
		stateLabel = "D (UNINTERRUPTIBLE — hung in kernel)"
	}
	printProcLine(mode, "State", stateLabel)
	if info.WChan != "" && info.WChan != "0" {
		wDesc := info.WChan
		if info.DState {
			wDesc += " ← kernel function blocking this process"
		}
		printProcLine(mode, "WChan (blocked on)", wDesc)
	}
}

func printProcResources(info *models.ProcInfo, mode output.OutputMode) {
	human := mode == output.ModeHuman
	if human {
		fmt.Fprintln(os.Stdout, "\n[Resources]")
	}
	printProcLine(mode, "CPU time", fmt.Sprintf("%.2fs", info.CPUSec))
	printProcLine(mode, "Threads", fmt.Sprintf("%d", info.Threads))
	printProcLine(mode, "RSS", fmt.Sprintf("%.1f MB", info.RSSMB))
	if info.SwapMB > 0 {
		printProcLine(mode, "Swap", fmt.Sprintf("%.1f MB", info.SwapMB))
	}
	fdStr := fmt.Sprintf("%d", info.FDCount)
	if info.FDLimit > 0 {
		fdStr += fmt.Sprintf(" / %d (%.0f%%)", info.FDLimit,
			float64(info.FDCount)/float64(info.FDLimit)*100)
	}
	if info.FDPressure {
		fdStr += " ⚠️  >80% of limit"
	}
	printProcLine(mode, "Open FDs", fdStr)
	if info.MemMap != nil {
		if human {
			fmt.Fprintln(os.Stdout, "\n[Memory map (smaps_rollup)]")
		}
		printProcLine(mode, "RSS", fmt.Sprintf("%d kB", info.MemMap.RSSKb))
		printProcLine(mode, "Private_Dirty (unique footprint)",
			fmt.Sprintf("%d kB  (%.1f MB)", info.MemMap.PrivateDirtyKb,
				float64(info.MemMap.PrivateDirtyKb)/1024))
		printProcLine(mode, "Shared_Clean (libraries)",
			fmt.Sprintf("%d kB", info.MemMap.SharedCleanKb))
		if info.MemMap.SwapKb > 0 {
			printProcLine(mode, "Swap", fmt.Sprintf("%d kB", info.MemMap.SwapKb))
		}
	}
}

func printProcFiles(info *models.ProcInfo, mode output.OutputMode, human bool) {
	if human {
		fmt.Fprintln(os.Stdout, "\n[Open file descriptors]")
	}
	printProcLine(mode, "Sockets", fmt.Sprintf("%d", info.SocketCount))
	printProcLine(mode, "Regular files", fmt.Sprintf("%d", info.FileCount))
	printProcLine(mode, "Pipes", fmt.Sprintf("%d", info.PipeCount))
	if len(info.DeletedLibs) > 0 {
		fmt.Println()
		if human {
			fmt.Fprintln(os.Stdout, "  ⚠️  Deleted shared libraries (restart process after package update):")
		}
		for _, lib := range info.DeletedLibs {
			fmt.Printf("     %s\n", lib)
		}
		if human {
			fmt.Printf("  → to restart: systemctl restart <service-name>\n")
		}
	}
}

func printProcConnections(info *models.ProcInfo, mode output.OutputMode, human bool) {
	if len(info.Connections) == 0 {
		return
	}
	if human {
		fmt.Fprintln(os.Stdout, "\n[Network connections]")
		fmt.Printf("  %-6s %-26s %-26s %s\n", "PROTO", "LOCAL", "REMOTE", "STATE")
		fmt.Println("  " + strings.Repeat("─", 70))
	}
	shown := 0
	for _, c := range info.Connections {
		if shown >= 20 {
			fmt.Printf("  … and %d more\n", len(info.Connections)-shown)
			break
		}
		fmt.Printf("  %-6s %-26s %-26s %s\n",
			c.Protocol, c.LocalAddr, c.RemoteAddr, c.State)
		shown++
	}
}

func printDStateGuide(wchan string, pid int) {
	fmt.Fprintln(os.Stdout, "\n[D-state diagnosis]")
	fmt.Printf("  This process is in uninterruptible sleep (D).\n")
	fmt.Printf("  It cannot be killed with SIGKILL while in D-state.\n")
	fmt.Printf("  wchan=%s — kernel function it is waiting for.\n\n", wchan)
	fmt.Printf("  Common causes:\n")
	fmt.Printf("    - NFS mount: stale/hung NFS server or network path\n")
	fmt.Printf("    - Block device: disk I/O wait or storage controller issue\n")
	fmt.Printf("    - Kernel bug: check dmesg for call traces\n")
	fmt.Printf("  Next:\n")
	fmt.Printf("    → dmesg | tail -50\n")
	fmt.Printf("    → cat /proc/%d/stack  (full kernel stack trace)\n", pid)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func printProcLine(mode output.OutputMode, label, value string) {
	if mode == output.ModeHuman {
		fmt.Printf("  %-34s %s\n", label, value)
	} else {
		fmt.Printf("%-34s %s\n", label, value)
	}
}

func truncateProcStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func fmtDuration(sec int) string {
	switch {
	case sec < 60:
		return fmt.Sprintf("%ds", sec)
	case sec < 3600:
		return fmt.Sprintf("%dm %ds", sec/60, sec%60)
	case sec < 86400:
		return fmt.Sprintf("%dh %dm", sec/3600, (sec%3600)/60)
	default:
		return fmt.Sprintf("%dd %dh", sec/86400, (sec%86400)/3600)
	}
}
