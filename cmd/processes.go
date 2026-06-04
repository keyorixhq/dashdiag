package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/drilldown"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(processesCmd)
	processesCmd.Flags().Duration("watch-interval", 5*time.Second, "refresh interval for --watch mode (default 5s; health uses 60s)")
}

var processesCmd = &cobra.Command{
	Use:   "processes",
	Short: "Process health — zombies, hung processes, top CPU and memory",
	RunE:  runProcesses,
}

func runProcesses(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	watchFlag, _ := cmd.Flags().GetBool("watch")
	if watchFlag {
		interval, _ := cmd.Flags().GetDuration("watch-interval")
		return watchProcesses(ctx, interval, mode)
	}

	p := output.NewCommandProgress("Process health", 5*time.Second, mode, 2)
	p.Start()
	defer p.Done()

	results := make([]runner.Result, 0, 2)
	cols := []runner.Collector{
		collectors.NewProcessesCollector(),
	}
	for r := range runner.RunAll(ctx, cols) {
		p.Step(r.Name)
		results = append(results, r)
	}

	elapsed := p.Elapsed()

	var procInfo *models.ProcessInfo
	for _, r := range results {
		if info, ok := r.Data.(*models.ProcessInfo); ok {
			procInfo = info
		}
	}

	if procInfo == nil {
		return nil
	}

	if mode == output.ModeJSON {
		return outputJSON(os.Stdout, procInfo)
	}

	printProcessesReport(ctx, procInfo, mode, elapsed)
	return nil
}

func watchProcesses(ctx context.Context, interval time.Duration, mode output.OutputMode) error {
	run := func() {
		if mode == output.ModeHuman {
			fmt.Print("\033[H\033[2J") // clear screen
		}
		var procInfo *models.ProcessInfo
		for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewProcessesCollector()}) {
			if info, ok := r.Data.(*models.ProcessInfo); ok {
				procInfo = info
			}
		}
		if procInfo == nil {
			return
		}
		fmt.Printf("\n── %s ──\n", time.Now().Format("15:04:05"))
		printProcessesReport(ctx, procInfo, mode, 0)
	}

	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			run()
		}
	}
}

func printProcessesReport(ctx context.Context, info *models.ProcessInfo, mode output.OutputMode, elapsed time.Duration) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	issues := 0

	// Zombies
	fmt.Printf("\nZombie Processes: %d\n", info.ZombieCount)
	if info.ZombieCount > 0 {
		issues++
		d, _ := drilldown.ZombiesWithParent(ctx)
		if d == nil {
			d = zombiesTable(info)
		}
		if d != nil {
			printProcessTable(d)
		}
		fmt.Println("  → to fix: restart the parent process to reap zombies")
	}

	// Hung processes
	fmt.Printf("\nHung (D-state) Processes: %d\n", info.HungCount)
	if info.HungCount > 0 {
		issues++
		d, _ := drilldown.HungProcesses(ctx)
		if d == nil {
			d = hungTable(info)
		}
		if d != nil {
			printProcessTable(d)
		}
		fmt.Println("  → to inspect: ps aux | grep ' D '")
		fmt.Println("  → to inspect: cat /proc/PID/wchan")
	}

	// Top processes by CPU
	fmt.Println("\nTop Processes by CPU:")
	if d, err := drilldown.TopProcessesByCPU(ctx, 10); err == nil && d != nil {
		printProcessTable(d)
	}

	// Top processes by memory
	fmt.Println("\nTop Processes by Memory:")
	if d, err := drilldown.TopProcessesByRSS(ctx, 10); err == nil && d != nil {
		printProcessTable(d)
	}

	fmt.Println()
	fmt.Println(sep)
	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("✅ Processes healthy. Checks passed%s", timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("⚠️  %d process concern(s) found%s", issues, timing)))
	}
}

func printProcessTable(d *models.Details) {
	const indent = "  "
	if d.Title != "" {
		fmt.Printf("%s%s:\n", indent, d.Title)
	}

	// Column widths
	widths := make([]int, len(d.Columns))
	for i, col := range d.Columns {
		widths[i] = len(col)
	}
	for _, row := range d.Rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Header
	var hdr strings.Builder
	hdr.WriteString(indent + "  ")
	for i, col := range d.Columns {
		if i > 0 {
			hdr.WriteString("  ")
		}
		fmt.Fprintf(&hdr, "%-*s", widths[i], col)
	}
	fmt.Println(hdr.String())

	// Rows
	for _, row := range d.Rows {
		var sb strings.Builder
		sb.WriteString(indent + "  ")
		for i, cell := range row {
			if i > 0 {
				sb.WriteString("  ")
			}
			w := 0
			if i < len(widths) {
				w = widths[i]
			}
			fmt.Fprintf(&sb, "%-*s", w, cell)
		}
		fmt.Println(sb.String())
	}
}

func zombiesTable(info *models.ProcessInfo) *models.Details {
	if len(info.ZombieProcs) == 0 {
		return nil
	}
	rows := make([][]string, 0, len(info.ZombieProcs))
	for _, p := range info.ZombieProcs {
		rows = append(rows, []string{
			fmt.Sprintf("%d", p.PID),
			fmt.Sprintf("%d", p.PPID),
			p.ParentName,
		})
	}
	return &models.Details{
		Type:    "process_table",
		Title:   "Zombie processes",
		Columns: []string{"PID", "PPID", "PARENT"},
		Rows:    rows,
	}
}

func hungTable(info *models.ProcessInfo) *models.Details {
	if len(info.HungProcs) == 0 {
		return nil
	}
	rows := make([][]string, 0, len(info.HungProcs))
	for _, p := range info.HungProcs {
		rows = append(rows, []string{
			fmt.Sprintf("%d", p.PID),
			p.Name,
			p.WChan,
		})
	}
	return &models.Details{
		Type:    "process_table",
		Title:   "Hung processes",
		Columns: []string{"PID", "NAME", "WCHAN"},
		Rows:    rows,
	}
}
