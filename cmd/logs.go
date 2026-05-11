package cmd

import (
	"context"
	"fmt"
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
	rootCmd.AddCommand(logsCmd)
	logsCmd.Flags().String("since", "1h", "how far back to look (e.g. 1h, 24h, 7d, 30d)")
}

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Log health — OOM kills, segfaults, crash loops, journal size",
	RunE:  runLogs,
}

func runLogs(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	mode := output.DetectMode(plain, false, "")

	sinceStr, _ := cmd.Flags().GetString("since")
	since := parseSinceDuration(sinceStr)

	p := output.NewCommandProgress("Log health", 5*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewLogsCollectorWithLookback(since)}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.LogsInfo)
	if !ok || info == nil {
		return result.Err
	}

	printLogsReport(info, mode, elapsed, since)
	return nil
}

// parseSinceDuration parses durations like "1h", "24h", "7d", "30d".
// Supports "d" suffix for days which Go's time.ParseDuration doesn't.
func parseSinceDuration(s string) time.Duration {
	if strings.HasSuffix(s, "d") {
		days, err := time.ParseDuration(strings.TrimSuffix(s, "d") + "h")
		if err == nil {
			return days * 24
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return time.Hour // default
	}
	return d
}

func printLogsReport(info *models.LogsInfo, mode output.OutputMode, elapsed time.Duration, since time.Duration) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())
	sinceStr := formatDuration(since)

	fmt.Printf("\nLog health — last %s\n", sinceStr)

	// OOM kills
	fmt.Printf("\nOOM Kills: ")
	if info.OOMKills == 0 {
		fmt.Println("none")
	} else {
		fmt.Printf("%d\n", info.OOMKills)
		fmt.Println("  Processes killed:")
		for _, p := range info.OOMProcesses {
			fmt.Printf("    ❌  %s\n", p)
		}
		fmt.Println("  → to inspect: dmesg | grep -i 'out of memory'")
	}

	// Segfaults
	fmt.Printf("\nSegfaults: ")
	if info.Segfaults == 0 {
		fmt.Println("none")
	} else {
		fmt.Printf("%d\n", info.Segfaults)
		fmt.Println("  Processes:")
		for _, p := range info.SegfaultProcs {
			fmt.Printf("    ⚠️   %s\n", p)
		}
		fmt.Println("  → to inspect: dmesg | grep segfault")
	}

	// Crash loops
	fmt.Printf("\nCrash loops: ")
	if len(info.CrashLoops) == 0 {
		fmt.Println("none")
	} else {
		fmt.Println()
		for _, u := range info.CrashLoops {
			unit := strings.Fields(u)[0]
			fmt.Printf("    ❌  %s\n", u)
			fmt.Printf("       → journalctl -u %s -n 20\n", unit)
		}
	}

	// Journal disk usage
	fmt.Printf("\nJournal size: ")
	if info.JournalSizeGB < 0.001 {
		fmt.Println("< 1 MB")
	} else if info.JournalSizeGB < 1.0 {
		fmt.Printf("%.0f MB\n", info.JournalSizeGB*1024)
	} else {
		fmt.Printf("%.1f GB\n", info.JournalSizeGB)
	}

	// Summary
	fmt.Println()
	fmt.Println(sep)
	issues := 0
	if info.OOMKills > 0 {
		issues++
	}
	if info.Segfaults > 0 {
		issues++
	}
	issues += len(info.CrashLoops)

	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("✅ Logs healthy. Checks passed%s", timing)))
	} else {
		fmt.Println(render.StyleCrit.Render(fmt.Sprintf("❌ %d log issue(s) found%s", issues, timing)))
	}
}

// formatDuration converts a duration to a human-readable string.
func formatDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%.0fd", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.0fh", d.Hours())
	default:
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
}
