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
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

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
	recordResultSeverity([]runner.Result{result})
	return nil
}

// parseSinceDuration parses durations like "1h", "24h", "7d", "30d".
func parseSinceDuration(s string) time.Duration {
	if strings.HasSuffix(s, "d") {
		days, err := time.ParseDuration(strings.TrimSuffix(s, "d") + "h")
		if err == nil {
			return days * 24
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return time.Hour
	}
	return d
}

func printLogsReport(info *models.LogsInfo, mode output.OutputMode, elapsed time.Duration, since time.Duration) {
	if mode == output.ModeJSON {
		printLogsJSON(info)
		return
	}

	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	fmt.Printf("\nLog health — last %s\n", formatDuration(since))
	printLogsSeverity(info, mode)
	printLogsOOM(info, mode)
	printLogsSegfaults(info, mode)
	printLogsCrashLoops(info, mode)
	printLogsCrashFiles(info, mode)
	printLogsJournalSize(info)

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
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("%s Logs healthy. Checks passed%s", asciiOr("ok", "✅", mode), timing)))
	} else {
		fmt.Println(render.StyleCrit.Render(fmt.Sprintf("%s %d log issue(s) found%s", asciiOr("fail", "❌", mode), issues, timing)))
	}
}

func printLogsSeverity(info *models.LogsInfo, mode output.OutputMode) {
	if info.ErrorCount == 0 && info.WarningCount == 0 {
		return
	}
	fmt.Printf("\nSeverity summary:\n")
	if info.ErrorCount > 0 {
		fmt.Printf("  %s  Errors:   %d\n", asciiOr("fail", "❌", mode), info.ErrorCount)
		if len(info.TopCritical) > 0 {
			for _, e := range info.TopCritical {
				if age := formatAgeMin(e.AgeMin); age != "" {
					fmt.Printf("       %s: %s — %s\n", e.Source, e.Message, age)
				} else {
					fmt.Printf("       %s: %s\n", e.Source, e.Message)
				}
			}
		} else {
			for _, e := range info.TopErrors {
				fmt.Printf("       %s\n", e)
			}
		}
	}
	if info.WarningCount > 0 {
		fmt.Printf("  %s   Warnings: %d\n", asciiOr("warn", "⚠️", mode), info.WarningCount)
	}
}

// printLogsJSON marshals the full logs report as indented JSON to stdout.
func printLogsJSON(info *models.LogsInfo) {
	_ = outputJSON(os.Stdout, info)
}

// formatAgeMin renders minutes as "Xm ago" (<60m), "Xh ago" (<24h), or
// "Xd ago" (>=24h). Returns "" when the age is unknown (negative).
func formatAgeMin(min int) string {
	switch {
	case min < 0:
		return ""
	case min < 60:
		return fmt.Sprintf("%dm ago", min)
	case min < 1440:
		return fmt.Sprintf("%dh ago", min/60)
	default:
		return fmt.Sprintf("%dd ago", min/1440)
	}
}

func printLogsOOM(info *models.LogsInfo, mode output.OutputMode) {
	fmt.Printf("\nOOM Kills: ")
	if info.OOMKills == 0 {
		fmt.Println("none")
		return
	}
	fmt.Printf("%d\n", info.OOMKills)
	for _, p := range info.OOMProcesses {
		fmt.Printf("    %s  %s\n", asciiOr("fail", "❌", mode), p)
	}
	fmt.Println("  → to inspect: dmesg | grep -i 'out of memory'")
}

func printLogsSegfaults(info *models.LogsInfo, mode output.OutputMode) {
	fmt.Printf("\nSegfaults: ")
	if info.Segfaults == 0 {
		fmt.Println("none")
		return
	}
	fmt.Printf("%d\n", info.Segfaults)
	for _, p := range info.SegfaultProcs {
		fmt.Printf("    %s   %s\n", asciiOr("warn", "⚠️", mode), p)
	}
	fmt.Println("  → to inspect: dmesg | grep segfault")
}

func printLogsCrashLoops(info *models.LogsInfo, mode output.OutputMode) {
	fmt.Printf("\nCrash loops: ")
	if len(info.CrashLoops) == 0 {
		fmt.Println("none")
		return
	}
	fmt.Println()
	for _, u := range info.CrashLoops {
		unit := strings.Fields(u)[0]
		fmt.Printf("    %s  %s\n", asciiOr("fail", "❌", mode), u)
		fmt.Printf("       → journalctl -u %s -n 20\n", unit)
	}
}

func printLogsCrashFiles(info *models.LogsInfo, mode output.OutputMode) {
	if info.CoreDumpCount == 0 {
		return
	}
	fmt.Printf("\nCrash dumps (%d found):\n", info.CoreDumpCount)
	for _, cf := range info.CrashFiles {
		ago := "today"
		if cf.AgeDays > 0 {
			ago = fmt.Sprintf("%dd ago", cf.AgeDays)
		}
		fmt.Printf("    %s   %-50s %6.1fMB  %s\n", asciiOr("warn", "⚠️", mode), cf.Path, cf.SizeMB, ago)
	}
	fmt.Println("  → to analyse: journalctl -k -b -1 | tail -50")
}

func printLogsJournalSize(info *models.LogsInfo) {
	fmt.Printf("\nJournal size: ")
	switch {
	case info.JournalSizeGB < 0.001:
		fmt.Println("< 1 MB")
	case info.JournalSizeGB < 1.0:
		fmt.Printf("%.0f MB\n", info.JournalSizeGB*1024)
	default:
		fmt.Printf("%.1f GB\n", info.JournalSizeGB)
	}
	if info.LogSource != "" && info.LogSource != "journald" {
		fmt.Printf("Log source:   %s\n", info.LogSource)
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
