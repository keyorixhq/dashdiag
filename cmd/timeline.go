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
	rootCmd.AddCommand(timelineCmd)
	timelineCmd.Flags().Int("hours", 1, "how many hours back to look (1, 6, 24)")
}

var timelineCmd = &cobra.Command{
	Use:   "timeline",
	Short: "Unified incident timeline — journal errors, kernel events, load spikes",
	RunE:  runTimeline,
}

func runTimeline(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	hours, _ := cmd.Flags().GetInt("hours")
	mode := output.DetectMode(plain, false, "")

	p := output.NewCommandProgress("Timeline", 20*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewTimelineCollector(hours)}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()
	info, ok := result.Data.(*models.TimelineInfo)
	if !ok || info == nil {
		return result.Err
	}

	printTimeline(info, elapsed)
	return nil
}

func printTimeline(info *models.TimelineInfo, elapsed time.Duration) {
	sep := strings.Repeat("─", 64)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	windowStr := fmt.Sprintf("%dh", info.WindowHours)
	fmt.Printf("\n⏱  Incident timeline — last %s\n", windowStr)

	// Load average header
	printTimelineLoad(info)

	// Event table
	if len(info.Events) == 0 {
		fmt.Println("\n  ✅  No errors or warnings found in this window.")
	} else {
		fmt.Printf("\n  %-8s  %-8s  %-18s  %s\n", "TIME", "LEVEL", "UNIT", "MESSAGE")
		fmt.Printf("  %s\n", strings.Repeat("─", 60))
		printTimelineEvents(info.Events)
	}

	fmt.Println()
	fmt.Println(sep)
	issues := info.CritCount + info.WarnCount
	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("✅ Timeline clean%s", timing)))
	} else {
		var parts []string
		if info.CritCount > 0 {
			parts = append(parts, fmt.Sprintf("%d CRIT", info.CritCount))
		}
		if info.WarnCount > 0 {
			parts = append(parts, fmt.Sprintf("%d WARN", info.WarnCount))
		}
		fmt.Println(render.StyleWarn.Render(
			fmt.Sprintf("⚠️  %s event(s) found%s", strings.Join(parts, ", "), timing)))
	}
}

func printTimelineLoad(info *models.TimelineInfo) {
	if len(info.LoadSpikes) == 0 {
		return
	}
	fmt.Printf("\n  Load average:\n")
	for _, s := range info.LoadSpikes {
		icon := "✅"
		if s.Load1 >= 8 {
			icon = "❌"
		} else if s.Load1 >= 4 {
			icon = "⚠️ "
		}
		fmt.Printf("  %s  %-16s  load: %.2f  %.2f  %.2f  (1m/5m/15m)\n",
			icon, s.TimeStr, s.Load1, s.Load5, s.Load15)
	}
}

func printTimelineEvents(events []models.TimelineEvent) {
	prevDay := ""
	for _, e := range events {
		day := time.Unix(e.TimestampUnix, 0).Format("Jan 02")
		if day != prevDay {
			fmt.Printf("  ── %s ─────────────────────────────────────────────\n", day)
			prevDay = day
		}
		icon := "⚠️ "
		switch e.Level {
		case "CRIT":
			icon = "❌"
		case "INFO":
			icon = "ℹ️ "
		}
		src := e.Source
		if e.Source == "journal" {
			src = "jrnl"
		}
		unit := e.Unit
		if len(unit) > 16 {
			unit = unit[:15] + "…"
		}
		msg := e.Message
		if len(msg) > 55 {
			msg = msg[:54] + "…"
		}
		countStr := ""
		if e.Count > 1 {
			countStr = fmt.Sprintf(" ×%d", e.Count)
		}
		fmt.Printf("  %s  %-8s  %-4s  %-16s  %s%s\n",
			icon, e.TimeStr, src, unit, msg, countStr)
	}
}
