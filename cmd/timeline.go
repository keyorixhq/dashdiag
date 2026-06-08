package cmd

import (
	"context"
	"encoding/json"
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
	rootCmd.AddCommand(timelineCmd)
	timelineCmd.Flags().String("since", "1h", "how far back to look (e.g. 1h, 6h, 24h)")
}

var timelineCmd = &cobra.Command{
	Use:   "timeline",
	Short: "Unified incident timeline — journal errors, kernel events, load spikes",
	RunE:  runTimeline,
}

func runTimeline(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	sinceStr, _ := cmd.Flags().GetString("since")
	since := parseSinceDuration(sinceStr)
	hours := int(since.Hours())
	if hours < 1 {
		hours = 1
	}
	jsonOut, _ := cmd.Flags().GetBool("json")
	mode := output.DetectMode(plain, false, "")

	// JSON mode: run silently (no progress spinner) and emit raw JSON.
	if jsonOut {
		var result runner.Result
		for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewTimelineCollector(hours)}) {
			result = r
		}
		info, ok := result.Data.(*models.TimelineInfo)
		if !ok || info == nil {
			return result.Err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

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

	printTimeline(info, elapsed, mode)
	return nil
}

func printTimeline(info *models.TimelineInfo, elapsed time.Duration, mode output.OutputMode) {
	sep := strings.Repeat("─", 64)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	windowStr := fmt.Sprintf("%dh", info.WindowHours)
	fmt.Printf("\n⏱  Incident timeline — last %s\n", windowStr)

	// Load average header
	printTimelineLoad(info, mode)

	// Event table
	if len(info.Events) == 0 {
		fmt.Printf("\n  %s  No errors or warnings found in this window.\n", asciiOr("ok", "✅", mode))
	} else {
		fmt.Printf("\n  %-8s  %-8s  %-18s  %s\n", "TIME", "LEVEL", "UNIT", "MESSAGE")
		fmt.Printf("  %s\n", strings.Repeat("─", 60))
		printTimelineEvents(info.Events, mode)
	}

	fmt.Println()
	fmt.Println(sep)
	issues := info.CritCount + info.WarnCount
	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("%s Timeline clean%s", asciiOr("ok", "✅", mode), timing)))
	} else {
		var parts []string
		if info.CritCount > 0 {
			parts = append(parts, fmt.Sprintf("%d CRIT", info.CritCount))
		}
		if info.WarnCount > 0 {
			parts = append(parts, fmt.Sprintf("%d WARN", info.WarnCount))
		}
		fmt.Println(render.StyleWarn.Render(
			fmt.Sprintf("%s  %s event(s) found%s", asciiOr("warn", "⚠️", mode), strings.Join(parts, ", "), timing)))
	}
}

func printTimelineLoad(info *models.TimelineInfo, mode output.OutputMode) {
	if len(info.LoadSpikes) == 0 {
		return
	}
	fmt.Printf("\n  Load average:\n")
	for _, s := range info.LoadSpikes {
		icon := asciiOr("ok", "✅", mode)
		if s.Load1 >= 8 {
			icon = asciiOr("fail", "❌", mode)
		} else if s.Load1 >= 4 {
			icon = asciiOr("warn", "⚠️ ", mode)
		}
		fmt.Printf("  %s  %-16s  load: %.2f  %.2f  %.2f  (1m/5m/15m)\n",
			icon, s.TimeStr, s.Load1, s.Load5, s.Load15)
	}
}

func printTimelineEvents(events []models.TimelineEvent, mode output.OutputMode) {
	prevDay := ""
	for _, e := range events {
		day := time.Unix(e.TimestampUnix, 0).Format("Jan 02")
		if day != prevDay {
			fmt.Printf("  ── %s ─────────────────────────────────────────────\n", day)
			prevDay = day
		}
		icon := asciiOr("warn", "⚠️ ", mode)
		switch e.Level {
		case "CRIT":
			icon = asciiOr("fail", "❌", mode)
		case "INFO":
			icon = asciiOr("info", "ℹ️ ", mode)
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

		// Print hint block if present — same contract as dsd health hints
		if h := e.Hint; h != nil {
			if h.Explain != "" {
				fmt.Printf("     → %s\n", h.Explain)
			}
			if h.Inspect != "" {
				fmt.Printf("     → to inspect: %s\n", h.Inspect)
			}
			if h.Fix != "" {
				fmt.Printf("     → to fix:     %s\n", h.Fix)
			}
			if h.Persist != "" {
				fmt.Printf("     → to persist: %s\n", h.Persist)
			}
		}
	}
}
