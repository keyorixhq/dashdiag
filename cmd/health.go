package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/tips"
	"github.com/keyorixhq/dashdiag/internal/version"
)

func init() {
	rootCmd.AddCommand(healthCmd)
	healthCmd.AddCommand(healthDeepCmd)
	healthCmd.Flags().Duration("watch-interval", 60*time.Second, "refresh interval for --watch mode")
}

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "System health check — CPU, memory, disk, network (~5s)",
	RunE:  runHealth,
}

var healthDeepCmd = &cobra.Command{
	Use:   "deep",
	Short: "Thorough health check including per-core CPU (~8s)",
	RunE:  runHealth,
}

func runHealth(cmd *cobra.Command, _ []string) error { //nolint:funlen // command handler dispatches many flags; sub-flows are extracted to runHealthOnce/runWatch
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	yamlOut, _ := cmd.Flags().GetBool("yaml")
	outputFmt := ""
	switch {
	case jsonOut:
		outputFmt = "json"
	case yamlOut:
		outputFmt = "yaml"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	ctrCtx := platform.DetectContainerContext()
	cloudEnv := platform.DetectCloudEnvironment()

	watchFlag, _ := cmd.Flags().GetBool("watch")
	if watchFlag {
		interval, _ := cmd.Flags().GetDuration("watch-interval")
		return runWatch(ctx, interval, ctrCtx, cloudEnv, mode)
	}

	state, _ := tips.LoadState()
	if state != nil {
		tips.MaybePrintReengagement(state, mode, version.Version)
	}

	results, insights, snap := runHealthOnce(ctx, ctrCtx, cloudEnv, mode)

	// --weekly: early return, reads state.json only
	weeklyFlag, _ := cmd.Flags().GetBool("weekly")
	if weeklyFlag {
		weeklyState, _ := tips.LoadState()
		if weeklyState == nil || weeklyState.TotalRuns < 7 {
			fmt.Println("ℹ️  Not enough data yet. Run dsd health for 7+ days first.")
			return nil
		}
		fmt.Println(render.RenderWeekly(weeklyState, "weekly"))
		return nil
	}

	// --story: deterministic narrative
	storyFlag, _ := cmd.Flags().GetBool("story")
	if storyFlag {
		fmt.Println(render.RenderStory(insights, snap))
		return nil
	}

	sdFlag, _ := cmd.Flags().GetBool("since-deploy")
	pmFlag, _ := cmd.Flags().GetString("post-mortem")
	if sdFlag {
		return baseline.RunSinceDeployDiff(mode)
	}
	if pmFlag != "" {
		fmt.Println(render.RenderPostMortem(pmFlag, snap, insights, mode))
		_ = baseline.SaveBaseline(snap)
		return nil
	}

	renderer := render.NewRenderer(mode)
	if ctrCtx.InContainer {
		renderer.PrintContainerBanner(ctrCtx)
	}
	switch mode {
	case output.ModeJSON:
		data, err := render.RenderJSON(results, insights)
		if err == nil {
			_, _ = os.Stdout.Write(data)
		}
	case output.ModeYAML:
		data, err := render.RenderYAML(results, insights)
		if err == nil {
			_, _ = os.Stdout.Write(data)
		}
	default:
		renderer.PrintAll(results, insights)
	}

	diffFlag, _ := cmd.Flags().GetBool("diff")
	if diffFlag {
		prev, err := baseline.LoadBaseline("")
		if err == nil {
			_ = render.PrintDiff(prev, snap, mode)
		} else {
			fmt.Fprintln(os.Stderr, "ℹ️  No previous baseline. Run dsd health again to enable --diff.")
		}
	}

	exitCode := renderer.PrintSummary(insights)
	_ = baseline.SaveBaseline(snap)

	// --qr: show QR code for share URL (shareURL stub until --share is implemented)
	qrFlag, _ := cmd.Flags().GetBool("qr")
	if qrFlag {
		shareURL := ""
		_ = output.PrintQRCode(shareURL, mode)
	}

	if state != nil {
		tips.MaybePrintMilestone(state, mode) // increments TotalRuns and updates streak
		tips.MaybePrintTip(state, mode)
		if state.CommandCounts == nil {
			state.CommandCounts = make(map[string]int)
		}
		state.CommandCounts["health"]++
		_ = state.Save()
	}

	if exitCode > 0 {
		os.Exit(exitCode)
	}
	return nil
}

func runHealthOnce(ctx context.Context, ctrCtx platform.ContainerContext, cloudEnv platform.CloudEnvironment, mode output.OutputMode) ([]runner.Result, []models.Insight, *baseline.Snapshot) {
	cols := buildHealthCollectors(ctrCtx)
	p := output.NewCommandProgress("System health", 5*time.Second, mode, len(cols))
	p.Start()
	defer p.Done()

	var results []runner.Result
	for r := range runner.RunAll(ctx, toRunnerCols(cols)) {
		p.Step(r.Name)
		results = append(results, r)
	}

	thresh := analysis.DefaultThresholds(cloudEnv)
	insights := analysis.ApplyThresholds(results, thresh, cloudEnv)
	snap := baseline.BuildSnapshot(results, insights)
	return results, insights, snap
}

func runWatch(ctx context.Context, interval time.Duration, ctrCtx platform.ContainerContext, cloudEnv platform.CloudEnvironment, mode output.OutputMode) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	run := func() {
		results, insights, _ := runHealthOnce(ctx, ctrCtx, cloudEnv, mode)
		renderer := render.NewRenderer(mode)
		fmt.Printf("\n── %s ──\n", time.Now().Format("2006-01-02 15:04:05"))
		renderer.PrintAll(results, insights)
		renderer.PrintSummary(insights) //nolint:errcheck
	}

	run()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			run()
		}
	}
}

func buildHealthCollectors(ctrCtx platform.ContainerContext) []collectors.Collector {
	return []collectors.Collector{
		collectors.NewCPUCollector(ctrCtx),
		collectors.NewMemoryCollector(ctrCtx),
		collectors.NewDiskCollector(),
		collectors.NewSwapCollector(ctrCtx),
		collectors.NewIOCollector(),
		collectors.NewNetworkCollector(),
		collectors.NewClockCollector(),
		collectors.NewFDLimitsCollector(),
		collectors.NewProcessesCollector(),
		collectors.NewSystemdCollector(),
		collectors.NewSysctlCollector(),
		collectors.NewMACPolicyCollector(),
	}
}

func toRunnerCols(cols []collectors.Collector) []runner.Collector {
	out := make([]runner.Collector, len(cols))
	for i, c := range cols {
		out[i] = c
	}
	return out
}
