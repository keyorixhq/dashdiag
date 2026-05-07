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

func runHealth(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	ctrCtx := platform.DetectContainerContext()
	cloudEnv := platform.DetectCloudEnvironment()

	state, _ := tips.LoadState()
	if state != nil {
		tips.MaybePrintReengagement(state, mode, version.Version)
	}

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
		baseline.SaveBaseline(snap) //nolint:errcheck
		return nil
	}

	renderer := render.NewRenderer(mode)
	if ctrCtx.InContainer {
		renderer.PrintContainerBanner(ctrCtx)
	}
	if mode == output.ModeJSON {
		data, err := render.RenderJSON(results, insights)
		if err == nil {
			os.Stdout.Write(data) //nolint:errcheck
		}
	} else {
		renderer.PrintAll(results, insights)
	}

	diffFlag, _ := cmd.Flags().GetBool("diff")
	if diffFlag {
		prev, err := baseline.LoadBaseline("")
		if err == nil {
			render.PrintDiff(prev, snap, mode) //nolint:errcheck
		} else {
			fmt.Fprintln(os.Stderr, "ℹ️  No previous baseline. Run dsd health again to enable --diff.")
		}
	}

	exitCode := renderer.PrintSummary(insights)
	baseline.SaveBaseline(snap) //nolint:errcheck

	// --qr: show QR code for share URL (shareURL stub until --share is implemented)
	qrFlag, _ := cmd.Flags().GetBool("qr")
	if qrFlag {
		shareURL := ""
		output.PrintQRCode(shareURL, mode) //nolint:errcheck
	}

	if state != nil {
		tips.MaybePrintMilestone(state, mode) // increments TotalRuns and updates streak
		tips.MaybePrintTip(state, mode)
		if state.CommandCounts == nil {
			state.CommandCounts = make(map[string]int)
		}
		state.CommandCounts["health"]++
		state.Save() //nolint:errcheck
	}

	if exitCode > 0 {
		os.Exit(exitCode)
	}
	return nil
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
