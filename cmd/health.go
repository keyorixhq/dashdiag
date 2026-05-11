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
	"github.com/keyorixhq/dashdiag/internal/debug"
	"github.com/keyorixhq/dashdiag/internal/drilldown"
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
	healthCmd.Flags().Duration("watch-interval", 60*time.Second, "refresh interval for --watch mode")
	healthCmd.Flags().Bool("terse", false, "skip inline drill-down on WARN/CRIT (show minimal verdict only)")
}

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "System health check — CPU, memory, disk, network (~5s)",
	RunE:  runHealth,
}

// TODO(backlog): dsd health deep — extended health check with per-core CPU breakdown,
// per-process memory detail, extended sysctl analysis, and kernel tuning recommendations.
// Build rule: implement only after dsd health fast variant is in production use.
// Estimated scope: ~3 days. Add back healthDeepCmd and wire into init() when ready.

// TODO(backlog): entropy collector — check /proc/sys/kernel/random/entropy_avail.
// Low entropy (<256) silently breaks crypto operations (TLS handshakes, key generation).
// Read: /proc/sys/kernel/random/entropy_avail and /proc/sys/kernel/random/poolsize.
// WARN < 256, CRIT < 64. Add to buildHealthCollectors().
// Estimated scope: ~2 hours.

// TODO(backlog): package security advisory collector — surface available security updates.
// Linux: parse `dnf check-update --security` or `apt list --upgradable` (distro-detect).
// macOS: `brew outdated --greedy` for Homebrew packages.
// Show count of security updates available; WARN if > 0 critical CVE updates pending.
// Estimated scope: ~1 day. Note: this is the only collector that shells out intentionally
// (no kernel interface for package state); follow existing macOS pgrep pattern.

// TODO(backlog): kernel tuning recommendations (sysctl advisor) — compare live sysctl
// values against known-good profiles for common workloads (web server, database, k8s node).
// Extend SysctlCollector to flag suboptimal values with specific recommended settings.
// Examples: vm.swappiness > 10 on SSD, net.core.rmem_max < 16MB on high-throughput host.
// Workload profile auto-detected from running processes (nginx, postgres, kubelet etc).
// Estimated scope: ~2 days.

// TODO(backlog): CVE exposure check — cross-reference installed packages against a local
// advisory feed. On RHEL/CentOS: parse /var/cache/dnf or query OVAL data from
// https://access.redhat.com/security/data/oval/. On Ubuntu: parse /var/lib/apt/lists/.
// No cloud registration required — advisory data downloaded and cached locally (~weekly).
// WARN: any CVE with CVSS >= 7.0. CRIT: any CVE with CVSS >= 9.0 or known exploited.
// Estimated scope: ~1 week (advisory feed parsing is the bulk of the work).

func runHealth(cmd *cobra.Command, _ []string) error { //nolint:funlen // command handler dispatches many flags; sub-flows are extracted to runHealthOnce/runWatch
	ctx := context.Background()
	debugFlag, _ := cmd.Flags().GetBool("debug")
	ctx = debug.With(ctx, debugFlag)
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	yamlOut, _ := cmd.Flags().GetBool("yaml")
	terse, _ := cmd.Flags().GetBool("terse")
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

	// --story: try history first without running collectors
	storyFlag, _ := cmd.Flags().GetBool("story")
	if storyFlag {
		history, err := baseline.LoadHistory(48)
		if err == nil && len(history) >= 2 {
			fmt.Println(render.RenderStoryFromHistory(history))
			return nil
		}
		// Not enough history yet — fall through to live run
	}

	results, insights, snap, elapsed := runHealthOnce(ctx, ctrCtx, cloudEnv, mode, terse)

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

	exitCode := renderer.PrintSummary(insights, elapsed)
	_ = baseline.SaveBaseline(snap)

	// --qr: show QR code for share URL (shareURL stub until --share is implemented)
	qrFlag, _ := cmd.Flags().GetBool("qr")
	if qrFlag {
		shareURL := ""
		_ = output.PrintQRCode(shareURL, mode)
	}

	if state != nil {
		tips.MaybePrintMilestone(state, mode)
		tips.MaybePrintTip(state, mode)
		tips.MaybePrintChangelog(state, mode, version.Version)
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

func runHealthOnce(ctx context.Context, ctrCtx platform.ContainerContext, cloudEnv platform.CloudEnvironment, mode output.OutputMode, terse bool) ([]runner.Result, []models.Insight, *baseline.Snapshot, time.Duration) {
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
	if !terse {
		insights = drilldown.PopulateAll(ctx, insights, results)
	}
	snap := baseline.BuildSnapshot(results, insights)
	return results, insights, snap, p.Elapsed()
}

func runWatch(ctx context.Context, interval time.Duration, ctrCtx platform.ContainerContext, cloudEnv platform.CloudEnvironment, mode output.OutputMode) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	startCountdown := func(cancelCh <-chan struct{}) {
		if mode != output.ModeHuman {
			return
		}
		countTicker := time.NewTicker(1 * time.Second)
		defer countTicker.Stop()
		remaining := interval
		for {
			select {
			case <-cancelCh:
				fmt.Print("\r\033[K") // clear countdown line before next run
				return
			case <-countTicker.C:
				remaining -= time.Second
				if remaining < 0 {
					remaining = 0
				}
				fmt.Printf("\r  ↻ next refresh in %ds   ", int(remaining.Seconds()))
			}
		}
	}

	run := func() {
		results, insights, _, _ := runHealthOnce(ctx, ctrCtx, cloudEnv, mode, false)
		renderer := render.NewRenderer(mode)
		fmt.Printf("\n── %s ──\n", time.Now().Format("2006-01-02 15:04:05"))
		renderer.PrintAll(results, insights)
		renderer.PrintSummary(insights, 0) //nolint:errcheck
	}

	run()
	cancelCh := make(chan struct{})
	go startCountdown(cancelCh)

	for {
		select {
		case <-ctx.Done():
			close(cancelCh)
			return nil
		case <-ticker.C:
			close(cancelCh)
			cancelCh = make(chan struct{})
			run()
			go startCountdown(cancelCh)
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
		collectors.NewKernelSecurityCollector(),
	}
}

func toRunnerCols(cols []collectors.Collector) []runner.Collector {
	out := make([]runner.Collector, len(cols))
	for i, c := range cols {
		out[i] = c
	}
	return out
}
