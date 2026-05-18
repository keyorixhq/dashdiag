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
	healthCmd.AddCommand(healthDeepCmd)
	healthCmd.Flags().Duration("watch-interval", 60*time.Second, "refresh interval for --watch mode")
	healthCmd.Flags().Bool("terse", false, "skip inline drill-down on WARN/CRIT (show minimal verdict only)")
	healthCmd.Flags().Bool("packages", false, "include package security advisory check (may be slow on unregistered systems)")
	healthCmd.Flags().Bool("gpu", false, "include GPU health check via nvidia-smi")
	healthCmd.Flags().Bool("tls", false, "include TLS certificate expiry check")
	healthCmd.Flags().Bool("deep", false, "extended analysis: per-core CPU breakdown, top memory consumers")
	healthCmd.Flags().Bool("firmware", false, "check for pending firmware upgrades via fwupd")
	healthCmd.Flags().Bool("report", false, "write a shareable markdown report to dsd-report-<host>-<date>.md")
	healthCmd.Flags().String("policy", "", "path to policy YAML — override thresholds and set CI exit behaviour")
}

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "System health check — CPU, memory, disk, network (~5s)",
	RunE:  runHealth,
}

// healthDeepCmd is `dsd health deep` — equivalent to `dsd health --deep`.
// Runs all fast checks plus per-core CPU breakdown and top memory consumers.
var healthDeepCmd = &cobra.Command{
	Use:   "deep",
	Short: "Extended health check — per-core CPU, top memory consumers (~8s)",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Set --deep on the parent command and delegate to runHealth
		if err := cmd.Parent().Flags().Set("deep", "true"); err != nil {
			return err
		}
		return runHealth(cmd.Parent(), args)
	},
}

// TODO(backlog): CVE exposure check — cross-reference installed packages against a local
// advisory feed. On RHEL/CentOS: parse /var/cache/dnf or OVAL from access.redhat.com.
// On Ubuntu: parse /var/lib/apt/lists/. Cache locally (~weekly). No cloud registration.
// WARN: CVSS >= 7.0. CRIT: CVSS >= 9.0 or known exploited.
// Estimated scope: ~1 week (advisory feed parsing is the bulk). See BACKLOG.md.

// TODO(backlog): CIS/STIG compliance checks — compare system config against CIS Benchmark
// or STIG profiles. Enterprise-only. Implement after core product is stable and paying
// customers exist. Estimated scope: ~2 weeks. See BACKLOG.md.

func runHealth(cmd *cobra.Command, _ []string) error { //nolint:funlen,cyclop // command handler dispatches many flags; sub-flows are extracted to runHealthOnce/runWatch/loadPolicyIfSet
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

	pkgFlag, _ := cmd.Flags().GetBool("packages")
	gpuFlag, _ := cmd.Flags().GetBool("gpu")
	tlsFlag, _ := cmd.Flags().GetBool("tls")
	deepFlag, _ := cmd.Flags().GetBool("deep")
	firmwareFlag, _ := cmd.Flags().GetBool("firmware")
	reportFlag, _ := cmd.Flags().GetBool("report")
	policyPath, _ := cmd.Flags().GetString("policy")
	policy, err := loadPolicyIfSet(policyPath)
	if err != nil {
		return err
	}

	results, insights, snap, elapsed := runHealthOnce(ctx, ctrCtx, cloudEnv, mode, terse, pkgFlag, gpuFlag, tlsFlag, deepFlag, firmwareFlag, policy)

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
	correlations := analysis.Correlate(insights)
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
		renderer.PrintCorrelations(correlations)
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

	// --report: write shareable markdown file
	if reportFlag && snap != nil {
		// Collect CVE data for report (runs quickly, uses same package manager)
		cveData := collectors.ScanAllCVEs(ctx)
		path, err := render.GenerateReport(snap, insights, elapsed, cveData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "report: %v\n", err)
		} else {
			fmt.Printf("\n📄 Report saved: %s\n", path)
		}
	}

	// Policy CI gate — override exit code based on deny rules.
	// Default (no policy): exit 1 on WARN, 2 on CRIT (already from PrintSummary).
	// With policy deny:[WARN]: exit non-zero on any WARN or CRIT.
	if policy != nil {
		for _, ins := range insights {
			if analysis.PolicyDeniesLevel(policy, ins.Level) && exitCode == 0 {
				exitCode = 1
			}
		}
		if policyPath != "" && mode == output.ModeHuman {
			fmt.Fprintf(os.Stderr, "\n── policy: %s ──\n", policyPath)
		}
	}

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

	// Print timing last — after tips so it is always the final line the operator sees.
	// Plain mode also prints here; JSON/YAML have timing embedded in their payload.
	if elapsed > 0 {
		switch mode {
		case output.ModeHuman:
			fmt.Fprintln(os.Stdout, render.StyleDim.Render(fmt.Sprintf("done in %.1fs", elapsed.Seconds())))
		case output.ModePlain:
			fmt.Fprintf(os.Stdout, "done in %.1fs\n", elapsed.Seconds())
		}
	}

	if exitCode > 0 {
		os.Exit(exitCode)
	}
	return nil
}

func runHealthOnce(ctx context.Context, ctrCtx platform.ContainerContext, cloudEnv platform.CloudEnvironment, mode output.OutputMode, terse bool, includePackages bool, includeGPU bool, includeTLS bool, includeDeep bool, includeFirmware bool, policy *analysis.PolicyFile) ([]runner.Result, []models.Insight, *baseline.Snapshot, time.Duration) {
	cols := buildHealthCollectors(ctrCtx, includePackages, includeGPU, includeTLS, includeDeep, includeFirmware)
	p := output.NewCommandProgress("System health", 5*time.Second, mode, len(cols))
	p.Start()
	defer p.Done()

	var results []runner.Result
	for r := range runner.RunAll(ctx, toRunnerCols(cols)) {
		p.Step(r.Name)
		results = append(results, r)
	}

	thresh := analysis.DefaultThresholds(cloudEnv)
	if ctrCtx.InContainer {
		analysis.ApplyContainerThresholds(&thresh)
	}
	thresh = analysis.ApplyPolicy(thresh, policy)
	insights := analysis.ApplyThresholds(results, thresh, cloudEnv, ctrCtx)
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
		if mode == output.ModeHuman {
			fmt.Print("\033[H\033[2J") // clear screen + move cursor to top
		}
		results, insights, _, _ := runHealthOnce(ctx, ctrCtx, cloudEnv, mode, false, false, false, false, false, false, nil)
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

// loadPolicyIfSet loads a policy file when path is non-empty.
// Returns nil policy (no error) when path is empty.
func loadPolicyIfSet(path string) (*analysis.PolicyFile, error) {
	if path == "" {
		return nil, nil
	}
	p, err := analysis.LoadPolicy(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsd: policy error: %v\n", err)
		return nil, err
	}
	return p, nil
}

func buildHealthCollectors(ctrCtx platform.ContainerContext, includePackages bool, includeGPU bool, includeTLS bool, includeDeep bool, includeFirmware bool) []collectors.Collector { //nolint:funlen // registration list — each line is a presence-gated collector, splitting would harm readability
	cols := []collectors.Collector{
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
		collectors.NewDBusCollector(), // Tier-0: D-Bus failure cascades to all IPC-dependent services
		collectors.NewSysctlCollector(),
		collectors.NewKernelSecurityCollector(),
		collectors.NewEntropyCollector(),
		collectors.NewLogsCollector(),
		collectors.NewSecurityCollector(),
	}
	// SUSE-specific collectors — only on SUSE/openSUSE hosts
	if collectors.IsSUSEHost() {
		cols = append(cols, collectors.NewSnapperCollector())
	}
	// Subscription check — any enterprise Linux with a subscription manager
	if collectors.HasSubscriptionManager() {
		cols = append(cols, collectors.NewSUSEConnectCollector())
	}
	cols = append(cols,
		collectors.NewThermalCollectorWithContext(ctrCtx.InContainer),
		collectors.NewBatteryCollector(),
		collectors.NewNVMeCollector(),
		collectors.NewPackagesCollector(), // security advisory summary — uses local package metadata, no network
	)
	// Storage HA — only register when technology is present on this host
	if collectors.IsRAIDPresent() {
		cols = append(cols, collectors.NewRAIDCollector())
	}
	if collectors.IsZFSPresent() {
		cols = append(cols, collectors.NewZFSCollector())
	}
	if collectors.IsLVMPresent() {
		cols = append(cols, collectors.NewLVMCollector())
	}
	if collectors.IsDRBDPresent() {
		cols = append(cols, collectors.NewDRBDCollector())
	}
	if collectors.IsPVEHost() {
		cols = append(cols, collectors.NewPVECollector())
	}
	// Bonding / LACP
	if collectors.IsBondingPresent() {
		cols = append(cols, collectors.NewBondingCollector())
	}
	// IPMI / BMC sensors
	if collectors.IsIPMIPresent() {
		cols = append(cols, collectors.NewIPMICollector())
	}
	// OOM killer events — always collected (reads journal, never root-only)
	cols = append(cols, collectors.NewOOMCollector())
	// Fibre Channel HBA
	if collectors.IsHBAPresent() {
		cols = append(cols, collectors.NewHBACollector())
	}
	// cgroup v2 PSI pressure
	if collectors.IsPSIAvailable() {
		cols = append(cols, collectors.NewPressureCollector())
	}
	// DM-MPIO multipath
	if collectors.IsMultipathPresent() {
		cols = append(cols, collectors.NewMultipathCollector())
	}
	// Medium priority: Ceph, Firewall, Auth, CloudMeta, Auditd
	if collectors.IsCephPresent() {
		cols = append(cols, collectors.NewCephCollector())
	}
	cols = append(cols, collectors.NewFirewallCollector())
	cols = append(cols, collectors.NewAuthCollector())
	if collectors.IsCloudInstance() {
		cols = append(cols, collectors.NewCloudMetaCollector())
	}
	if collectors.IsAuditdPresent() {
		cols = append(cols, collectors.NewAuditCollector())
	}
	// Low priority: NUMA, VLAN, iSCSI, InfiniBand, SR-IOV, Nspawn
	if collectors.IsNUMAPresent() {
		cols = append(cols, collectors.NewNUMACollector())
	}
	if collectors.IsVLANPresent() {
		cols = append(cols, collectors.NewVLANCollector())
	}
	if collectors.IsISCSIPresent() {
		cols = append(cols, collectors.NewISCSICollector())
	}
	if collectors.IsInfiniBandPresent() {
		cols = append(cols, collectors.NewInfiniBandCollector())
	}
	if collectors.IsSRIOVPresent() {
		cols = append(cols, collectors.NewSRIOVCollector())
	}
	if collectors.IsNspawnPresent() {
		cols = append(cols, collectors.NewNspawnCollector())
	}
	// Always collected — world-readable sysfs/proc paths
	cols = append(cols, collectors.NewHugePagesCollector())
	if collectors.IsCPUFreqAvailable() {
		cols = append(cols, collectors.NewCPUFreqCollector())
	}
	if includeGPU {
		cols = append(cols, collectors.NewGPUCollector())
	}
	if includeTLS {
		cols = append(cols, collectors.NewTLSCollector())
	}
	if includeDeep {
		cols = append(cols, collectors.NewHealthDeepCollector())
	}
	if includeFirmware {
		cols = append(cols, collectors.NewFirmwareCollector())
	}
	return cols
}

func toRunnerCols(cols []collectors.Collector) []runner.Collector {
	out := make([]runner.Collector, len(cols))
	for i, c := range cols {
		out[i] = c
	}
	return out
}
