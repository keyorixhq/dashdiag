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
	"github.com/keyorixhq/dashdiag/internal/selfupdate"
	"github.com/keyorixhq/dashdiag/internal/share"
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
	healthCmd.Flags().Bool("cve", false, "include CVE security advisory scan (CVSS>=7 WARN, >=9 or CISA KEV CRIT; may be slow)")
	healthCmd.Flags().Bool("report", false, "write a shareable markdown report to dsd-report-<host>-<date>.md")
	healthCmd.Flags().Bool("blob", false, "emit a compact, copy-pasteable encoded report blob (network-optional; decode with `dsd decode`)")
	healthCmd.Flags().String("policy", "", "path to policy YAML — override thresholds and set CI exit behaviour")
	healthCmd.Flags().Bool("explain", false, "after the verdict, explain each flagged subsystem (see also: dsd explain)")
	healthCmd.Flags().Bool("fix", false, "after the verdict, list the remediation commands for each flagged subsystem")
	healthCmd.Flags().Bool("nagios", false, "single-line monitoring-plugin output (Nagios/Icinga/check_mk); exit 0/1/2")
	healthCmd.Flags().Bool("prometheus", false, "Prometheus exposition metrics (node_exporter textfile collector / scrape)")
	healthCmd.Flags().Bool("debug", false, "enable debug logging")
	healthCmd.Flags().Bool("diff", false, "show diff from previous run")
	healthCmd.Flags().Bool("since-deploy", false, "show metrics since last deploy")
	healthCmd.Flags().Bool("story", false, "human-readable narrative of current state")
	healthCmd.Flags().Bool("weekly", false, "show weekly usage report")
	healthCmd.Flags().Bool("yaml", false, "YAML output")
	healthCmd.Flags().String("post-mortem", "", "generate post-mortem for given incident ID")
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

// CVE exposure check — SHIPPED via `dsd health --cve` (CVEHealthCollector).
// Cross-references the package manager's pending security advisories (dnf/apt/
// zypper/pacman) against the CISA KEV catalog. WARN: advisories the manager rates
// Important/High. CRIT: advisories rated Critical, or any CISA KEV match. The
// bucket is the manager's published severity rating, not a CVSS score the
// advisory-list scan measures. KEV catalog is a local sidecar file (no cloud
// registration) — see `dsd cve info` for the fetch command.

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
	blobFlag, _ := cmd.Flags().GetBool("blob")
	outputFmt := ""
	switch {
	case jsonOut:
		outputFmt = "json"
	case yamlOut:
		outputFmt = "yaml"
	case blobFlag:
		// Run as quietly as JSON mode (no progress/banner on stdout) so the
		// emitted block is clean to copy; the blob itself is printed below.
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	// --nagios emits a single status line; run quietly (no progress/banner/board)
	// so stdout carries only that line, then branch out below after collection.
	nagiosFlag, _ := cmd.Flags().GetBool("nagios")
	promFlag, _ := cmd.Flags().GetBool("prometheus")
	if (nagiosFlag || promFlag) && mode == output.ModeHuman {
		mode = output.ModePlain
	}

	ctrCtx := platform.DetectContainerContext()
	cloudEnv := platform.DetectCloudEnvironment()
	profile := platform.Detect()
	debug.Logf(ctx, "Platform", "%s", profile.DebugLine())

	watchFlag, _ := cmd.Flags().GetBool("watch")
	if watchFlag {
		interval, _ := cmd.Flags().GetDuration("watch-interval")
		return runWatch(ctx, interval, ctrCtx, cloudEnv, profile, mode)
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
	cveFlag, _ := cmd.Flags().GetBool("cve")
	reportFlag, _ := cmd.Flags().GetBool("report")
	policyPath, _ := cmd.Flags().GetString("policy")
	policy, err := loadPolicyIfSet(policyPath)
	if err != nil {
		return err
	}

	results, insights, snap, elapsed := runHealthOnce(ctx, ctrCtx, cloudEnv, profile, mode, terse, pkgFlag, gpuFlag, tlsFlag, deepFlag, firmwareFlag, cveFlag, policy)

	// --nagios: emit one monitoring-plugin status line and exit with the mapped
	// code (0/1/2), suppressing all normal rendering.
	if nagiosFlag {
		line, code := render.NagiosLine(results, insights)
		fmt.Println(line)
		_ = baseline.SaveBaseline(snap)
		if code > 0 {
			os.Exit(code)
		}
		return nil
	}
	// --prometheus: emit exposition metrics and exit 0 — the health state lives in
	// the metric values, not the exit code (textfile collectors expect success).
	if promFlag {
		fmt.Print(render.PrometheusMetrics(results, insights))
		_ = baseline.SaveBaseline(snap)
		return nil
	}

	// --blob: emit a compact, copy-pasteable encoded report (network-optional).
	// stdout gets only the block (so `--out` / a pipe captures it cleanly); the
	// human instructions go to stderr.
	if blobFlag {
		data, err := render.RenderJSON(results, insights)
		if err != nil {
			return fmt.Errorf("blob: %w", err)
		}
		fmt.Print(share.Encode(data))
		fmt.Fprintln(os.Stderr, "\n↑ Copy the whole block above (including the BEGIN/END lines) and send it to support.")
		fmt.Fprintln(os.Stderr, "  They turn it back into a readable report with:  dsd decode   (paste it, or `dsd decode file.txt`)")
		fmt.Fprintln(os.Stderr, "  Note: the block is compressed + encoded, NOT encrypted or redacted — it contains this host's")
		fmt.Fprintln(os.Stderr, "  name, addresses, and open ports. Send it through a trusted channel; don't post it publicly.")
		_ = baseline.SaveBaseline(snap)
		return nil
	}

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
	correlations := analysis.CorrelateDeep(insights, extractOOM(results), extractDocker(results), extractIO(results), extractSysctl(results))
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
		// Deep mode: show top processes with cgroup scope
		if deepFlag {
			printTopProcsWithCgroup(results, mode)
		}
	}

	// In machine modes (JSON/YAML) stdout must stay a single document, so route
	// the diff and the report notice to stderr instead of corrupting it.
	machineMode := mode == output.ModeJSON || mode == output.ModeYAML
	noticeW := os.Stdout
	if machineMode {
		noticeW = os.Stderr
	}

	diffFlag, _ := cmd.Flags().GetBool("diff")
	if diffFlag {
		prev, err := baseline.LoadBaseline("")
		if err == nil {
			_ = render.PrintDiff(noticeW, prev, snap, mode)
		} else {
			fmt.Fprintln(os.Stderr, "ℹ️  No previous baseline. Run dsd health again to enable --diff.")
		}
	}

	exitCode := renderer.PrintSummary(insights, elapsed)
	if explainFlag, _ := cmd.Flags().GetBool("explain"); explainFlag {
		printHealthExplanations(insights, mode)
	}
	if fixFlag, _ := cmd.Flags().GetBool("fix"); fixFlag {
		printHealthFixes(insights, mode)
	}
	_ = baseline.SaveBaseline(snap)

	// --report: write shareable markdown file
	if reportFlag && snap != nil {
		// Collect CVE data for report (runs quickly, uses same package manager)
		cveData := collectors.ScanAllCVEs(ctx)
		path, err := render.GenerateReport(snap, insights, elapsed, cveData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "report: %v\n", err)
		} else {
			fmt.Fprintf(noticeW, "\n📄 Report saved: %s\n", path)
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

	// Passive "newer version available" nudge — interactive runs only, reads a
	// 24h cache (no network in the hot path beyond a bounded one-off refresh),
	// silenced by DSD_NO_UPDATE_CHECK. Never affects exit code or output data.
	if mode == output.ModeHuman {
		if line := selfupdate.MaybeNudge(version.Version); line != "" {
			fmt.Println(line)
		}
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

func runHealthOnce(ctx context.Context, ctrCtx platform.ContainerContext, cloudEnv platform.CloudEnvironment, profile platform.Profile, mode output.OutputMode, terse bool, includePackages bool, includeGPU bool, includeTLS bool, includeDeep bool, includeFirmware bool, includeCVE bool, policy *analysis.PolicyFile) ([]runner.Result, []models.Insight, *baseline.Snapshot, time.Duration) {
	cols := buildHealthCollectors(ctrCtx, profile, includePackages, includeGPU, includeTLS, includeDeep, includeFirmware, includeCVE)
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

func runWatch(ctx context.Context, interval time.Duration, ctrCtx platform.ContainerContext, cloudEnv platform.CloudEnvironment, profile platform.Profile, mode output.OutputMode) error {
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

	var prev []models.Insight
	hasPrev := false
	run := func() {
		if mode == output.ModeHuman {
			fmt.Print("\033[H\033[2J") // clear screen + move cursor to top
		}
		results, insights, _, _ := runHealthOnce(ctx, ctrCtx, cloudEnv, profile, mode, false, false, false, false, false, false, false, nil)
		renderer := render.NewRenderer(mode)
		fmt.Printf("\n── %s ──\n", time.Now().Format("2006-01-02 15:04:05"))
		renderer.PrintAll(results, insights)
		renderer.PrintSummary(insights, 0) //nolint:errcheck
		// Surface the delta from the previous tick (skipped on the first render,
		// when there is no baseline to compare against).
		if hasPrev {
			added, resolved, changed := render.InsightChanges(prev, insights)
			render.PrintInsightChanges(os.Stdout, added, resolved, changed, mode)
		}
		prev = insights
		hasPrev = true
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

func buildHealthCollectors(ctrCtx platform.ContainerContext, profile platform.Profile, includePackages bool, includeGPU bool, includeTLS bool, includeDeep bool, includeFirmware bool, includeCVE bool) []collectors.Collector { //nolint:funlen,cyclop // registration list — each line is a presence-gated collector
	cols := []collectors.Collector{
		collectors.NewCPUCollector(ctrCtx),
		collectors.NewMemoryCollector(ctrCtx),
		collectors.NewDiskCollector(ctrCtx),
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
		collectors.NewLogsCollectorWithProfile(profile),
		collectors.NewSecurityCollectorWithProfile(profile),
	}
	// SUSE-specific collectors — only on SUSE/openSUSE hosts
	if collectors.IsSUSEHost() {
		cols = append(cols, collectors.NewSnapperCollector())
	}
	// Subscription check — any enterprise Linux with a subscription manager
	if collectors.HasSubscriptionManager() {
		cols = append(cols, collectors.NewSUSEConnectCollector())
	}
	if includePackages && !includeDeep {
		// Fast package check — security advisory summary (no integrity scan)
		cols = append(cols, collectors.NewPackagesCollector())
	}
	cols = append(cols,
		collectors.NewThermalCollectorWithContext(ctrCtx.InContainer),
		collectors.NewBatteryCollector(),
		collectors.NewLaunchdCollector(),
		collectors.NewNVMeCollector(),
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
	// cloud-init — gate on the CLI / runtime status file (zero-cost otherwise).
	// Generic to every cloud-init platform, so gated independently of IsCloudInstance.
	if collectors.CloudInitAvailable() {
		cols = append(cols, collectors.NewCloudInitCollector())
	}
	// VMware guest config — gate on DMI vendor (silent on every non-VMware host).
	if collectors.VMwareGuestAvailable() {
		cols = append(cols, collectors.NewVMwareCollector())
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
	// Docker/Podman — gate on socket availability (no root required for detection).
	// Also include when Podman quadlets are present: those are systemd-managed and
	// invisible to the socket, so a socket-inactive quadlet host must still be checked.
	if sock, _ := collectors.DetectContainerSocket(); sock != "" || collectors.PodmanQuadletsPresent() {
		cols = append(cols, collectors.NewDockerCollectorWithProfile(profile))
	}
	// Containerd standalone — only when containerd socket is present AND no k8s layer.
	// When kubelet is active, dsd k8s already covers containerd via its OS-layer checks.
	if collectors.ContainerdAvailable() && !collectors.K8sAvailable() {
		cols = append(cols, collectors.NewContainerdCollector())
	}
	// Kubernetes — gate on kubectl/k3s availability
	if collectors.K8sAvailable() {
		cols = append(cols, collectors.NewK8sCollector())
	}
	// KVM/libvirt — gate on virsh availability
	if collectors.KVMAvailable() {
		cols = append(cols, collectors.NewKVMCollector())
	}
	// SteamOS / Steam Deck — gate on os-release (zero cost off-SteamOS)
	if collectors.SteamOSAvailable() {
		cols = append(cols, collectors.NewSteamOSCollector())
	}
	// Always collected — world-readable sysfs/proc paths
	cols = append(cols, collectors.NewHugePagesCollector())
	cols = append(cols, collectors.NewSessionsCollector())
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
		// Package integrity always included in deep mode (Spec 12):
		// dpkg --audit, dnf check, missing shared libs
		cols = append(cols, collectors.NewPackagesDeepCollector())
	}
	if includeFirmware {
		cols = append(cols, collectors.NewFirmwareCollector())
	}
	if includeCVE {
		cols = append(cols, collectors.NewCVEHealthCollector())
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

// printTopProcsWithCgroup shows top memory consumers with cgroup scope labels
// in dsd health deep output.
func printTopProcsWithCgroup(results []runner.Result, _ output.OutputMode) {
	for _, r := range results {
		deep, ok := r.Data.(*models.HealthDeepInfo)
		if !ok || deep == nil || len(deep.TopProcs) == 0 {
			continue
		}
		fmt.Printf("\n[Top processes — cgroup context]\n")
		fmt.Printf("  %-6s  %-5s  %-20s  %s\n", "PID", "MEM%", "NAME", "SCOPE")
		for _, p := range deep.TopProcs {
			scope := p.CgroupScope
			if scope == "" {
				scope = "unknown"
			}
			fmt.Printf("  %-6d  %4.1f%%  %-20s  %s\n",
				p.PID, p.MemPct, truncateStr(p.Name, 20), scope)
		}
		return
	}
}

// truncateStr truncates a string to at most n runes with an ellipsis. It slices
// by rune, not byte, so a multibyte character at the boundary is never split
// into invalid UTF-8.
func truncateStr(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// extractOOM type-asserts *models.OOMInfo from a runner results slice.
// Returns nil when the OOM collector was not included or returned an error.
func extractOOM(results []runner.Result) *models.OOMInfo {
	for _, r := range results {
		if r.Err == nil {
			if v, ok := r.Data.(*models.OOMInfo); ok {
				return v
			}
		}
	}
	return nil
}

// extractDocker type-asserts *models.DockerInfo from a runner results slice.
func extractDocker(results []runner.Result) *models.DockerInfo {
	for _, r := range results {
		if r.Err == nil {
			if v, ok := r.Data.(*models.DockerInfo); ok {
				return v
			}
		}
	}
	return nil
}

// extractIO type-asserts *models.IOInfo from a runner results slice.
// Returns nil when the IO collector was not included or returned an error.
func extractIO(results []runner.Result) *models.IOInfo {
	for _, r := range results {
		if r.Err == nil {
			if v, ok := r.Data.(*models.IOInfo); ok {
				return v
			}
		}
	}
	return nil
}

// extractSysctl type-asserts *models.SysctlInfo from a runner results slice.
// Returns nil when the Sysctl collector was not included or returned an error.
func extractSysctl(results []runner.Result) *models.SysctlInfo {
	for _, r := range results {
		if r.Err == nil {
			if v, ok := r.Data.(*models.SysctlInfo); ok {
				return v
			}
		}
	}
	return nil
}
