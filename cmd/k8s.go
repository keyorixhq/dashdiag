package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(k8sCmd)
	k8sCmd.Flags().Bool("deep", false, "deep mode: OS-layer checks (kubelet, CNI, iptables, certs)")
}

var k8sCmd = &cobra.Command{
	Use:   "k8s",
	Short: "Kubernetes health — nodes, pods, restarts, crash loops",
	RunE:  runK8s,
}

func runK8s(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	p := output.NewCommandProgress("Kubernetes health", 15*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	deepFlag, _ := cmd.Flags().GetBool("deep")
	col := collectors.Collector(collectors.NewK8sCollector())
	if deepFlag {
		col = collectors.NewK8sDeepCollector()
	}
	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{col}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.K8sInfo)
	if !ok || info == nil {
		return result.Err
	}

	recordResultSeverity([]runner.Result{result}) // BUG-022: honour 0/1/2 exit contract

	if mode == output.ModeJSON {
		return outputJSON(os.Stdout, info)
	}

	printK8sReport(info, mode, elapsed)
	return nil
}

func printK8sReport(info *models.K8sInfo, mode output.OutputMode, elapsed time.Duration) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	if !info.Detected {
		fmt.Println("\nNo Kubernetes installation detected on this host.")
		fmt.Println()
		fmt.Println(sep)
		fmt.Println(render.StyleInfo.Render(asciiOr("info", "ℹ️  ", mode) + "kubectl / k3s not found in PATH"))
		return
	}

	// kubectl/k3s present but no cluster query succeeded (API down, bad kubeconfig,
	// insufficient RBAC). Every count is 0 because the cluster was never reached —
	// don't render that as "✅ Cluster healthy" (false-OK). Mirrors the health
	// heuristic (checkK8s → "cluster API was unreachable — health NOT verified").
	if !info.APIReachable {
		fmt.Printf("\nKubernetes Health  (via %s)\n", info.KubeBin)
		fmt.Println()
		fmt.Println(sep)
		fmt.Println(render.StyleInfo.Render(asciiOr("info", "ℹ️  ", mode) +
			" cluster API unreachable — cluster health NOT verified (check: kubectl get nodes; kubeconfig/RBAC/API server up?)"))
		return
	}

	fmt.Printf("\nKubernetes Health  (via %s)\n", info.KubeBin)

	printK8sNodes(info.Nodes, mode)
	printK8sPodsOverview(info.Pods, mode)
	printK8sAllPodsTable(info.Pods, mode)

	// OS layer (only populated by `dsd k8s --deep`)
	if info.OSLayer != nil {
		fmt.Printf("\n[OS layer]\n")
		printK8sOSLayer(*info.OSLayer, mode)
	}

	// Summary
	fmt.Println()
	fmt.Println(sep)
	printK8sSummary(info, timing, mode)
}

func printK8sNodes(nodes []models.K8sNodeInfo, mode output.OutputMode) {
	fmt.Printf("\nNodes (%d)\n", len(nodes))
	for _, n := range nodes {
		icon := asciiOr("ok", iconOK, mode)
		if n.Status != "Ready" {
			icon = asciiOr("fail", "❌", mode)
		}
		fmt.Printf("  %s  %-35s %-14s %-20s %s\n",
			icon, n.Name, n.Status, n.Roles, n.Version)
	}
}

// k8sPodNeedsAttention reports whether a pod belongs in the "problem pods"
// callout — crash-looping, erroring, stuck pending, OOM-killed, high-restart,
// or reporting 0 ready containers while marked Running.
func k8sPodNeedsAttention(p models.K8sPodInfo) bool {
	notReady := strings.HasPrefix(p.Ready, "0/") && p.Status == "Running"
	return strings.Contains(p.Status, "CrashLoop") ||
		strings.Contains(p.Status, "Error") ||
		p.Status == "Pending" ||
		p.Status == "OOMKilled" ||
		p.Status == "Unknown" ||
		p.Restarts >= 10 ||
		notReady
}

func printK8sPodsOverview(pods []models.K8sPodInfo, mode output.OutputMode) {
	running := 0
	var problemPods []models.K8sPodInfo
	for _, p := range pods {
		if p.Status == "Running" || p.Status == "Completed" || p.Status == "Succeeded" {
			running++
		}
		if k8sPodNeedsAttention(p) {
			problemPods = append(problemPods, p)
		}
	}

	fmt.Printf("\nPods (%d total, %d healthy)\n", len(pods), running)

	if len(problemPods) == 0 {
		fmt.Println("  " + asciiOr("ok", iconOK, mode) + "  All pods healthy")
		return
	}

	fmt.Printf("  %s  %d pod(s) need attention:\n", asciiOr("warn", iconWarnSp, mode), len(problemPods))
	fmt.Printf("  %-20s %-42s %-22s %-8s %s\n",
		"NAMESPACE", "NAME", "STATUS", "RESTARTS", "AGE")
	for _, p := range problemPods {
		icon := asciiOr("warn", iconWarnSp, mode)
		if strings.Contains(p.Status, "CrashLoop") || strings.Contains(p.Status, "Error") {
			icon = asciiOr("fail", "❌", mode)
		}
		name := p.Name
		if len(name) > 40 {
			name = name[:37] + "..."
		}
		fmt.Printf("  %s %-20s %-42s %-22s %-8d %s\n",
			icon, p.Namespace, name, p.Status, p.Restarts, p.Age)
	}
}

func printK8sAllPodsTable(pods []models.K8sPodInfo, mode output.OutputMode) {
	fmt.Printf("\nAll Pods:\n")
	fmt.Printf("  %-20s %-42s %-8s %-22s %-8s %s\n",
		"NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "AGE")
	for _, p := range pods {
		restartIcon := ""
		if p.Restarts >= 10 {
			restartIcon = " " + asciiOr("warn", "⚠️", mode)
		}
		name := p.Name
		if len(name) > 40 {
			name = name[:37] + "..."
		}
		fmt.Printf("  %-20s %-42s %-8s %-22s %-6d%s %s\n",
			p.Namespace, name, p.Ready, p.Status, p.Restarts, restartIcon, p.Age)
	}
}

// k8sOSLayerInsights runs the node's OS-layer facts through the EXACT heuristic
// `dsd health` uses on the same data (analysis.CheckK8sOSLayer), rather than
// re-deriving the concern conditions by hand in cmd/ — the fix for the
// cmd↔health tally-drift class (#275): a hand-duplicated condition here would
// silently rot out of sync with the shared heuristic. nil OSLayer (fast mode,
// or --deep off a k8s node) yields no insights.
func k8sOSLayerInsights(info *models.K8sInfo) []models.Insight {
	if info.OSLayer == nil {
		return nil
	}
	return analysis.CheckK8sOSLayer(*info.OSLayer)
}

// k8sHasConcern reports whether the standalone `dsd k8s` verdict flags a problem,
// kept as one pure function so it can't drift from `dsd health`'s k8s heuristics
// (the sibling-divergence class, #275 — WorkloadsDown/PVCsNotBound/Events must
// count). Pinned by the cmd↔health consistency test (cmd_health_consistency_test.go).
//
// OS-layer insights only count as a concern at WARN/CRIT, never INFO — the same
// "INFO never raises the verdict" convention `dsd health` follows everywhere else
// (exitCodeFromInsights, healthHasConcern in the consistency test). Checking
// len(...) > 0 here used to silently disagree with that convention; it just never
// surfaced because K8sOSLayer rarely emitted a bare INFO. It does now
// (checkK8sOSLayerCoverageGaps discloses KubeForwardChecked/CNIChecked=false), which
// is what caught this.
func k8sHasConcern(info *models.K8sInfo) bool {
	issues := info.NodesNotReady + info.CrashLooping + info.Pending + info.PodsNotReady +
		info.UnknownStatus + info.WorkloadsDown + info.PVCsNotBound + len(info.Events)
	if issues > 0 || info.HighRestarts > 0 {
		return true
	}
	for _, ins := range k8sOSLayerInsights(info) {
		if ins.Level == "WARN" || ins.Level == "CRIT" {
			return true
		}
	}
	return false
}

// printK8sOSLayer renders each OS-layer insight as a line, exactly mirroring what
// `dsd health --deep` would report for the same node — so a down kubelet/expired
// cert/disabled ip_forward can never print "✅ Cluster healthy" here while
// CRITing in dsd health.
func printK8sOSLayer(l models.K8sOSLayer, mode output.OutputMode) {
	insights := analysis.CheckK8sOSLayer(l)
	if len(insights) == 0 {
		fmt.Println("  " + asciiOr("ok", iconOK, mode) + "  No OS-layer issues")
		return
	}
	for _, ins := range insights {
		statusKey := "info"
		switch ins.Level {
		case "CRIT":
			statusKey = "fail"
		case "WARN":
			statusKey = "warn"
		}
		fmt.Printf("  %s  %s\n", output.StatusIcon(statusKey, mode), ins.Message)
	}
}

func printK8sSummary(info *models.K8sInfo, timing string, mode output.OutputMode) {
	if !k8sHasConcern(info) {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("%s Cluster healthy. Checks passed%s", asciiOr("ok", iconOK, mode), timing)))
		return
	}
	var parts []string
	if info.NodesNotReady > 0 {
		parts = append(parts, fmt.Sprintf("%d node(s) not ready", info.NodesNotReady))
	}
	if info.CrashLooping > 0 {
		parts = append(parts, fmt.Sprintf("%d pod(s) crash looping", info.CrashLooping))
	}
	if info.PodsNotReady > 0 {
		parts = append(parts, fmt.Sprintf("%d pod(s) not ready", info.PodsNotReady))
	}
	if info.Pending > 0 {
		parts = append(parts, fmt.Sprintf("%d pod(s) pending", info.Pending))
	}
	if info.UnknownStatus > 0 {
		parts = append(parts, fmt.Sprintf("%d pod(s) unknown status", info.UnknownStatus))
	}
	if info.HighRestarts > 0 {
		parts = append(parts, fmt.Sprintf("%d pod(s) high restarts", info.HighRestarts))
	}
	if info.WorkloadsDown > 0 {
		parts = append(parts, fmt.Sprintf("%d workload(s) degraded", info.WorkloadsDown))
	}
	if info.PVCsNotBound > 0 {
		parts = append(parts, fmt.Sprintf("%d PVC(s) not bound", info.PVCsNotBound))
	}
	if len(info.Events) > 0 {
		parts = append(parts, fmt.Sprintf("%d warning event(s)", len(info.Events)))
	}
	if osIssues := len(k8sOSLayerInsights(info)); osIssues > 0 {
		parts = append(parts, fmt.Sprintf("%d OS-layer issue(s)", osIssues))
	}
	fmt.Println(render.StyleWarn.Render(fmt.Sprintf("%s %s%s", asciiOr("warn", iconWarnSp, mode), strings.Join(parts, ", "), timing)))
}
