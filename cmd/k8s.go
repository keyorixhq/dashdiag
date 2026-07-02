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

	// Nodes
	fmt.Printf("\nNodes (%d)\n", len(info.Nodes))
	for _, n := range info.Nodes {
		icon := asciiOr("ok", "✅", mode)
		if n.Status != "Ready" {
			icon = asciiOr("fail", "❌", mode)
		}
		fmt.Printf("  %s  %-35s %-14s %-20s %s\n",
			icon, n.Name, n.Status, n.Roles, n.Version)
	}

	// Pods summary
	total := len(info.Pods)
	running := 0
	for _, p := range info.Pods {
		if p.Status == "Running" || p.Status == "Completed" || p.Status == "Succeeded" {
			running++
		}
	}

	fmt.Printf("\nPods (%d total, %d healthy)\n", total, running)

	// Show only unhealthy pods + high-restart pods
	var problemPods []models.K8sPodInfo
	for _, p := range info.Pods {
		// 0/1 Running = container not ready
		notReady := strings.HasPrefix(p.Ready, "0/") && p.Status == "Running"
		isBad := strings.Contains(p.Status, "CrashLoop") ||
			strings.Contains(p.Status, "Error") ||
			p.Status == "Pending" ||
			p.Status == "OOMKilled" ||
			p.Restarts >= 10 ||
			notReady
		if isBad {
			problemPods = append(problemPods, p)
		}
	}

	if len(problemPods) == 0 {
		fmt.Println("  " + asciiOr("ok", "✅", mode) + "  All pods healthy")
	} else {
		fmt.Printf("  %s  %d pod(s) need attention:\n", asciiOr("warn", "⚠️ ", mode), len(problemPods))
		fmt.Printf("  %-20s %-42s %-22s %-8s %s\n",
			"NAMESPACE", "NAME", "STATUS", "RESTARTS", "AGE")
		for _, p := range problemPods {
			icon := asciiOr("warn", "⚠️ ", mode)
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

	// All pods table
	fmt.Printf("\nAll Pods:\n")
	fmt.Printf("  %-20s %-42s %-8s %-22s %-8s %s\n",
		"NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "AGE")
	for _, p := range info.Pods {
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
func k8sHasConcern(info *models.K8sInfo) bool {
	issues := info.NodesNotReady + info.CrashLooping + info.Pending + info.PodsNotReady +
		info.WorkloadsDown + info.PVCsNotBound + len(info.Events)
	return issues > 0 || info.HighRestarts > 0 || len(k8sOSLayerInsights(info)) > 0
}

// printK8sOSLayer renders each OS-layer insight as a line, exactly mirroring what
// `dsd health --deep` would report for the same node — so a down kubelet/expired
// cert/disabled ip_forward can never print "✅ Cluster healthy" here while
// CRITing in dsd health.
func printK8sOSLayer(l models.K8sOSLayer, mode output.OutputMode) {
	insights := analysis.CheckK8sOSLayer(l)
	if len(insights) == 0 {
		fmt.Println("  " + asciiOr("ok", "✅", mode) + "  No OS-layer issues")
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
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("%s Cluster healthy. Checks passed%s", asciiOr("ok", "✅", mode), timing)))
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
	fmt.Println(render.StyleWarn.Render(fmt.Sprintf("%s %s%s", asciiOr("warn", "⚠️ ", mode), strings.Join(parts, ", "), timing)))
}
