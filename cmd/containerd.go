package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(containerdCmd)
}

var containerdCmd = &cobra.Command{
	Use:   "containerd",
	Short: "Standalone containerd health — socket, service state, version, namespaces, container counts (~5s)",
	RunE:  runContainerd,
}

func runContainerd(cmd *cobra.Command, _ []string) error {
	// No containerd socket at all → "not detected" INFO, exit 0 (mirrors dsd kvm/k8s
	// on an absent runtime). runDiagnostic's heuristic (checkContainerd) WARNs on an
	// unreachable socket — correct in `dsd health`, which only runs that check when
	// the socket EXISTS, but a false alarm here where containerd is simply not
	// installed. So short-circuit before the gating pipeline.
	if !collectors.ContainerdAvailable() {
		plain, _ := cmd.Flags().GetBool("plain")
		jsonOut, _ := cmd.Flags().GetBool("json")
		outputFmt := ""
		if jsonOut {
			outputFmt = "json"
		}
		mode := output.DetectMode(plain, false, outputFmt)

		// containerd IS running but managed by a Kubernetes distro (k3s/RKE2) at a
		// bundle socket — don't say "not detected" (a false negative). Point the user
		// at `dsd k8s`, which covers this runtime via its OS-layer checks.
		status, reason, line := "not-detected",
			"containerd socket not found — not installed or not running",
			"containerd not detected — socket not found (not installed or not running)"
		if collectors.ContainerdK8sManaged() {
			status = "k8s-managed"
			reason = "containerd is running but Kubernetes-managed (k3s/RKE2) — run `dsd k8s` for workload health"
			line = "containerd is running but Kubernetes-managed (k3s/RKE2) — run `dsd k8s` for workload health"
		}

		if mode == output.ModeJSON {
			return outputJSON(os.Stdout, &models.ContainerdInfo{
				Available: false, Status: status, StatusReason: reason,
			})
		}
		fmt.Println()
		fmt.Println(render.StyleInfo.Render(asciiOr("info", "ℹ️  ", mode) + line))
		return nil
	}

	return runDiagnostic(cmd, diagnostic{
		label:   "Containerd health",
		timeout: 10 * time.Second,
		cols:    []runner.Collector{collectors.NewContainerdCollector()},
		jsonValue: func(r []runner.Result) (any, error) {
			info := resultData[*models.ContainerdInfo](r)
			if info == nil {
				return nil, firstErr(r)
			}
			return info, nil
		},
		render: func(r []runner.Result, mode output.OutputMode, _ time.Duration) error {
			info := resultData[*models.ContainerdInfo](r)
			if info == nil {
				return firstErr(r)
			}
			printContainerd(info, mode)
			return nil
		},
	})
}

func printContainerd(info *models.ContainerdInfo, mode output.OutputMode) {
	if mode == output.ModeHuman {
		fmt.Fprintln(os.Stdout, "\n📦  Containerd")
	}

	// Not connectable: either containerd isn't installed/running, or the socket
	// couldn't be read (e.g. needs root). Report the reason as INFO, never a green OK.
	if !info.Available {
		reason := info.StatusReason
		if reason == "" {
			reason = "containerd socket not found — not installed or not running"
		}
		printLine(mode, "info", "Containerd", reason)
		return
	}

	if info.SocketPath != "" {
		printLine(mode, "ok", "Socket", info.SocketPath)
	}
	switch info.ServiceState {
	case "active":
		printLine(mode, "ok", "Service", "active")
	case "failed":
		printLine(mode, "warn", "Service", "failed")
	case "", "unknown":
		printLine(mode, "info", "Service", "state unknown")
	default:
		printLine(mode, "info", "Service", info.ServiceState)
	}
	if info.Version != "" {
		printLine(mode, "ok", "Version", info.Version)
	}
	printLine(mode, "ok", "Containers",
		fmt.Sprintf("%d across %d namespace(s)", info.TotalContainers, len(info.Namespaces)))
	for _, ns := range info.Namespaces {
		fmt.Printf("     %-20s %d container(s)\n", ns.Name, ns.ContainerCount)
	}
}
