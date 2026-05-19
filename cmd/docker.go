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

const crashLoopRestartThreshold = 5

func init() {
	rootCmd.AddCommand(dockerCmd)
}

var dockerCmd = &cobra.Command{
	Use:   "docker",
	Short: "Docker/Podman health — containers, images, volumes, disk usage",
	RunE:  runDocker,
}

func runDocker(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	mode := output.DetectMode(plain, false, "")

	p := output.NewCommandProgress("Docker health", 10*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewDockerCollector()}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.DockerInfo)
	if !ok || info == nil {
		return result.Err
	}

	printDockerReport(info, mode, elapsed)
	return nil
}

func printDockerReport(info *models.DockerInfo, mode output.OutputMode, elapsed time.Duration) { //nolint:cyclop
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	if !info.Available {
		if info.StatusReason != "" {
			fmt.Printf("\n  ⚠️   %s\n", info.StatusReason)
		} else {
			fmt.Println("\n  ℹ️   Docker/Podman not available on this system")
		}
		fmt.Println()
		fmt.Println(sep)
		fmt.Println(render.StyleOK.Render("✅ No container runtime detected" + timing))
		return
	}

	fmt.Printf("\nRuntime: %s\n", info.Runtime)
	printDockerContainers(info)
	printDockerSecurity(info)
	printDockerEvents(info)
	printDockerResources(info)

	issues := info.UnhealthyCount + info.CrashLoopCount
	if info.StoppedCount > 0 && info.RunningCount == 0 {
		issues++
	}
	issues += info.OOMEvents
	if info.ContainersWithSecrets > 0 {
		issues++
	}
	if info.SocketMountedCount > 0 {
		issues++
	}

	fmt.Println()
	fmt.Println(sep)
	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("✅ Docker healthy. Checks passed%s", timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("⚠️  %d container concern(s) found%s", issues, timing)))
	}
}

func printDockerContainers(info *models.DockerInfo) {
	fmt.Printf("\nContainers (%d total)\n", info.TotalContainers)
	if info.TotalContainers == 0 {
		fmt.Println("  ✅  no containers")
		return
	}
	runIcon := "✅"
	if info.RunningCount == 0 {
		runIcon = "⚠️ "
	}
	fmt.Printf("  %s  running:   %d\n", runIcon, info.RunningCount)
	if info.StoppedCount > 0 {
		fmt.Printf("  ⚠️   stopped:   %d\n", info.StoppedCount)
	}
	if info.UnhealthyCount > 0 {
		fmt.Printf("  ❌  unhealthy: %d\n", info.UnhealthyCount)
	}
	if info.CrashLoopCount > 0 {
		fmt.Printf("  ❌  crash loop: %d\n", info.CrashLoopCount)
	}
	if len(info.Containers) == 0 {
		return
	}
	fmt.Println()
	for _, c := range info.Containers {
		icon := "✅"
		if c.State != "running" {
			icon = "⚠️ "
		}
		if c.Health == "unhealthy" || c.Restart >= crashLoopRestartThreshold {
			icon = "❌"
		}
		health := ""
		if c.Health != "" && c.Health != "none" {
			health = fmt.Sprintf(" [%s]", c.Health)
		}
		restarts := ""
		if c.Restart > 0 {
			restarts = fmt.Sprintf(" restarts:%d", c.Restart)
		}
		exitStr := ""
		if c.ExitCode != 0 {
			exitStr = fmt.Sprintf(" exit:%d", c.ExitCode)
			if c.ExitLabel != "" {
				exitStr = fmt.Sprintf(" exit:%d (%s)", c.ExitCode, c.ExitLabel)
			}
		}
		fmt.Printf("  %s  %-20s %-12s %s%s%s%s\n",
			icon, c.Name, c.State, c.Image, health, restarts, exitStr)
	}
}

func printDockerSecurity(info *models.DockerInfo) {
	hasIssues := info.ContainersWithSecrets > 0 || info.SocketMountedCount > 0 || info.RunningAsRootCount > 0
	if !hasIssues {
		return
	}
	fmt.Printf("\n[Security]\n")

	// Plaintext secrets
	for _, c := range info.Containers {
		if len(c.PlaintextSecrets) > 0 {
			fmt.Printf("  ⚠️   %-20s plaintext secrets in env: %s\n",
				c.Name, strings.Join(c.PlaintextSecrets, ", "))
		}
	}
	if info.ContainersWithSecrets > 0 {
		fmt.Println("     Env vars visible in 'docker inspect' — use Docker secrets or a vault.")
	}

	// Docker socket mounted
	for _, c := range info.Containers {
		if c.DockerSocketMounted {
			fmt.Printf("  ❌  %-20s docker socket mounted — grants root access to host\n", c.Name)
		}
	}
	if info.SocketMountedCount > 0 {
		fmt.Println("     → Remove socket mount unless this is an intentional CI/Docker agent.")
	}

	// Running as root
	rootCount := 0
	for _, c := range info.Containers {
		if c.RunsAsRoot && c.State == "running" {
			rootCount++
		}
	}
	if rootCount > 0 {
		fmt.Printf("  ⚠️   %d running container(s) using root user\n", rootCount)
		fmt.Println("     → Add USER directive to Dockerfile or use --user flag.")
	}
}

func printDockerEvents(info *models.DockerInfo) {
	if len(info.RecentEvents) == 0 {
		return
	}
	fmt.Printf("\n[Recent events — last 1h]\n")
	for _, ev := range info.RecentEvents {
		evIcon := "⚠️ "
		if ev.Action == "oom" {
			evIcon = "❌"
		}
		fmt.Printf("  %s  %-8s  %s\n", evIcon, ev.Action, ev.Actor)
	}
	if info.OOMEvents > 0 {
		fmt.Printf("  → %d OOM kill(s) — check container memory limits\n", info.OOMEvents)
	}
}

func printDockerResources(info *models.DockerInfo) {
	fmt.Printf("\nImages: %d", info.ImagesCount)
	if info.DanglingImages > 0 {
		fmt.Printf("  ⚠️  %d dangling", info.DanglingImages)
	}
	fmt.Println()
	if info.VolumesCount > 0 {
		fmt.Printf("Volumes: %d\n", info.VolumesCount)
	}
	if info.DiskUsageGB > 0 {
		diskIcon := "✅"
		if info.DiskUsageGB > 20 {
			diskIcon = "⚠️ "
		}
		fmt.Printf("Disk usage: %s %.1f GB\n", diskIcon, info.DiskUsageGB)
	}
}
