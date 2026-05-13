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

	// Container summary
	fmt.Printf("\nContainers (%d total)\n", info.TotalContainers)
	if info.TotalContainers == 0 {
		fmt.Println("  ✅  no containers")
	} else {
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
	}

	// Container list
	if len(info.Containers) > 0 {
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
			fmt.Printf("  %s  %-20s %-12s %s%s%s\n",
				icon, c.Name, c.State, c.Image, health, restarts)
		}
	}

	// Images & volumes
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

	// Summary
	issues := info.UnhealthyCount + info.CrashLoopCount
	if info.StoppedCount > 0 && info.RunningCount == 0 {
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
