package cmd

import (
	"context"
	"fmt"
	"os"
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
	dockerCmd.Flags().Bool("deep", false, "deep mode: log driver config + container log file sizes")
}

var dockerCmd = &cobra.Command{
	Use:   "docker",
	Short: "Docker/Podman health — containers, images, volumes, disk usage",
	RunE:  runDocker,
}

func runDocker(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	deep, _ := cmd.Flags().GetBool("deep")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	col := collectors.Collector(collectors.NewDockerCollector())
	if deep {
		col = collectors.NewDockerDeepCollector()
	}

	p := output.NewCommandProgress("Docker health", 10*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{col}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.DockerInfo)
	if !ok || info == nil {
		return result.Err
	}

	recordResultSeverity([]runner.Result{result}) // BUG-022: honour 0/1/2 exit contract

	if mode == output.ModeJSON {
		return outputJSON(os.Stdout, info)
	}

	printDockerReport(info, mode, elapsed)
	return nil
}

func printDockerReport(info *models.DockerInfo, mode output.OutputMode, elapsed time.Duration) { //nolint:cyclop
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	if !info.Available {
		if info.StatusReason != "" {
			fmt.Printf("\n  %s  %s\n", asciiOr("warn", "⚠️ ", mode), info.StatusReason)
		} else {
			fmt.Printf("\n  %s  Docker/Podman not available on this system\n", asciiOr("info", "ℹ️ ", mode))
		}
		fmt.Println()
		fmt.Println(sep)
		fmt.Println(render.StyleOK.Render(asciiOr("ok", "✅", mode) + " No container runtime detected" + timing))
		return
	}

	fmt.Printf("\nRuntime: %s\n", info.Runtime)
	printDockerDaemon(info, mode)
	printDockerContainers(info, mode)
	printPodmanQuadlets(info, mode)
	printDockerSecurity(info, mode)
	printDockerEvents(info, mode)
	printDockerResources(info, mode)
	if info.LogDriver != nil {
		printDockerLogDriver(info.LogDriver, mode)
	}

	issues := info.UnhealthyCount + info.CrashLoopCount
	if info.StoppedCount > 0 && info.RunningCount == 0 {
		issues++
	}
	issues += info.OOMEvents
	for _, q := range info.PodmanQuadlets {
		if q.Failed {
			issues++
		}
	}
	if info.ContainersWithSecrets > 0 {
		issues++
	}
	if info.SocketMountedCount > 0 {
		issues++
	}

	fmt.Println()
	fmt.Println(sep)
	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("%s Docker healthy. Checks passed%s", asciiOr("ok", "✅", mode), timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("%s %d container concern(s) found%s", asciiOr("warn", "⚠️ ", mode), issues, timing)))
	}
}

func printDockerDaemon(info *models.DockerInfo, mode output.OutputMode) {
	d := info.Daemon
	if d == nil {
		return
	}
	verStr := ""
	if d.Version != "" {
		verStr = d.Version
		if d.APIVersion != "" {
			verStr += fmt.Sprintf(" (API %s)", d.APIVersion)
		}
	}
	driverStr := ""
	if d.StorageDriver != "" {
		icon := asciiOr("ok", "✅", mode)
		if d.StorageDriver == "devicemapper" {
			icon = asciiOr("warn", "⚠️ ", mode)
		}
		// normalise: "overlayfs" → "overlay2" display
		driver := d.StorageDriver
		if driver == "overlayfs" {
			driver = "overlay"
		}
		driverStr = fmt.Sprintf("  %s Storage: %s", icon, driver)
	}
	fmt.Printf("\n[Daemon]  version: %s%s\n", verStr, driverStr)
	// Compose (Spec 7d)
	switch {
	case d.ComposePlugin != "" && d.ComposeStandalone != "":
		fmt.Printf("  %s  Compose: v%s (plugin) + v%s (standalone) — both present\n",
			asciiOr("warn", "⚠️ ", mode), d.ComposePlugin, d.ComposeStandalone)
	case d.ComposePlugin != "":
		fmt.Printf("  %s  Compose: v%s (plugin)\n", asciiOr("ok", "✅", mode), d.ComposePlugin)
	case d.ComposeStandalone != "":
		fmt.Printf("  %s  Compose: v%s (standalone — deprecated)\n", asciiOr("warn", "⚠️ ", mode), d.ComposeStandalone)
	default:
		fmt.Printf("  %s  Compose: not installed\n", asciiOr("info", "ℹ️ ", mode))
	}
	if d.RecentErrors > 0 {
		fmt.Printf("  %s  %d error(s) in last 10m", asciiOr("warn", "⚠️ ", mode), d.RecentErrors)
		if d.LastDaemonError != "" {
			fmt.Printf(": %s", d.LastDaemonError)
		}
		fmt.Println()
		fmt.Println("     → journalctl -u docker -n 50 --no-pager")
	}
	// Swarm mode (Spec 7j) — INFO only when active, silent otherwise
	if d.SwarmState == "active" {
		role := d.SwarmRole
		if role == "" {
			role = "node"
		}
		fmt.Printf("  %s  Swarm mode: active (role: %s)\n", asciiOr("info", "ℹ️ ", mode), role)
		fmt.Println("     Container restarts and placement may be controlled by the Swarm scheduler.")
		fmt.Println("     → docker node ls")
		fmt.Println("     → docker service ps <svc>")
	}
}

func printDockerContainers(info *models.DockerInfo, mode output.OutputMode) {
	fmt.Printf("\nContainers (%d total)\n", info.TotalContainers)
	if info.TotalContainers == 0 {
		fmt.Printf("  %s  no containers\n", asciiOr("ok", "✅", mode))
		return
	}
	runIcon := asciiOr("ok", "✅", mode)
	if info.RunningCount == 0 {
		runIcon = asciiOr("warn", "⚠️ ", mode)
	}
	fmt.Printf("  %s  running:   %d\n", runIcon, info.RunningCount)
	if info.StoppedCount > 0 {
		fmt.Printf("  %s  stopped:   %d\n", asciiOr("warn", "⚠️ ", mode), info.StoppedCount)
	}
	if info.UnhealthyCount > 0 {
		fmt.Printf("  %s  unhealthy: %d\n", asciiOr("fail", "❌", mode), info.UnhealthyCount)
	}
	if info.CrashLoopCount > 0 {
		fmt.Printf("  %s  crash loop: %d\n", asciiOr("fail", "❌", mode), info.CrashLoopCount)
	}
	if len(info.Containers) == 0 {
		return
	}
	fmt.Println()
	for _, c := range info.Containers {
		icon := asciiOr("ok", "✅", mode)
		if c.State != "running" {
			icon = asciiOr("warn", "⚠️ ", mode)
		}
		if c.Health == "unhealthy" || c.Restart >= crashLoopRestartThreshold {
			icon = asciiOr("fail", "❌", mode)
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

// printPodmanQuadlets renders systemd-managed Podman containers/pods.
// Only shown when quadlet files were found (Podman hosts). Zero output on
// Docker hosts or when no quadlet files exist.
func printPodmanQuadlets(info *models.DockerInfo, mode output.OutputMode) {
	if len(info.PodmanQuadlets) == 0 {
		return
	}
	fmt.Printf("\n[Podman quadlets]\n")

	// All active → single summary line, no noise.
	allActive := true
	for _, q := range info.PodmanQuadlets {
		if !q.Active {
			allActive = false
			break
		}
	}
	if allActive {
		fmt.Printf("  %s %d quadlet(s) active\n", asciiOr("ok", "✅", mode), len(info.PodmanQuadlets))
		return
	}

	for _, q := range info.PodmanQuadlets {
		icon := asciiOr("ok", "✅", mode)
		if !q.Active {
			icon = asciiOr("warn", "⚠️ ", mode)
		}
		if q.Failed {
			icon = asciiOr("fail", "❌", mode)
		}
		state := q.State
		if state == "" {
			state = "unknown"
		}
		fmt.Printf("  %s  %-14s %-9s %s\n", icon, q.Name, state, q.ServiceUnit)
		if q.Failed {
			fmt.Printf("     → systemctl status %s\n", q.ServiceUnit)
			fmt.Printf("     → journalctl -u %s -n 20\n", q.ServiceUnit)
		}
	}
}

func printDockerSecurity(info *models.DockerInfo, mode output.OutputMode) {
	hasIssues := info.ContainersWithSecrets > 0 || info.SocketMountedCount > 0 || info.RunningAsRootCount > 0
	if !hasIssues {
		return
	}
	fmt.Printf("\n[Security]\n")

	// Plaintext secrets
	for _, c := range info.Containers {
		if len(c.PlaintextSecrets) > 0 {
			fmt.Printf("  %s  %-20s plaintext secrets in env: %s\n",
				asciiOr("warn", "⚠️ ", mode), c.Name, strings.Join(c.PlaintextSecrets, ", "))
		}
	}
	if info.ContainersWithSecrets > 0 {
		fmt.Println("     Env vars visible in 'docker inspect' — use Docker secrets or a vault.")
	}

	// Docker socket mounted
	for _, c := range info.Containers {
		if c.DockerSocketMounted {
			fmt.Printf("  %s  %-20s docker socket mounted — grants root access to host\n", asciiOr("fail", "❌", mode), c.Name)
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
		fmt.Printf("  %s  %d running container(s) using root user\n", asciiOr("warn", "⚠️ ", mode), rootCount)
		fmt.Println("     → Add USER directive to Dockerfile or use --user flag.")
	}
}

func printDockerEvents(info *models.DockerInfo, mode output.OutputMode) {
	if len(info.RecentEvents) == 0 {
		return
	}
	fmt.Printf("\n[Recent events — last 1h]\n")
	for _, ev := range info.RecentEvents {
		evIcon := asciiOr("warn", "⚠️ ", mode)
		if ev.Action == "oom" {
			evIcon = asciiOr("fail", "❌", mode)
		}
		fmt.Printf("  %s  %-8s  %s\n", evIcon, ev.Action, ev.Actor)
	}
	if info.OOMEvents > 0 {
		fmt.Printf("  → %d OOM kill(s) — check container memory limits\n", info.OOMEvents)
	}
}

func printDockerResources(info *models.DockerInfo, mode output.OutputMode) {
	fmt.Printf("\nImages: %d", info.ImagesCount)
	if info.DanglingImages > 0 {
		fmt.Printf("  %s %d dangling", asciiOr("warn", "⚠️ ", mode), info.DanglingImages)
	}
	fmt.Println()
	if info.VolumesCount > 0 {
		fmt.Printf("Volumes: %d\n", info.VolumesCount)
	}
	if info.DiskUsageGB > 0 {
		diskIcon := asciiOr("ok", "✅", mode)
		if info.DiskUsageGB > 20 {
			diskIcon = asciiOr("warn", "⚠️ ", mode)
		}
		fmt.Printf("Disk usage: %s %.1f GB\n", diskIcon, info.DiskUsageGB)
	}
}

func printDockerLogDriver(ld *models.DockerLogDriverInfo, mode output.OutputMode) {
	if ld.Driver == "journald" || ld.Driver == "local" {
		fmt.Printf("\n[Log driver]  %s (managed/bounded) %s\n", ld.Driver, asciiOr("ok", "✅", mode))
		return
	}
	// json-file — check if bounded
	icon := asciiOr("warn", "⚠️ ", mode)
	status := "json-file — no max-size (logs grow unbounded)"
	if ld.MaxSizeSet && ld.MaxFileSet {
		icon = asciiOr("ok", "✅", mode)
		status = "json-file (max-size and max-file set)"
	} else if ld.MaxSizeSet {
		icon = asciiOr("ok", "✅", mode)
		status = "json-file (max-size set, max-file not set)"
	}
	fmt.Printf("\n[Log driver]  %s %s\n", icon, status)
	if !ld.MaxSizeSet {
		fmt.Println(`  → Add to /etc/docker/daemon.json:`)
		fmt.Println(`    {"log-driver":"json-file","log-opts":{"max-size":"100m","max-file":"3"}}`)
		fmt.Println("  → systemctl restart docker")
	}

	// Container log file sizes
	hasLarge := false
	for _, cl := range ld.ContainerLogs {
		if cl.SizeMB >= 500 {
			hasLarge = true
			icon := asciiOr("warn", "⚠️ ", mode)
			if cl.SizeMB >= 1024 {
				icon = asciiOr("fail", "❌", mode)
			}
			fmt.Printf("  %s %-20s  %.0f MB\n", icon, cl.Name, cl.SizeMB)
		}
	}
	if hasLarge {
		fmt.Println("  → truncate large log: truncate -s 0 /var/lib/docker/containers/<id>/<id>-json.log")
	}
}
