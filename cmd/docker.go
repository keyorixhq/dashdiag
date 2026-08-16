//go:build linux || darwin

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

// dockerConcerns counts the actionable issues in the standalone `dsd docker`
// verdict, kept as one pure function so it can't drift from `dsd health`'s docker
// heuristics (the sibling-divergence class, #275 — e.g. root-user containers,
// which checkDockerSecurity WARNs on, must count). Pinned by the cmd↔health
// consistency test (cmd_health_consistency_test.go).
func dockerConcerns(info *models.DockerInfo) int {
	issues := info.UnhealthyCount + info.CrashLoopCount
	// Daemon reachable but containers couldn't be listed — never read as healthy
	// (matches checkDocker, which WARNs on Status=="error").
	if info.Status == "error" {
		issues++
	}
	// NOTE: "containers present but all stopped" is NOT counted — a stopped container
	// is a state, not a fault (it may be intentionally stopped), and a container that
	// died badly is already caught by UnhealthyCount / CrashLooping / exit-code checks.
	// checkDocker (health) has no all-stopped rule either; counting it here made
	// `dsd docker` report a concern while `dsd health` stayed clean (#275 class, BUG-089).
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
	// Root-user containers — matches checkDockerSecurity (WARN), which the
	// standalone verdict previously ignored.
	if info.RunningAsRootCount > 0 {
		issues++
	}
	// Log driver (deep-only) — matches checkDocker, which WARNs on either signal.
	// Without this, `dsd docker --deep` could render red [Log driver] rows under
	// a green "✅ Docker healthy" summary.
	if info.LogDriver != nil {
		if len(info.LogDriver.UnboundedContainers) > 0 {
			issues++
		}
		if info.LogDriver.LargeLogCount > 0 {
			issues++
		}
	}
	return issues
}

func printDockerReport(info *models.DockerInfo, mode output.OutputMode, elapsed time.Duration) { //nolint:cyclop // NOSONAR — flat display renderer — each branch is a distinct display condition
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	if !info.Available {
		// A StatusReason means a runtime IS installed but unusable (e.g. "Docker
		// installed but daemon not running"). Don't then print "No container runtime
		// detected" — that flatly contradicts "installed". Only the truly-nothing case
		// gets the green "no runtime" verdict.
		if info.StatusReason != "" {
			fmt.Printf("\n  %s  %s\n", asciiOr("warn", iconWarnSp, mode), info.StatusReason)
			fmt.Println()
			fmt.Println(sep)
			fmt.Println(render.StyleWarn.Render(asciiOr("warn", iconWarnSp, mode) + " Container runtime installed but not running" + timing))
			return
		}
		fmt.Printf("\n  %s  Docker/Podman not available on this system\n", asciiOr("info", iconInfoSp, mode))
		fmt.Println()
		fmt.Println(sep)
		fmt.Println(render.StyleOK.Render(asciiOr("ok", iconOK, mode) + " No container runtime detected" + timing))
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

	issues := dockerConcerns(info)

	fmt.Println()
	fmt.Println(sep)
	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("%s Docker healthy. Checks passed%s", asciiOr("ok", iconOK, mode), timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("%s %d container concern(s) found%s", asciiOr("warn", iconWarnSp, mode), issues, timing)))
	}
}

func printDockerDaemon(info *models.DockerInfo, mode output.OutputMode) {
	d := info.Daemon
	if d == nil {
		return
	}
	// Daemon Version/APIVersion/StorageDriver/Compose/LastDaemonError all
	// originate from `docker inspect`/`docker version`/journal text, which any
	// local actor able to create a container/image (or a malicious daemon
	// proxy) can influence — sanitize before they reach the terminal.
	verStr := ""
	if d.Version != "" {
		verStr = output.SanitizeControl(d.Version)
		if d.APIVersion != "" {
			verStr += fmt.Sprintf(" (API %s)", output.SanitizeControl(d.APIVersion))
		}
	}
	driverStr := ""
	if d.StorageDriver != "" {
		icon := asciiOr("ok", iconOK, mode)
		if d.StorageDriver == "devicemapper" {
			icon = asciiOr("warn", iconWarnSp, mode)
		}
		// normalise: "overlayfs" → "overlay2" display
		driver := output.SanitizeControl(d.StorageDriver)
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
			asciiOr("warn", iconWarnSp, mode), output.SanitizeControl(d.ComposePlugin), output.SanitizeControl(d.ComposeStandalone))
	case d.ComposePlugin != "":
		fmt.Printf("  %s  Compose: v%s (plugin)\n", asciiOr("ok", iconOK, mode), output.SanitizeControl(d.ComposePlugin))
	case d.ComposeStandalone != "":
		fmt.Printf("  %s  Compose: v%s (standalone — deprecated)\n", asciiOr("warn", iconWarnSp, mode), output.SanitizeControl(d.ComposeStandalone))
	default:
		fmt.Printf("  %s  Compose: not installed\n", asciiOr("info", iconInfoSp, mode))
	}
	if d.RecentErrors > 0 {
		fmt.Printf("  %s  %d error(s) in last 10m", asciiOr("warn", iconWarnSp, mode), d.RecentErrors)
		if d.LastDaemonError != "" {
			fmt.Printf(": %s", output.SanitizeControl(d.LastDaemonError))
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
		fmt.Printf("  %s  Swarm mode: active (role: %s)\n", asciiOr("info", iconInfoSp, mode), role)
		fmt.Println("     Container restarts and placement may be controlled by the Swarm scheduler.")
		fmt.Println("     → docker node ls")
		fmt.Println("     → docker service ps <svc>")
	}
}

func printDockerContainers(info *models.DockerInfo, mode output.OutputMode) {
	fmt.Printf("\nContainers (%d total)\n", info.TotalContainers)
	if info.TotalContainers == 0 {
		fmt.Printf("  %s  no containers\n", asciiOr("ok", iconOK, mode))
		return
	}
	runIcon := asciiOr("ok", iconOK, mode)
	if info.RunningCount == 0 {
		runIcon = asciiOr("warn", iconWarnSp, mode)
	}
	fmt.Printf("  %s  running:   %d\n", runIcon, info.RunningCount)
	if info.StoppedCount > 0 {
		fmt.Printf("  %s  stopped:   %d\n", asciiOr("warn", iconWarnSp, mode), info.StoppedCount)
	}
	if info.UnhealthyCount > 0 {
		fmt.Printf("  %s  unhealthy: %d\n", asciiOr("fail", iconFail, mode), info.UnhealthyCount)
	}
	if info.CrashLoopCount > 0 {
		fmt.Printf("  %s  crash loop: %d\n", asciiOr("fail", iconFail, mode), info.CrashLoopCount)
	}
	if len(info.Containers) == 0 {
		return
	}
	fmt.Println()
	for _, c := range info.Containers {
		icon := asciiOr("ok", iconOK, mode)
		if c.State != "running" {
			icon = asciiOr("warn", iconWarnSp, mode)
		}
		// Key on the gated CrashLooping decision (not raw restart count) so a stabilized
		// container's row doesn't show ❌ while the verdict says it's fine.
		if c.Health == "unhealthy" || c.CrashLooping {
			icon = asciiOr("fail", iconFail, mode)
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
		// c.Name/State/Image originate from `docker inspect`/`docker ps`, all
		// settable by anyone able to create a container/image (docker run
		// --name, image tags) — sanitize before printing.
		fmt.Printf("  %s  %-20s %-12s %s%s%s%s\n",
			icon, output.SanitizeControl(c.Name), output.SanitizeControl(c.State), output.SanitizeControl(c.Image), health, restarts, exitStr)
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
		fmt.Printf("  %s %d quadlet(s) active\n", asciiOr("ok", iconOK, mode), len(info.PodmanQuadlets))
		return
	}

	for _, q := range info.PodmanQuadlets {
		icon := asciiOr("ok", iconOK, mode)
		if !q.Active {
			icon = asciiOr("warn", iconWarnSp, mode)
		}
		if q.Failed {
			icon = asciiOr("fail", iconFail, mode)
		}
		state := q.State
		if state == "" {
			state = "unknown"
		}
		// q.Name/State/ServiceUnit come from Podman quadlet unit files, which
		// anyone able to place a quadlet on the host controls — sanitize.
		name := output.SanitizeControl(q.Name)
		unit := output.SanitizeControl(q.ServiceUnit)
		fmt.Printf("  %s  %-14s %-9s %s\n", icon, name, output.SanitizeControl(state), unit)
		if q.Failed {
			fmt.Printf("     → systemctl status %s\n", unit)
			fmt.Printf("     → journalctl -u %s -n 20\n", unit)
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
			sanitizedSecrets := make([]string, 0, len(c.PlaintextSecrets))
			for _, s := range c.PlaintextSecrets {
				sanitizedSecrets = append(sanitizedSecrets, output.SanitizeControl(s))
			}
			fmt.Printf("  %s  %-20s plaintext secrets in env: %s\n",
				asciiOr("warn", iconWarnSp, mode), output.SanitizeControl(c.Name), strings.Join(sanitizedSecrets, ", "))
		}
	}
	if info.ContainersWithSecrets > 0 {
		fmt.Println("     Env vars visible in 'docker inspect' — use Docker secrets or a vault.")
	}

	// Docker socket mounted
	for _, c := range info.Containers {
		if c.DockerSocketMounted {
			fmt.Printf("  %s  %-20s docker socket mounted — grants root access to host\n", asciiOr("fail", iconFail, mode), output.SanitizeControl(c.Name))
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
		fmt.Printf("  %s  %d running container(s) using root user\n", asciiOr("warn", iconWarnSp, mode), rootCount)
		fmt.Println("     → Add USER directive to Dockerfile or use --user flag.")
	}
}

func printDockerEvents(info *models.DockerInfo, mode output.OutputMode) {
	if len(info.RecentEvents) == 0 {
		return
	}
	fmt.Printf("\n[Recent events — last 1h]\n")
	for _, ev := range info.RecentEvents {
		evIcon := asciiOr("warn", iconWarnSp, mode)
		if ev.Action == "oom" {
			evIcon = asciiOr("fail", iconFail, mode)
		}
		// ev.Actor (container/image name) comes from `docker events`, settable
		// by anyone able to create a container/image — sanitize.
		fmt.Printf("  %s  %-8s  %s\n", evIcon, output.SanitizeControl(ev.Action), output.SanitizeControl(ev.Actor))
	}
	if info.OOMEvents > 0 {
		fmt.Printf("  → %d OOM kill(s) — check container memory limits\n", info.OOMEvents)
	}
}

func printDockerResources(info *models.DockerInfo, mode output.OutputMode) {
	fmt.Printf("\nImages: %d", info.ImagesCount)
	if info.DanglingImages > 0 {
		fmt.Printf("  %s %d dangling", asciiOr("warn", iconWarnSp, mode), info.DanglingImages)
	}
	fmt.Println()
	if info.VolumesCount > 0 {
		fmt.Printf("Volumes: %d\n", info.VolumesCount)
	}
	if info.DiskUsageGB > 0 {
		diskIcon := asciiOr("ok", iconOK, mode)
		if info.DiskUsageGB > 20 {
			diskIcon = asciiOr("warn", iconWarnSp, mode)
		}
		fmt.Printf("Disk usage: %s %.1f GB\n", diskIcon, info.DiskUsageGB)
	}
}

func printDockerLogDriver(ld *models.DockerLogDriverInfo, mode output.OutputMode) {
	// ld.Driver comes from `docker info`/daemon config — sanitize defensively
	// alongside the other daemon-sourced strings in this file.
	driver := output.SanitizeControl(ld.Driver)
	if ld.Driver == "journald" || ld.Driver == "local" {
		fmt.Printf("\n[Log driver]  %s (managed/bounded) %s\n", driver, asciiOr("ok", iconOK, mode))
		return
	}
	// json-file — check if bounded
	icon := asciiOr("warn", iconWarnSp, mode)
	status := "json-file — no max-size (logs grow unbounded)"
	if ld.MaxSizeSet && ld.MaxFileSet {
		icon = asciiOr("ok", iconOK, mode)
		status = "json-file (max-size and max-file set)"
	} else if ld.MaxSizeSet {
		icon = asciiOr("ok", iconOK, mode)
		status = "json-file (max-size set, max-file not set)"
	}
	fmt.Printf("\n[Log driver]  %s %s\n", icon, status)
	if !ld.MaxSizeSet {
		fmt.Println(`  → Add to /etc/docker/daemon.json:`)
		fmt.Println(`    {"log-driver":"json-file","log-opts":{"max-size":"100m","max-file":"3"}}`)
		fmt.Println("  → " + analysis.PlatformServiceCmd("systemctl restart docker"))
	}

	// Container log file sizes
	hasLarge := false
	for _, cl := range ld.ContainerLogs {
		if cl.SizeMB >= 500 {
			hasLarge = true
			icon := asciiOr("warn", iconWarnSp, mode)
			if cl.SizeMB >= 1024 {
				icon = asciiOr("fail", iconFail, mode)
			}
			fmt.Printf("  %s %-20s  %.0f MB\n", icon, output.SanitizeControl(cl.Name), cl.SizeMB)
		}
	}
	if hasLarge {
		fmt.Println("  → truncate large log: truncate -s 0 /var/lib/docker/containers/<id>/<id>-json.log")
	}
}
