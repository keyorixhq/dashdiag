//go:build linux || darwin

package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for docker.go's per-section renderers (printDockerReport's
// Available=false early returns are already covered in docker_report_test.go —
// this covers the Available=true body: printDockerDaemon/Containers/
// PodmanQuadlets/Security/Events/Resources/LogDriver). Plain data structs, no
// live I/O. No t.Parallel() (corrupts captureStdout's shared os.Stdout swap).

func TestPrintDockerDaemon(t *testing.T) {
	if out := captureStdout(t, func() { printDockerDaemon(&models.DockerInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("nil daemon should print nothing, got:\n%s", out)
	}

	devicemapper := captureStdout(t, func() {
		printDockerDaemon(&models.DockerInfo{Daemon: &models.DockerDaemon{Version: "24.0", StorageDriver: "devicemapper"}}, output.ModePlain)
	})
	if !strings.Contains(devicemapper, "WARN") {
		t.Errorf("devicemapper storage driver should render WARN, got:\n%s", devicemapper)
	}

	bothCompose := captureStdout(t, func() {
		printDockerDaemon(&models.DockerInfo{Daemon: &models.DockerDaemon{ComposePlugin: "2.29.1", ComposeStandalone: "1.29.2"}}, output.ModePlain)
	})
	if !strings.Contains(bothCompose, "both present") {
		t.Errorf("plugin+standalone compose both installed should be flagged, got:\n%s", bothCompose)
	}

	swarm := captureStdout(t, func() {
		printDockerDaemon(&models.DockerInfo{Daemon: &models.DockerDaemon{SwarmState: "active", SwarmRole: "manager"}}, output.ModePlain)
	})
	if !strings.Contains(swarm, "Swarm mode: active (role: manager)") {
		t.Errorf("active swarm should show its role, got:\n%s", swarm)
	}

	recentErrs := captureStdout(t, func() {
		printDockerDaemon(&models.DockerInfo{Daemon: &models.DockerDaemon{RecentErrors: 3, LastDaemonError: "OOM"}}, output.ModePlain)
	})
	if !strings.Contains(recentErrs, "3 error(s)") || !strings.Contains(recentErrs, "OOM") {
		t.Errorf("recent daemon errors should be shown with the last error message, got:\n%s", recentErrs)
	}
}

func TestPrintDockerContainers(t *testing.T) {
	empty := captureStdout(t, func() { printDockerContainers(&models.DockerInfo{}, output.ModePlain) })
	if !strings.Contains(empty, "no containers") {
		t.Errorf("zero containers should say so, got:\n%s", empty)
	}

	// A stabilized container's row must show OK, not CRIT, even with a nonzero
	// restart count — CrashLooping (the gated decision) drives the icon, not
	// the raw restart count.
	stabilized := captureStdout(t, func() {
		printDockerContainers(&models.DockerInfo{TotalContainers: 1, RunningCount: 1, Containers: []models.ContainerInfo{
			{Name: "web", State: "running", Restart: 5, CrashLooping: false},
		}}, output.ModePlain)
	})
	if strings.Contains(stabilized, "CRIT") {
		t.Errorf("a stabilized container (restarts but not crash-looping) must not render CRIT, got:\n%s", stabilized)
	}

	crashLoop := captureStdout(t, func() {
		printDockerContainers(&models.DockerInfo{TotalContainers: 1, Containers: []models.ContainerInfo{
			{Name: "web", State: "restarting", Restart: 20, CrashLooping: true},
		}}, output.ModePlain)
	})
	if !strings.Contains(crashLoop, "CRIT") {
		t.Errorf("a crash-looping container must render CRIT, got:\n%s", crashLoop)
	}

	noneRunning := captureStdout(t, func() {
		printDockerContainers(&models.DockerInfo{TotalContainers: 2, RunningCount: 0, StoppedCount: 2}, output.ModePlain)
	})
	if !strings.Contains(noneRunning, "WARN") {
		t.Errorf("zero running containers should render WARN on the running count, got:\n%s", noneRunning)
	}
}

func TestPrintPodmanQuadlets(t *testing.T) {
	if out := captureStdout(t, func() { printPodmanQuadlets(&models.DockerInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("no quadlets should print nothing, got:\n%s", out)
	}

	// All active: a single clean summary line, no per-quadlet noise.
	allActive := captureStdout(t, func() {
		printPodmanQuadlets(&models.DockerInfo{PodmanQuadlets: []models.PodmanQuadlet{
			{Name: "web", Active: true}, {Name: "db", Active: true},
		}}, output.ModePlain)
	})
	if !strings.Contains(allActive, "2 quadlet(s) active") {
		t.Errorf("all-active quadlets should summarize as a count, got:\n%s", allActive)
	}
	if strings.Contains(allActive, "web") {
		t.Errorf("all-active quadlets should not list individual names, got:\n%s", allActive)
	}

	failed := captureStdout(t, func() {
		printPodmanQuadlets(&models.DockerInfo{PodmanQuadlets: []models.PodmanQuadlet{
			{Name: "web", Active: true}, {Name: "db", Active: false, Failed: true, ServiceUnit: "db.service"},
		}}, output.ModePlain)
	})
	if !strings.Contains(failed, "CRIT") || !strings.Contains(failed, "db.service") {
		t.Errorf("a failed quadlet should render CRIT with remediation for its service unit, got:\n%s", failed)
	}
}

func TestPrintDockerSecurity(t *testing.T) {
	if out := captureStdout(t, func() { printDockerSecurity(&models.DockerInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("no security issues should print nothing, got:\n%s", out)
	}

	secrets := captureStdout(t, func() {
		printDockerSecurity(&models.DockerInfo{
			ContainersWithSecrets: 1,
			Containers:            []models.ContainerInfo{{Name: "web", PlaintextSecrets: []string{"DB_PASSWORD"}}},
		}, output.ModePlain)
	})
	if !strings.Contains(secrets, "DB_PASSWORD") {
		t.Errorf("a plaintext secret env var should be named, got:\n%s", secrets)
	}

	socket := captureStdout(t, func() {
		printDockerSecurity(&models.DockerInfo{
			SocketMountedCount: 1,
			Containers:         []models.ContainerInfo{{Name: "ci-runner", DockerSocketMounted: true}},
		}, output.ModePlain)
	})
	if !strings.Contains(socket, "CRIT") || !strings.Contains(socket, "grants root access") {
		t.Errorf("a socket-mounted container should render CRIT with the root-access warning, got:\n%s", socket)
	}

	root := captureStdout(t, func() {
		printDockerSecurity(&models.DockerInfo{
			RunningAsRootCount: 1,
			Containers:         []models.ContainerInfo{{Name: "web", State: "running", RunsAsRoot: true}},
		}, output.ModePlain)
	})
	if !strings.Contains(root, "1 running container(s) using root user") {
		t.Errorf("a root-user container should be counted, got:\n%s", root)
	}
}

func TestPrintDockerEvents(t *testing.T) {
	if out := captureStdout(t, func() { printDockerEvents(&models.DockerInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("no events should print nothing, got:\n%s", out)
	}

	oom := captureStdout(t, func() {
		printDockerEvents(&models.DockerInfo{
			OOMEvents:    1,
			RecentEvents: []models.DockerEvent{{Action: "oom", Actor: "web"}},
		}, output.ModePlain)
	})
	if !strings.Contains(oom, "CRIT") || !strings.Contains(oom, "OOM kill(s)") {
		t.Errorf("an OOM event should render CRIT with the OOM kill callout, got:\n%s", oom)
	}
}

func TestPrintDockerResources(t *testing.T) {
	dangling := captureStdout(t, func() {
		printDockerResources(&models.DockerInfo{ImagesCount: 10, DanglingImages: 3}, output.ModePlain)
	})
	if !strings.Contains(dangling, "3 dangling") {
		t.Errorf("dangling images should be counted, got:\n%s", dangling)
	}

	bigDisk := captureStdout(t, func() {
		printDockerResources(&models.DockerInfo{DiskUsageGB: 25}, output.ModePlain)
	})
	if !strings.Contains(bigDisk, "WARN") {
		t.Errorf("25GB disk usage (>20GB) should render WARN, got:\n%s", bigDisk)
	}
}

func TestPrintDockerLogDriver(t *testing.T) {
	managed := captureStdout(t, func() {
		printDockerLogDriver(&models.DockerLogDriverInfo{Driver: "journald"}, output.ModePlain)
	})
	if !strings.Contains(managed, "managed/bounded") {
		t.Errorf("journald should be recognized as managed/bounded, got:\n%s", managed)
	}

	unbounded := captureStdout(t, func() {
		printDockerLogDriver(&models.DockerLogDriverInfo{Driver: "json-file"}, output.ModePlain)
	})
	if !strings.Contains(unbounded, "grow unbounded") {
		t.Errorf("json-file with no max-size should warn of unbounded growth, got:\n%s", unbounded)
	}

	bounded := captureStdout(t, func() {
		printDockerLogDriver(&models.DockerLogDriverInfo{Driver: "json-file", MaxSizeSet: true, MaxFileSet: true}, output.ModePlain)
	})
	if !strings.Contains(bounded, "max-size and max-file set") {
		t.Errorf("a fully bounded json-file driver should say so, got:\n%s", bounded)
	}

	largeLog := captureStdout(t, func() {
		printDockerLogDriver(&models.DockerLogDriverInfo{
			Driver: "json-file", MaxSizeSet: true, MaxFileSet: true,
			ContainerLogs: []models.DockerContainerLogFile{{Name: "web", SizeMB: 1200}},
		}, output.ModePlain)
	})
	if !strings.Contains(largeLog, "CRIT") {
		t.Errorf("a 1.2GB container log (>=1024MB) should render CRIT, got:\n%s", largeLog)
	}
}

// TestPrintDockerReportFullDispatch exercises the Available=true body of
// printDockerReport end to end — the early-return branches are covered in
// docker_report_test.go.
func TestPrintDockerReportFullDispatch(t *testing.T) {
	out := captureStdout(t, func() {
		printDockerReport(&models.DockerInfo{
			Available: true, Runtime: "docker",
			TotalContainers: 1, RunningCount: 1,
			Containers: []models.ContainerInfo{{Name: "web", State: "running"}},
		}, output.ModePlain, 0)
	})
	if !strings.Contains(out, "Runtime: docker") {
		t.Errorf("the runtime name should be shown, got:\n%s", out)
	}
	if !strings.Contains(out, "Docker healthy") {
		t.Errorf("a clean docker host should read healthy, got:\n%s", out)
	}
}

// TestRunDocker exercises runDocker's real (read-only) collector wiring in
// --plain and --json mode. No Docker/Podman is expected on this test host, so
// both should render the "not available" report without error — the same
// real-I/O precedent as cpu_report_test.go / hardware_test.go.
func TestRunDocker(t *testing.T) {
	plainCmd := newBareCloudCmd()
	plainCmd.SetContext(context.Background())
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runDocker(plainCmd, nil); err != nil {
			t.Fatalf("runDocker (plain): %v", err)
		}
	})
	if plainOut == "" {
		t.Error("runDocker (plain) produced no output")
	}

	jsonCmd := newBareCloudCmd()
	jsonCmd.SetContext(context.Background())
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runDocker(jsonCmd, nil); err != nil {
			t.Fatalf("runDocker (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, "{") {
		t.Errorf("json mode should emit JSON, got: %q", jsonOut)
	}
}
