//go:build linux || darwin

package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// TestPrintDockerReportAbsentVsDown: printDockerReport keys off StatusReason to tell
// "a runtime is installed but its daemon is down" (actionable WARN) from "nothing is
// installed" (benign). The collector must leave StatusReason empty for the truly-absent
// case, or a host with NO container runtime reads "Container runtime installed but not
// running" (a false alarm — regression seen live on AlmaLinux after #564, where the
// collector set StatusReason for both cases). Podman is daemonless, so its idle "no
// socket" state is the absent case, not a fault.
func TestPrintDockerReportAbsentVsDown(t *testing.T) {
	absent := &models.DockerInfo{Available: false, StatusReason: ""}
	out := captureStdout(t, func() { printDockerReport(absent, output.ModeHuman, 0) })
	if strings.Contains(out, "installed but not running") {
		t.Errorf("absent runtime must NOT claim 'installed but not running'; got:\n%s", out)
	}
	if !strings.Contains(out, "No container runtime detected") {
		t.Errorf("absent runtime should read 'No container runtime detected'; got:\n%s", out)
	}

	down := &models.DockerInfo{Available: false, StatusReason: "Docker installed but daemon not running"}
	out2 := captureStdout(t, func() { printDockerReport(down, output.ModeHuman, 0) })
	if !strings.Contains(out2, "installed but not running") {
		t.Errorf("installed-but-down runtime should WARN 'installed but not running'; got:\n%s", out2)
	}
	if strings.Contains(out2, "No container runtime detected") {
		t.Errorf("installed-but-down must NOT show the green 'No container runtime detected'; got:\n%s", out2)
	}
}

// TestPrintDockerSanitizesControlChars guards against terminal-escape
// injection via Docker/Podman-sourced strings: any local actor able to
// create a container/image (docker run --name, image tags) or a malicious
// daemon proxy controls container Name/Image/State, daemon Version/
// APIVersion/StorageDriver/Compose versions/LastDaemonError, quadlet
// Name/ServiceUnit, event Actor, and container-log file names. See
// finding cmd-04-03.
func TestPrintDockerSanitizesControlChars(t *testing.T) {
	const esc = "\x1b[2J"

	daemonOut := captureStdout(t, func() {
		printDockerDaemon(&models.DockerInfo{Daemon: &models.DockerDaemon{
			Responding:        true,
			Version:           "24.0" + esc,
			APIVersion:        "1.43" + esc,
			StorageDriver:     "overlay2" + esc,
			ComposePlugin:     "2.29" + esc,
			ComposeStandalone: "1.29" + esc,
			RecentErrors:      1,
			LastDaemonError:   "boom" + esc,
		}}, output.ModeHuman)
	})
	if strings.Contains(daemonOut, esc) {
		t.Errorf("printDockerDaemon must strip terminal escape sequences, got:\n%q", daemonOut)
	}

	containersOut := captureStdout(t, func() {
		printDockerContainers(&models.DockerInfo{
			TotalContainers: 1, RunningCount: 1,
			Containers: []models.ContainerInfo{{Name: "evil" + esc, State: "running" + esc, Image: "img" + esc}},
		}, output.ModeHuman)
	})
	if strings.Contains(containersOut, esc) {
		t.Errorf("printDockerContainers must strip terminal escape sequences, got:\n%q", containersOut)
	}

	quadletsOut := captureStdout(t, func() {
		printPodmanQuadlets(&models.DockerInfo{
			PodmanQuadlets: []models.PodmanQuadlet{{Name: "q" + esc, ServiceUnit: "svc" + esc, State: "failed" + esc, Failed: true}},
		}, output.ModeHuman)
	})
	if strings.Contains(quadletsOut, esc) {
		t.Errorf("printPodmanQuadlets must strip terminal escape sequences, got:\n%q", quadletsOut)
	}

	eventsOut := captureStdout(t, func() {
		printDockerEvents(&models.DockerInfo{
			RecentEvents: []models.DockerEvent{{Action: "die" + esc, Actor: "container" + esc}},
		}, output.ModeHuman)
	})
	if strings.Contains(eventsOut, esc) {
		t.Errorf("printDockerEvents must strip terminal escape sequences, got:\n%q", eventsOut)
	}

	logDriverOut := captureStdout(t, func() {
		printDockerLogDriver(&models.DockerLogDriverInfo{
			Driver:        "json-file",
			ContainerLogs: []models.DockerContainerLogFile{{Name: "log" + esc, SizeMB: 600}},
		}, output.ModeHuman)
	})
	if strings.Contains(logDriverOut, esc) {
		t.Errorf("printDockerLogDriver must strip terminal escape sequences, got:\n%q", logDriverOut)
	}
}
