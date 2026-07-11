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
