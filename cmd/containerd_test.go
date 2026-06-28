package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// TestPrintContainerd_FailedServiceIsCrit: a failed containerd service must render
// as CRIT, matching checkContainerd + the exit code (regression: the display showed
// the WARN icon while the verdict/exit were CRIT — an under-statement).
func TestPrintContainerd_FailedServiceIsCrit(t *testing.T) {
	info := &models.ContainerdInfo{Available: true, ServiceState: "failed", SocketPath: "/run/containerd/containerd.sock"}
	out := captureStdout(t, func() { printContainerd(info, output.ModePlain) })

	if !strings.Contains(out, "CRIT") {
		t.Errorf("failed containerd service should render CRIT:\n%s", out)
	}
	if strings.Contains(out, "WARN") {
		t.Errorf("failed containerd service must not render WARN (under-states the CRIT verdict):\n%s", out)
	}
}
