package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckVMware_ToolsRunningUnverified is the regression test for
// internal-collectors-34-03: when open-vm-tools appears to be running but
// that signal came only from a /proc/*/comm process-name match (systemd
// gave no usable answer), it must be disclosed as unverified — a process
// name is spoofable by any unprivileged local process, unlike the
// authoritative systemctl check.
func TestCheckVMware_ToolsRunningUnverified(t *testing.T) {
	t.Parallel()
	got := checkVMware(models.VMwareInfo{
		IsGuest: true, ToolsInstalled: true, ToolsRunning: true,
		ToolsRunningVerified: false,
	})
	if !hasInsightMsg(got, "INFO", "could not be confirmed via systemd") {
		t.Errorf("expected an unverified tools-running disclosure, got %+v", got)
	}
}

// TestCheckVMware_ToolsRunningVerifiedIsSilent confirms the disclosure does
// NOT fire once systemd has authoritatively confirmed the tools are running.
func TestCheckVMware_ToolsRunningVerifiedIsSilent(t *testing.T) {
	t.Parallel()
	got := checkVMware(models.VMwareInfo{
		IsGuest: true, ToolsInstalled: true, ToolsRunning: true,
		ToolsRunningVerified: true, StatAvailable: true,
	})
	if hasInsightMsg(got, "INFO", "could not be confirmed via systemd") {
		t.Errorf("verified tools-running must not disclose as unverified, got %+v", got)
	}
}
