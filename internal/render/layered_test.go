package render

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// TestPrintAllLayered_Grouping verifies the three-layer grouping: a hardware
// collector, a platform collector (VMware), and an OS collector each land under
// the right header, in stack order (hardware → platform → OS), with the verdict
// tally on top and the VMware zoom-in hint present.
func TestPrintAllLayered_Grouping(t *testing.T) {
	r := NewRenderer(output.ModePlain)
	results := []runner.Result{
		{Name: "Systemd"}, // OS — deliberately first to prove regrouping, not input order
		{Name: "Memory"},  // hardware
		{Name: "VMware"},  // platform
	}
	insights := []models.Insight{
		{Level: "OK", Check: "Systemd"},
		{Level: "OK", Check: "Memory"},
		{Level: "WARN", Check: "VMware", Message: "emulated NIC"},
	}

	out := captureStdout(t, func() { r.PrintAllLayered(results, insights) })

	hw := strings.Index(out, "Hardware & storage")
	plat := strings.Index(out, "Platform")
	os := strings.Index(out, "OS & services")
	if hw < 0 || plat < 0 || os < 0 {
		t.Fatalf("all three layer headers must be present:\n%s", out)
	}
	if hw >= plat || plat >= os {
		t.Errorf("layers out of stack order: hw=%d platform=%d os=%d", hw, plat, os)
	}

	// Each collector must sit under its own layer's header.
	mem := strings.Index(out, "Memory")
	vmw := strings.Index(out, "VMware")
	sysd := strings.Index(out, "Systemd")
	if hw >= mem || mem >= plat {
		t.Errorf("Memory must render under Hardware (hw=%d mem=%d platform=%d)", hw, mem, plat)
	}
	if plat >= vmw || vmw >= os {
		t.Errorf("VMware must render under Platform (platform=%d vmw=%d os=%d)", plat, vmw, os)
	}
	if sysd < os {
		t.Errorf("Systemd must render under OS & services (os=%d sysd=%d)", os, sysd)
	}

	if !strings.Contains(out, "0 critical · 1 warnings · 0 info") {
		t.Errorf("verdict tally missing/incorrect:\n%s", out)
	}
	if !strings.Contains(out, "full detail: dsd vmware") {
		t.Errorf("VMware zoom-in hint missing:\n%s", out)
	}
	if strings.Contains(out, "Other") {
		t.Errorf("no collector should fall into Other here:\n%s", out)
	}
}

// TestPrintAllLayered_BareMetal: with no platform collector, the Platform layer
// shows the explicit bare-metal note rather than silently vanishing.
func TestPrintAllLayered_BareMetal(t *testing.T) {
	r := NewRenderer(output.ModePlain)
	results := []runner.Result{{Name: "Memory"}, {Name: "Systemd"}}
	insights := []models.Insight{{Level: "OK", Check: "Memory"}, {Level: "OK", Check: "Systemd"}}

	out := captureStdout(t, func() { r.PrintAllLayered(results, insights) })

	if !strings.Contains(out, "bare metal — no hypervisor/cloud layer") {
		t.Errorf("bare-metal Platform note missing:\n%s", out)
	}
	if strings.Contains(out, "full detail: dsd vmware") {
		t.Errorf("must not show the VMware hint with no VMware collector present")
	}
}
