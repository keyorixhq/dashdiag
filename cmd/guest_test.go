package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// A misconfigured container: no memory limit + root (deployer-fixable), and CPU
// throttling + OOM kills (limits enforced against it).
func misconfiguredContainer() models.ContainerGuestInfo {
	return models.ContainerGuestInfo{
		InContainer: true, Runtime: "docker", CgroupV2: true,
		MemLimitBytes: 0, // no limit
		RunAsRoot:     true,
		CPUQuotaCores: 0.3, ThrottledPct: 100,
		OOMKills: 2, MemCurrentBytes: 1, // mem pct n/a (limit 0)
	}
}

func TestPrintGuestView_ContainerTwoBlock(t *testing.T) {
	info := misconfiguredContainer()
	view := guestView{
		identity:   "📦 Container (docker)",
		insights:   analysis.ContainerGuestInsights(info),
		hostSide:   containerInsightHostSide,
		recognized: isContainerRecognitionLine,
		guestTitle: "Your container — you can fix these",
		hostTitle:  "Resource limits — enforced against you",
		healthyMsg: "container healthy",
	}
	var buf bytes.Buffer
	printGuestView(&buf, view, output.ModePlain)
	out := buf.String()
	t.Logf("\n%s", out)

	gi := strings.Index(out, "Your container")
	hi := strings.Index(out, "Resource limits")
	if gi < 0 || hi < 0 || gi > hi {
		t.Fatalf("both blocks present, container before limits:\n%s", out)
	}
	guestBlock, hostBlock := out[gi:hi], out[hi:]

	// Deployer-fixable in the guest block.
	for _, want := range []string{"no memory limit", "runs as root"} {
		if !strings.Contains(guestBlock, want) {
			t.Errorf("guest block missing %q", want)
		}
	}
	// Enforced-against-you in the host block.
	for _, want := range []string{"throttled", "OOM-kill"} {
		if !strings.Contains(hostBlock, want) {
			t.Errorf("host block missing %q", want)
		}
	}
	if strings.Contains(guestBlock, "throttled") {
		t.Error("CPU throttling leaked into the deployer-fixable block")
	}
}

func TestPrintGuestView_HealthyContainer(t *testing.T) {
	info := models.ContainerGuestInfo{
		InContainer: true, Runtime: "kubernetes", CgroupV2: true,
		MemLimitBytes: 256 << 20, CPUQuotaCores: 2.0,
	}
	view := guestView{
		identity: "📦 Container (kubernetes)", insights: analysis.ContainerGuestInsights(info),
		hostSide: containerInsightHostSide, recognized: isContainerRecognitionLine,
		guestTitle: "Your container — you can fix these", hostTitle: "Resource limits — enforced against you",
		healthyMsg: "container healthy — limits set, non-root, no throttling or OOM-kills",
	}
	var buf bytes.Buffer
	printGuestView(&buf, view, output.ModePlain)
	out := buf.String()
	if !strings.Contains(out, "container healthy") {
		t.Errorf("clean container should print healthy summary:\n%s", out)
	}
	if strings.Count(out, "nothing flagged") != 2 {
		t.Errorf("both blocks should show 'nothing flagged':\n%s", out)
	}
}

// TestHealthySummary_DemotesUnverifiedPressure: when a finding says host pressure
// was NOT verified, the all-clear line must not assert "no host pressure".
func TestHealthySummary_DemotesUnverifiedPressure(t *testing.T) {
	const base = "VMware guest healthy — guest tools running, paravirtual drivers in use, no host pressure"

	unver := []models.Insight{{Level: "INFO", Message: "VMware resource-pressure stats unavailable — ballooning / host-swap / host caps NOT verified"}}
	got := healthySummary(base, unver)
	if strings.Contains(got, "no host pressure") {
		t.Errorf("must not claim 'no host pressure' when it was NOT verified: %q", got)
	}
	if !strings.Contains(got, "not verified") {
		t.Errorf("should state pressure was not verified: %q", got)
	}

	if got := healthySummary(base, nil); got != base {
		t.Errorf("with verified pressure the line is unchanged, got %q", got)
	}
}

// TestPrintGuestView_PressureUnverified: the end-to-end clean-but-unverified path
// keeps the healthy verdict but drops the false "no host pressure" claim.
func TestPrintGuestView_PressureUnverified(t *testing.T) {
	view := guestView{
		identity: "🟦 VMware guest — test",
		insights: []models.Insight{{Level: "INFO", Check: "VMware", Message: "VMware resource-pressure stats unavailable (vmware-toolbox-cmd stat failed) — ballooning / host-swap / host caps NOT verified"}},
		hostSide: vmwareInsightHostSide, recognized: isVMwareRecognitionLine,
		guestTitle: "Your VM — you can fix these", hostTitle: "Host-side — evidence to share with your cloud provider",
		healthyMsg: "VMware guest healthy — guest tools running, paravirtual drivers in use, no host pressure",
	}
	var buf bytes.Buffer
	printGuestView(&buf, view, output.ModePlain)
	out := buf.String()
	if !strings.Contains(out, "VMware guest healthy") {
		t.Errorf("verdict stays healthy (the unverified case is INFO, not a concern):\n%s", out)
	}
	if strings.Contains(out, "no host pressure") {
		t.Errorf("must not assert 'no host pressure' when stats were unavailable:\n%s", out)
	}
}
