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
