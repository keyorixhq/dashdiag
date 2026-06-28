package cmd

import (
	"bytes"
	"os"
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

// dsd guest now auto-detects cloud: an EC2 guest renders the same two-block split
// the standalone dsd aws produces, through the shared guest renderer.
func TestPrintGuestView_AWSCloudTwoBlock(t *testing.T) {
	view := guestView{
		identity:   "🟧 EC2 guest — m5.large",
		insights:   analysis.AWSInsights(*ec2Info()),
		hostSide:   awsInsightProviderSide,
		recognized: isAWSRecognitionLine,
		guestTitle: "Your instance — you can fix these",
		hostTitle:  "AWS-imposed limits — evidence to share with AWS support",
		healthyMsg: "EC2 guest healthy",
	}
	var buf bytes.Buffer
	printGuestView(&buf, view, output.ModePlain)
	out := buf.String()

	gi := strings.Index(out, "Your instance")
	hi := strings.Index(out, "AWS-imposed limits")
	if gi < 0 || hi < 0 || gi > hi {
		t.Fatalf("both blocks present, instance before provider:\n%s", out)
	}
	guestBlock, hostBlock := out[gi:hi], out[hi:]
	for _, want := range []string{"IMDSv1", "amazon-ssm-agent"} {
		if !strings.Contains(guestBlock, want) {
			t.Errorf("self-serve block missing %q", want)
		}
	}
	for _, want := range []string{"allowance", "EBS"} {
		if !strings.Contains(hostBlock, want) {
			t.Errorf("provider block missing %q", want)
		}
	}
	if strings.Contains(hostBlock, "IMDSv1") {
		t.Error("IMDSv1 (self-serve) leaked into the provider block")
	}
}

// The cloud commands must not claim a clean headline when it wasn't checked: an
// EC2 'healthy' summary with EBS throttling unverified (needs root) gets a caveat.
func TestHealthySummary_CloudUnverifiedCaveat(t *testing.T) {
	base := "EC2 guest healthy — no guest-side throttling or posture issues found"
	for _, msg := range []string{
		"EBS performance stats need root — run dsd as root to check whether EBS IOPS/throughput is being throttled",
		"could not read EBS performance stats (...) — EBS throttling NOT verified",
	} {
		got := healthySummary(base, []models.Insight{{Level: "INFO", Message: msg}})
		if !strings.Contains(got, "could not be verified") {
			t.Errorf("unverified EBS (%q) must caveat the clean summary, got: %q", msg, got)
		}
	}
	// A genuinely-clean instance keeps the plain summary.
	if got := healthySummary(base, nil); got != base {
		t.Errorf("clean summary must be unchanged, got: %q", got)
	}
}

// dsd guest --report-html writes a self-contained two-block HTML leave-behind.
func TestWriteGuestReportHTML_AWS(t *testing.T) {
	t.Chdir(t.TempDir())
	view := guestView{
		identity:   "🟧 EC2 guest — m5.large",
		insights:   analysis.AWSInsights(*ec2Info()),
		hostSide:   awsInsightProviderSide,
		recognized: isAWSRecognitionLine,
		guestTitle: "Your instance — you can fix these",
		hostTitle:  "AWS-imposed limits — evidence to share with AWS support",
		healthyMsg: "EC2 guest healthy",
	}
	path, err := writeGuestReportHTML(view)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	for _, want := range []string{"Your instance", "AWS-imposed limits", "IMDSv1", "EBS", "issue(s) found", "<!DOCTYPE html>"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
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
