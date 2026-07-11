package cmd

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/collectors"
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

// TestDetectGuestView_Container exercises detectGuestView's real innermost-
// isolation-layer detection. Skipped when not running inside a container
// (GitHub-hosted runners are Azure VMs or bare-metal macOS, not containers).
// The other DMI-gated branches (AWS/Azure/GCP/OCI/VMware/KVM) and the
// bare-metal not-found branch are covered directly via the per-provider
// ...GuestView tests below, since detectGuestView has no injection point to
// force a specific platform.
func TestDetectGuestView_Container(t *testing.T) {
	t.Parallel()
	if !collectors.ContainerGuestAvailable() {
		t.Skip("not running inside a container")
	}
	view, found := detectGuestView(context.Background())
	if !found {
		t.Fatal("ContainerGuestAvailable returned true but detectGuestView reported found=false")
	}
	if !strings.Contains(view.identity, "Container") {
		t.Errorf("identity should name the container runtime, got %q", view.identity)
	}
}

// TestGuestViewFactories exercises every per-platform ...GuestView constructor
// (and, transitively, runGuestCollector) via a real collector run. Off-platform
// (this test host is on none of these clouds/hypervisors — see
// TestZZZProbeAvailability-class checks elsewhere), each collector still
// returns a real, well-formed info struct with the platform flag false; the
// constructors don't gate on availability themselves (detectGuestView does),
// so this is a legitimate direct call, same shape as production use after the
// gate already passed.
func TestGuestViewFactories(t *testing.T) {
	t.Parallel()

	checkCommon := func(t *testing.T, v guestView, wantIdentitySubstr string) {
		t.Helper()
		if !strings.Contains(v.identity, wantIdentitySubstr) {
			t.Errorf("identity %q should contain %q", v.identity, wantIdentitySubstr)
		}
		if v.guestTitle == "" || v.hostTitle == "" || v.healthyMsg == "" {
			t.Errorf("guestView must have non-empty titles/healthyMsg: %+v", v)
		}
		if v.hostSide == nil || v.recognized == nil {
			t.Errorf("guestView must have non-nil classifier funcs: %+v", v)
		}
		if v.jsonData == nil {
			t.Errorf("guestView must have non-nil jsonData")
		}
	}

	t.Run("aws", func(t *testing.T) {
		t.Parallel()
		v := awsGuestView(context.Background())
		checkCommon(t, v, "EC2")
		if _, ok := v.jsonData.(*models.AWSInfo); !ok {
			t.Errorf("jsonData should be *models.AWSInfo, got %T", v.jsonData)
		}
	})
	t.Run("azure", func(t *testing.T) {
		t.Parallel()
		v := azureGuestView(context.Background())
		checkCommon(t, v, "Azure")
		if _, ok := v.jsonData.(*models.AzureInfo); !ok {
			t.Errorf("jsonData should be *models.AzureInfo, got %T", v.jsonData)
		}
	})
	t.Run("gcp", func(t *testing.T) {
		t.Parallel()
		v := gcpGuestView(context.Background())
		checkCommon(t, v, "GCE")
		if _, ok := v.jsonData.(*models.GCPInfo); !ok {
			t.Errorf("jsonData should be *models.GCPInfo, got %T", v.jsonData)
		}
	})
	t.Run("oci", func(t *testing.T) {
		t.Parallel()
		v := ociGuestView(context.Background())
		checkCommon(t, v, "OCI")
		if _, ok := v.jsonData.(*models.OCIInfo); !ok {
			t.Errorf("jsonData should be *models.OCIInfo, got %T", v.jsonData)
		}
		// ociInsightProviderSide is always false — every finding is guest-fixable.
		if v.hostSide("anything") {
			t.Errorf("ociInsightProviderSide should always be false")
		}
	})
	t.Run("vmware", func(t *testing.T) {
		t.Parallel()
		v := vmwareGuestView(context.Background())
		checkCommon(t, v, "VMware")
		if _, ok := v.jsonData.(*models.VMwareInfo); !ok {
			t.Errorf("jsonData should be *models.VMwareInfo, got %T", v.jsonData)
		}
	})
	t.Run("kvm", func(t *testing.T) {
		t.Parallel()
		v := kvmGuestView(context.Background())
		checkCommon(t, v, "QEMU/KVM")
		if _, ok := v.jsonData.(*models.KVMGuestInfo); !ok {
			t.Errorf("jsonData should be *models.KVMGuestInfo, got %T", v.jsonData)
		}
	})
	t.Run("container", func(t *testing.T) {
		t.Parallel()
		v := containerGuestView(context.Background())
		checkCommon(t, v, "Container")
		if _, ok := v.jsonData.(*models.ContainerGuestInfo); !ok {
			t.Errorf("jsonData should be *models.ContainerGuestInfo, got %T", v.jsonData)
		}
	})
}

// TestWriteGuestReportHTML_CritEscalatesLevel covers the CRIT-scan branch in
// writeGuestReportHTML (not exercised by TestWriteGuestReportHTML_AWS, whose
// fixture only has WARN-level findings).
func TestWriteGuestReportHTML_CritEscalatesLevel(t *testing.T) {
	t.Chdir(t.TempDir())
	view := guestView{
		identity: "test guest",
		insights: []models.Insight{{Level: "CRIT", Check: "Test", Message: "disk failing"}},
		hostSide: func(string) bool { return false },
		recognized: func(string) bool {
			return false
		},
		guestTitle: "Guest", hostTitle: "Host", healthyMsg: "healthy",
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
	if !strings.Contains(out, `verdict crit`) {
		t.Errorf("a CRIT-level insight should escalate the report verdict to crit, got:\n%s", out)
	}
	if !strings.Contains(out, "disk failing") {
		t.Errorf("the CRIT finding message should be rendered, got:\n%s", out)
	}
}

// TestWriteGuestReportHTML_WriteError exercises the os.WriteFile failure path
// in writeGuestReportHTML (and, transitively, runGuest's --report-html error
// wrap): a cwd whose directory permissions block file creation.
func TestWriteGuestReportHTML_WriteError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // let t.TempDir clean up
	t.Chdir(dir)

	view := guestView{
		identity: "test guest", healthyMsg: "healthy",
		hostSide: func(string) bool { return false }, recognized: func(string) bool { return false },
		guestTitle: "Guest", hostTitle: "Host",
	}
	if _, err := writeGuestReportHTML(view); err == nil {
		t.Fatal("expected an error writing to a read-only directory, got nil")
	}

	// The runGuest path only reaches the report-html branch when detectGuestView
	// returns found=true. Skip on non-container hosts (Azure runners, macOS).
	if !collectors.ContainerGuestAvailable() {
		return
	}
	htmlCmd := newBareCloudCmd()
	_ = htmlCmd.Flags().Set("report-html", "true")
	if err := runGuest(htmlCmd, nil); err == nil {
		t.Error("runGuest --report-html should propagate the write error")
	} else if !strings.Contains(err.Error(), "writing report") {
		t.Errorf("runGuest should wrap the error with context, got: %v", err)
	}
}

// TestRunGuest exercises runGuest's real detection + wiring in --plain,
// --json, and --report-html mode. Skipped on non-container hosts (GitHub
// runners are Azure VMs or bare macOS). No t.Parallel() — captureStdout
// swaps the shared os.Stdout.
func TestRunGuest(t *testing.T) {
	if !collectors.ContainerGuestAvailable() {
		t.Skip("not running inside a container")
	}
	plainCmd := newBareCloudCmd()
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runGuest(plainCmd, nil); err != nil {
			t.Fatalf("runGuest (plain): %v", err)
		}
	})
	if !strings.Contains(plainOut, "Container") {
		t.Errorf("plain mode should render the container identity, got: %q", plainOut)
	}

	jsonCmd := newBareCloudCmd()
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runGuest(jsonCmd, nil); err != nil {
			t.Fatalf("runGuest (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, `"in_container"`) {
		t.Errorf("json mode should encode a ContainerGuestInfo, got: %q", jsonOut)
	}

	t.Chdir(t.TempDir())
	htmlCmd := newBareCloudCmd()
	_ = htmlCmd.Flags().Set("report-html", "true")
	if err := runGuest(htmlCmd, nil); err != nil {
		t.Fatalf("runGuest (report-html): %v", err)
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "dsd-guest-report-") {
			found = true
		}
	}
	if !found {
		t.Error("runGuest --report-html should write a dsd-guest-report-*.html file")
	}
}
