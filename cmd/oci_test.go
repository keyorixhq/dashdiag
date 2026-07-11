package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// newBareCloudCmd builds a standalone *cobra.Command (not wired to rootCmd)
// with the flags the cloud/guest/hardware runXxx functions in this package
// read via cmd.Flags().Get*, so a run function can be exercised directly
// without going through cobra's root command tree. Shared across this
// package's cmd-wiring tests (aws/azure/gcp/oci/vmware/kvm/kvm-guest/guest/
// hardware) the same way captureStdout (net_dns_test.go) is shared.
func newBareCloudCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("plain", false, "")
	f.Bool("json", false, "")
	f.Bool("report-html", false, "")
	f.Bool("deep", false, "")
	return c
}

// ociInstanceInfo has guest-fixable posture issues only — legacy IMDS access
// open, the cloud agent stopped, NTP not on the metadata server, and a VNIC
// ring-buffer drop counter. ociInsightProviderSide always returns false (OCI
// has no provider-imposed-limit signal today), so every finding lands in the
// self-serve block and the provider block always renders "nothing flagged".
func ociInstanceInfo() *models.OCIInfo {
	return &models.OCIInfo{
		IsOCI: true, Shape: "VM.Standard.A1.Flex",
		IMDSChecked: true, IMDSv1Open: true,
		AgentChecked: true, AgentInstalled: true, AgentRunning: false, AgentUpdaterRunning: true,
		TimeSyncChecked: true, UsesOCITimeSync: false,
		VNICs: []models.OCIVNIC{{Iface: "ens3", Driver: "virtio_net", RxDrops: 12}},
	}
}

func TestPrintOCIReport_TwoBlockSplit(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	printOCIReport(&buf, ociInstanceInfo(), 100*time.Millisecond, output.ModePlain)
	out := buf.String()
	t.Logf("\n%s", out)

	guestHdr := "Your instance — you can fix these"
	provHdr := "Provider-imposed — evidence to share with Oracle support"
	gi, pi := strings.Index(out, guestHdr), strings.Index(out, provHdr)
	if gi < 0 || pi < 0 {
		t.Fatalf("both block headers must be present; got:\n%s", out)
	}
	if gi > pi {
		t.Errorf("self-serve block must come before the provider block")
	}
	guestBlock, provBlock := out[gi:pi], out[pi:]

	for _, want := range []string{"legacy/unauthenticated IMDS", "oracle-cloud-agent", "rx drop"} {
		if !strings.Contains(guestBlock, want) {
			t.Errorf("self-serve block missing %q; got:\n%s", want, guestBlock)
		}
	}
	if !strings.Contains(provBlock, "nothing flagged") {
		t.Errorf("provider block should be empty (OCI has no provider-side signal today), got:\n%s", provBlock)
	}
	// IMDS + agent stopped + VNIC drops = 3 WARN; time-sync is INFO.
	if c := ociConcerns(ociInstanceInfo()); c != 3 {
		t.Errorf("ociConcerns = %d, want 3 (IMDS + agent + VNIC WARNs; time-sync is INFO)", c)
	}
	if !strings.Contains(out, "3 OCI issue(s) found") {
		t.Errorf("summary should report 3 issues; got:\n%s", out)
	}
}

func TestPrintOCIReport_Healthy(t *testing.T) {
	t.Parallel()
	clean := &models.OCIInfo{
		IsOCI: true, Shape: "VM.Standard3.Flex",
		IMDSChecked: true, IMDSv1Open: false,
		AgentChecked: true, AgentInstalled: true, AgentRunning: true, AgentUpdaterRunning: true,
		TimeSyncChecked: true, UsesOCITimeSync: true, TimeSynced: true,
	}
	var buf bytes.Buffer
	printOCIReport(&buf, clean, 50*time.Millisecond, output.ModePlain)
	out := buf.String()
	if ociConcerns(clean) != 0 {
		t.Fatalf("clean instance should have 0 concerns, got %d", ociConcerns(clean))
	}
	if !strings.Contains(out, "OCI instance healthy") {
		t.Errorf("clean instance should print the healthy summary; got:\n%s", out)
	}
	if strings.Count(out, "nothing flagged") != 2 {
		t.Errorf("both blocks should show 'nothing flagged'; got:\n%s", out)
	}
}

// A shape-less info (IMDS unreachable) falls back to the generic "instance" label.
func TestPrintOCIReport_NoShapeFallback(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	printOCIReport(&buf, &models.OCIInfo{IsOCI: true}, 10*time.Millisecond, output.ModePlain)
	out := buf.String()
	if !strings.Contains(out, "OCI instance — instance") {
		t.Errorf("empty shape should fall back to generic 'instance', got:\n%s", out)
	}
}

// TestRunOCI_NotOnOCI exercises runOCI's real availability gate (this test
// host is not on OCI) in both --plain and --json mode. No t.Parallel() —
// captureStdout swaps the shared os.Stdout, same constraint as net_dns_test.go.
func TestRunOCI_NotOnOCI(t *testing.T) {
	plainCmd := newBareCloudCmd()
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runOCI(plainCmd, nil); err != nil {
			t.Fatalf("runOCI (plain): %v", err)
		}
	})
	if !strings.Contains(plainOut, "not running on OCI") {
		t.Errorf("plain mode should report 'not running on OCI', got: %q", plainOut)
	}

	jsonCmd := newBareCloudCmd()
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runOCI(jsonCmd, nil); err != nil {
			t.Fatalf("runOCI (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, `"is_oci"`) {
		t.Errorf("json mode should encode an empty OCIInfo, got: %q", jsonOut)
	}
}
