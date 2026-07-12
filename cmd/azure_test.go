package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// azureVMInfo has self-serve config issues (waagent stopped, persistent data on the
// ephemeral temp disk, a data disk with ReadWrite host caching, plus INFO-level time
// sync + NVMe-timeout tuning) and the platform-evidence headline: an Accelerated-
// Networking VF that is present but not bonded (the portal-enabled false-green).
func azureVMInfo() *models.AzureInfo {
	return &models.AzureInfo{
		IsAzure:          true,
		SyntheticNICs:    []string{"eth0"},
		AN:               []models.ANIface{{VF: "enP1s2", Driver: "mlx5_core", Bonded: false}},
		WAAgentInstalled: true, WAAgentRunning: false,
		TempDiskPresent: true, PersistentDataAtRisk: true, TempDiskMount: "/mnt",
		DisksChecked: true, Disks: []models.AzureDisk{{Name: "datadisk0", IsOS: false, Lun: 0, Caching: "ReadWrite"}},
		TimeSyncChecked: true, UsesHyperVPTP: false,
		NVMeIOTimeoutChecked: true, NVMeIOTimeoutSecs: 30,
	}
}

func TestPrintAzureReport_TwoBlockSplit(t *testing.T) {
	var buf bytes.Buffer
	printAzureReport(&buf, azureVMInfo(), 100*time.Millisecond, output.ModePlain)
	out := buf.String()
	t.Logf("\n%s", out)

	guestHdr := "Your VM — you can fix these"
	provHdr := "Accelerated networking — evidence to share with Azure support"
	gi, pi := strings.Index(out, guestHdr), strings.Index(out, provHdr)
	if gi < 0 || pi < 0 {
		t.Fatalf("both block headers must be present; got:\n%s", out)
	}
	if gi > pi {
		t.Errorf("self-serve block must come before the provider-evidence block")
	}
	guestBlock, provBlock := out[gi:pi], out[pi:]

	for _, want := range []string{"waagent", "temp", "ReadWrite"} {
		if !strings.Contains(guestBlock, want) {
			t.Errorf("self-serve block missing %q", want)
		}
	}
	if !strings.Contains(provBlock, "Accelerated Networking") {
		t.Errorf("provider block missing the AN finding")
	}
	if strings.Contains(provBlock, "waagent") {
		t.Errorf("waagent (self-serve) leaked into the provider block")
	}
	// AN + waagent + temp-disk + RW caching = 4 WARN; time-sync + NVMe are INFO.
	if c := azureConcerns(azureVMInfo()); c != 4 {
		t.Errorf("azureConcerns = %d, want 4 (AN + waagent + temp-disk + caching; time-sync/NVMe INFO)", c)
	}
	if !strings.Contains(out, "4 Azure issue(s) found") {
		t.Errorf("summary should report 4 issues; got:\n%s", out)
	}
}

// TestRunAzure_NotOnAzure exercises runAzure's real availability gate in both
// --plain and --json mode. Skipped on Azure hosts (GitHub-hosted runners are
// Azure VMs) because those reach the full-check branch, not the gate. No
// t.Parallel() — captureStdout swaps the shared os.Stdout.
func TestRunAzure_NotOnAzure(t *testing.T) {
	if collectors.AzureGuestAvailable() {
		t.Skip("test requires a non-Azure host; this runner is on Azure")
	}
	plainCmd := newBareCloudCmd()
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runAzure(plainCmd, nil); err != nil {
			t.Fatalf("runAzure (plain): %v", err)
		}
	})
	if !strings.Contains(plainOut, "not running on Azure") {
		t.Errorf("plain mode should report 'not running on Azure', got: %q", plainOut)
	}

	jsonCmd := newBareCloudCmd()
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runAzure(jsonCmd, nil); err != nil {
			t.Fatalf("runAzure (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, `"is_azure"`) {
		t.Errorf("json mode should encode an empty AzureInfo, got: %q", jsonOut)
	}
}

func TestPrintAzureReport_Healthy(t *testing.T) {
	clean := &models.AzureInfo{
		IsAzure: true, HasVF: true,
		AN:               []models.ANIface{{VF: "enP1s2", Driver: "mlx5_core", Synthetic: "eth0", Bonded: true, Up: true}},
		WAAgentInstalled: true, WAAgentRunning: true,
		TimeSyncChecked: true, UsesHyperVPTP: true,
	}
	var buf bytes.Buffer
	printAzureReport(&buf, clean, 50*time.Millisecond, output.ModePlain)
	out := buf.String()
	if azureConcerns(clean) != 0 {
		t.Fatalf("clean VM should have 0 concerns, got %d", azureConcerns(clean))
	}
	if !strings.Contains(out, "Azure VM healthy") {
		t.Errorf("clean VM should print the healthy summary; got:\n%s", out)
	}
	if strings.Count(out, "nothing flagged") != 2 {
		t.Errorf("both blocks should show 'nothing flagged'; got:\n%s", out)
	}
}
