package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// gceInfo has self-serve config issues (guest agent stopped, a TERMINATE-on-
// maintenance policy on a non-preemptible VM, non-metadata time sync) and the
// Google-side activity item: a host-maintenance event in progress.
func gceInfo() *models.GCPInfo {
	return &models.GCPInfo{
		IsGCP: true, UsesGVNIC: true,
		GuestAgentInstalled: true, GuestAgentRunning: false,
		MaintenanceChecked: true, ActiveMaintenance: "MIGRATE_ON_HOST_MAINTENANCE",
		OnHostMaintenance: "TERMINATE", Preemptible: false,
		TimeSyncChecked: true, UsesMetadataNTP: false,
	}
}

func TestPrintGCPReport_TwoBlockSplit(t *testing.T) {
	var buf bytes.Buffer
	printGCPReport(&buf, gceInfo(), 100*time.Millisecond, output.ModePlain)
	out := buf.String()
	t.Logf("\n%s", out)

	guestHdr := "Your VM — you can fix these"
	provHdr := "Host-side — Google Cloud activity to correlate"
	gi, pi := strings.Index(out, guestHdr), strings.Index(out, provHdr)
	if gi < 0 || pi < 0 {
		t.Fatalf("both block headers must be present; got:\n%s", out)
	}
	if gi > pi {
		t.Errorf("self-serve block must come before the provider block")
	}
	guestBlock, provBlock := out[gi:pi], out[pi:]

	for _, want := range []string{"guest agent", "TERMINATE"} {
		if !strings.Contains(guestBlock, want) {
			t.Errorf("self-serve block missing %q", want)
		}
	}
	if !strings.Contains(provBlock, "maintenance event is in progress") {
		t.Errorf("provider block missing the active-maintenance finding")
	}
	if strings.Contains(provBlock, "guest agent") {
		t.Errorf("guest agent (self-serve) leaked into the provider block")
	}
	// guest agent + TERMINATE policy + active maintenance = 3 WARN; time sync is INFO.
	if c := gcpConcerns(gceInfo()); c != 3 {
		t.Errorf("gcpConcerns = %d, want 3 (guest agent + TERMINATE + active maintenance; time-sync INFO)", c)
	}
	if !strings.Contains(out, "3 GCE issue(s) found") {
		t.Errorf("summary should report 3 issues; got:\n%s", out)
	}
}

func TestPrintGCPReport_Healthy(t *testing.T) {
	clean := &models.GCPInfo{
		IsGCP: true, UsesGVNIC: true,
		GuestAgentInstalled: true, GuestAgentRunning: true,
		MaintenanceChecked: true, OnHostMaintenance: "MIGRATE", Preemptible: false,
		TimeSyncChecked: true, UsesMetadataNTP: true,
	}
	var buf bytes.Buffer
	printGCPReport(&buf, clean, 50*time.Millisecond, output.ModePlain)
	out := buf.String()
	if gcpConcerns(clean) != 0 {
		t.Fatalf("clean VM should have 0 concerns, got %d", gcpConcerns(clean))
	}
	if !strings.Contains(out, "GCE guest healthy") {
		t.Errorf("clean VM should print the healthy summary; got:\n%s", out)
	}
	if strings.Count(out, "nothing flagged") != 2 {
		t.Errorf("both blocks should show 'nothing flagged'; got:\n%s", out)
	}
}
