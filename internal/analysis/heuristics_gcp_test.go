package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckGCP_NonGCPSilent(t *testing.T) {
	if got := checkGCP(models.GCPInfo{}); got != nil {
		t.Errorf("non-GCP should yield no insights, got %v", got)
	}
}

func TestCheckGCP_HealthyRecognition(t *testing.T) {
	g := models.GCPInfo{
		IsGCP:               true,
		NICDriver:           "gve",
		UsesGVNIC:           true,
		GuestAgentInstalled: true, GuestAgentRunning: true,
		MaintenanceChecked: true, OnHostMaintenance: "MIGRATE",
		OSLoginChecked: true, OSLoginEnabled: true,
		TimeSyncChecked: true, UsesMetadataNTP: true,
	}
	got := checkGCP(g)
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("healthy = %+v, want one INFO recognition line", got)
	}
	for _, want := range []string{"gVNIC", "guest agent running", "on-host-maintenance=MIGRATE", "OS Login enabled", "metadata NTP"} {
		if !strings.Contains(got[0].Message, want) {
			t.Errorf("recognition line missing %q: %q", want, got[0].Message)
		}
	}
}

func TestCheckGCP_GuestAgentDownWarns(t *testing.T) {
	got := checkGCP(models.GCPInfo{IsGCP: true, GuestAgentInstalled: true, GuestAgentRunning: false})
	if !hasAWSInsight(got, "WARN", "guest agent", "installed but not running") {
		t.Errorf("guest agent installed-not-running should WARN, got %+v", got)
	}
}

func TestCheckGCP_TerminatePolicyWarnsOnNonPreemptible(t *testing.T) {
	got := checkGCP(models.GCPInfo{
		IsGCP: true, MaintenanceChecked: true, OnHostMaintenance: "TERMINATE", Preemptible: false,
	})
	if !hasAWSInsight(got, "WARN", "TERMINATE", "STOPPED") {
		t.Errorf("TERMINATE on non-preemptible should WARN, got %+v", got)
	}
}

func TestCheckGCP_TerminateOnPreemptibleIsQuiet(t *testing.T) {
	// A preemptible VM is EXPECTED to terminate on maintenance — must not WARN.
	got := checkGCP(models.GCPInfo{
		IsGCP: true, MaintenanceChecked: true, OnHostMaintenance: "TERMINATE", Preemptible: true,
	})
	for _, i := range got {
		if i.Level == "WARN" && strings.Contains(i.Message, "TERMINATE") {
			t.Errorf("preemptible TERMINATE must not WARN: %q", i.Message)
		}
	}
}

func TestCheckGCP_ActiveMaintenanceWarns(t *testing.T) {
	got := checkGCP(models.GCPInfo{
		IsGCP: true, MaintenanceChecked: true, OnHostMaintenance: "MIGRATE",
		ActiveMaintenance: "MIGRATE_ON_HOST_MAINTENANCE",
	})
	if !hasAWSInsight(got, "WARN", "host-maintenance event is in progress") {
		t.Errorf("active maintenance should WARN, got %+v", got)
	}
}

func TestCheckGCP_UnreadMaintenanceNotClaimed(t *testing.T) {
	// This collector only runs behind IsGCP (DMI-confirmed), so
	// MaintenanceChecked==false here means the metadata query itself failed —
	// on-host-maintenance is a MANDATORY attribute every GCE VM has, unlike
	// OSLoginChecked (optional, a 404 is normal). Must disclose an explicit
	// could-not-verify INFO, not just omit the policy from a fallback
	// recognition line.
	got := checkGCP(models.GCPInfo{IsGCP: true, MaintenanceChecked: false})
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("unread maintenance = %+v, want one INFO disclosure", got)
	}
	if strings.Contains(got[0].Message, "on-host-maintenance=") {
		t.Errorf("must not state a maintenance policy when unmeasured: %q", got[0].Message)
	}
	if !strings.Contains(got[0].Message, "could not verify") {
		t.Errorf("must disclose that maintenance policy could not be verified, got %q", got[0].Message)
	}
}

func TestCheckGCP_TimeSyncInfo(t *testing.T) {
	got := checkGCP(models.GCPInfo{IsGCP: true, TimeSyncChecked: true, UsesMetadataNTP: false})
	if !hasAWSInsight(got, "INFO", "metadata server") {
		t.Errorf("non-metadata time sync should INFO, got %+v", got)
	}
}
