package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// hasOCIInsight reports whether any insight matches level and contains all substrings.
func hasOCIInsight(ins []models.Insight, level string, subs ...string) bool {
	for _, i := range ins {
		if i.Level != level {
			continue
		}
		ok := true
		for _, s := range subs {
			if !strings.Contains(i.Message, s) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestCheckOCI_NonOCISilent(t *testing.T) {
	if got := checkOCI(models.OCIInfo{}); got != nil {
		t.Errorf("non-OCI should yield no insights, got %v", got)
	}
}

// A clean instance (IMDS v2 enforced, agent + updater running, time synced,
// clean VNIC) must emit exactly one INFO recognition line asserting only what
// was actually verified.
func TestCheckOCI_HealthyRecognition(t *testing.T) {
	o := models.OCIInfo{
		IsOCI:               true,
		Shape:               "VM.Standard.A1.Flex",
		IMDSChecked:         true,
		AgentChecked:        true,
		AgentInstalled:      true,
		AgentRunning:        true,
		AgentUpdaterRunning: true,
		TimeSyncChecked:     true,
		UsesOCITimeSync:     true,
		TimeSynced:          true,
		VNICChecked:         true,
		VNICs:               []models.OCIVNIC{{Iface: "enp0s6", Driver: "virtio_net"}},
	}
	got := checkOCI(o)
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("healthy = %+v, want one INFO line", got)
	}
	for _, want := range []string{"VM.Standard.A1.Flex", "IMDS v2 enforced", "cloud agent running", "time synced", "VNIC rings clean"} {
		if !strings.Contains(got[0].Message, want) {
			t.Errorf("recognition line missing %q: %q", want, got[0].Message)
		}
	}
}

func TestCheckOCI_IMDSv1OpenWarns(t *testing.T) {
	o := models.OCIInfo{IsOCI: true, IMDSChecked: true, IMDSv1Open: true}
	got := checkOCI(o)
	if !hasOCIInsight(got, "WARN", "legacy/unauthenticated IMDS access") {
		t.Errorf("expected IMDS v1 open WARN, got %+v", got)
	}
}

func TestCheckOCI_IMDSNotCheckedSilent(t *testing.T) {
	// IMDSChecked=false must never imply a posture — no insight from this sub-check.
	o := models.OCIInfo{IsOCI: true}
	got := checkOCI(o)
	if hasOCIInsight(got, "WARN", "IMDS") {
		t.Errorf("unchecked IMDS should not fire any IMDS insight, got %+v", got)
	}
}

func TestCheckOCI_AgentInstalledNotRunningWarns(t *testing.T) {
	o := models.OCIInfo{
		IsOCI: true, AgentChecked: true, AgentInstalled: true,
		AgentRunning: false, AgentUpdaterRunning: true,
	}
	got := checkOCI(o)
	if !hasOCIInsight(got, "WARN", "oracle-cloud-agent is installed but not running") {
		t.Errorf("expected agent-not-running WARN, got %+v", got)
	}
}

func TestCheckOCI_AgentNotInstalledSilent(t *testing.T) {
	// Not installed (e.g. a custom, non-Oracle-provided image) must not fire any
	// agent insight — only "installed but broken" is actionable.
	o := models.OCIInfo{IsOCI: true, AgentChecked: true, AgentInstalled: false}
	got := checkOCI(o)
	if hasOCIInsight(got, "WARN", "oracle-cloud-agent") || hasOCIInsight(got, "INFO", "oracle-cloud-agent") {
		t.Errorf("agent-not-installed should not fire an agent insight, got %+v", got)
	}
}

func TestCheckOCI_UpdaterNotRunningInfo(t *testing.T) {
	o := models.OCIInfo{
		IsOCI: true, AgentChecked: true, AgentInstalled: true,
		AgentRunning: true, AgentUpdaterRunning: false,
	}
	got := checkOCI(o)
	if !hasOCIInsight(got, "INFO", "oracle-cloud-agent-updater is not running") {
		t.Errorf("expected updater-not-running INFO, got %+v", got)
	}
}

func TestCheckOCI_NotUsingOCITimeSyncIsInfoNotWarn(t *testing.T) {
	o := models.OCIInfo{IsOCI: true, TimeSyncChecked: true, UsesOCITimeSync: false}
	got := checkOCI(o)
	if !hasOCIInsight(got, "INFO", "NTP is not pointed at OCI's metadata NTP server") {
		t.Errorf("expected not-using-OCI-NTP INFO, got %+v", got)
	}
	if hasOCIInsight(got, "WARN", "NTP") {
		t.Errorf("not using OCI's NTP source is a preference, not a fault — should not WARN, got %+v", got)
	}
}

func TestCheckOCI_ConfiguredButNotSyncedWarns(t *testing.T) {
	// Configured against OCI's NTP server but chrony shows no synced source —
	// a real gap (e.g. a security-list change blocking the link-local path).
	o := models.OCIInfo{IsOCI: true, TimeSyncChecked: true, UsesOCITimeSync: true, TimeSynced: false}
	got := checkOCI(o)
	if !hasOCIInsight(got, "WARN", "configured against OCI's metadata NTP server but chrony shows no synced source") {
		t.Errorf("expected configured-but-not-synced WARN, got %+v", got)
	}
}

func TestCheckOCI_VNICRingDropsWarn(t *testing.T) {
	o := models.OCIInfo{
		IsOCI: true, VNICChecked: true,
		VNICs: []models.OCIVNIC{{Iface: "enp0s6", Driver: "virtio_net", RxDrops: 42, TxTimeouts: 1}},
	}
	got := checkOCI(o)
	if !hasOCIInsight(got, "WARN", "enp0s6", "42 rx drop(s)", "1 tx timeout(s)") {
		t.Errorf("expected VNIC ring-drop WARN with both counts, got %+v", got)
	}
}

func TestCheckOCI_VNICCleanNoInsight(t *testing.T) {
	o := models.OCIInfo{
		IsOCI: true, VNICChecked: true,
		VNICs: []models.OCIVNIC{{Iface: "enp0s6", Driver: "virtio_net", RxDrops: 0, TxTimeouts: 0}},
	}
	got := checkOCI(o)
	if hasOCIInsight(got, "WARN", "enp0s6") {
		t.Errorf("zero drops/timeouts should not fire a VNIC insight, got %+v", got)
	}
}
