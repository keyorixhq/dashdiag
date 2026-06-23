package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckAzure_NonAzureSilent(t *testing.T) {
	if got := checkAzure(models.AzureInfo{}); got != nil {
		t.Errorf("non-Azure should yield no insights, got %v", got)
	}
}

func TestCheckAzure_HealthyANRecognition(t *testing.T) {
	// AN active (VF bonded + up), waagent running, Hyper-V PTP → one INFO recognition
	// line asserting only what was observed.
	a := models.AzureInfo{
		IsAzure:          true,
		SyntheticNICs:    []string{"eth0"},
		AN:               []models.ANIface{{VF: "enP1s2", Driver: "mlx5_core", Synthetic: "eth0", Bonded: true, Up: true}},
		HasVF:            true,
		WAAgentInstalled: true, WAAgentRunning: true,
		TimeSyncChecked: true, UsesHyperVPTP: true,
	}
	got := checkAzure(a)
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("healthy = %+v, want one INFO line", got)
	}
	for _, want := range []string{"Accelerated Networking active", "mlx5_core", "waagent running", "Hyper-V PTP"} {
		if !strings.Contains(got[0].Message, want) {
			t.Errorf("recognition line missing %q: %q", want, got[0].Message)
		}
	}
}

func TestCheckAzure_SyntheticOnlyIsQuiet(t *testing.T) {
	// A VM with no AN VF (AN simply not enabled) must NOT be nagged — it gets a single
	// recognition line describing the synthetic path, no WARN.
	a := models.AzureInfo{
		IsAzure:          true,
		SyntheticNICs:    []string{"eth0"},
		HasVF:            false,
		WAAgentInstalled: true, WAAgentRunning: true,
		TimeSyncChecked: true, UsesHyperVPTP: true,
	}
	got := checkAzure(a)
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("synthetic-only = %+v, want one INFO line, no WARN", got)
	}
	if !strings.Contains(got[0].Message, "synthetic hv_netvsc path") {
		t.Errorf("recognition line should note the synthetic path: %q", got[0].Message)
	}
}

func TestCheckAzure_VFPresentNotBonded(t *testing.T) {
	// The real AN failure: a VF exists but is not bonded under a synthetic NIC → WARN,
	// and no "AN active" recognition line.
	a := models.AzureInfo{
		IsAzure:       true,
		SyntheticNICs: []string{"eth0"},
		AN:            []models.ANIface{{VF: "enP1s2", Driver: "mlx5_core", Bonded: false, Up: true}},
		HasVF:         true,
	}
	got := checkAzure(a)
	if !hasAWSInsight(got, "WARN", "enP1s2", "NOT bonded") {
		t.Errorf("unbonded VF should WARN, got %+v", got)
	}
	for _, i := range got {
		if strings.Contains(i.Message, "Accelerated Networking active") {
			t.Errorf("must not claim AN active when the VF is unbonded: %q", i.Message)
		}
	}
}

func TestCheckAzure_VFBondedButDown(t *testing.T) {
	a := models.AzureInfo{
		IsAzure: true,
		AN:      []models.ANIface{{VF: "enP1s2", Driver: "mana", Synthetic: "eth0", Bonded: true, Up: false}},
		HasVF:   true,
	}
	got := checkAzure(a)
	if !hasAWSInsight(got, "WARN", "enP1s2", "operstate is down") {
		t.Errorf("bonded-but-down VF should WARN, got %+v", got)
	}
}

func TestCheckAzure_WAAgentDown(t *testing.T) {
	got := checkAzure(models.AzureInfo{IsAzure: true, WAAgentInstalled: true, WAAgentRunning: false})
	if !hasAWSInsight(got, "WARN", "waagent", "installed but not running") {
		t.Errorf("waagent installed-not-running should WARN, got %+v", got)
	}
}

func TestCheckAzure_TimeSyncInfo(t *testing.T) {
	got := checkAzure(models.AzureInfo{IsAzure: true, TimeSyncChecked: true, UsesHyperVPTP: false})
	if !hasAWSInsight(got, "INFO", "Hyper-V PTP clock") {
		t.Errorf("non-PTP time sync should INFO, got %+v", got)
	}
}
