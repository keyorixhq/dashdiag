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
		DisksChecked: true,
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
		DisksChecked: true,
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

func TestCheckAzure_TempDiskPersistentDataWarns(t *testing.T) {
	got := checkAzure(models.AzureInfo{
		IsAzure:         true,
		TempDiskPresent: true, TempDiskMount: "/mnt/resource", PersistentDataAtRisk: true,
	})
	if !hasAWSInsight(got, "WARN", "EPHEMERAL", "/mnt/resource") {
		t.Errorf("persistent data on temp disk should WARN, got %+v", got)
	}
}

func TestCheckAzure_TempDiskNormalIsQuiet(t *testing.T) {
	// A temp disk used as scratch (no persistent data) must not WARN — it folds into
	// the recognition line.
	got := checkAzure(models.AzureInfo{
		IsAzure:         true,
		TempDiskPresent: true, TempDiskMount: "/mnt", PersistentDataAtRisk: false,
		DisksChecked: true,
	})
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("normal temp disk = %+v, want one INFO line", got)
	}
	if !strings.Contains(got[0].Message, "temp disk at /mnt (ephemeral)") {
		t.Errorf("recognition should note the ephemeral temp disk: %q", got[0].Message)
	}
}

func TestCheckAzure_DataDiskReadWriteCachingWarns(t *testing.T) {
	got := checkAzure(models.AzureInfo{
		IsAzure:      true,
		DisksChecked: true,
		Disks: []models.AzureDisk{
			{IsOS: true, Caching: "ReadWrite"},                        // OS disk RW is fine — must not WARN
			{IsOS: false, Lun: 0, Caching: "None"},                    // fine
			{IsOS: false, Lun: 3, Name: "logs", Caching: "ReadWrite"}, // hazard
		},
	})
	if !hasAWSInsight(got, "WARN", "LUN 3", "ReadWrite host caching") {
		t.Errorf("data disk with ReadWrite caching should WARN, got %+v", got)
	}
	// Exactly one caching WARN — the OS disk's ReadWrite must not be flagged.
	warns := 0
	for _, i := range got {
		if i.Level == "WARN" && strings.Contains(i.Message, "host caching") {
			warns++
		}
	}
	if warns != 1 {
		t.Errorf("want exactly 1 caching WARN (not the OS disk), got %d: %+v", warns, got)
	}
}

func TestCheckAzure_UnreadStorageProfileNotClaimedOK(t *testing.T) {
	// This collector only runs behind IsAzure (DMI-confirmed), so
	// DisksChecked==false here means the IMDS storageProfile query itself
	// failed, not "not on Azure" — it must disclose an explicit could-not-
	// verify INFO, not just quietly omit "host caching OK" from a fallback
	// recognition line (the false-clean bug this test used to only half-guard:
	// silence and disclosure both satisfy "never claims OK", but only
	// disclosure tells the operator anything was unverified at all).
	got := checkAzure(models.AzureInfo{IsAzure: true, DisksChecked: false})
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("unread profile = %+v, want one INFO disclosure", got)
	}
	if strings.Contains(got[0].Message, "host caching OK") {
		t.Errorf("must not claim caching OK when unmeasured: %q", got[0].Message)
	}
	if !strings.Contains(got[0].Message, "could not verify") {
		t.Errorf("must disclose that caching could not be verified, got %q", got[0].Message)
	}
}

func TestCheckAzure_DynamicMemoryInRecognition(t *testing.T) {
	got := checkAzure(models.AzureInfo{IsAzure: true, DynamicMemory: true, DynMemMaxMB: 8192, DisksChecked: true})
	if len(got) != 1 || !strings.Contains(got[0].Message, "Dynamic Memory enabled (max 8192 MB)") {
		t.Errorf("DM should appear in recognition line, got %+v", got)
	}
}

func TestCheckAzure_LowNVMeTimeoutInfo(t *testing.T) {
	got := checkAzure(models.AzureInfo{
		IsAzure: true, NVMePresent: true, NVMeIOTimeoutChecked: true, NVMeIOTimeoutSecs: 30,
	})
	if !hasAWSInsight(got, "INFO", "nvme_core.io_timeout is 30s", "240s") {
		t.Errorf("low NVMe io_timeout should INFO, got %+v", got)
	}
}

func TestCheckAzure_AdequateNVMeTimeoutInRecognition(t *testing.T) {
	got := checkAzure(models.AzureInfo{
		IsAzure: true, NVMePresent: true, NVMeIOTimeoutChecked: true, NVMeIOTimeoutSecs: 240,
		DisksChecked: true,
	})
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("adequate timeout = %+v, want one recognition line", got)
	}
	if !strings.Contains(got[0].Message, "NVMe io_timeout=240s") {
		t.Errorf("recognition should note the tuned io_timeout: %q", got[0].Message)
	}
}

func TestCheckAzure_UnreadNVMeTimeoutNotClaimed(t *testing.T) {
	// NVMe present but io_timeout unreadable → no INFO and no recognition claim.
	got := checkAzure(models.AzureInfo{IsAzure: true, NVMePresent: true, NVMeIOTimeoutChecked: false})
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("unread timeout = %+v, want one recognition line", got)
	}
	if strings.Contains(got[0].Message, "io_timeout") {
		t.Errorf("must not state io_timeout when unmeasured: %q", got[0].Message)
	}
}
