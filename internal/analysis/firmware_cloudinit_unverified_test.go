package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// firmware / cloud-init "query failed → silent OK" closures (FALSE_OK_SWEEP #32/#35/#43).

func TestFirmwareQueryUnverified(t *testing.T) {
	// fwupd present, query failed (StatusReason set, no UpgradeCount) → INFO.
	got := checkFirmware(models.FirmwareInfo{Available: true, StatusReason: "fwupdmgr get-upgrades failed"})
	if !hasInsightMsg(got, "INFO", "could not be verified") {
		t.Errorf("failed firmware query must INFO, got %+v", got)
	}
	// recognized "nothing to do" (Status OK, no upgrades) → clean.
	if got := checkFirmware(models.FirmwareInfo{Available: true, Status: "OK"}); len(got) != 0 {
		t.Errorf("Status OK with no upgrades must be clean, got %+v", got)
	}
	// not installed → silent.
	if got := checkFirmware(models.FirmwareInfo{Available: false, StatusReason: "fwupd not installed"}); len(got) != 0 {
		t.Errorf("fwupd absent must be silent, got %+v", got)
	}
}

func TestCloudInitStatusUnverified(t *testing.T) {
	got := checkCloudInit(models.CloudInitInfo{Available: true, StatusUnverified: true})
	if !hasInsightMsg(got, "INFO", "could NOT be read") {
		t.Errorf("unverified cloud-init must INFO, got %+v", got)
	}
	// done/clean → silent.
	if got := checkCloudInit(models.CloudInitInfo{Available: true, Status: "done"}); len(got) != 0 {
		t.Errorf("done cloud-init must be silent, got %+v", got)
	}
}

// FALSE_OK_SWEEP #14: SUSEConnect --status failed → registration unverified (INFO),
// not a confident "not registered" WARN.
func TestSUSESubscriptionQueryFailed(t *testing.T) {
	got := checkSUSEConnect(models.SUSEConnectInfo{Platform: "suse", Registered: false, Status: "query-failed"})
	if !hasInsightMsg(got, "INFO", "not verified") {
		t.Errorf("query-failed SUSE registration must INFO, got %+v", got)
	}
	// Genuinely unregistered (status not query-failed) → still the WARN.
	got = checkSUSEConnect(models.SUSEConnectInfo{Platform: "suse", Registered: false})
	if !hasInsightMsg(got, "WARN", "not registered") {
		t.Errorf("genuinely unregistered must WARN, got %+v", got)
	}
}

// FALSE_OK_SWEEP #41: a transient IMDS error on the spot-termination probe must
// surface as INFO, not read as "no termination scheduled".
func TestCloudMetaSpotCheckFailed(t *testing.T) {
	got := checkCloudMeta(models.CloudInfo{Available: true, Provider: "aws", SpotCheckFailed: true})
	if !hasInsightMsg(got, "INFO", "could not be confirmed") {
		t.Errorf("spot-check-failed must INFO, got %+v", got)
	}
	// A real termination notice still CRITs (and suppresses the INFO).
	got = checkCloudMeta(models.CloudInfo{Available: true, Provider: "aws", SpotTermination: true, SpotCheckFailed: true})
	if !hasInsightMsg(got, "CRIT", "scheduled for termination") || hasInsightMsg(got, "INFO", "could not be confirmed") {
		t.Errorf("termination CRIT must win over check-failed INFO, got %+v", got)
	}
	// Normal instance (404, no flags) → silent.
	if got := checkCloudMeta(models.CloudInfo{Available: true, Provider: "aws"}); len(got) != 0 {
		t.Errorf("normal instance must be silent, got %+v", got)
	}
}
