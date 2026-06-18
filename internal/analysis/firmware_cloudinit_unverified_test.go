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
