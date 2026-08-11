package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestDiskGrowthHints_Default covers the default case in diskGrowthHints — a
// filesystem type that is not ext*, xfs, or btrfs must produce a generic grow hint.
func TestDiskGrowthHints_Default(t *testing.T) {
	t.Parallel()
	fs := models.FilesystemInfo{Mount: "/srv", Device: "/dev/sdc1", FSType: "vfat"}
	hints := diskGrowthHints(fs)
	if len(hints) == 0 {
		t.Fatal("expected at least one hint for unknown filesystem type, got none")
	}
	if !strings.Contains(hints[0], "vfat") {
		t.Errorf("default hint must name the filesystem type, got %q", hints[0])
	}
}

// TestCheckAppArmorDenials_MoreThanFiveGroups covers the i >= 5 break branch inside
// checkAppArmorDenials — when more than 5 denial groups are present, the hints list
// must cap at 5 entries and append a "...and N more" line.
func TestCheckAppArmorDenials_MoreThanFiveGroups(t *testing.T) {
	t.Parallel()
	groups := make([]models.AppArmorDenial, 7)
	for i := range groups {
		groups[i] = models.AppArmorDenial{
			Profile:   "/usr/sbin/app",
			Operation: "read",
			Path:      "/etc/shadow",
			Count:     i + 1,
		}
	}
	sec := models.SecurityInfo{AppArmorGroups: groups}
	got := checkAppArmorDenials(sec)
	if len(got) == 0 {
		t.Fatal("expected a WARN insight, got none")
	}
	if got[0].Level != "WARN" {
		t.Errorf("expected WARN, got %q", got[0].Level)
	}
	found := false
	for _, h := range got[0].Hints {
		if strings.Contains(h, "more group") {
			found = true
		}
	}
	if !found {
		t.Errorf("hints must contain '... and N more group(s)' when >5 groups, got %v", got[0].Hints)
	}
}

// TestCheckPostBoot_UnrecognizedStateDisclosesUnrecognized covers the default
// case at the end of checkPostBoot — when Available is true but State is not
// one of the three known values. internal-analysis-06-02: this must disclose
// an INFO rather than silently return nil, without panicking.
func TestCheckPostBoot_UnrecognizedStateDisclosesUnrecognized(t *testing.T) {
	t.Parallel()
	got := checkPostBoot(models.PostBootInfo{Available: true, State: "unknown-future-state"})
	if !hasInsightMsg(got, "INFO", "not a recognized value") {
		t.Errorf("unrecognized state must disclose it could not be confirmed, got %+v", got)
	}
}

// TestSecurityUpdateInsight_Default covers the default case in securityUpdateInsight
// — a package manager with real severity (e.g. dnf) that has security updates but
// zero critical or important ones falls through to a generic WARN.
func TestSecurityUpdateInsight_Default(t *testing.T) {
	t.Parallel()
	pkg := models.PackagesInfo{
		PackageManager:   "dnf",
		SecurityUpdates:  3,
		CriticalUpdates:  0,
		ImportantUpdates: 0,
	}
	got := securityUpdateInsight(pkg)
	if len(got) == 0 {
		t.Fatal("expected a WARN insight for default security updates, got none")
	}
	if got[0].Level != "WARN" {
		t.Errorf("default security updates must be WARN, got %q", got[0].Level)
	}
	if !strings.Contains(got[0].Message, "3 security update") {
		t.Errorf("message must report count, got %q", got[0].Message)
	}
}

// TestVMwareVMXNETCheck_RxOOB covers the RxOOB branch inside vmwareVMXNETCheck —
// a NIC with RX ring out-of-buffer events above the rate floor must WARN and name
// the specific counter in the message.
func TestVMwareVMXNETCheck_RxOOB(t *testing.T) {
	t.Parallel()
	v := models.VMwareInfo{
		IsGuest: true,
		VMXNETStats: []models.VMXNETStats{
			{Iface: "ens192", RxOOB: 50_000, RxPackets: 1_000_000, TxPackets: 1_000_000},
		},
	}
	got := vmwareVMXNETCheck(v)
	if len(got) == 0 {
		t.Fatal("expected a WARN for high RxOOB, got none")
	}
	if got[0].Level != "WARN" {
		t.Errorf("expected WARN, got %q", got[0].Level)
	}
	if !strings.Contains(got[0].Message, "out-of-buffer") {
		t.Errorf("message must mention RX ring out-of-buffer, got %q", got[0].Message)
	}
}
