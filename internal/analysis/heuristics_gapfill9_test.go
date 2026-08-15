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

// TestDiskGrowthHints_UnsafeTokenFallback covers cmd-04-05: fs.Device/fs.Mount
// are parsed verbatim from /proc/mounts-shaped data with no charset
// restriction. diskGrowthHints splices them into copy-pasteable "to fix:"
// shell commands for ext*/xfs/btrfs, so a value containing shell
// metacharacters must never reach the spliced hint — it must fall back to a
// generic, non-pasteable hint instead (mirrors the RAUC inactive-slot pattern
// in heuristics_steamos.go). A well-formed value must still produce the
// specific, copy-pasteable command.
func TestDiskGrowthHints_UnsafeTokenFallback(t *testing.T) {
	t.Parallel()
	const evil = "/dev/sda1; rm -rf /"
	cases := []struct {
		name       string
		fs         models.FilesystemInfo
		wantSubstr string // must appear in hints[0]
		wantAbsent string // must NOT appear anywhere in hints
	}{
		{"ext4 safe device produces specific command", models.FilesystemInfo{FSType: "ext4", Device: "/dev/sda1"}, "resize2fs /dev/sda1", ""},
		{"ext4 unsafe device falls back to generic hint", models.FilesystemInfo{FSType: "ext4", Device: evil}, "withheld", evil},
		{"xfs safe mount produces specific command", models.FilesystemInfo{FSType: "xfs", Mount: "/data"}, "xfs_growfs /data", ""},
		{"xfs unsafe mount falls back to generic hint", models.FilesystemInfo{FSType: "xfs", Mount: evil}, "withheld", evil},
		{"btrfs safe mount produces specific command", models.FilesystemInfo{FSType: "btrfs", Mount: "/data"}, "btrfs filesystem resize max /data", ""},
		{"btrfs unsafe mount falls back to generic hint", models.FilesystemInfo{FSType: "btrfs", Mount: evil}, "withheld", evil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			hints := diskGrowthHints(c.fs)
			if len(hints) == 0 {
				t.Fatal("expected at least one hint, got none")
			}
			if !strings.Contains(hints[0], c.wantSubstr) {
				t.Errorf("hints[0] = %q, want substring %q", hints[0], c.wantSubstr)
			}
			if c.wantAbsent != "" {
				for _, h := range hints {
					if strings.Contains(h, c.wantAbsent) {
						t.Errorf("hint %q must not splice unsafe raw value %q", h, c.wantAbsent)
					}
				}
			}
		})
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
