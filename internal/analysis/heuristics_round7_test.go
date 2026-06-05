package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
)

// Round-7 characterization tests for the subscription/compliance tail:
// SUSE/RHEL/Ubuntu-Pro/PVE subscriptions, journald config & activity, LVM RAID,
// security-baseline drift, and cron quality/anacron schedules. Pure functions.

func TestCheckSUSESubscription(t *testing.T) {
	tests := []struct {
		name string
		s    models.SUSEConnectInfo
		want string
	}{
		{"unregistered is WARN", models.SUSEConnectInfo{Registered: false}, "WARN"},
		{"expired is CRIT", models.SUSEConnectInfo{Registered: true, ExpiresDays: 0}, "CRIT"},
		{"expiring soon is CRIT", models.SUSEConnectInfo{Registered: true, ExpiresDays: 10}, "CRIT"},
		{"expiring within 30d is WARN", models.SUSEConnectInfo{Registered: true, ExpiresDays: 20}, "WARN"},
		{"healthy is clean", models.SUSEConnectInfo{Registered: true, ExpiresDays: 60}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkSUSESubscription(tt.s), tt.want)
		})
	}
}

func TestCheckRHELSubscription(t *testing.T) {
	assertLevel(t, checkRHELSubscription(models.SUSEConnectInfo{Status: "current"}), "")
	assertLevel(t, checkRHELSubscription(models.SUSEConnectInfo{Status: "unregistered"}), "WARN")
	assertLevel(t, checkRHELSubscription(models.SUSEConnectInfo{Status: "expired"}), "CRIT")
}

func TestCheckUbuntuPro(t *testing.T) {
	assertLevel(t, checkUbuntuPro(models.SUSEConnectInfo{Status: "attached"}), "")
	assertLevel(t, checkUbuntuPro(models.SUSEConnectInfo{Status: "detached"}), "INFO")
}

// TestCheckSUSEConnect covers the platform dispatcher.
func TestCheckSUSEConnect(t *testing.T) {
	assertLevel(t, checkSUSEConnect(models.SUSEConnectInfo{Platform: "rhel", Status: "expired"}), "CRIT")
	assertLevel(t, checkSUSEConnect(models.SUSEConnectInfo{Platform: "ubuntu-pro", Status: "detached"}), "INFO")
	assertLevel(t, checkSUSEConnect(models.SUSEConnectInfo{Platform: "suse", Registered: false}), "WARN")
	assertLevel(t, checkSUSEConnect(models.SUSEConnectInfo{Platform: "", Registered: true, ExpiresDays: 60}), "")
}

func TestCheckPVESubscription(t *testing.T) {
	pve := func(status string) models.PVEInfo {
		return models.PVEInfo{Subscription: models.PVESubscription{Status: status}}
	}
	assertLevel(t, checkPVESubscription(pve("active")), "")
	assertLevel(t, checkPVESubscription(pve("notfound")), "WARN")
	assertLevel(t, checkPVESubscription(pve("")), "WARN")
	assertLevel(t, checkPVESubscription(pve("expired")), "CRIT")
}

func TestCheckJournalConfig(t *testing.T) {
	tests := []struct {
		name string
		logs models.LogsInfo
		want string
	}{
		{"clean is empty", models.LogsInfo{}, ""},
		{"corrupt journal is CRIT", models.LogsInfo{JournalCorrupt: true}, "CRIT"},
		{"volatile journal is WARN", models.LogsInfo{JournalVolatile: true}, "WARN"},
		{"no text fallback is INFO", models.LogsInfo{JournalNoTextFallback: true}, "INFO"},
		{"log disk >=90 is CRIT", models.LogsInfo{LogDiskUsedPct: 95, LogDiskMount: "/var"}, "CRIT"},
		{"log disk >=80 is WARN", models.LogsInfo{LogDiskUsedPct: 85, LogDiskMount: "/var"}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkJournalConfig(tt.logs), tt.want)
		})
	}
}

func TestCheckJournalActivity(t *testing.T) {
	assertLevel(t, checkJournalActivity(models.LogsInfo{}), "")
	assertLevel(t, checkJournalActivity(models.LogsInfo{CoreDumpCount: 1}), "WARN")
	assertLevel(t, checkJournalActivity(models.LogsInfo{ErrorCount: 60}), "WARN")
	assertLevel(t, checkJournalActivity(models.LogsInfo{ErrorCount: 20}), "INFO")
}

func TestCheckLVMRaid(t *testing.T) {
	assertLevel(t, checkLVMRaid(models.LVMInfo{}), "")
	assertLevel(t, checkLVMRaid(models.LVMInfo{RaidLVs: []models.LVMRaidLV{{Name: "lv", VG: "vg", Type: "raid1", Degraded: true}}}), "CRIT")
	assertLevel(t, checkLVMRaid(models.LVMInfo{RaidLVs: []models.LVMRaidLV{{Name: "lv", VG: "vg", Type: "raid1", Resyncing: true, SyncPct: 50}}}), "INFO")
}

func TestCheckSecurityDrift(t *testing.T) {
	assertLevel(t, checkSecurityDrift(nil), "")
	assertLevel(t, checkSecurityDrift(&baseline.SecurityDiff{}), "") // no changes
	assertLevel(t, checkSecurityDrift(&baseline.SecurityDiff{NewSUIDs: []string{"/usr/local/bin/x"}}), "CRIT")
	assertLevel(t, checkSecurityDrift(&baseline.SecurityDiff{ChangedSSHFiles: []string{"sshd_config"}}), "WARN")
	assertLevel(t, checkSecurityDrift(&baseline.SecurityDiff{NewSudoEntries: []string{"bob NOPASSWD"}}), "WARN")
}

func TestCheckCronQuality(t *testing.T) {
	assertLevel(t, checkCronQuality(nil), "")
	assertLevel(t, checkCronQuality([]models.CronJob{{Source: "/etc/cron.d/x", Issues: []string{"command not found: foo"}}}), "WARN")
	assertLevel(t, checkCronQuality([]models.CronJob{{Source: "/etc/cron.d/x", Issues: []string{"no PATH= set"}}}), "INFO")
}

func TestCheckAnacronSchedules(t *testing.T) {
	assertLevel(t, checkAnacronSchedules(nil), "")
	assertLevel(t, checkAnacronSchedules([]models.AnacronJob{{Name: "daily", LastRunH: -1}}), "INFO")
	assertLevel(t, checkAnacronSchedules([]models.AnacronJob{{Name: "daily", LastRunH: 48, OverdueH: 24}}), "WARN")
}
