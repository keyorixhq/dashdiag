package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Round-6 characterization tests for the long-tail heuristics: package updates &
// integrity, firmware, cloud-metadata events, auditd, huge pages, CPU frequency
// governor, D-Bus, launchd, and cgroup-v2 slices. Pure functions; reuses assertLevel.

func TestCheckPackages(t *testing.T) {
	tests := []struct {
		name string
		pkg  models.PackagesInfo
		want string
	}{
		{"no security repo is WARN", models.PackagesInfo{Status: "no-security-repo"}, "WARN"},
		{"no updates is clean", models.PackagesInfo{SecurityUpdates: 0}, ""},
		{"stale metadata is INFO (unverified, not up-to-date)", models.PackagesInfo{SecurityUpdates: 0, Status: "stale-metadata", PackageManager: "apt", StatusReason: "update metadata is 40 days old — cannot confirm packages are up to date"}, "INFO"},
		// The security query itself failed → INFO "couldn't verify", never a silent
		// clean 0-updates OK (dnf/zypper/apt errored; zypper used to claim Status:OK).
		{"query failed is INFO (unverified, not clean)", models.PackagesInfo{SecurityUpdates: 0, Status: "query-failed", PackageManager: "dnf", StatusReason: "dnf advisory/updateinfo unavailable"}, "INFO"},
		{"ESM-only updates is WARN", models.PackagesInfo{SecurityUpdates: 0, ESMUpdates: 3}, "WARN"},
		{"critical updates is CRIT", models.PackagesInfo{SecurityUpdates: 5, CriticalUpdates: 1, PackageManager: "apt"}, "CRIT"},
		{"important updates is WARN", models.PackagesInfo{SecurityUpdates: 5, ImportantUpdates: 1, PackageManager: "apt"}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkPackages(tt.pkg), tt.want)
		})
	}
}

func TestCheckPackageIntegrity(t *testing.T) {
	tests := []struct {
		name string
		pi   models.PackageIntegrity
		want string
	}{
		{"healthy is clean", models.PackageIntegrity{LdconfigOK: true}, ""},
		{"broken packages is CRIT", models.PackageIntegrity{LdconfigOK: true, BrokenPackages: []string{"x"}}, "CRIT"},
		{"unmet deps is CRIT", models.PackageIntegrity{LdconfigOK: true, UnmetDeps: []string{"y"}}, "CRIT"},
		{"missing libs is CRIT", models.PackageIntegrity{LdconfigOK: true, MissingLibs: []string{"libz.so"}}, "CRIT"},
		{"rpm verify failures is WARN", models.PackageIntegrity{LdconfigOK: true, RPMVerifyFailed: []string{"/bin/ls"}}, "WARN"},
		{"ldconfig broken is WARN", models.PackageIntegrity{LdconfigOK: false}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkPackageIntegrity(tt.pi), tt.want)
		})
	}
}

func TestCheckFirmware(t *testing.T) {
	assertLevel(t, checkFirmware(models.FirmwareInfo{Available: false}), "")
	assertLevel(t, checkFirmware(models.FirmwareInfo{Available: true, UpgradeCount: 0}), "")
	assertLevel(t, checkFirmware(models.FirmwareInfo{
		Available: true, UpgradeCount: 1, SecurityCount: 1,
		Upgrades: []models.FirmwareUpgrade{{Name: "BIOS", SecurityFix: true}},
	}), "WARN")
	assertLevel(t, checkFirmware(models.FirmwareInfo{Available: true, UpgradeCount: 1, SecurityCount: 0}), "INFO")
}

func TestCheckCloudMeta(t *testing.T) {
	assertLevel(t, checkCloudMeta(models.CloudInfo{Available: false}), "")
	assertLevel(t, checkCloudMeta(models.CloudInfo{Available: true, Provider: "aws", SpotTermination: true}), "CRIT")
	assertLevel(t, checkCloudMeta(models.CloudInfo{Available: true, Provider: "gcp", MaintenanceEvent: true}), "WARN")
}

func TestCheckAuditd(t *testing.T) {
	assertLevel(t, checkAuditd(models.AuditInfo{Available: false}), "")
	assertLevel(t, checkAuditd(models.AuditInfo{Available: true, Running: true}), "")
	assertLevel(t, checkAuditd(models.AuditInfo{Available: true, Running: false}), "WARN")
	assertLevel(t, checkAuditd(models.AuditInfo{Available: true, Running: true, AuditLogSizeGB: 15}), "WARN")
}

func TestCheckHugePages(t *testing.T) {
	tests := []struct {
		name string
		h    models.HugePagesInfo
		want string
	}{
		{"not configured is silent", models.HugePagesInfo{Configured: 0, THPEnabled: false}, ""},
		{"mostly-unused static pages is WARN", models.HugePagesInfo{Configured: 100, Used: 10, ReservedGB: 2}, "WARN"},
		{"fully-used pages is INFO", models.HugePagesInfo{Configured: 100, Used: 100, ReservedGB: 1}, "INFO"},
		{"THP always is INFO", models.HugePagesInfo{THPEnabled: true, THPMode: "always"}, "INFO"},
		{"normal usage is clean", models.HugePagesInfo{Configured: 100, Used: 50, THPMode: "never"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkHugePages(tt.h), tt.want)
		})
	}
}

func TestCheckCPUFreq(t *testing.T) {
	assertLevel(t, checkCPUFreq(models.CPUFreqInfo{Governor: ""}), "") // unavailable
	assertLevel(t, checkCPUFreq(models.CPUFreqInfo{Governor: "performance"}), "")
	assertLevel(t, checkCPUFreq(models.CPUFreqInfo{Governor: "powersave", CurrentMHz: 800, MaxMHz: 3000}), "WARN")
	assertLevel(t, checkCPUFreq(models.CPUFreqInfo{Governor: "schedutil", ThrottledPct: 50, CurrentMHz: 1500, MaxMHz: 3000}), "WARN")
}

func TestCheckDBus(t *testing.T) {
	assertLevel(t, checkDBus(models.DBusInfo{Status: "n/a"}), "") // not applicable
	assertLevel(t, checkDBus(models.DBusInfo{Active: true, Status: "active"}), "")
	assertLevel(t, checkDBus(models.DBusInfo{Active: false, Status: "failed"}), "CRIT")
}

func TestCheckLaunchd(t *testing.T) {
	assertLevel(t, checkLaunchd(models.LaunchdInfo{}), "")
	assertLevel(t, checkLaunchd(models.LaunchdInfo{Failed: []models.LaunchdService{{Label: "com.example.daemon"}}}), "WARN")
}

func TestCheckCgroupV2(t *testing.T) {
	slice := func(s models.CgroupSlice) models.CgroupV2Info {
		return models.CgroupV2Info{Available: true, Slices: []models.CgroupSlice{s}}
	}
	tests := []struct {
		name string
		cg   models.CgroupV2Info
		want string
	}{
		{"unavailable is silent", models.CgroupV2Info{Available: false}, ""},
		{"available and quiet is clean", models.CgroupV2Info{Available: true}, ""},
		{"oom kills is CRIT", models.CgroupV2Info{Available: true, OOMKills: 1}, "CRIT"},
		{"heavy CPU throttle is CRIT", slice(models.CgroupSlice{Name: "system.slice", ThrottledPct: 25}), "CRIT"},
		{"mild CPU throttle is WARN", slice(models.CgroupSlice{Name: "system.slice", ThrottledPct: 10}), "WARN"},
		{"memory near limit is CRIT", slice(models.CgroupSlice{Name: "user.slice", HasMemLimit: true, MemUsedPct: 95}), "CRIT"},
		{"memory elevated is WARN", slice(models.CgroupSlice{Name: "user.slice", HasMemLimit: true, MemUsedPct: 80}), "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkCgroupV2(tt.cg), tt.want)
		})
	}
}
