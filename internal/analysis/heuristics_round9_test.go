package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Round-9 characterization tests: the dispatcher wrappers (Docker/ZFS/DRBD/
// journal), IPMI sensors, DNS resolv.conf quality, SUSE migration risks, cron
// daemon health, and the full SteamOS / Steam Deck check suite.

func boolPtr(b bool) *bool { return &b }

func TestCheckDocker(t *testing.T) {
	assertLevel(t, checkDocker(models.DockerInfo{Available: false}), "") // absent, no reason
	assertLevel(t, checkDocker(models.DockerInfo{Available: false, StatusReason: "docker not running"}), "WARN")
	assertLevel(t, checkDocker(models.DockerInfo{Available: true, CrashLooping: []string{"web"}}), "CRIT") // delegates
}

func TestCheckIPMI(t *testing.T) {
	assertLevel(t, checkIPMI(models.IPMIInfo{Available: false}), "")
	assertLevel(t, checkIPMI(models.IPMIInfo{Available: true}), "")
	assertLevel(t, checkIPMI(models.IPMIInfo{Available: true, PSUFailed: 1}), "CRIT")
	assertLevel(t, checkIPMI(models.IPMIInfo{Available: true, FanFailed: 1}), "WARN")
	assertLevel(t, checkIPMI(models.IPMIInfo{Available: true, TempCritical: 1}), "CRIT")
	// A failed BMC/sensor read (Status="error", Available=false) must surface as
	// WARN, not be silently swallowed by the !Available early return.
	assertLevel(t, checkIPMI(models.IPMIInfo{Available: false, Status: "error",
		StatusReason: "ipmitool available but sdr read failed"}), "WARN")
}

func TestCheckDNSQuality(t *testing.T) {
	tests := []struct {
		name string
		d    models.DNSResolverInfo
		want string
	}{
		{"clean is empty", models.DNSResolverInfo{}, ""},
		{"too many nameservers is WARN", models.DNSResolverInfo{TooManyNameservers: true, Nameservers: []string{"1", "2", "3", "4"}}, "WARN"},
		{"loopback resolver is WARN", models.DNSResolverInfo{HasLoopback: true}, "WARN"},
		{"high ndots is WARN", models.DNSResolverInfo{NdotsHigh: 5}, "WARN"},
		{"ipv6-only is WARN", models.DNSResolverInfo{IPv6Only: true}, "WARN"},
		{"duplicate nameserver is INFO", models.DNSResolverInfo{DuplicateNameserver: []string{"8.8.8.8"}}, "INFO"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkDNSQuality(tt.d), tt.want)
		})
	}
}

func TestCheckPackageExtras(t *testing.T) {
	assertLevel(t, checkPackageExtras(models.PackagesInfo{}), "")
	assertLevel(t, checkPackageExtras(models.PackagesInfo{SUSEMigrationRisks: []string{"grub2-x86_64-efi not locked"}}), "WARN")
}

func TestCheckJournalHealthInsights(t *testing.T) {
	assertLevel(t, checkJournalHealthInsights(models.LogsInfo{}), "")
	assertLevel(t, checkJournalHealthInsights(models.LogsInfo{JournalCorrupt: true}), "CRIT")
}

func TestCheckZFS(t *testing.T) {
	assertLevel(t, checkZFS(models.ZFSInfo{}), "")
	assertLevel(t, checkZFS(models.ZFSInfo{Pools: []models.ZFSPool{{Name: "tank", State: "DEGRADED", ScrubAgeDays: 5}}}), "CRIT")
}

func TestCheckDRBD(t *testing.T) {
	assertLevel(t, checkDRBD(models.DRBDInfo{}), "")
	assertLevel(t, checkDRBD(models.DRBDInfo{Resources: []models.DRBDResource{{ConnState: "SplitBrain"}}}), "CRIT")
}

func TestCheckCron(t *testing.T) {
	tests := []struct {
		name string
		c    models.CronInfo
		want string
	}{
		{"active daemon is clean", models.CronInfo{DaemonActive: true}, ""},
		{"anacron-only is INFO", models.CronInfo{DaemonActive: false, AnacronPresent: true}, "INFO"},
		{"no cron at all is WARN", models.CronInfo{DaemonActive: false, AnacronPresent: false, SystemdTimers: 0}, "WARN"},
		{"timers-only is INFO", models.CronInfo{DaemonActive: false, AnacronPresent: false, SystemdTimers: 3}, "INFO"},
		{"job failures is WARN", models.CronInfo{DaemonActive: true, Failures: []models.CronFailure{{Job: "backup.sh"}}}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkCron(tt.c), tt.want)
		})
	}
}

// ── SteamOS / Steam Deck suite ────────────────────────────────────────────────

func TestCheckSteamOSDevice(t *testing.T) {
	assertLevel(t, checkSteamOSDevice(models.SteamOSInfo{DeviceRecognised: true}), "")
	assertLevel(t, checkSteamOSDevice(models.SteamOSInfo{DeviceProductRaw: "Mystery Handheld", DeviceRecognised: false}), "INFO")
	assertLevel(t, checkSteamOSDevice(models.SteamOSInfo{SecureBootApplicable: true, SecureBootEnabled: boolPtr(true)}), "WARN")
}

func TestCheckSteamOSUpdate(t *testing.T) {
	assertLevel(t, checkSteamOSUpdate(models.SteamOSInfo{RAUCAvailable: true, RAUCBootedSlot: "A", RAUCBootedStatus: "good"}), "")
	assertLevel(t, checkSteamOSUpdate(models.SteamOSInfo{RAUCAvailable: true, RAUCBootedSlot: "A", RAUCBootedStatus: "bad"}), "CRIT")
	assertLevel(t, checkSteamOSUpdate(models.SteamOSInfo{RAUCAvailable: true, RAUCInactiveSlot: "B", RAUCInactiveStatus: "bad"}), "WARN")
}

func TestCheckSteamOSSession(t *testing.T) {
	assertLevel(t, checkSteamOSSession(models.SteamOSInfo{SessionMode: "gamemode", GamescopeActive: true}), "")
	assertLevel(t, checkSteamOSSession(models.SteamOSInfo{SessionMode: "desktop"}), "")
	assertLevel(t, checkSteamOSSession(models.SteamOSInfo{SessionMode: "gamemode", GamescopeActive: false}), "CRIT")
}

func TestCheckSteamOSStorage(t *testing.T) {
	tests := []struct {
		name string
		s    models.SteamOSInfo
		want string
	}{
		{"clean is empty", models.SteamOSInfo{VarUsedPct: 40, HomeUsedPct: 50}, ""},
		{"/var elevated is WARN", models.SteamOSInfo{VarUsedPct: 75}, "WARN"},
		{"/var full is CRIT", models.SteamOSInfo{VarUsedPct: 90}, "CRIT"},
		{"/home elevated is WARN", models.SteamOSInfo{HomeUsedPct: 90}, "WARN"},
		{"/home full is CRIT", models.SteamOSInfo{HomeUsedPct: 97}, "CRIT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkSteamOSStorage(tt.s), tt.want)
		})
	}
}

func TestCheckSteamOSNetwork(t *testing.T) {
	assertLevel(t, checkSteamOSNetwork(models.SteamOSInfo{UpdateServerKnown: false}), "")
	assertLevel(t, checkSteamOSNetwork(models.SteamOSInfo{UpdateServerKnown: true, UpdateServerReachable: true}), "")
	assertLevel(t, checkSteamOSNetwork(models.SteamOSInfo{UpdateServerKnown: true, UpdateServerReachable: false}), "WARN")
}

func TestCheckSteamOSRemotePlay(t *testing.T) {
	rp := func(r models.SteamOSRemotePlay) models.SteamOSInfo {
		return models.SteamOSInfo{RemotePlay: &r}
	}
	assertLevel(t, checkSteamOSRemotePlay(models.SteamOSInfo{}), "") // no remote-play data
	assertLevel(t, checkSteamOSRemotePlay(rp(models.SteamOSRemotePlay{
		Ports: []models.RemotePlayPort{{Protocol: "udp", Port: 27031, Bound: true}},
	})), "")
	assertLevel(t, checkSteamOSRemotePlay(rp(models.SteamOSRemotePlay{
		Ports: []models.RemotePlayPort{{Protocol: "udp", Port: 27031, Bound: false, Optional: false}},
	})), "WARN")
	assertLevel(t, checkSteamOSRemotePlay(rp(models.SteamOSRemotePlay{FirewallBlocking: true})), "WARN")
	assertLevel(t, checkSteamOSRemotePlay(rp(models.SteamOSRemotePlay{ARPChecked: true, APIsolationSuspected: true})), "WARN")
}
