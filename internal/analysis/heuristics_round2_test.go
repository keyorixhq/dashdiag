package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Round-2 characterization tests for untested heuristics: data-integrity (btrfs),
// core resource pressure (IO/FD/thermal/entropy/systemd/processes), and the
// network-service checks (NFS/BIND) that pair with the collector parser tests.
// Pure functions; thresholds driven off defaultThresh. Reuses assertLevel.

// ── btrfs data integrity ──────────────────────────────────────────────────────

func TestCheckBtrfsVolume(t *testing.T) {
	tests := []struct {
		name string
		vol  models.BtrfsVolume
		want string
	}{
		{"healthy is clean", models.BtrfsVolume{MountPoint: "/data", Status: "healthy", ShowRead: true, StatsRead: true}, ""},
		{"missing device is CRIT", models.BtrfsVolume{MountPoint: "/data", ShowRead: true, MissingDevs: 1}, "CRIT"},
		{"stats unread is INFO not silent OK", models.BtrfsVolume{MountPoint: "/data", Status: "healthy", ShowRead: true, StatsRead: false}, "INFO"},
		// Non-root "device unreadable" artifact must be INFO, never the DEGRADED CRIT
		// (false-CRIT found on the Fedora EC2 box: unprivileged btrfs shows present
		// devices as MISSING). MissingDevs stays 0; DevReadUnverified drives the INFO.
		{"non-root unverified device state is INFO not CRIT", models.BtrfsVolume{MountPoint: "/", ShowRead: true, DevReadUnverified: true, StatsRead: false}, "INFO"},
		{
			name: "device I/O errors are CRIT",
			vol:  models.BtrfsVolume{MountPoint: "/data", Status: "errors", ShowRead: true, StatsRead: true, Devices: []models.BtrfsDev{{ReadErrs: 5}}},
			want: "CRIT",
		},
		{
			name: "corruption only is WARN (scrub-correctable)",
			vol:  models.BtrfsVolume{MountPoint: "/data", Status: "errors", ShowRead: true, StatsRead: true, Devices: []models.BtrfsDev{{CorruptErrs: 3}}},
			want: "WARN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkBtrfsVolume(tt.vol), tt.want)
		})
	}
}

// TestCheckBtrfsVolume_ShowFailed is a regression guard for
// internal-collectors-03-01: `btrfs filesystem show` itself failed — every
// other field is zero-value, which happens to also trip the "stats unread"
// branch at the same INFO level, silently masking whether the specific
// ShowRead check actually fired. Assert the message text, not just the
// level, so a revert of the ShowRead check can't hide behind that overlap.
func TestCheckBtrfsVolume_ShowFailed(t *testing.T) {
	got := checkBtrfsVolume(models.BtrfsVolume{MountPoint: "/data", ShowRead: false})
	if !hasInsightMsg(got, "INFO", "could not be checked") {
		t.Errorf("a failed `btrfs filesystem show` must disclose it could not be checked, got %+v", got)
	}
}

// ── disk IO saturation ────────────────────────────────────────────────────────

func TestCheckIO(t *testing.T) {
	dev := func(util float64) models.IOInfo {
		return models.IOInfo{Devices: []models.IODeviceInfo{{Name: "sda", DriveType: "ssd", UtilPct: util}}}
	}
	assertLevel(t, checkIO(dev(10), defaultThresh), "")
	assertLevel(t, checkIO(dev(defaultThresh.IOUtilWarnPctSSD), defaultThresh), "WARN")
	assertLevel(t, checkIO(dev(defaultThresh.IOUtilCritPctSSD), defaultThresh), "CRIT")
}

// ── file descriptor exhaustion ────────────────────────────────────────────────

func TestCheckFD(t *testing.T) {
	tests := []struct {
		name string
		fd   models.FDInfo
		want string
	}{
		{"below warn is clean", models.FDInfo{UsedPct: 10}, ""},
		{"at warn is WARN", models.FDInfo{UsedPct: defaultThresh.FDSystemWarnPct, OpenCount: 800, MaxCount: 1000}, "WARN"},
		{"at crit is CRIT", models.FDInfo{UsedPct: defaultThresh.FDSystemCritPct, OpenCount: 900, MaxCount: 1000}, "CRIT"},
		{"large deleted-but-open is WARN", models.FDInfo{UsedPct: 10, DeletedOpenSizeGB: 2}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkFD(tt.fd, defaultThresh), tt.want)
		})
	}
}

// ── CPU thermal ───────────────────────────────────────────────────────────────

func TestCheckThermal(t *testing.T) {
	tests := []struct {
		name string
		th   models.ThermalInfo
		want string
	}{
		{"no data is clean", models.ThermalInfo{CPUTempC: 0, Source: ""}, ""},
		{"normal temp is clean", models.ThermalInfo{CPUTempC: 50, Source: "hwmon"}, ""},
		{"elevated is WARN", models.ThermalInfo{CPUTempC: 87, Source: "hwmon"}, "WARN"},
		{"throttling is CRIT", models.ThermalInfo{CPUTempC: 96, Source: "hwmon"}, "CRIT"},
		// A faulted/virtual sensor reporting garbage must NOT fire the throttling CRIT
		// — reject it as unverified (WARN), like the VMware vNVMe 11758°C class.
		{"implausibly high is WARN not CRIT", models.ThermalInfo{CPUTempC: 11758, Source: "hwmon"}, "WARN"},
		{"implausibly low (negative offset) is WARN", models.ThermalInfo{CPUTempC: -60, Source: "k10temp"}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkThermal(tt.th, defaultThresh), tt.want)
		})
	}
}

// TestCheckThermalLowLoad pins the load-aware idle thermal branch. 60–74°C at low
// load is normal for mini-PCs/laptops/high-TDP chips and must NOT warn (was a
// false-alarm at the old 60°C floor); ≥75°C at idle stays a genuine cooling WARN.
func TestCheckThermalLowLoad(t *testing.T) {
	lowLoad := func(pct float64) Thresholds {
		th := defaultThresh
		th.CPULoadPct = pct
		return th
	}
	tests := []struct {
		name   string
		th     models.ThermalInfo
		thresh Thresholds
		want   string
	}{
		{"66C at 8% load is clean (normal idle)", models.ThermalInfo{CPUTempC: 66, Source: "hwmon"}, lowLoad(8), ""},
		{"74C at 8% load is still clean", models.ThermalInfo{CPUTempC: 74, Source: "hwmon"}, lowLoad(8), ""},
		{"78C at 8% load is WARN (hot at idle)", models.ThermalInfo{CPUTempC: 78, Source: "hwmon"}, lowLoad(8), "WARN"},
		{"78C at 50% load is clean (not idle)", models.ThermalInfo{CPUTempC: 78, Source: "hwmon"}, lowLoad(50), ""},
		{"no load data does not fire idle branch", models.ThermalInfo{CPUTempC: 78, Source: "hwmon"}, lowLoad(0), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkThermal(tt.th, tt.thresh), tt.want)
		})
	}
}

// ── entropy starvation ────────────────────────────────────────────────────────

func TestCheckEntropy(t *testing.T) {
	tests := []struct {
		name string
		e    models.EntropyInfo
		want string
	}{
		{"unavailable is silent", models.EntropyInfo{Available: false, EntropyBits: 1}, ""},
		{"healthy pool is clean", models.EntropyInfo{Available: true, EntropyBits: 512}, ""},
		{"low pool is WARN", models.EntropyInfo{Available: true, EntropyBits: 128}, "WARN"},
		{"critically low is CRIT", models.EntropyInfo{Available: true, EntropyBits: 32}, "CRIT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkEntropy(tt.e), tt.want)
		})
	}
}

// ── systemd failed units ──────────────────────────────────────────────────────

func TestCheckSystemd(t *testing.T) {
	assertLevel(t, checkSystemd(models.SystemdInfo{Available: false}), "") // platform hides row
	assertLevel(t, checkSystemd(models.SystemdInfo{Available: true}), "")  // no failures
	assertLevel(t, checkSystemd(models.SystemdInfo{Available: true, FailedUnits: []string{"x.service"}}), "CRIT")
}

// ── processes (zombies / hung) ────────────────────────────────────────────────

func TestCheckProcesses(t *testing.T) {
	tests := []struct {
		name string
		p    models.ProcessInfo
		want string
	}{
		{"clean", models.ProcessInfo{}, ""},
		{"few zombies is WARN", models.ProcessInfo{ZombieCount: 3}, "WARN"},
		{"many zombies is CRIT", models.ProcessInfo{ZombieCount: 10}, "CRIT"},
		{"few hung is WARN", models.ProcessInfo{HungCount: 2}, "WARN"},
		{"many hung is CRIT", models.ProcessInfo{HungCount: 5}, "CRIT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Default thresholds must reproduce the historical hardcoded behaviour.
			assertLevel(t, checkProcesses(tt.p, defaultThresh), tt.want)
		})
	}
}

// The policy knobs zombie_warn_count and hung_d_state_crit must actually take
// effect (previously they were defined but never read).
func TestCheckProcessesHonoursThresholds(t *testing.T) {
	th := defaultThresh
	th.ZombieWarnCount = 5
	th.HungDStateCrit = 1

	// 3 zombies is below the raised warn count → no insight.
	assertLevel(t, checkProcesses(models.ProcessInfo{ZombieCount: 3}, th), "")
	// 5 zombies reaches the raised warn count → WARN.
	assertLevel(t, checkProcesses(models.ProcessInfo{ZombieCount: 5}, th), "WARN")
	// A single hung process is CRIT once the crit threshold is lowered to 1.
	assertLevel(t, checkProcesses(models.ProcessInfo{HungCount: 1}, th), "CRIT")
}

// ── NFS ───────────────────────────────────────────────────────────────────────

func TestCheckNFS(t *testing.T) {
	tests := []struct {
		name string
		nfs  models.NFSInfo
		want string
	}{
		{"empty is clean", models.NFSInfo{}, ""},
		{
			name: "stale mount is CRIT",
			nfs:  models.NFSInfo{Mounts: []models.NFSMount{{Mount: "/mnt/nfs", Stale: true}}},
			want: "CRIT",
		},
		{
			name: "mount option warning is WARN",
			nfs:  models.NFSInfo{Mounts: []models.NFSMount{{Mount: "/mnt/nfs", Healthy: true, OptionsWarnings: []string{"soft without timeo"}}}},
			want: "WARN",
		},
		{
			// statfs returned a prompt non-ESTALE error → !Healthy && !Stale. Must
			// WARN, not read green (the false-OK fix).
			name: "unhealthy mount (statfs error) is WARN",
			nfs:  models.NFSInfo{Mounts: []models.NFSMount{{Mount: "/mnt/nfs", Server: "10.0.0.5", Healthy: false, Stale: false}}, RpcbindActive: true},
			want: "WARN",
		},
		{"high retransmission rate is WARN", models.NFSInfo{RetransPerMin: 200, RPCCalls: 2000}, "WARN"},
		{
			name: "rpcbind inactive with mounts is WARN",
			nfs:  models.NFSInfo{Mounts: []models.NFSMount{{Mount: "/mnt/nfs", Healthy: true}}, RpcbindActive: false},
			want: "WARN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkNFS(tt.nfs), tt.want)
		})
	}
}

// ── BIND ──────────────────────────────────────────────────────────────────────

func TestCheckBIND(t *testing.T) {
	healthy := models.BINDInfo{
		Detected: true, ServiceActive: true, PortsChecked: true, Port53TCP: true, Port53UDP: true,
		ConfigOK: true, QueryOK: true, QueryTested: true,
	}
	tests := []struct {
		name string
		b    models.BINDInfo
		want string
	}{
		{"not detected is silent", models.BINDInfo{Detected: false}, ""},
		{"healthy is clean", healthy, ""},
		{"service down is CRIT", models.BINDInfo{Detected: true, ServiceActive: false}, "CRIT"},
		{
			name: "not listening on 53 is WARN",
			b:    models.BINDInfo{Detected: true, ServiceActive: true, PortsChecked: true, Port53TCP: false, Port53UDP: true, ConfigOK: true, QueryOK: true, QueryTested: true},
			want: "WARN",
		},
		{
			name: "ports not checked (ss absent) is INFO not WARN",
			b:    models.BINDInfo{Detected: true, ServiceActive: true, PortsChecked: false, ConfigOK: true, QueryOK: true, QueryTested: true},
			want: "INFO",
		},
		{
			name: "bad config is CRIT",
			b:    models.BINDInfo{Detected: true, ServiceActive: true, PortsChecked: true, Port53TCP: true, Port53UDP: true, ConfigOK: false, QueryOK: true, QueryTested: true},
			want: "CRIT",
		},
		{
			name: "tested and not answering queries is CRIT",
			b:    models.BINDInfo{Detected: true, ServiceActive: true, PortsChecked: true, Port53TCP: true, Port53UDP: true, ConfigOK: true, QueryOK: false, QueryTested: true},
			want: "CRIT",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkBIND(tt.b), tt.want)
		})
	}
}
