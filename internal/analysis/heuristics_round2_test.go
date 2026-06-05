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
		{"healthy is clean", models.BtrfsVolume{MountPoint: "/data", Status: "healthy"}, ""},
		{"missing device is CRIT", models.BtrfsVolume{MountPoint: "/data", MissingDevs: 1}, "CRIT"},
		{
			name: "device I/O errors are CRIT",
			vol:  models.BtrfsVolume{MountPoint: "/data", Status: "errors", Devices: []models.BtrfsDev{{ReadErrs: 5}}},
			want: "CRIT",
		},
		{
			name: "corruption only is WARN (scrub-correctable)",
			vol:  models.BtrfsVolume{MountPoint: "/data", Status: "errors", Devices: []models.BtrfsDev{{CorruptErrs: 3}}},
			want: "WARN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkBtrfsVolume(tt.vol), tt.want)
		})
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkThermal(tt.th, defaultThresh), tt.want)
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
			assertLevel(t, checkProcesses(tt.p), tt.want)
		})
	}
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
			nfs:  models.NFSInfo{Mounts: []models.NFSMount{{Mount: "/mnt/nfs", OptionsWarnings: []string{"soft without timeo"}}}},
			want: "WARN",
		},
		{"elevated retransmissions is WARN", models.NFSInfo{RetransPerMin: 150}, "WARN"},
		{
			name: "rpcbind inactive with mounts is WARN",
			nfs:  models.NFSInfo{Mounts: []models.NFSMount{{Mount: "/mnt/nfs"}}, RpcbindActive: false},
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
		Detected: true, ServiceActive: true, Port53TCP: true, Port53UDP: true,
		ConfigOK: true, QueryOK: true,
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
			b:    models.BINDInfo{Detected: true, ServiceActive: true, Port53TCP: false, Port53UDP: true, ConfigOK: true, QueryOK: true},
			want: "WARN",
		},
		{
			name: "bad config is CRIT",
			b:    models.BINDInfo{Detected: true, ServiceActive: true, Port53TCP: true, Port53UDP: true, ConfigOK: false, QueryOK: true},
			want: "CRIT",
		},
		{
			name: "not answering queries is CRIT",
			b:    models.BINDInfo{Detected: true, ServiceActive: true, Port53TCP: true, Port53UDP: true, ConfigOK: true, QueryOK: false},
			want: "CRIT",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkBIND(tt.b), tt.want)
		})
	}
}
