package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Characterization tests for the container (Docker/K8s) and drive (NVMe/SATA)
// heuristics — the WARN/CRIT verdicts for the most operationally painful
// failures (crash loops, OOM kills, socket mounts, failing drives). Pure
// functions (models in, []Insight out). Reuses assertLevel/hasLevel from
// heuristics_test.go.

// ── Kubernetes ────────────────────────────────────────────────────────────────

func TestCheckK8s(t *testing.T) {
	tests := []struct {
		name string
		info models.K8sInfo
		want string
	}{
		{"not detected yields nothing", models.K8sInfo{Detected: false, CrashLooping: 5}, ""},
		{"nodes not ready is CRIT", models.K8sInfo{Detected: true, NodesNotReady: 1}, "CRIT"},
		{"crash looping is CRIT", models.K8sInfo{Detected: true, CrashLooping: 2}, "CRIT"},
		{"pods not ready is WARN", models.K8sInfo{Detected: true, PodsNotReady: 1}, "WARN"},
		{"pending is WARN", models.K8sInfo{Detected: true, Pending: 1}, "WARN"},
		{"high restarts is WARN", models.K8sInfo{Detected: true, HighRestarts: 1}, "WARN"},
		{
			name: "node pressure condition is CRIT",
			info: models.K8sInfo{Detected: true, Nodes: []models.K8sNodeInfo{
				{Name: "n1", Conditions: map[string]string{"DiskPressure": "True"}},
			}},
			want: "CRIT",
		},
		{
			name: "node Ready=True is fine",
			info: models.K8sInfo{Detected: true, Nodes: []models.K8sNodeInfo{
				{Name: "n1", Conditions: map[string]string{"Ready": "True"}},
			}},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkK8s(tt.info), tt.want)
		})
	}
}

// ── Docker containers ─────────────────────────────────────────────────────────

func TestCheckDockerContainers(t *testing.T) {
	tests := []struct {
		name string
		info models.DockerInfo
		want string
	}{
		{"empty is clean", models.DockerInfo{}, ""},
		{"crash looping is CRIT", models.DockerInfo{CrashLooping: []string{"web"}}, "CRIT"},
		{"unhealthy is WARN", models.DockerInfo{Unhealthy: []string{"db"}}, "WARN"},
		// Raw stopped count no longer warns — the WARN now counts only failed-exit
		// containers (see TestDockerStoppedCleanExitNotFlagged); clean-exit oneshots
		// are expected. A non-zero-exit container is the real signal.
		{"6 clean-stopped (no exit codes) is fine", models.DockerInfo{Stopped: 6}, ""},
		{"6 failed-exit stopped is WARN", models.DockerInfo{Containers: []models.ContainerInfo{
			{State: "exited", ExitCode: 1}, {State: "exited", ExitCode: 1}, {State: "exited", ExitCode: 1},
			{State: "exited", ExitCode: 1}, {State: "exited", ExitCode: 1}, {State: "exited", ExitCode: 137},
		}}, "WARN"},
		{"oom events is CRIT", models.DockerInfo{OOMEvents: 1}, "CRIT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkDockerContainers(tt.info), tt.want)
		})
	}
}

// ── Docker security ───────────────────────────────────────────────────────────

func TestCheckDockerSecurity(t *testing.T) {
	tests := []struct {
		name string
		info models.DockerInfo
		want string
	}{
		{"empty is clean", models.DockerInfo{}, ""},
		{"docker.sock mounted is CRIT", models.DockerInfo{SocketMountedCount: 1}, "CRIT"},
		{"running as root is WARN", models.DockerInfo{RunningAsRootCount: 2}, "WARN"},
		{"plaintext secrets is WARN", models.DockerInfo{ContainersWithSecrets: 1}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkDockerSecurity(tt.info), tt.want)
		})
	}
}

// ── NVMe / SATA drive health ──────────────────────────────────────────────────

func TestCheckNVMe(t *testing.T) {
	// These fixtures represent drives whose SMART log was read (they carry real
	// values), so mark them SmartRead — otherwise they trip the new "SMART not
	// read" INFO. The unread case is covered explicitly below.
	nvme := func(d models.NVMeDevice) models.NVMeInfo {
		d.SmartRead = true
		return models.NVMeInfo{Devices: []models.NVMeDevice{d}}
	}
	// SATA fixtures with explicit attributes represent drives whose SMART verdict
	// was read; mark SmartRead so they don't trip the "SMART not read" INFO. The
	// unread case is covered explicitly below.
	sata := func(d models.SATADevice) models.NVMeInfo {
		d.SmartRead = true
		return models.NVMeInfo{SATADevices: []models.SATADevice{d}}
	}
	tests := []struct {
		name string
		info models.NVMeInfo
		want string
	}{
		{"no drives is clean", models.NVMeInfo{}, ""},
		{"healthy nvme is clean", nvme(models.NVMeDevice{Name: "nvme0", PercentageUsed: 10, TempC: 40}), ""},
		{"nvme critical warning is CRIT", nvme(models.NVMeDevice{Name: "nvme0", CriticalWarning: 1}), "CRIT"},
		{"nvme media errors is CRIT", nvme(models.NVMeDevice{Name: "nvme0", MediaErrors: 5}), "CRIT"},
		{"nvme spare below threshold is CRIT", nvme(models.NVMeDevice{Name: "nvme0", AvailableSparePct: 5, SpareThresholdPct: 10}), "CRIT"},
		// 0% available spare is the worst reading and must CRIT (the old `> 0`
		// guard silently dropped it). Threshold>0 proves the SMART log was read.
		{"nvme spare exhausted (0%) is CRIT", nvme(models.NVMeDevice{Name: "nvme0", AvailableSparePct: 0, SpareThresholdPct: 10}), "CRIT"},
		// Threshold zero → spare not evaluated, stay silent (no false spare CRIT).
		{"nvme spare unread (0/0) is clean", nvme(models.NVMeDevice{Name: "nvme0", AvailableSparePct: 0, SpareThresholdPct: 0}), ""},
		// Device detected via sysfs but SMART log never read (no nvme-cli) → INFO,
		// not a confident "healthy". Note: no SmartRead, so not via the nvme() helper.
		{"nvme smart unread is INFO", models.NVMeInfo{Devices: []models.NVMeDevice{{Name: "nvme0"}}}, "INFO"},
		{"nvme spare low is WARN", nvme(models.NVMeDevice{Name: "nvme0", AvailableSparePct: 15}), "WARN"},
		{"nvme wear >=90 is WARN", nvme(models.NVMeDevice{Name: "nvme0", PercentageUsed: 95}), "WARN"},
		{"nvme hot is WARN", nvme(models.NVMeDevice{Name: "nvme0", TempC: 75}), "WARN"},
		{"sata smart fail is CRIT", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: false}), "CRIT"},
		{"sata uncorrectable is CRIT", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: true, UncorrectableErrors: 1}), "CRIT"},
		{"sata reallocated is WARN", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: true, ReallocatedSectors: 4}), "WARN"},
		{"sata read error skipped", sata(models.SATADevice{Name: "/dev/sda", SmartOK: false, Error: "permission denied"}), ""},
		// Detected but SMART never reported (controller/USB bridge/virtual disk) →
		// INFO, NOT a confident "drive may be failing" CRIT. No SmartRead → not via
		// the sata() helper.
		{"sata smart unread is INFO", models.NVMeInfo{SATADevices: []models.SATADevice{{Name: "/dev/sda", Type: "sata", SmartOK: false}}}, "INFO"},
		// Power-on-hours is age, not wear: a healthy long-lived drive must NOT WARN
		// (real endurance is PercentageUsed/spare for NVMe, reallocated sectors for SATA).
		{"nvme high power-on-hours healthy is INFO not WARN", nvme(models.NVMeDevice{Name: "nvme0", PercentageUsed: 10, TempC: 40, PowerOnHours: 40000}), "INFO"},
		{"sata high power-on-hours healthy is INFO not WARN", sata(models.SATADevice{Name: "/dev/sda", Type: "sata", SmartOK: true, PowerOnHours: 50000}), "INFO"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkNVMe(tt.info), tt.want)
		})
	}
}
