package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Round-5 characterization tests: Proxmox VE (cluster/storage/backups), GPU,
// containerd, snapper snapshots, and the niche fabric/topology checks (NUMA,
// VLAN, iSCSI, InfiniBand, nspawn). Pure functions; reuses assertLevel.

func TestCheckPVECluster(t *testing.T) {
	ok := models.PVEInfo{QuorumOK: true, HAFencingOK: true} // healthy baseline
	tests := []struct {
		name string
		p    models.PVEInfo
		want string
	}{
		{"healthy is clean", ok, ""},
		{"quorum lost is CRIT", models.PVEInfo{QuorumOK: false, HAFencingOK: true}, "CRIT"},
		{"HA fencing down is CRIT", models.PVEInfo{QuorumOK: true, HAFencingOK: false}, "CRIT"},
		{
			name: "mixed versions is WARN",
			p: models.PVEInfo{QuorumOK: true, HAFencingOK: true, Nodes: []models.PVENode{
				{Name: "a", Online: true, Version: "8.1"}, {Name: "b", Online: true, Version: "8.2"},
			}},
			want: "WARN",
		},
		{
			name: "offline node is CRIT",
			p: models.PVEInfo{QuorumOK: true, HAFencingOK: true, Nodes: []models.PVENode{
				{Name: "a", Online: true, Version: "8.1"}, {Name: "b", Online: false, Version: "8.1"},
			}},
			want: "CRIT",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkPVECluster(tt.p), tt.want)
		})
	}
}

func TestCheckPVEStorage(t *testing.T) {
	stor := func(active bool, used float64) models.PVEInfo {
		return models.PVEInfo{Storages: []models.PVEStorage{{Name: "local", Type: "dir", Active: active, UsedPct: used, TotalGB: 100}}}
	}
	assertLevel(t, checkPVEStorage(models.PVEInfo{}), "") // no storage
	assertLevel(t, checkPVEStorage(stor(true, 50)), "")
	assertLevel(t, checkPVEStorage(stor(false, 0)), "CRIT") // inactive
	assertLevel(t, checkPVEStorage(stor(true, 85)), "WARN") // 80-90
	assertLevel(t, checkPVEStorage(stor(true, 92)), "CRIT") // >=90
}

func TestCheckPVEBackups(t *testing.T) {
	// One non-template guest exists (BackupStatuses populated) for the cases that
	// should fire on backup age.
	oneGuest := []models.PVEBackupStatus{{VMID: 100, Name: "vm", LastBackupDays: -1}}
	assertLevel(t, checkPVEBackups(models.PVEInfo{BackupAgeDays: 3, BackupStatuses: oneGuest}), "")      // recent, no failures
	assertLevel(t, checkPVEBackups(models.PVEInfo{BackupAgeDays: -1, BackupStatuses: oneGuest}), "CRIT") // real VM, never backed up
	assertLevel(t, checkPVEBackups(models.PVEInfo{BackupAgeDays: 10, BackupStatuses: oneGuest}), "WARN") // stale
	assertLevel(t, checkPVEBackups(models.PVEInfo{BackupAgeDays: 3, RecentBackups: []models.PVEBackupTask{{Status: "ERROR"}}}), "WARN")
	// FALSE-POSITIVE GUARD: a fresh / template-only node (no backable guests →
	// empty BackupStatuses) has nothing to back up, so "no backup" must NOT CRIT.
	assertLevel(t, checkPVEBackups(models.PVEInfo{BackupAgeDays: -1}), "")
}

func TestCheckGPU(t *testing.T) {
	dev := func(d models.GPUDevice) models.GPUInfo { return models.GPUInfo{Devices: []models.GPUDevice{d}} }
	tests := []struct {
		name string
		gpu  models.GPUInfo
		want string
	}{
		{"no gpu is silent", models.GPUInfo{}, ""},
		{"healthy gpu is clean", dev(models.GPUDevice{Name: "card0", TempC: 50}), ""},
		{"nvidia no driver is INFO", models.GPUInfo{Status: "nvidia-no-driver"}, "INFO"},
		{"hot gpu is CRIT", dev(models.GPUDevice{Name: "card0", TempC: 92}), "CRIT"},
		{"elevated gpu is WARN", dev(models.GPUDevice{Name: "card0", TempC: 82}), "WARN"},
		{"junction emergency is CRIT", dev(models.GPUDevice{Name: "card0", TempJunctionC: 105}), "CRIT"},
		{"tdp throttling is WARN", dev(models.GPUDevice{Name: "card0", Throttling: true, TDPCurrentW: 15, TDPLimitW: 15}), "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkGPU(tt.gpu), tt.want)
		})
	}
}

func TestCheckContainerd(t *testing.T) {
	assertLevel(t, checkContainerd(models.ContainerdInfo{Available: false, StatusReason: "socket not found"}), "WARN")
	assertLevel(t, checkContainerd(models.ContainerdInfo{Available: true, ServiceState: "active"}), "")
	assertLevel(t, checkContainerd(models.ContainerdInfo{Available: true, ServiceState: "failed"}), "CRIT")
}

func TestCheckSnapper(t *testing.T) {
	tests := []struct {
		name string
		s    models.SnapperInfo
		want string
	}{
		{"not installed is silent", models.SnapperInfo{Available: false}, ""},
		{"permission error is WARN", models.SnapperInfo{Available: true, Error: "permission denied"}, "WARN"},
		{"run-as-root note is INFO", models.SnapperInfo{Available: true, Error: "run as root for snapshot list"}, "INFO"},
		{"no snapshots is WARN", models.SnapperInfo{Available: true, SnapshotCount: 0}, "WARN"},
		{"very stale is CRIT", models.SnapperInfo{Available: true, SnapshotCount: 5, LastSnapshotH: 80}, "CRIT"},
		{"stale is WARN", models.SnapperInfo{Available: true, SnapshotCount: 5, LastSnapshotH: 30}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkSnapper(tt.s), tt.want)
		})
	}
}

func TestCheckNUMA(t *testing.T) {
	assertLevel(t, checkNUMA(models.NUMAInfo{Available: false}), "")
	assertLevel(t, checkNUMA(models.NUMAInfo{Available: true, Imbalanced: false}), "")
	assertLevel(t, checkNUMA(models.NUMAInfo{Available: true, Imbalanced: true, NodeCount: 2}), "WARN")
}

func TestCheckVLAN(t *testing.T) {
	assertLevel(t, checkVLAN(models.VLANInfo{}), "") // none
	assertLevel(t, checkVLAN(models.VLANInfo{Interfaces: []models.VLANInterface{{Name: "eth0.100", VLANID: 100, Up: true}}}), "")
	assertLevel(t, checkVLAN(models.VLANInfo{Interfaces: []models.VLANInterface{{Name: "eth0.100", VLANID: 100, Up: false}}}), "WARN")
}

func TestCheckISCSI(t *testing.T) {
	assertLevel(t, checkISCSI(models.ISCSIInfo{Available: false}), "")
	assertLevel(t, checkISCSI(models.ISCSIInfo{Available: true, Sessions: []models.ISCSISession{{}}, FailedCount: 0}), "")
	assertLevel(t, checkISCSI(models.ISCSIInfo{Available: true, Sessions: []models.ISCSISession{{}}, FailedCount: 1}), "CRIT")
}

func TestCheckInfiniBand(t *testing.T) {
	assertLevel(t, checkInfiniBand(models.InfiniBandInfo{}), "")
	assertLevel(t, checkInfiniBand(models.InfiniBandInfo{Ports: []models.IBPort{{Device: "mlx5_0", Port: 1, State: "ACTIVE"}}}), "")
	assertLevel(t, checkInfiniBand(models.InfiniBandInfo{Ports: []models.IBPort{{Device: "mlx5_0", Port: 1, State: "DOWN"}}}), "WARN")
}

func TestCheckNspawn(t *testing.T) {
	assertLevel(t, checkNspawn(models.NspawnInfo{Available: false}), "")
	assertLevel(t, checkNspawn(models.NspawnInfo{Available: true, Containers: []models.NspawnContainer{{}}, FailedCount: 0}), "")
	assertLevel(t, checkNspawn(models.NspawnInfo{Available: true, Containers: []models.NspawnContainer{{}}, FailedCount: 1}), "WARN")
}
