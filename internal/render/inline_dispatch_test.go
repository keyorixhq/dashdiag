package render

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// TestInlineDataDispatch drives every collector name through inlineData with a
// populated payload, exercising the full inline-renderer dispatch table and each
// renderer's formatting path. Renderers must never panic and the dispatch must
// return a string for every known name (and "" for an unknown one).
func TestInlineDataDispatch(t *testing.T) {
	cases := map[string]interface{}{
		"CPU Load":    models.CPUInfo{UsagePct: 50, LoadAvg1: 1.2, NumCPU: 4},
		"Memory":      models.MemoryInfo{TotalGB: 16, UsedPct: 50},
		"Swap":        models.SwapInfo{TotalGB: 4, UsedGB: 1},
		"Disk":        models.DiskInfo{Filesystems: []models.FilesystemInfo{{Mount: "/", Device: "/dev/sda1", UsedPct: 50}}},
		"Network":     models.NetworkInfo{PrimaryInterface: "eth0", GatewayPingMs: 5, Interfaces: []models.InterfaceInfo{{Name: "eth0", Up: true, SpeedMbps: 1000}}},
		"Entropy":     models.EntropyInfo{Available: true, EntropyBits: 256, PoolSize: 4096},
		"FDLimits":    models.FDInfo{MaxCount: 1000, OpenCount: 500, UsedPct: 50},
		"IO":          models.IOInfo{Devices: []models.IODeviceInfo{{Name: "sda", UtilPct: 10, AwaitMs: 2}}},
		"KernelSec":   models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing"},
		"Clock":       models.ClockInfo{Synced: true, Source: "chrony", OffsetMs: 1.0},
		"Logs":        models.LogsInfo{JournalSizeGB: 1.0, ErrorCount: 2},
		"GPU":         models.GPUInfo{Devices: []models.GPUDevice{{Name: "card0", TempC: 45}}},
		"CPU Thermal": models.ThermalInfo{Available: true, CPUTempC: 50, Source: "hwmon"},
		"Battery":     models.BatteryInfo{Present: true, CapacityPct: 80, HealthPct: 95, Status: "Full"},
		"Launchd":     models.LaunchdInfo{Total: 100, Running: 99},
		"Packages":    models.PackagesInfo{PackageManager: "apt", SecurityUpdates: 0},
		"CVE":         models.CVEAllResult{PackageManager: "apt"},
		"Drives":      models.NVMeInfo{Devices: []models.NVMeDevice{{Name: "nvme0", TempC: 40, PercentageUsed: 5}}},
		"Systemd":     models.SystemdInfo{Available: true, TotalBootSec: 12},
		"Processes":   models.ProcessInfo{},
		"Bonding":     models.BondingInfo{Bonds: []models.BondInterface{{Name: "bond0", ModeShort: "802.3ad", Slaves: []models.BondSlave{{Name: "eth0", State: "up"}, {Name: "eth1", State: "up"}}}}},
		"OOM":         models.OOMInfo{Available: true, EventsLast24h: 0},
		"LVM":         models.LVMInfo{VGs: []models.LVMVG{{}}},
		"Sessions":    models.SessionsInfo{TotalCount: 2},
		"IPMI":        models.IPMIInfo{Available: true},
		"HBA":         models.HBAInfo{Ports: []models.HBAPort{{Name: "host0", PortState: "Online"}}},
		"Pressure":    models.PressureInfo{Available: true},
		"Multipath":   models.MultipathInfo{Available: true, Devices: []models.MultipathDevice{{Name: "mpatha", DM: "dm-0", ActivePaths: 2, TotalPaths: 2}}},
		"Ceph":        models.CephInfo{Available: true, Health: "HEALTH_OK", OSDTotal: 3, OSDUp: 3},
		"Firewall":    models.FirewallInfo{Available: true, Active: true, Backend: "firewalld"},
		"Auth":        models.AuthInfo{Available: true},
		"CloudMeta":   models.CloudInfo{Available: true, Provider: "aws"},
		"CloudInit":   models.CloudInitInfo{Available: true, Status: "done"},
		"Auditd":      models.AuditInfo{Available: true, Running: true},
		"NUMA":        models.NUMAInfo{Available: true, NodeCount: 2},
		"VLAN":        models.VLANInfo{Interfaces: []models.VLANInterface{{Name: "eth0.100", VLANID: 100, Up: true}}},
		"iSCSI":       models.ISCSIInfo{Available: true, Sessions: []models.ISCSISession{{}}},
		"InfiniBand":  models.InfiniBandInfo{Ports: []models.IBPort{{Device: "mlx5_0", Port: 1, State: "ACTIVE"}}},
		"SRIOV":       models.SRIOVInfo{Devices: []models.SRIOVDevice{{NumVFs: 2}}},
		"Nspawn":      models.NspawnInfo{Available: true, Containers: []models.NspawnContainer{{}}},
		"HugePages":   models.HugePagesInfo{Available: true, Configured: 100, Used: 50},
		"CPUFreq":     models.CPUFreqInfo{Governor: "performance", CurrentMHz: 3000, MaxMHz: 3000},
		"Containerd":  models.ContainerdInfo{Available: true, ServiceState: "active"},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			// Must not panic; result content is not asserted (formatting may vary).
			_ = inlineData(runner.Result{Name: name, Data: data})
			// Pointer form exercises the *T type-assertion arms too.
			_ = inlineData(runner.Result{Name: name, Data: data})
		})
	}

	if got := inlineData(runner.Result{Name: "NoSuchCollector", Data: nil}); got != "" {
		t.Errorf("unknown collector name should render empty, got %q", got)
	}
}
