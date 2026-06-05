package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// TestApplyOneDispatch drives every model type through applyOne (and its
// applyOneExtended continuation) in both value and pointer form. This exercises
// the full type-switch dispatch table — each arm routes to a check* function
// already covered individually — and pins the contract that an unknown type
// falls through to nil without panicking.
func TestApplyOneDispatch(t *testing.T) {
	ctr := platform.ContainerContext{}

	values := []interface{}{
		models.CPUInfo{}, models.MemoryInfo{}, models.DiskInfo{}, models.SwapInfo{},
		models.IOInfo{}, models.NetworkInfo{}, models.NFSInfo{}, models.BINDInfo{},
		models.ClockInfo{}, models.FDInfo{}, models.SystemdInfo{}, models.SysctlInfo{},
		models.KernelSecurityInfo{}, models.LogsInfo{}, models.EntropyInfo{},
		models.PackagesInfo{}, models.CVEAllResult{}, models.NVMeInfo{}, models.RAIDInfo{},
		models.ZFSInfo{}, models.LVMInfo{}, models.DRBDInfo{}, models.PVEInfo{},
		models.BatteryInfo{}, models.ThermalInfo{}, models.HealthDeepInfo{}, models.FirmwareInfo{},
		models.DockerInfo{}, models.ContainerdInfo{}, models.K8sInfo{}, models.KVMInfo{},
		models.SteamOSInfo{}, models.TLSInfo{}, models.GPUInfo{}, models.SecurityInfo{},
		models.ProcessInfo{}, models.SnapperInfo{}, models.SUSEConnectInfo{}, models.HardwareInfo{},
		models.BondingInfo{}, models.IPMIInfo{}, models.OOMInfo{}, models.HBAInfo{},
		models.PressureInfo{}, models.MultipathInfo{}, models.CephInfo{}, models.FirewallInfo{},
		models.AuthInfo{}, models.CloudInfo{}, models.CloudInitInfo{}, models.AuditInfo{},
		models.NUMAInfo{}, models.VLANInfo{}, models.ISCSIInfo{}, models.InfiniBandInfo{},
		models.SRIOVInfo{}, models.NspawnInfo{}, models.HugePagesInfo{}, models.CPUFreqInfo{},
		models.LaunchdInfo{}, models.DBusInfo{}, models.SessionsInfo{}, models.CronInfo{},
		models.DNSResolverInfo{},
	}
	for _, v := range values {
		_ = applyOne(v, defaultThresh, ctr) // must not panic; result content covered elsewhere
	}

	pointers := []interface{}{
		&models.CPUInfo{}, &models.MemoryInfo{}, &models.DiskInfo{}, &models.SwapInfo{},
		&models.IOInfo{}, &models.NetworkInfo{}, &models.NFSInfo{}, &models.BINDInfo{},
		&models.ClockInfo{}, &models.FDInfo{}, &models.SystemdInfo{}, &models.SysctlInfo{},
		&models.KernelSecurityInfo{}, &models.LogsInfo{}, &models.EntropyInfo{},
		&models.PackagesInfo{}, &models.CVEAllResult{}, &models.NVMeInfo{}, &models.RAIDInfo{},
		&models.ZFSInfo{}, &models.LVMInfo{}, &models.DRBDInfo{}, &models.PVEInfo{},
		&models.BatteryInfo{}, &models.ThermalInfo{}, &models.HealthDeepInfo{}, &models.FirmwareInfo{},
		&models.DockerInfo{}, &models.ContainerdInfo{}, &models.K8sInfo{}, &models.KVMInfo{},
		&models.SteamOSInfo{}, &models.TLSInfo{}, &models.GPUInfo{}, &models.SecurityInfo{},
		&models.ProcessInfo{}, &models.SnapperInfo{}, &models.SUSEConnectInfo{}, &models.HardwareInfo{},
		&models.BondingInfo{}, &models.IPMIInfo{}, &models.OOMInfo{}, &models.HBAInfo{},
		&models.PressureInfo{}, &models.MultipathInfo{}, &models.CephInfo{}, &models.FirewallInfo{},
		&models.AuthInfo{}, &models.CloudInfo{}, &models.CloudInitInfo{}, &models.AuditInfo{},
		&models.NUMAInfo{}, &models.VLANInfo{}, &models.ISCSIInfo{}, &models.InfiniBandInfo{},
		&models.SRIOVInfo{}, &models.NspawnInfo{}, &models.HugePagesInfo{}, &models.CPUFreqInfo{},
		&models.LaunchdInfo{}, &models.DBusInfo{}, &models.SessionsInfo{}, &models.CronInfo{},
		&models.DNSResolverInfo{},
	}
	for _, p := range pointers {
		_ = applyOne(p, defaultThresh, ctr)
	}

	// Unknown type must fall through both dispatchers to nil.
	if got := applyOne(struct{ X int }{}, defaultThresh, ctr); got != nil {
		t.Errorf("unknown type should dispatch to nil, got %+v", got)
	}
}
