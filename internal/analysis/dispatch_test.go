package analysis

import (
	"reflect"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// TestApplyOneDispatch drives every model type through applyOne (and its
// applyOneExtended continuation) in both value and pointer form. This exercises
// the full type-switch dispatch table — each arm routes to a check* function
// already covered individually — and pins the contract that an unknown type,
// or a typed-nil pointer (e.g. a collector returning `var info *models.XInfo;
// return info, nil`), falls through to nil without panicking.
func TestApplyOneDispatch(t *testing.T) {
	ctr := platform.ContainerContext{}

	values := []any{
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
		models.KdumpInfo{}, models.TunedInfo{}, models.KernelPatchInfo{},
		models.KspliceInfo{}, models.ServiceRestartInfo{},
		models.NetworkdConfigInfo{}, models.RootFSInfo{}, models.FstabInfo{},
		models.PostgresInfo{}, models.MySQLInfo{}, models.RedisInfo{}, models.MemcachedInfo{},
		models.NginxInfo{}, models.ApacheInfo{}, models.HAProxyInfo{}, models.RabbitMQInfo{},
		models.ElasticsearchInfo{}, models.MongoDBInfo{}, models.KafkaInfo{}, models.PrometheusInfo{},
		models.AlertmanagerInfo{}, models.GrafanaInfo{}, models.TraefikInfo{}, models.EnvoyInfo{},
		models.RancherInfo{}, models.HAInfo{}, models.MTEInfo{}, models.HWRaidInfo{},
		models.VMwareInfo{}, models.KVMGuestInfo{}, models.ContainerGuestInfo{},
		models.AWSInfo{}, models.AzureInfo{}, models.GCPInfo{}, models.OCIInfo{}, models.PostBootInfo{},
		models.KernelRetentionInfo{}, models.LivePatchInfo{}, models.TransactionalInfo{}, models.ServicesInfo{},
	}
	for _, v := range values {
		_ = applyOne(v, defaultThresh, ctr) // must not panic; result content covered elsewhere
	}

	pointers := []any{
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
		&models.KdumpInfo{}, &models.TunedInfo{}, &models.KernelPatchInfo{},
		&models.KspliceInfo{}, &models.ServiceRestartInfo{},
		&models.NetworkdConfigInfo{}, &models.RootFSInfo{}, &models.FstabInfo{},
		&models.PostgresInfo{}, &models.MySQLInfo{}, &models.RedisInfo{}, &models.MemcachedInfo{},
		&models.NginxInfo{}, &models.ApacheInfo{}, &models.HAProxyInfo{}, &models.RabbitMQInfo{},
		&models.ElasticsearchInfo{}, &models.MongoDBInfo{}, &models.KafkaInfo{}, &models.PrometheusInfo{},
		&models.AlertmanagerInfo{}, &models.GrafanaInfo{}, &models.TraefikInfo{}, &models.EnvoyInfo{},
		&models.RancherInfo{}, &models.HAInfo{}, &models.MTEInfo{}, &models.HWRaidInfo{},
		&models.VMwareInfo{}, &models.KVMGuestInfo{}, &models.ContainerGuestInfo{},
		&models.AWSInfo{}, &models.AzureInfo{}, &models.GCPInfo{}, &models.OCIInfo{}, &models.PostBootInfo{},
		&models.KernelRetentionInfo{}, &models.LivePatchInfo{}, &models.TransactionalInfo{}, &models.ServicesInfo{},
	}
	for _, p := range pointers {
		_ = applyOne(p, defaultThresh, ctr)
	}

	// Typed-nil pointers (the interface{} boxes a real *models.XInfo whose value
	// is nil) must also fall through without panicking. Derived by reflection
	// from the pointers list above so it can't drift out of sync with it.
	for _, p := range pointers {
		nilPtr := reflect.Zero(reflect.TypeOf(p)).Interface()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("applyOne panicked on nil %T: %v", nilPtr, r)
				}
			}()
			_ = applyOne(nilPtr, defaultThresh, ctr)
		}()
	}

	// Unknown type must fall through both dispatchers to nil.
	if got := applyOne(struct{ X int }{}, defaultThresh, ctr); got != nil {
		t.Errorf("unknown type should dispatch to nil, got %+v", got)
	}
}
