package models

import "testing"

// TestIsAvailableMethods exercises every IsAvailable() one-liner in
// availability.go with both Available=true and Available=false, verifying the
// method reflects the struct's Available field exactly. Table-driven so that
// adding a new type + method (guarded by TestAvailableStructsImplementIsAvailable
// in availability_meta_test.go) is a one-line addition here too.
func TestIsAvailableMethods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fn   func(available bool) bool
	}{
		{"AuditInfo", func(a bool) bool { return AuditInfo{Available: a}.IsAvailable() }},
		{"AuthInfo", func(a bool) bool { return AuthInfo{Available: a}.IsAvailable() }},
		{"CephInfo", func(a bool) bool { return CephInfo{Available: a}.IsAvailable() }},
		{"CgroupV2Info", func(a bool) bool { return CgroupV2Info{Available: a}.IsAvailable() }},
		{"CloudInfo", func(a bool) bool { return CloudInfo{Available: a}.IsAvailable() }},
		{"CloudInitInfo", func(a bool) bool { return CloudInitInfo{Available: a}.IsAvailable() }},
		{"ContainerdInfo", func(a bool) bool { return ContainerdInfo{Available: a}.IsAvailable() }},
		{"DBusInfo", func(a bool) bool { return DBusInfo{Available: a}.IsAvailable() }},
		{"DNSResolverInfo", func(a bool) bool { return DNSResolverInfo{Available: a}.IsAvailable() }},
		{"DockerInfo", func(a bool) bool { return DockerInfo{Available: a}.IsAvailable() }},
		{"EntropyInfo", func(a bool) bool { return EntropyInfo{Available: a}.IsAvailable() }},
		{"FirewallInfo", func(a bool) bool { return FirewallInfo{Available: a}.IsAvailable() }},
		{"FirmwareInfo", func(a bool) bool { return FirmwareInfo{Available: a}.IsAvailable() }},
		{"HugePagesInfo", func(a bool) bool { return HugePagesInfo{Available: a}.IsAvailable() }},
		{"IPMIInfo", func(a bool) bool { return IPMIInfo{Available: a}.IsAvailable() }},
		{"ISCSIInfo", func(a bool) bool { return ISCSIInfo{Available: a}.IsAvailable() }},
		{"KernelSecurityInfo", func(a bool) bool { return KernelSecurityInfo{Available: a}.IsAvailable() }},
		{"RancherInfo", func(a bool) bool { return RancherInfo{Available: a}.IsAvailable() }},
		{"HAInfo", func(a bool) bool { return HAInfo{Available: a}.IsAvailable() }},
		{"LogsInfo", func(a bool) bool { return LogsInfo{Available: a}.IsAvailable() }},
		{"MultipathInfo", func(a bool) bool { return MultipathInfo{Available: a}.IsAvailable() }},
		{"MTEInfo", func(a bool) bool { return MTEInfo{Available: a}.IsAvailable() }},
		{"HWRaidInfo", func(a bool) bool { return HWRaidInfo{Available: a}.IsAvailable() }},
		{"NspawnInfo", func(a bool) bool { return NspawnInfo{Available: a}.IsAvailable() }},
		{"NUMAInfo", func(a bool) bool { return NUMAInfo{Available: a}.IsAvailable() }},
		{"OOMInfo", func(a bool) bool { return OOMInfo{Available: a}.IsAvailable() }},
		{"PostBootInfo", func(a bool) bool { return PostBootInfo{Available: a}.IsAvailable() }},
		{"PressureInfo", func(a bool) bool { return PressureInfo{Available: a}.IsAvailable() }},
		{"PVEPerf", func(a bool) bool { return PVEPerf{Available: a}.IsAvailable() }},
		{"SnapperInfo", func(a bool) bool { return SnapperInfo{Available: a}.IsAvailable() }},
		{"SysctlInfo", func(a bool) bool { return SysctlInfo{Available: a}.IsAvailable() }},
		{"SystemdInfo", func(a bool) bool { return SystemdInfo{Available: a}.IsAvailable() }},
		{"ThermalInfo", func(a bool) bool { return ThermalInfo{Available: a}.IsAvailable() }},
		{"UserUnitsInfo", func(a bool) bool { return UserUnitsInfo{Available: a}.IsAvailable() }},
		{"KdumpInfo", func(a bool) bool { return KdumpInfo{Available: a}.IsAvailable() }},
		{"TunedInfo", func(a bool) bool { return TunedInfo{Available: a}.IsAvailable() }},
		{"KernelPatchInfo", func(a bool) bool { return KernelPatchInfo{Available: a}.IsAvailable() }},
		{"KspliceInfo", func(a bool) bool { return KspliceInfo{Available: a}.IsAvailable() }},
		{"ServiceRestartInfo", func(a bool) bool { return ServiceRestartInfo{Available: a}.IsAvailable() }},
		{"KernelRetentionInfo", func(a bool) bool { return KernelRetentionInfo{Available: a}.IsAvailable() }},
		{"LivePatchInfo", func(a bool) bool { return LivePatchInfo{Available: a}.IsAvailable() }},
		{"TransactionalInfo", func(a bool) bool { return TransactionalInfo{Available: a}.IsAvailable() }},
		{"VaultInfo", func(a bool) bool { return VaultInfo{Available: a}.IsAvailable() }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.fn(true); got != true {
				t.Errorf("%s.IsAvailable() with Available=true = %v, want true", tt.name, got)
			}
			if got := tt.fn(false); got != false {
				t.Errorf("%s.IsAvailable() with Available=false = %v, want false", tt.name, got)
			}
		})
	}
}
