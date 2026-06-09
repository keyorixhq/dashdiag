package models

// IsAvailable methods implement the runner availability contract
// (runner.IsAvailable): a collector result is "present / applicable" on this
// host unless it says otherwise via Available=false. Both surfaces that decide
// visibility — live dsd health (render.shouldHideRow) and dsd health --report
// (baseline.BuildSnapshot) — go through that one contract, so a not-applicable
// collector (e.g. Ceph with the CLI but no cluster) is hidden identically in
// both. Value receivers so both T and *T satisfy the interface.
//
// Every struct in this package that has an `Available bool` field MUST have a
// method here. That is enforced by TestAvailableStructsImplementIsAvailable
// (availability_meta_test.go) — if you add an Available field and the tests
// fail, add the one-line method below. (Differently-named fields such as
// RAUCAvailable/EDACAvailable are NOT part of this contract — they describe a
// sub-probe, not whether the whole collector result applies.)

func (i AuditInfo) IsAvailable() bool          { return i.Available }
func (i AuthInfo) IsAvailable() bool           { return i.Available }
func (i CephInfo) IsAvailable() bool           { return i.Available }
func (i CgroupV2Info) IsAvailable() bool       { return i.Available }
func (i CloudInfo) IsAvailable() bool          { return i.Available }
func (i CloudInitInfo) IsAvailable() bool      { return i.Available }
func (i ContainerdInfo) IsAvailable() bool     { return i.Available }
func (i DBusInfo) IsAvailable() bool           { return i.Available }
func (i DNSResolverInfo) IsAvailable() bool    { return i.Available }
func (i DockerInfo) IsAvailable() bool         { return i.Available }
func (i EntropyInfo) IsAvailable() bool        { return i.Available }
func (i FirewallInfo) IsAvailable() bool       { return i.Available }
func (i FirmwareInfo) IsAvailable() bool       { return i.Available }
func (i HugePagesInfo) IsAvailable() bool      { return i.Available }
func (i IPMIInfo) IsAvailable() bool           { return i.Available }
func (i ISCSIInfo) IsAvailable() bool          { return i.Available }
func (i KernelSecurityInfo) IsAvailable() bool { return i.Available }
func (i LogsInfo) IsAvailable() bool           { return i.Available }
func (i MultipathInfo) IsAvailable() bool      { return i.Available }
func (i NspawnInfo) IsAvailable() bool         { return i.Available }
func (i NUMAInfo) IsAvailable() bool           { return i.Available }
func (i OOMInfo) IsAvailable() bool            { return i.Available }
func (i PressureInfo) IsAvailable() bool       { return i.Available }
func (i PVEPerf) IsAvailable() bool            { return i.Available }
func (i SnapperInfo) IsAvailable() bool        { return i.Available }
func (i SysctlInfo) IsAvailable() bool         { return i.Available }
func (i SystemdInfo) IsAvailable() bool        { return i.Available }
func (i ThermalInfo) IsAvailable() bool        { return i.Available }
func (i UserUnitsInfo) IsAvailable() bool      { return i.Available }
