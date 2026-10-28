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

func (i AuditInfo) IsAvailable() bool           { return i.Available }
func (i AuthInfo) IsAvailable() bool            { return i.Available }
func (i CephInfo) IsAvailable() bool            { return i.Available }
func (i CgroupV2Info) IsAvailable() bool        { return i.Available }
func (i CloudInfo) IsAvailable() bool           { return i.Available }
func (i CloudInitInfo) IsAvailable() bool       { return i.Available }
func (i ContainerdInfo) IsAvailable() bool      { return i.Available }
func (i DBusInfo) IsAvailable() bool            { return i.Available }
func (i DNSResolverInfo) IsAvailable() bool     { return i.Available }
func (i DockerInfo) IsAvailable() bool          { return i.Available }
func (i EntropyInfo) IsAvailable() bool         { return i.Available }
func (i FirewallInfo) IsAvailable() bool        { return i.Available }
func (i FirmwareInfo) IsAvailable() bool        { return i.Available }
func (i HugePagesInfo) IsAvailable() bool       { return i.Available }
func (i IPMIInfo) IsAvailable() bool            { return i.Available }
func (i ISCSIInfo) IsAvailable() bool           { return i.Available }
func (i KernelSecurityInfo) IsAvailable() bool  { return i.Available }
func (i RancherInfo) IsAvailable() bool         { return i.Available }
func (i HAInfo) IsAvailable() bool              { return i.Available }
func (i LogsInfo) IsAvailable() bool            { return i.Available }
func (i MultipathInfo) IsAvailable() bool       { return i.Available }
func (i MTEInfo) IsAvailable() bool             { return i.Available }
func (i HWRaidInfo) IsAvailable() bool          { return i.Available }
func (i NspawnInfo) IsAvailable() bool          { return i.Available }
func (i NUMAInfo) IsAvailable() bool            { return i.Available }
func (i OOMInfo) IsAvailable() bool             { return i.Available }
func (i PostBootInfo) IsAvailable() bool        { return i.Available }
func (i PressureInfo) IsAvailable() bool        { return i.Available }
func (i PVEPerf) IsAvailable() bool             { return i.Available }
func (i SnapperInfo) IsAvailable() bool         { return i.Available }
func (i SysctlInfo) IsAvailable() bool          { return i.Available }
func (i SystemdInfo) IsAvailable() bool         { return i.Available }
func (i ThermalInfo) IsAvailable() bool         { return i.Available }
func (i UserUnitsInfo) IsAvailable() bool       { return i.Available }
func (i KdumpInfo) IsAvailable() bool           { return i.Available }
func (i TunedInfo) IsAvailable() bool           { return i.Available }
func (i KernelPatchInfo) IsAvailable() bool     { return i.Available }
func (i KspliceInfo) IsAvailable() bool         { return i.Available }
func (i ServiceRestartInfo) IsAvailable() bool  { return i.Available }
func (i KernelRetentionInfo) IsAvailable() bool { return i.Available }
func (i LivePatchInfo) IsAvailable() bool       { return i.Available }
func (i TransactionalInfo) IsAvailable() bool   { return i.Available }
func (i VaultInfo) IsAvailable() bool           { return i.Available }

// Collectors that signal absence with Detected (or Present) instead of Available.
// buildHealthCollectors registers most of them after a probe, but a probe can pass
// while the collector then finds nothing (a port answers but is not that product,
// kubectl is installed but there is no cluster); without these methods that result
// would read as a phantom "OK" in checks[] and count as checked. With them it
// counts as not applicable, as an Available=false one does; an insight about it
// (for example "kubectl present but the API was unreachable") still keeps it
// visible and not_checked. TestAbsenceFlagStructsImplementIsAvailable enforces it.
func (i AlertmanagerInfo) IsAvailable() bool   { return i.Detected }
func (i ApacheInfo) IsAvailable() bool         { return i.Detected }
func (i BatteryInfo) IsAvailable() bool        { return i.Present }
func (i BINDInfo) IsAvailable() bool           { return i.Detected }
func (i ElasticsearchInfo) IsAvailable() bool  { return i.Detected }
func (i EnvoyInfo) IsAvailable() bool          { return i.Detected }
func (i GrafanaInfo) IsAvailable() bool        { return i.Detected }
func (i HAProxyInfo) IsAvailable() bool        { return i.Detected }
func (i K8sInfo) IsAvailable() bool            { return i.Detected }
func (i KafkaInfo) IsAvailable() bool          { return i.Detected }
func (i KVMInfo) IsAvailable() bool            { return i.Detected }
func (i MemcachedInfo) IsAvailable() bool      { return i.Detected }
func (i MongoDBInfo) IsAvailable() bool        { return i.Detected }
func (i MySQLInfo) IsAvailable() bool          { return i.Detected }
func (i NetworkdConfigInfo) IsAvailable() bool { return i.Detected }
func (i NginxInfo) IsAvailable() bool          { return i.Detected }
func (i PostgresInfo) IsAvailable() bool       { return i.Detected }
func (i PrometheusInfo) IsAvailable() bool     { return i.Detected }
func (i RabbitMQInfo) IsAvailable() bool       { return i.Detected }
func (i RedisInfo) IsAvailable() bool          { return i.Detected }
func (i SteamOSInfo) IsAvailable() bool        { return i.Detected }
func (i TraefikInfo) IsAvailable() bool        { return i.Detected }
