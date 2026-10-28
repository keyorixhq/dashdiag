package render

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// GUARD C (DD-COVERAGE-1) — every check resolves to exactly one coverage value.
//
// Coverage is derived in ONE place (coverage.go) from signals the collectors
// already emit: Result.Err, nil data, Available=false (runner.IsAvailable) and
// Unverified/NeedsRoot insights. The one thing a new collector can get wrong is
// HOW it says "nothing here": through the IsAvailable contract, through nil data,
// or not at all (it is registered only when its subsystem is present, see
// cmd/health.go buildHealthCollectors). coverageRegistry records that decision for
// every Collect()-implementing type, and TestGuardC_RegistryMatchesCollectors
// fails when
//
//   - a new collector has no row (collector #111 cannot be added silently),
//   - a row is stale, or
//   - the row no longer matches what the Collect body does (it started returning
//     nil, nil, or began setting Available): the author must re-decide.
//
// TestGuardC_EveryCollectorResolvesToOneCoverage then runs every row through the
// four runs the brief names: normal, all-errored, non-root and not-present.

type presence int

const (
	// presenceAlways: no absence signal in Collect. The result is always data;
	// "not present" is the collector not being registered (cmd/health.go gates it
	// on a probe), so it never reaches Coverage at all. Not counted as
	// not_applicable: it never ran.
	presenceAlways presence = iota
	// presenceAvailable: Collect sets Available (models.*Info.IsAvailable): an
	// Available=false result is not_applicable / not_present.
	presenceAvailable
	// presenceNilGate: Collect returns (nil, nil) when there is nothing here (or
	// on this platform): not_applicable / not_supported_platform.
	presenceNilGate
	// presenceBoth: either of the above.
	presenceBoth
)

func (p presence) String() string {
	return [...]string{"always", "available", "nilgate", "both"}[p]
}

type presenceRow struct {
	kind  presence
	files string // where Collect lives; the row's evidence
}

// coverageRegistry maps each Collect()-implementing type to how it signals "not
// present". Keyed by type name; a collector with per-platform files is one row.
var coverageRegistry = map[string]presenceRow{
	"AWSCollector":             {presenceAlways, "aws_linux.go aws_notlinux.go"},
	"AlertmanagerCollector":    {presenceAlways, "alertmanager_linux.go alertmanager_notlinux.go"},
	"ApacheCollector":          {presenceAlways, "apache_linux.go apache_notlinux.go"},
	"AuditCollector":           {presenceAvailable, "auditd_linux.go auditd_notlinux.go"},
	"AuthCollector":            {presenceAvailable, "auth_darwin.go auth_linux.go auth_notlinux.go"},
	"AzureCollector":           {presenceAlways, "azure_linux.go azure_notlinux.go"},
	"BINDCollector":            {presenceNilGate, "bind_linux.go bind_notlinux.go"},
	"BatteryCollector":         {presenceNilGate, "battery_darwin.go battery_linux.go battery_notlinux.go"},
	"BondingCollector":         {presenceAlways, "bonding_linux.go bonding_notlinux.go"},
	"CPUCollector":             {presenceAlways, "cpu.go"},
	"CPUFreqCollector":         {presenceAlways, "cpufreq_linux.go cpufreq_notlinux.go"},
	"CVEHealthCollector":       {presenceAlways, "cve_health.go"},
	"CephCollector":            {presenceAvailable, "ceph_linux.go ceph_notlinux.go"},
	"ClockCollector":           {presenceAlways, "clock.go"},
	"CloudInitCollector":       {presenceAvailable, "cloudinit_linux.go cloudinit_notlinux.go"},
	"CloudMetaCollector":       {presenceAlways, "cloudmeta_linux.go cloudmeta_notlinux.go"},
	"ContainerGuestCollector":  {presenceAlways, "containerguest_linux.go containerguest_notlinux.go"},
	"ContainerdCollector":      {presenceBoth, "containerd_linux.go containerd_other.go"},
	"CronCollector":            {presenceAlways, "cron_linux.go cron_notlinux.go"},
	"DBusCollector":            {presenceBoth, "dbus_linux.go dbus_notlinux.go"},
	"DNSCollector":             {presenceAvailable, "dns_linux.go dns_notlinux.go"},
	"DNSResolverCollector":     {presenceNilGate, "dns_resolver_linux.go dns_resolver_notlinux.go"},
	"DRBDCollector":            {presenceNilGate, "drbd_linux.go drbd_notlinux.go"},
	"DiskCollector":            {presenceAlways, "disk.go"},
	"DockerCollector":          {presenceAvailable, "docker.go"},
	"ElasticsearchCollector":   {presenceAlways, "elasticsearch_linux.go elasticsearch_notlinux.go"},
	"EntropyCollector":         {presenceAvailable, "entropy_linux.go entropy_notlinux.go"},
	"EnvoyCollector":           {presenceAlways, "envoy_linux.go envoy_notlinux.go"},
	"FDLimitsCollector":        {presenceAlways, "fdlimits.go"},
	"FirewallCollector":        {presenceAlways, "firewall_linux.go firewall_notlinux.go"},
	"FirmwareCollector":        {presenceAvailable, "firmware.go firmware_other.go"},
	"FstabDriftCollector":      {presenceNilGate, "fstab_drift_linux.go fstab_drift_notlinux.go"},
	"GCPCollector":             {presenceAlways, "gcp_linux.go gcp_notlinux.go"},
	"GPUCollector":             {presenceAlways, "gpu_linux.go gpu_notlinux.go"},
	"GrafanaCollector":         {presenceAlways, "grafana_linux.go grafana_notlinux.go"},
	"HACollector":              {presenceAvailable, "ha_collector.go ha_notlinux.go"},
	"HAProxyCollector":         {presenceAlways, "haproxy_linux.go haproxy_notlinux.go"},
	"HBACollector":             {presenceAlways, "hba_linux.go hba_notlinux.go"},
	"HWRaidCollector":          {presenceBoth, "hwraid_linux.go hwraid_notlinux.go"},
	"HardwareCollector":        {presenceAlways, "hardware_linux.go hardware_other.go"},
	"HealthDeepCollector":      {presenceAvailable, "health_deep_linux.go health_deep_other.go"},
	"HugePagesCollector":       {presenceAvailable, "hugepages_linux.go hugepages_notlinux.go"},
	"IOCollector":              {presenceAlways, "io.go"},
	"IPMICollector":            {presenceAvailable, "ipmi_linux.go ipmi_notlinux.go"},
	"ISCSICollector":           {presenceBoth, "iscsi_linux.go iscsi_notlinux.go"},
	"InfiniBandCollector":      {presenceAlways, "infiniband_linux.go infiniband_notlinux.go"},
	"K8sCollector":             {presenceAlways, "k8s.go"},
	"KVMCollector":             {presenceAlways, "kvm_linux.go kvm_notlinux.go"},
	"KVMGuestCollector":        {presenceAlways, "kvmguest_linux.go kvmguest_notlinux.go"},
	"KafkaCollector":           {presenceAlways, "kafka_linux.go kafka_notlinux.go"},
	"KdumpCollector":           {presenceAvailable, "maintenance_linux.go maintenance_notlinux.go"},
	"KernelPatchCollector":     {presenceAvailable, "maintenance_linux.go maintenance_notlinux.go"},
	"KernelRetentionCollector": {presenceAvailable, "maintenance_linux.go maintenance_notlinux.go"},
	"KernelSecurityCollector":  {presenceAvailable, "kernel_security.go"},
	"KspliceCollector":         {presenceAvailable, "maintenance_linux.go maintenance_notlinux.go"},
	"LVMCollector":             {presenceAlways, "lvm_linux.go lvm_notlinux.go"},
	"LaunchdCollector":         {presenceNilGate, "launchd_darwin.go launchd_notdarwin.go"},
	"LivePatchCollector":       {presenceAvailable, "maintenance_linux.go maintenance_notlinux.go"},
	"LogsCollector":            {presenceAvailable, "logs_linux.go logs_notlinux.go"},
	"MTECollector":             {presenceAvailable, "mte_linux.go mte_notlinux.go"},
	"MemcachedCollector":       {presenceAlways, "memcached_linux.go memcached_notlinux.go"},
	"MemoryCollector":          {presenceAvailable, "memory.go"},
	"MongoDBCollector":         {presenceAlways, "mongodb_linux.go mongodb_notlinux.go"},
	"MultipathCollector":       {presenceBoth, "multipath_linux.go multipath_notlinux.go"},
	"MySQLCollector":           {presenceAlways, "mysql_linux.go mysql_notlinux.go"},
	"NFSCollector":             {presenceNilGate, "nfs_linux.go nfs_notlinux.go"},
	"NUMACollector":            {presenceAvailable, "numa_linux.go numa_notlinux.go"},
	"NVMeCollector":            {presenceNilGate, "nvme_darwin.go nvme_linux.go nvme_notlinux.go"},
	"NetworkCollector":         {presenceAlways, "network_quick.go"},
	"NetworkDeepCollector":     {presenceAlways, "network_deep.go"},
	"NetworkdConfigCollector":  {presenceNilGate, "networkd_config_linux.go networkd_config_notlinux.go"},
	"NginxCollector":           {presenceAlways, "nginx_linux.go nginx_notlinux.go"},
	"NspawnCollector":          {presenceAvailable, "nspawn_linux.go nspawn_notlinux.go"},
	"OCICollector":             {presenceAlways, "oci_linux.go oci_notlinux.go"},
	"OOMCollector":             {presenceAvailable, "oom_linux.go oom_notlinux.go"},
	"PVECollector":             {presenceAlways, "pve_linux.go pve_notlinux.go"},
	"PackagesCollector":        {presenceAlways, "packages_linux.go packages_notlinux.go"},
	"PostBootCollector":        {presenceAvailable, "postboot_linux.go postboot_notlinux.go"},
	"PostgresCollector":        {presenceAlways, "postgres_linux.go postgres_notlinux.go"},
	"PressureCollector":        {presenceAvailable, "pressure_linux.go pressure_notlinux.go"},
	"ProcCollector":            {presenceAlways, "proc_linux.go proc_notlinux.go"},
	"ProcessesCollector":       {presenceAlways, "processes.go"},
	"PrometheusCollector":      {presenceAlways, "prometheus_linux.go prometheus_notlinux.go"},
	"RAIDCollector":            {presenceAlways, "raid_linux.go raid_notlinux.go"},
	"RabbitMQCollector":        {presenceAlways, "rabbitmq_linux.go rabbitmq_notlinux.go"},
	"RancherCollector":         {presenceAvailable, "rancher_collector.go"},
	"RedisCollector":           {presenceAlways, "redis_linux.go redis_notlinux.go"},
	"RootFSCollector":          {presenceNilGate, "rootfs_linux.go rootfs_notlinux.go"},
	"SRIOVCollector":           {presenceAlways, "sriov_linux.go sriov_notlinux.go"},
	"SUSEConnectCollector":     {presenceAlways, "suseconnect_collector.go"},
	"SecurityCollector":        {presenceAlways, "security_darwin.go security_linux.go security_notlinux.go"},
	"ServiceRestartCollector":  {presenceAvailable, "maintenance_linux.go maintenance_notlinux.go"},
	"ServicesCollector":        {presenceAlways, "services.go"},
	"ServicesDeepCollector":    {presenceAlways, "services_deep_linux.go services_deep_notlinux.go"},
	"SessionsCollector":        {presenceAlways, "sessions.go"},
	"SnapperCollector":         {presenceAlways, "snapper_collector.go"},
	"SteamOSCollector":         {presenceAlways, "steamos_linux.go steamos_notlinux.go"},
	"SwapCollector":            {presenceAlways, "swap.go"},
	"SysctlCollector":          {presenceAlways, "sysctl.go"},
	"SystemdCollector":         {presenceAvailable, "systemd.go"},
	"TLSCollector":             {presenceAlways, "tls.go"},
	"ThermalCollector":         {presenceBoth, "thermal_linux.go thermal_notlinux.go thermal_other.go"},
	"TimelineCollector":        {presenceAlways, "timeline_linux.go timeline_notlinux.go"},
	"TraefikCollector":         {presenceAlways, "traefik_linux.go traefik_notlinux.go"},
	"TransactionalCollector":   {presenceAvailable, "maintenance_linux.go maintenance_notlinux.go"},
	"TunedCollector":           {presenceAvailable, "maintenance_linux.go maintenance_notlinux.go"},
	"VLANCollector":            {presenceNilGate, "vlan_linux.go vlan_notlinux.go"},
	"VMwareCollector":          {presenceAlways, "vmware_linux.go vmware_notlinux.go"},
	"VaultCollector":           {presenceAvailable, "vault_linux.go vault_notlinux.go"},
	"ZFSCollector":             {presenceAlways, "zfs.go"},
}

// classifyCollectors parses internal/collectors and reports, per Collect()
// type, whether its body returns (nil, nil) and whether it sets Available.
func classifyCollectors(t *testing.T) map[string]presence {
	t.Helper()
	dir := filepath.Join("..", "collectors")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	type sig struct{ nilNil, avail bool }
	found := map[string]*sig{}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "Collect" || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Body == nil {
				continue
			}
			rt := fn.Recv.List[0].Type
			if star, ok := rt.(*ast.StarExpr); ok {
				rt = star.X
			}
			id, ok := rt.(*ast.Ident)
			if !ok || !strings.HasSuffix(id.Name, "Collector") {
				continue
			}
			s := found[id.Name]
			if s == nil {
				s = &sig{}
				found[id.Name] = s
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.ReturnStmt:
					if len(x.Results) == 2 && isNilIdent(x.Results[0]) && isNilIdent(x.Results[1]) {
						s.nilNil = true
					}
				case *ast.KeyValueExpr:
					if k, ok := x.Key.(*ast.Ident); ok && k.Name == "Available" {
						s.avail = true
					}
				case *ast.SelectorExpr:
					if x.Sel.Name == "Available" {
						s.avail = true
					}
				}
				return true
			})
		}
	}
	out := map[string]presence{}
	for n, s := range found {
		switch {
		case s.avail && s.nilNil:
			out[n] = presenceBoth
		case s.avail:
			out[n] = presenceAvailable
		case s.nilNil:
			out[n] = presenceNilGate
		default:
			out[n] = presenceAlways
		}
	}
	return out
}

func isNilIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "nil"
}

func TestGuardC_RegistryMatchesCollectors(t *testing.T) {
	found := classifyCollectors(t)
	var unregistered, stale, changed []string
	for name, kind := range found {
		row, ok := coverageRegistry[name]
		switch {
		case !ok:
			unregistered = append(unregistered, name+" ("+kind.String()+")")
		case row.kind != kind:
			changed = append(changed, name+": registry says "+row.kind.String()+", Collect now looks like "+kind.String())
		}
	}
	for name := range coverageRegistry {
		if _, ok := found[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(unregistered)
	sort.Strings(stale)
	sort.Strings(changed)
	if len(unregistered) > 0 {
		t.Errorf("%d Collect() type(s) have no coverageRegistry row: %s\n"+
			"Decide how the collector says \"nothing here\" (IsAvailable contract / nil data / registration gate in cmd/health.go) and add a row.",
			len(unregistered), strings.Join(unregistered, ", "))
	}
	if len(stale) > 0 {
		t.Errorf("coverageRegistry rows without a Collect() type (remove or rename): %s", strings.Join(stale, ", "))
	}
	if len(changed) > 0 {
		t.Errorf("a collector's absence signal changed; re-check its coverage and update the row:\n  %s", strings.Join(changed, "\n  "))
	}
	for name, row := range coverageRegistry {
		if strings.TrimSpace(row.files) == "" {
			t.Errorf("%s: row has no evidence (files)", name)
		}
	}
}

// coverageScenario is one of the four runs every collector must resolve under.
type coverageScenario struct {
	name     string
	results  func(check string) []runner.Result
	insights func(check string, results []runner.Result) []models.Insight
	// want is the single coverage value and (for not_checked / not_applicable) a
	// reason from the allowed set.
	want    string
	reasons []string
	verdict string // the verdict the scenario alone must produce
}

func coverageScenarios() []coverageScenario {
	thresh := analysis.DefaultThresholds(platform.CloudEnvironment(0))
	return []coverageScenario{
		{
			name:    "normal run",
			results: func(c string) []runner.Result { return []runner.Result{{Name: c, Data: &models.CPUInfo{}}} },
			want:    models.CoverageChecked, reasons: []string{""}, verdict: "OK",
		},
		{
			name:    "all errored",
			results: func(c string) []runner.Result { return []runner.Result{{Name: c, Err: errors.New("collector failed")}} },
			insights: func(_ string, r []runner.Result) []models.Insight {
				return analysis.ApplyThresholds(r, thresh, platform.CloudEnvironment(0), platform.ContainerContext{})
			},
			want: models.CoverageNotChecked, reasons: []string{models.ReasonCollectorError, models.ReasonTimeout, models.ReasonUnreadable}, verdict: "WARN",
		},
		{
			name:    "non-root",
			results: func(c string) []runner.Result { return []runner.Result{{Name: c, Data: &models.CPUInfo{}}} },
			insights: func(c string, _ []runner.Result) []models.Insight {
				return []models.Insight{needsRootInsight(c, "root-only read skipped")}
			},
			// A root-only read skipped on a non-root run: the check still ran.
			want: models.CoverageChecked, reasons: []string{""}, verdict: "OK",
		},
	}
}

// notPresentScenarios returns the "not present" fixtures a collector of this
// kind can produce: one per absence signal it has.
func notPresentScenarios(kind presence) []coverageScenario {
	var out []coverageScenario
	if kind == presenceAvailable || kind == presenceBoth {
		out = append(out, coverageScenario{
			name: "not present (Available=false)",
			results: func(c string) []runner.Result {
				return []runner.Result{{Name: c, Data: models.CephInfo{Available: false}}}
			},
			want: models.CoverageNotApplicable, reasons: []string{models.ReasonNotPresent}, verdict: "OK",
		})
	}
	if kind == presenceNilGate || kind == presenceBoth {
		out = append(out, coverageScenario{
			name:    "not present (nil data)",
			results: func(c string) []runner.Result { return []runner.Result{{Name: c}} },
			want:    models.CoverageNotApplicable, reasons: []string{models.ReasonNotSupportedPlatform}, verdict: "OK",
		})
	}
	return out
}

func TestGuardC_EveryCollectorResolvesToOneCoverage(t *testing.T) {
	names := make([]string, 0, len(coverageRegistry))
	for n := range coverageRegistry {
		names = append(names, n)
	}
	sort.Strings(names)
	allowed := map[string]bool{"": true}
	for _, r := range models.CoverageReasons {
		allowed[r] = true
	}
	for _, typeName := range names {
		check := strings.TrimSuffix(typeName, "Collector")
		row := coverageRegistry[typeName]
		scenarios := append(coverageScenarios(), notPresentScenarios(row.kind)...)
		for _, sc := range scenarios {
			t.Run(typeName+"/"+sc.name, func(t *testing.T) {
				results := sc.results(check)
				var insights []models.Insight
				if sc.insights != nil {
					insights = sc.insights(check, results)
				}
				cov := Coverage(results, insights)

				// Exactly one entry for the check, with exactly one value.
				var entries []models.CheckCoverage
				for _, c := range cov.Checks {
					if c.Name == check {
						entries = append(entries, c)
					}
				}
				if len(entries) != 1 {
					t.Fatalf("%d coverage entries for %q, want exactly 1: %+v", len(entries), check, cov.Checks)
				}
				got := entries[0]
				if got.Coverage != sc.want {
					t.Fatalf("coverage = %q, want %q", got.Coverage, sc.want)
				}
				ok := false
				for _, r := range sc.reasons {
					ok = ok || got.Reason == r
				}
				if !ok || !allowed[got.Reason] {
					t.Errorf("reason %q not in the allowed %v (documented: %v)", got.Reason, sc.reasons, models.CoverageReasons)
				}
				if cov.Checked+cov.NotApplicable+countWholeNotChecked(cov) != len(cov.Checks) {
					t.Errorf("counts do not partition the checks: %+v", cov)
				}
				if v := Verdict(results, insights).Level; v != sc.verdict {
					t.Errorf("verdict = %s, want %s: coverage must not move it", v, sc.verdict)
				}
			})
		}
	}
}

func countWholeNotChecked(c models.CoverageSummary) int {
	n := 0
	for _, cc := range c.Checks {
		if cc.Coverage == models.CoverageNotChecked {
			n++
		}
	}
	return n
}

// TestGuardC_NotCheckedNeverClean: a run with anything not checked is never
// worded as clean/healthy: Verdict.Clean() is false whenever NotChecked > 0.
func TestGuardC_NotCheckedNeverClean(t *testing.T) {
	runs := append(guardRuns(), needsRootOnly())
	for _, run := range runs {
		t.Run(run.name, func(t *testing.T) {
			cov := Coverage(run.results, run.insights)
			if cov.NotChecked > 0 && Verdict(run.results, run.insights).Clean() {
				t.Errorf("%d item(s) not checked but the verdict is Clean (may be worded healthy): %+v", cov.NotChecked, cov)
			}
		})
	}
}

// passedMarker matches the spellings an output uses for "this passed".
var passedMarker = []string{"✅", "passed", "healthy", "all clear", "class=\"st ok\"", "class=\"verdict ok\""}

var okWord = func(s string) bool {
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') }) {
		if f == "OK" {
			return true
		}
	}
	return false
}

func isHeading(line string) bool {
	l := strings.TrimSpace(line)
	return strings.HasPrefix(l, "#") || strings.Contains(l, "<h2") || strings.Contains(l, "<h3")
}

// passedViolations lists where text shows one of the not-checked check names on
// a "passed" line, or under a heading that says passed/OK/healthy.
func passedViolations(text string, notChecked []string) []string {
	var out []string
	heading := ""
	headingPassed := false
	for _, line := range strings.Split(text, "\n") {
		if isHeading(line) {
			heading = strings.TrimSpace(line)
			low := strings.ToLower(line)
			headingPassed = strings.Contains(low, "passed") || strings.Contains(low, "healthy") || okWord(line)
			continue
		}
		for _, name := range notChecked {
			if !strings.Contains(line, name) {
				continue
			}
			low := strings.ToLower(line)
			marked := okWord(line)
			for _, m := range passedMarker {
				marked = marked || strings.Contains(low, strings.ToLower(m))
			}
			// The Not checked section itself says "this is not a pass".
			if strings.Contains(low, "not a pass") || strings.Contains(low, "not checked") || strings.Contains(low, "not looked at") {
				marked = false
			}
			if marked || headingPassed {
				out = append(out, "line "+strings.TrimSpace(line)+" (under "+heading+")")
			}
		}
	}
	return out
}

// TestGuardC_NotCheckedNeverUnderPassedHeading extends Guard A: no output may
// render a not-checked check on a passed/OK/healthy line or under such a heading.
func TestGuardC_NotCheckedNeverUnderPassedHeading(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, run := range append(guardRuns(), needsRootOnly()) {
		cov := Coverage(run.results, run.insights)
		var names []string
		for _, it := range NotCheckedItems(&cov) {
			names = append(names, it.Check)
		}
		if len(names) == 0 {
			continue
		}
		for _, out := range guardOutputs() {
			t.Run(run.name+"/"+out.name, func(t *testing.T) {
				text := out.render(t, run)
				if v := passedViolations(text, names); len(v) > 0 {
					t.Errorf("%s shows a not-checked check as passed:\n  %s\n--- output ---\n%s", out.name, strings.Join(v, "\n  "), text)
				}
			})
		}
		// The terminal summary with the run's coverage, both modes.
		snap := guardSnap(run)
		for _, mode := range []output.OutputMode{output.ModeHuman, output.ModePlain} {
			text := captureStdout(t, func() { NewRenderer(mode).SetCoverageFrom(snap).PrintSummary(run.insights, 0) })
			if v := passedViolations(text, names); len(v) > 0 {
				t.Errorf("%s/terminal mode %v shows a not-checked check as passed:\n  %s", run.name, mode, strings.Join(v, "\n  "))
			}
		}
	}
}

// TestGuardC_DetectorCatchesTheNegativeExample proves the detector above has
// teeth: testdata/coverage_negative_report.md is a report that files a
// not-checked check under a "passed" heading and on an "✅ OK" row; the detector
// must flag both, and must flag nothing in the good example next to it.
func TestGuardC_DetectorCatchesTheNegativeExample(t *testing.T) {
	bad, err := os.ReadFile(filepath.Join("testdata", "coverage_negative_report.md"))
	if err != nil {
		t.Fatal(err)
	}
	got := passedViolations(string(bad), []string{"Hardening", "Memory"})
	if len(got) < 2 {
		t.Errorf("detector found %d violation(s) in the negative example, want at least 2 (an OK row and a passed heading): %v", len(got), got)
	}
	good, err := os.ReadFile(filepath.Join("testdata", "coverage_good_report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if v := passedViolations(string(good), []string{"Hardening", "Memory"}); len(v) > 0 {
		t.Errorf("detector flagged the good example: %v", v)
	}
}

// TestGuardC_ReasonsMatchTheSchema: the reasons dsd can emit are exactly the
// schema's enums, so a new reason cannot ship undocumented.
func TestGuardC_ReasonsMatchTheSchema(t *testing.T) {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, r := range models.CoverageReasons {
		if !strings.Contains(text, "\""+r+"\"") {
			t.Errorf("reason %q is not in schema/dsd-output.json", r)
		}
	}
}
