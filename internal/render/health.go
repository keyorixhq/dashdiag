package render

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

type Renderer struct{ mode output.OutputMode }

func NewRenderer(mode output.OutputMode) *Renderer { return &Renderer{mode: mode} }

// insightForResult returns the highest-severity insight for a collector result.
// It matches on exact check name or the "Name " prefix (e.g. "IO" matches "IO sda").
// Analysis check names must equal the collector name; this prefix rule is a safety net.
func insightForResult(name string, insights []models.Insight) *models.Insight {
	order := map[string]int{"CRIT": 3, "WARN": 2, "INFO": 1, "OK": 0}
	prefix := name + " "
	slash := name + "/"
	var worst *models.Insight
	for i := range insights {
		check := insights[i].Check
		if check != name && !strings.HasPrefix(check, prefix) && !strings.HasPrefix(check, slash) {
			continue
		}
		if worst == nil || order[insights[i].Level] > order[worst.Level] {
			worst = &insights[i]
		}
	}
	return worst
}

// DisplayOrder returns the canonical row order for external callers (e.g. dsd capture).
func DisplayOrder() []string { return displayOrder }

// displayOrder defines the canonical row order for dsd health output.
// Collectors run in parallel — without this they appear in completion order.
// Groups: identity → compute → storage → network → security → platform-specific
var displayOrder = []string{
	// Compute
	"CPU Load", "CPU Thermal", "Memory", "Swap", "GPU",
	// Storage
	"Disk", "IO", "Drives", "LVM", "RAID", "ZFS", "DRBD",
	// Network
	"Network",
	// System
	"Systemd", "Processes", "FDLimits", "Entropy",
	"Clock", "Logs", "Sysctl",
	// Security
	"KernelSec", "Hardening", "Packages",
	// Platform-specific
	"Subscription", "Snapshots", "Battery", "Launchd", "PVE",
	"Bonding", "IPMI", "OOM", "HBA", "Pressure", "Multipath",
	"Ceph", "Firewall", "Auth", "CloudMeta", "Auditd",
	"NUMA", "VLAN", "iSCSI", "InfiniBand", "SRIOV", "Nspawn",
	"HugePages", "CPUFreq",
	// Optional
	"TLS", "Docker", "K8s", "Hardware",
}

// sortedResults reorders runner results into the canonical display order.
// Unknown collector names fall to the end in their original relative order.
func sortedResults(results []runner.Result) []runner.Result {
	pos := make(map[string]int, len(displayOrder))
	for i, name := range displayOrder {
		pos[name] = i
	}
	sorted := make([]runner.Result, len(results))
	copy(sorted, results)
	sort.SliceStable(sorted, func(i, j int) bool {
		pi, oki := pos[sorted[i].Name]
		pj, okj := pos[sorted[j].Name]
		if oki && okj {
			return pi < pj
		}
		if oki {
			return true
		}
		if okj {
			return false
		}
		return false // both unknown — preserve original order
	})
	return sorted
}

func levelToStatusKey(level string) string {
	switch level {
	case "CRIT":
		return "fail"
	case "WARN":
		return "warn"
	case "INFO":
		return "info"
	default:
		return "ok"
	}
}

// PrintAllMock renders rows from fixture data using an external inline func.
// Used by `dsd mock` — same styling as PrintAll, no collector data needed.
func (r *Renderer) PrintAllMock(results []runner.Result, insights []models.Insight, inlineFn func(string) string) {
	sorted := sortedResults(results)
	for _, res := range sorted {
		ins := insightForResult(res.Name, insights)
		level := "OK"
		msg := ""
		if ins != nil {
			level = ins.Level
			msg = ins.Message
		}
		if level == "OK" {
			msg = inlineFn(res.Name)
		}

		icon := output.StatusIcon(levelToStatusKey(level), r.mode)
		name := fmt.Sprintf("%-12s", res.Name)

		var line string
		switch r.mode {
		case output.ModeHuman:
			styledName := StyleBold.Render(name)
			styledIcon := styleForStatus(level).Render(icon)
			if msg != "" {
				line = fmt.Sprintf("%s %s  %s", styledName, styledIcon, StyleDim.Render(msg))
			} else {
				line = fmt.Sprintf("%s %s", styledName, styledIcon)
			}
		default:
			if msg != "" {
				line = fmt.Sprintf("%s %s  %s", name, icon, msg)
			} else {
				line = fmt.Sprintf("%s %s", name, icon)
			}
		}
		fmt.Fprintln(os.Stdout, line)

		if ins != nil && ins.Details != nil {
			r.renderDetails(ins.Details)
		}
	}
}

// PrintAll renders rows from real collector results.
func (r *Renderer) PrintAll(results []runner.Result, insights []models.Insight) {
	sorted := sortedResults(results)
	for _, res := range sorted {
		// Hide rows where the collector signals it has nothing to show on
		// this platform (e.g. Systemd on macOS, KernelSec without SELinux/AppArmor).
		if shouldHideRow(res, insights) {
			continue
		}

		ins := insightForResult(res.Name, insights)
		level := "OK"
		msg := ""
		if ins != nil {
			level = ins.Level
			msg = ins.Message
		}

		// Inline data for OK rows — lets the admin judge at a glance.
		// Only shown when the check is OK (WARN/CRIT already have a message).
		if level == "OK" {
			msg = inlineData(res)
		}

		icon := output.StatusIcon(levelToStatusKey(level), r.mode)
		name := fmt.Sprintf("%-12s", res.Name)

		var line string
		switch r.mode {
		case output.ModeHuman:
			styledName := StyleBold.Render(name)
			styledIcon := styleForStatus(level).Render(icon)
			if msg != "" {
				line = fmt.Sprintf("%s %s  %s", styledName, styledIcon, StyleDim.Render(msg))
			} else {
				line = fmt.Sprintf("%s %s", styledName, styledIcon)
			}
		default:
			if msg != "" {
				line = fmt.Sprintf("%s %s  %s", name, icon, msg)
			} else {
				line = fmt.Sprintf("%s %s", name, icon)
			}
		}
		fmt.Fprintln(os.Stdout, line)

		if ins != nil && ins.Details != nil && (r.mode == output.ModeHuman || r.mode == output.ModePlain) {
			r.renderDetails(ins.Details)
		}
	}
}

// shouldHideRow returns true when a collector has nothing meaningful to show.
// This happens when a technology isn't present on the current platform
// (e.g. Systemd on macOS, KernelSec on macOS, Battery on a desktop without one).
// The rule: hide when Available=false AND no insights AND inline data is empty.
func shouldHideRow(res runner.Result, insights []models.Insight) bool {
	// Must have no insights for this collector
	if insightForResult(res.Name, insights) != nil {
		return false
	}
	// Must produce no inline data
	if inlineData(res) != "" {
		return false
	}
	// Check if the collector signals unavailability via an Available field
	return !isAvailable(res.Data)
}

// isAvailable returns false when the data struct has an Available field set to false.
// Collectors that are not applicable on the current platform set Available=false.
func isAvailable(data interface{}) bool {
	if data == nil {
		return false
	}
	type availabler interface{ IsAvailable() bool }
	if a, ok := data.(availabler); ok {
		return a.IsAvailable()
	}
	// Use reflection to check common Available bool field
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return true // unknown type — show by default
	}
	f := v.FieldByName("Available")
	if !f.IsValid() || f.Kind() != reflect.Bool {
		return true // no Available field or wrong type — always show
	}
	return f.Bool()
}

// Follows Option C: ≤2 items shown individually, 3+ shows count + worst.
//
//nolint:cyclop // flat name→function dispatch; splitting would harm readability
func inlineData(res runner.Result) string {
	switch res.Name {
	case "CPU Load":
		return inlineCPULoad(res.Data)
	case "Memory":
		return inlineMemory(res.Data)
	case "Swap":
		return inlineSwap(res.Data)
	case "Disk":
		return diskInline(res.Data)
	case "Network":
		return networkInline(res.Data)
	case "Entropy":
		return inlineEntropy(res.Data)
	case "FDLimits":
		return inlineFDLimits(res.Data)
	case "IO":
		return inlineIO(res.Data)
	case "KernelSec":
		return inlineKernelSec(res.Data)
	case "Clock":
		return inlineClock(res.Data)
	case "Logs":
		return inlineLogs(res.Data)
	case "GPU":
		return inlineGPU(res.Data)
	case "CPU Thermal":
		return inlineCPUThermal(res.Data)
	case "Battery":
		return inlineBattery(res.Data)
	case "Launchd":
		return inlineLaunchd(res.Data)
	case "Packages":
		return inlinePackages(res.Data)
	case "Drives":
		return inlineDrives(res.Data)
	case "Systemd":
		return inlineSystemd(res.Data)
	case "Processes":
		return inlineProcesses(res.Data)
	case "Bonding":
		return inlineBonding(res.Data)
	case "IPMI":
		return inlineIPMI(res.Data)
	case "HBA":
		return inlineHBA(res.Data)
	case "Pressure":
		return inlinePressure(res.Data)
	case "Multipath":
		return inlineMultipath(res.Data)
	case "Ceph":
		return inlineCeph(res.Data)
	case "Firewall":
		return inlineFirewall(res.Data)
	case "Auth":
		return inlineAuth(res.Data)
	case "CloudMeta":
		return inlineCloudMeta(res.Data)
	case "Auditd":
		return inlineAuditd(res.Data)
	case "NUMA":
		return inlineNUMA(res.Data)
	case "VLAN":
		return inlineVLAN(res.Data)
	case "iSCSI":
		return inlineISCSI(res.Data)
	case "InfiniBand":
		return inlineInfiniBand(res.Data)
	case "SRIOV":
		return inlineSRIOV(res.Data)
	case "Nspawn":
		return inlineNspawn(res.Data)
	case "HugePages":
		return inlineHugePages(res.Data)
	case "CPUFreq":
		return inlineCPUFreq(res.Data)
	}
	return ""
}

func inlineCPULoad(data interface{}) string {
	cpu := asCPUInfo(data)
	if cpu != nil && cpu.LoadPct >= 0 {
		return fmt.Sprintf("%.0f%%", cpu.LoadPct)
	}
	return ""
}

func inlineMemory(data interface{}) string {
	var r *models.MemoryInfo
	if v, ok := data.(*models.MemoryInfo); ok {
		r = v
	} else if v, ok := data.(models.MemoryInfo); ok {
		r = &v
	}
	if r == nil || r.TotalGB == 0 {
		return ""
	}
	used := r.TotalGB * r.UsedPct / 100
	return fmt.Sprintf("%.1f/%.0f GB (%.0f%%)", used, r.TotalGB, r.UsedPct)
}

func inlineSwap(data interface{}) string {
	var s *models.SwapInfo
	if v, ok := data.(*models.SwapInfo); ok {
		s = v
	} else if v, ok := data.(models.SwapInfo); ok {
		s = &v
	}
	if s == nil {
		return ""
	}
	if s.TotalGB == 0 {
		return "none"
	}
	return fmt.Sprintf("%.0f MB used", s.UsedGB*1024)
}

func inlineEntropy(data interface{}) string {
	var e *models.EntropyInfo
	if v, ok := data.(*models.EntropyInfo); ok {
		e = v
	} else if v, ok := data.(models.EntropyInfo); ok {
		e = &v
	}
	if e == nil || e.Available <= 0 {
		return ""
	}
	return fmt.Sprintf("%d bits", e.Available)
}

func inlineFDLimits(data interface{}) string {
	var fd *models.FDInfo
	if v, ok := data.(*models.FDInfo); ok {
		fd = v
	} else if v, ok := data.(models.FDInfo); ok {
		fd = &v
	}
	if fd == nil || fd.MaxCount == 0 || fd.MaxCount >= 1<<40 {
		return ""
	}
	return fmt.Sprintf("%.0f%% system (%s/%s open)",
		fd.UsedPct, formatCount(fd.OpenCount), formatCount(fd.MaxCount))
}

func inlineIO(data interface{}) string {
	var io *models.IOInfo
	if v, ok := data.(*models.IOInfo); ok {
		io = v
	} else if v, ok := data.(models.IOInfo); ok {
		io = &v
	}
	if io == nil || len(io.Devices) == 0 {
		return ""
	}
	return ioInline(io.Devices)
}

func inlineKernelSec(data interface{}) string {
	var k *models.KernelSecurityInfo
	if v, ok := data.(*models.KernelSecurityInfo); ok {
		k = v
	} else if v, ok := data.(models.KernelSecurityInfo); ok {
		k = &v
	}
	if k == nil {
		return ""
	}
	return kernelSecInline(k)
}

func inlineClock(data interface{}) string {
	var c *models.ClockInfo
	if v, ok := data.(*models.ClockInfo); ok {
		c = v
	} else if v, ok := data.(models.ClockInfo); ok {
		c = &v
	}
	if c == nil || !c.Synced {
		return ""
	}
	if c.Source != "" {
		return fmt.Sprintf("±%.0f ms  %s", abs(c.OffsetMs), c.Source)
	}
	return fmt.Sprintf("±%.0f ms", abs(c.OffsetMs))
}

func inlineLogs(data interface{}) string {
	var l *models.LogsInfo
	if v, ok := data.(*models.LogsInfo); ok {
		l = v
	} else if v, ok := data.(models.LogsInfo); ok {
		l = &v
	}
	if l == nil || l.JournalSizeGB == 0 {
		return ""
	}
	return fmt.Sprintf("%.0f MB journal", l.JournalSizeGB*1024)
}

func inlineCPUThermal(data interface{}) string {
	var t *models.ThermalInfo
	if v, ok := data.(*models.ThermalInfo); ok {
		t = v
	} else if v, ok := data.(models.ThermalInfo); ok {
		t = &v
	}
	if t == nil || t.CPUTempC == 0 {
		return ""
	}
	return fmt.Sprintf("%.0f°C", t.CPUTempC)
}

func inlineBattery(data interface{}) string {
	var b *models.BatteryInfo
	if v, ok := data.(*models.BatteryInfo); ok {
		b = v
	} else if v, ok := data.(models.BatteryInfo); ok {
		b = &v
	}
	if b == nil || !b.Present {
		return ""
	}
	s := fmt.Sprintf("%d%%", b.CapacityPct)
	if b.Status != "" {
		s += "  " + strings.ToLower(b.Status)
	}
	return s
}

func inlineDrives(data interface{}) string {
	var n *models.NVMeInfo
	if v, ok := data.(*models.NVMeInfo); ok {
		n = v
	} else if v, ok := data.(models.NVMeInfo); ok {
		n = &v
	}
	if n == nil {
		return ""
	}
	total := len(n.Devices) + len(n.SATADevices)
	if total == 0 {
		return ""
	}
	if total == 1 {
		if len(n.Devices) == 1 {
			return n.Devices[0].Name + "  healthy"
		}
		return n.SATADevices[0].Name + "  healthy"
	}
	return fmt.Sprintf("%d drives  healthy", total)
}

func inlineSystemd(data interface{}) string {
	var s *models.SystemdInfo
	if v, ok := data.(*models.SystemdInfo); ok {
		s = v
	} else if v, ok := data.(models.SystemdInfo); ok {
		s = &v
	}
	if s == nil || !s.Available {
		return ""
	}
	if s.TotalBootSec > 0 {
		return fmt.Sprintf("boot %.0fs", s.TotalBootSec)
	}
	return ""
}

func inlineProcesses(data interface{}) string {
	var p *models.ProcessInfo
	if v, ok := data.(*models.ProcessInfo); ok {
		p = v
	} else if v, ok := data.(models.ProcessInfo); ok {
		p = &v
	}
	if p == nil {
		return ""
	}
	if p.ZombieCount > 0 || p.HungCount > 0 {
		return fmt.Sprintf("%d zombie  %d hung", p.ZombieCount, p.HungCount)
	}
	if p.Total > 0 {
		return fmt.Sprintf("%d running", p.Total)
	}
	return ""
}

func inlineBonding(data interface{}) string {
	var b *models.BondingInfo
	if v, ok := data.(*models.BondingInfo); ok {
		b = v
	} else if v, ok := data.(models.BondingInfo); ok {
		b = &v
	}
	if b == nil || len(b.Bonds) == 0 {
		return ""
	}
	total := 0
	for _, bond := range b.Bonds {
		total += len(bond.Slaves)
	}
	if len(b.Bonds) == 1 {
		bond := b.Bonds[0]
		return fmt.Sprintf("%s  %d/%d slaves up  %s", bond.Name, len(bond.Slaves)-bond.DownSlaves, len(bond.Slaves), bond.ModeShort)
	}
	return fmt.Sprintf("%d bonds  %d slaves", len(b.Bonds), total)
}

func inlineIPMI(data interface{}) string {
	var i *models.IPMIInfo
	if v, ok := data.(*models.IPMIInfo); ok {
		i = v
	} else if v, ok := data.(models.IPMIInfo); ok {
		i = &v
	}
	if i == nil || !i.Available {
		return ""
	}
	return fmt.Sprintf("%d sensors  ok", len(i.Sensors))
}

func inlineHBA(data interface{}) string {
	var h *models.HBAInfo
	if v, ok := data.(*models.HBAInfo); ok {
		h = v
	} else if v, ok := data.(models.HBAInfo); ok {
		h = &v
	}
	if h == nil || len(h.Ports) == 0 {
		return ""
	}
	online := 0
	for _, p := range h.Ports {
		if strings.EqualFold(p.PortState, "online") || strings.EqualFold(p.PortState, "linkup") {
			online++
		}
	}
	return fmt.Sprintf("%d/%d ports online", online, len(h.Ports))
}

func inlinePressure(data interface{}) string {
	var p *models.PressureInfo
	if v, ok := data.(*models.PressureInfo); ok {
		p = v
	} else if v, ok := data.(models.PressureInfo); ok {
		p = &v
	}
	if p == nil || !p.Available {
		return ""
	}
	// Show the highest pressure metric
	if p.MemoryFull.Avg10 > 0 || p.MemorySome.Avg10 > 0 || p.CPUSome.Avg10 > 0 || p.IOSome.Avg10 > 0 {
		return fmt.Sprintf("mem %.0f%%  cpu %.0f%%  io %.0f%%", p.MemorySome.Avg10, p.CPUSome.Avg10, p.IOSome.Avg10)
	}
	return "no pressure"
}

func inlineMultipath(data interface{}) string {
	var m *models.MultipathInfo
	if v, ok := data.(*models.MultipathInfo); ok {
		m = v
	} else if v, ok := data.(models.MultipathInfo); ok {
		m = &v
	}
	if m == nil || !m.Available || len(m.Devices) == 0 {
		return ""
	}
	totalPaths := 0
	for _, d := range m.Devices {
		totalPaths += d.TotalPaths
	}
	return fmt.Sprintf("%d devices  %d paths", len(m.Devices), totalPaths)
}

func inlineCeph(data interface{}) string {
	var c *models.CephInfo
	if v, ok := data.(*models.CephInfo); ok {
		c = v
	} else if v, ok := data.(models.CephInfo); ok {
		c = &v
	}
	if c == nil || !c.Available {
		return ""
	}
	if c.OSDTotal > 0 {
		return fmt.Sprintf("%s  %d/%d OSDs up", c.Health, c.OSDUp, c.OSDTotal)
	}
	return c.Health
}

func inlineFirewall(data interface{}) string {
	var f *models.FirewallInfo
	if v, ok := data.(*models.FirewallInfo); ok {
		f = v
	} else if v, ok := data.(models.FirewallInfo); ok {
		f = &v
	}
	if f == nil || !f.Available {
		return ""
	}
	if !f.Active || f.TotalRules == 0 {
		return f.Backend + "  no rules"
	}
	drop := ""
	if f.DefaultDrop {
		drop = "  INPUT drop"
	}
	return fmt.Sprintf("%s  %d rules%s", f.Backend, f.TotalRules, drop)
}

func inlineAuth(data interface{}) string {
	var a *models.AuthInfo
	if v, ok := data.(*models.AuthInfo); ok {
		a = v
	} else if v, ok := data.(models.AuthInfo); ok {
		a = &v
	}
	if a == nil {
		return ""
	}
	if a.FailedLast24h > 0 {
		return fmt.Sprintf("%d failed logins in 24h", a.FailedLast24h)
	}
	if a.Checked {
		return "0 failed logins"
	}
	return ""
}

func inlineCloudMeta(data interface{}) string {
	var c *models.CloudInfo
	if v, ok := data.(*models.CloudInfo); ok {
		c = v
	} else if v, ok := data.(models.CloudInfo); ok {
		c = &v
	}
	if c == nil || !c.Available {
		return ""
	}
	s := c.Provider
	if c.InstanceType != "" {
		s += "  " + c.InstanceType
	}
	if c.Region != "" {
		s += "  " + c.Region
	}
	return s
}

func inlineAuditd(data interface{}) string {
	var a *models.AuditInfo
	if v, ok := data.(*models.AuditInfo); ok {
		a = v
	} else if v, ok := data.(models.AuditInfo); ok {
		a = &v
	}
	if a == nil || !a.Available {
		return ""
	}
	if !a.Running {
		return "not running"
	}
	return fmt.Sprintf("%d rules  running", a.RulesLoaded)
}

func inlineNUMA(data interface{}) string {
	var n *models.NUMAInfo
	if v, ok := data.(*models.NUMAInfo); ok {
		n = v
	} else if v, ok := data.(models.NUMAInfo); ok {
		n = &v
	}
	if n == nil || !n.Available {
		return ""
	}
	return fmt.Sprintf("%d nodes", n.NodeCount)
}

func inlineVLAN(data interface{}) string {
	var v *models.VLANInfo
	if x, ok := data.(*models.VLANInfo); ok {
		v = x
	} else if x, ok := data.(models.VLANInfo); ok {
		v = &x
	}
	if v == nil || len(v.Interfaces) == 0 {
		return ""
	}
	up := 0
	for _, i := range v.Interfaces {
		if i.Up {
			up++
		}
	}
	return fmt.Sprintf("%d VLANs  %d/%d up", len(v.Interfaces), up, len(v.Interfaces))
}

func inlineISCSI(data interface{}) string {
	var i *models.ISCSIInfo
	if v, ok := data.(*models.ISCSIInfo); ok {
		i = v
	} else if v, ok := data.(models.ISCSIInfo); ok {
		i = &v
	}
	if i == nil || !i.Available || len(i.Sessions) == 0 {
		return ""
	}
	return fmt.Sprintf("%d session(s)  logged in", len(i.Sessions))
}

func inlineInfiniBand(data interface{}) string {
	var ib *models.InfiniBandInfo
	if v, ok := data.(*models.InfiniBandInfo); ok {
		ib = v
	} else if v, ok := data.(models.InfiniBandInfo); ok {
		ib = &v
	}
	if ib == nil || len(ib.Ports) == 0 {
		return ""
	}
	active := 0
	for _, p := range ib.Ports {
		if strings.EqualFold(p.State, "active") {
			active++
		}
	}
	return fmt.Sprintf("%d/%d ports active", active, len(ib.Ports))
}

func inlineSRIOV(data interface{}) string {
	var s *models.SRIOVInfo
	if v, ok := data.(*models.SRIOVInfo); ok {
		s = v
	} else if v, ok := data.(models.SRIOVInfo); ok {
		s = &v
	}
	if s == nil || len(s.Devices) == 0 {
		return ""
	}
	totalVFs := 0
	for _, d := range s.Devices {
		totalVFs += d.NumVFs
	}
	return fmt.Sprintf("%d devices  %d VFs active", len(s.Devices), totalVFs)
}

func inlineNspawn(data interface{}) string {
	var n *models.NspawnInfo
	if v, ok := data.(*models.NspawnInfo); ok {
		n = v
	} else if v, ok := data.(models.NspawnInfo); ok {
		n = &v
	}
	if n == nil || !n.Available || len(n.Containers) == 0 {
		return ""
	}
	running := 0
	for _, c := range n.Containers {
		if c.State == "running" {
			running++
		}
	}
	return fmt.Sprintf("%d containers  %d running", len(n.Containers), running)
}

func inlineGPU(data interface{}) string {
	var g *models.GPUInfo
	if v, ok := data.(*models.GPUInfo); ok {
		g = v
	} else if v, ok := data.(models.GPUInfo); ok {
		g = &v
	}
	if g == nil || len(g.Devices) == 0 {
		return ""
	}
	if len(g.Devices) == 1 {
		d := g.Devices[0]
		s := d.Name
		if d.TempC > 0 {
			s += fmt.Sprintf("  %d°C", d.TempC)
		}
		if d.UtilPct > 0 {
			s += fmt.Sprintf("  %d%%", d.UtilPct)
		}
		if d.MemTotalMB > 0 {
			s += fmt.Sprintf("  %d/%d MB VRAM", d.MemUsedMB, d.MemTotalMB)
		}
		return s
	}
	// Multiple GPUs — ≤2 show both with clear labels
	if len(g.Devices) == 2 {
		var parts []string
		for _, d := range g.Devices {
			s := d.Name
			if d.TempC > 0 {
				s += fmt.Sprintf(" %d°C", d.TempC)
			}
			parts = append(parts, s)
		}
		return fmt.Sprintf("2 GPUs: %s", strings.Join(parts, " · "))
	}
	// 3+ GPUs — show count + hottest
	hottest := g.Devices[0]
	for _, d := range g.Devices[1:] {
		if d.TempC > hottest.TempC {
			hottest = d
		}
	}
	s := fmt.Sprintf("%d GPUs", len(g.Devices))
	if hottest.TempC > 0 {
		s += fmt.Sprintf("  max %d°C (%s)", hottest.TempC, hottest.Name)
	}
	return s
}

// diskInline implements Option C for multiple mount points:
// ≤2 mounts: show all → "/ 45%  /boot 12%"
// 3+ mounts: show count + worst → "6 mounts, max 82% (/data)"
// Any with WARN-level usage (>70%): always highlight the offending mount.
func diskInline(data interface{}) string {
	var fs []models.FilesystemInfo
	if d, ok := data.(*models.DiskInfo); ok && d != nil {
		fs = d.Filesystems
	} else if d, ok := data.(models.DiskInfo); ok {
		fs = d.Filesystems
	}
	if len(fs) == 0 {
		return ""
	}
	if len(fs) <= 2 {
		var parts []string
		for _, f := range fs {
			parts = append(parts, fmt.Sprintf("%s %.0f%%", f.Mount, f.UsedPct))
		}
		return strings.Join(parts, "  ")
	}
	// 3+ mounts: find worst
	worst := fs[0]
	for _, f := range fs[1:] {
		if f.UsedPct > worst.UsedPct {
			worst = f
		}
	}
	return fmt.Sprintf("%d mounts, max %.0f%% (%s)", len(fs), worst.UsedPct, worst.Mount)
}

// networkInline implements Option C for multiple NICs.
func networkInline(data interface{}) string {
	var n *models.NetworkInfo
	if v, ok := data.(*models.NetworkInfo); ok && v != nil {
		n = v
	} else if v, ok := data.(models.NetworkInfo); ok {
		n = &v
	}
	if n == nil {
		return ""
	}
	var up []models.InterfaceInfo
	for _, iface := range n.Interfaces {
		if iface.Up {
			up = append(up, iface)
		}
	}
	if len(up) == 0 {
		return ""
	}
	ifaceStr := func(i models.InterfaceInfo) string {
		if i.SpeedMbps >= 1000 {
			return fmt.Sprintf("%s %dGbps", i.Name, i.SpeedMbps/1000)
		}
		if i.SpeedMbps > 0 {
			return fmt.Sprintf("%s %dMbps", i.Name, i.SpeedMbps)
		}
		return i.Name
	}
	ifaceSummary := ""
	if len(up) <= 2 {
		var parts []string
		for _, iface := range up {
			parts = append(parts, ifaceStr(iface))
		}
		ifaceSummary = strings.Join(parts, "  ")
	} else {
		ifaceSummary = fmt.Sprintf("%d NICs, %s", len(up), ifaceStr(up[0]))
	}
	// Append gateway ping if available.
	// TCP fallback can return sub-1ms — show "<1 ms" instead of "0 ms" to
	// avoid the confusing "0.0 ms" cosmetic issue on non-root runs.
	if n.GatewayPingMs > 0 {
		gw := n.GatewayPingMs
		if gw < 1 {
			ifaceSummary += "  gw <1 ms"
		} else {
			ifaceSummary += fmt.Sprintf("  gw %.0f ms", gw)
		}
	}
	return ifaceSummary
}

// ioInline picks the worst await latency across all IO devices.
func ioInline(devices []models.IODeviceInfo) string {
	if len(devices) == 0 {
		return ""
	}
	worst := devices[0]
	for _, d := range devices[1:] {
		if d.AwaitMs > worst.AwaitMs {
			worst = d
		}
	}
	if len(devices) == 1 {
		return fmt.Sprintf("%.1f ms", worst.AwaitMs)
	}
	return fmt.Sprintf("%.1f ms (%s)", worst.AwaitMs, worst.Name)
}

// kernelSecInline summarises the active security module.
func kernelSecInline(k *models.KernelSecurityInfo) string {
	if k.SELinuxPresent && k.SELinuxMode != "" {
		return "SELinux " + k.SELinuxMode
	}
	if k.AppArmorPresent && k.AppArmorMode != "" {
		return "AppArmor " + k.AppArmorMode
	}
	return ""
}

func asCPUInfo(data interface{}) *models.CPUInfo {
	if cpu, ok := data.(*models.CPUInfo); ok {
		return cpu
	}
	if cpu, ok := data.(models.CPUInfo); ok {
		return &cpu
	}
	return nil
}

func formatCount(n uint64) string {
	if n >= 1000 {
		return fmt.Sprintf("%.0fk", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

func (r *Renderer) renderDetails(d *models.Details) {
	const indent = "   "

	if d.Title != "" {
		fmt.Fprintf(os.Stdout, "%s%s\n", indent, StyleDim.Render(d.Title+":"))
	}

	if len(d.Columns) > 0 && len(d.Rows) > 0 {
		// Compute column widths
		widths := make([]int, len(d.Columns))
		for i, col := range d.Columns {
			widths[i] = len(col)
		}
		for _, row := range d.Rows {
			for i, cell := range row {
				if i < len(widths) && len(cell) > widths[i] {
					widths[i] = len(cell)
				}
			}
		}

		// Header
		var hdr strings.Builder
		hdr.WriteString(indent)
		for i, col := range d.Columns {
			if i > 0 {
				hdr.WriteString("  ")
			}
			fmt.Fprintf(&hdr, "%-*s", widths[i], col)
		}
		fmt.Fprintln(os.Stdout, StyleDim.Render(hdr.String()))

		// Rows
		for _, row := range d.Rows {
			var sb strings.Builder
			sb.WriteString(indent)
			for i, cell := range row {
				if i > 0 {
					sb.WriteString("  ")
				}
				w := 0
				if i < len(widths) {
					w = widths[i]
				}
				fmt.Fprintf(&sb, "%-*s", w, cell)
			}
			fmt.Fprintln(os.Stdout, StyleDim.Render(sb.String()))
		}
	}

	if d.Type == "log_tail" {
		if tail, ok := d.KV["log_tail"]; ok {
			for _, line := range strings.Split(strings.TrimSpace(tail), "\n") {
				fmt.Fprintf(os.Stdout, "%s%s\n", indent, StyleDim.Render(line))
			}
		}
	} else if len(d.KV) > 0 && len(d.Rows) == 0 {
		for k, v := range d.KV {
			fmt.Fprintf(os.Stdout, "%s%s: %s\n", indent, StyleDim.Render(k), v)
		}
	}

	if d.Note != "" {
		fmt.Fprintf(os.Stdout, "%s%s\n", indent, StyleDim.Render("note: "+d.Note))
	}
}

func (r *Renderer) PrintSummary(insights []models.Insight, elapsed time.Duration) int {
	if r.mode == output.ModeJSON {
		return exitCodeFromInsights(insights)
	}

	var crits, warns, infos []models.Insight
	for _, ins := range insights {
		switch ins.Level {
		case "CRIT":
			crits = append(crits, ins)
		case "WARN":
			warns = append(warns, ins)
		case "INFO":
			infos = append(infos, ins)
		}
	}

	sep := strings.Repeat("─", 56)
	fmt.Fprintln(os.Stdout, sep)

	timing := ""
	if elapsed > 0 {
		timing = fmt.Sprintf(" in %.1fs", elapsed.Seconds())
	}

	if len(crits)+len(warns) == 0 {
		if r.mode == output.ModeHuman {
			fmt.Fprintln(os.Stdout, StyleOK.Render(fmt.Sprintf("✅ System healthy. Checks passed%s", timing)))
		} else {
			fmt.Fprintf(os.Stdout, "OK: All checks passed%s\n", timing)
		}
		return 0
	}

	r.printInsightGroup(crits)
	r.printInsightGroup(warns)
	r.printInsightGroup(infos)

	return exitCodeFromInsights(insights)
}

func (r *Renderer) printInsightGroup(ins []models.Insight) {
	for _, i := range ins {
		if r.mode == output.ModeHuman {
			icon := styleForStatus(i.Level).Render(output.StatusIcon(levelToStatusKey(i.Level), r.mode))
			fmt.Fprintf(os.Stdout, "%s  %s: %s\n", icon, StyleBold.Render(i.Check), i.Message)
			r.printHints(i.Hints)
		} else {
			fmt.Fprintf(os.Stdout, "%s: %s: %s\n", i.Level, i.Check, i.Message)
			r.printHintsPlain(i.Hints)
		}
	}
}

// printHints groups hints by their prefix (to inspect / to fix) and prints them
// as a labelled block rather than repeating the prefix on every line.
func (r *Renderer) printHints(hints []string) {
	type group struct {
		label string
		cmds  []string
	}

	// Preserve order of first appearance of each label
	seen := make(map[string]int) // label → index in groups
	var groups []group

	for _, h := range hints {
		label := ""
		cmd := h
		for _, prefix := range []string{"to inspect: ", "to fix: ", "to persist: ", "to inspect:", "to fix:", "to persist:"} {
			if strings.HasPrefix(h, prefix) {
				label = strings.TrimSuffix(strings.TrimSpace(prefix), ":")
				cmd = strings.TrimPrefix(h, prefix)
				break
			}
		}
		if label == "" {
			// No known prefix — print as-is
			fmt.Fprintf(os.Stdout, "   %s %s\n", StyleDim.Render("→"), h)
			continue
		}
		if idx, exists := seen[label]; exists {
			groups[idx].cmds = append(groups[idx].cmds, cmd)
		} else {
			seen[label] = len(groups)
			groups = append(groups, group{label: label, cmds: []string{cmd}})
		}
	}

	for _, g := range groups {
		if len(g.cmds) == 1 {
			fmt.Fprintf(os.Stdout, "   %s %s: %s\n",
				StyleDim.Render("→"), g.label, StyleDim.Render(g.cmds[0]))
		} else {
			fmt.Fprintf(os.Stdout, "   %s %s:\n", StyleDim.Render("→"), g.label)
			for _, cmd := range g.cmds {
				fmt.Fprintf(os.Stdout, "     %s\n", StyleDim.Render(cmd))
			}
		}
	}
}

// printHintsPlain is the plain-text version of printHints — same grouping, no styling.
func (r *Renderer) printHintsPlain(hints []string) {
	type group struct {
		label string
		cmds  []string
	}
	seen := make(map[string]int)
	var groups []group

	for _, h := range hints {
		label := ""
		cmd := h
		for _, prefix := range []string{"to inspect: ", "to fix: ", "to persist: "} {
			if strings.HasPrefix(h, prefix) {
				label = strings.TrimSuffix(prefix, ": ")
				cmd = strings.TrimPrefix(h, prefix)
				break
			}
		}
		if label == "" {
			fmt.Fprintf(os.Stdout, "   -> %s\n", h)
			continue
		}
		if idx, exists := seen[label]; exists {
			groups[idx].cmds = append(groups[idx].cmds, cmd)
		} else {
			seen[label] = len(groups)
			groups = append(groups, group{label: label, cmds: []string{cmd}})
		}
	}

	for _, g := range groups {
		if len(g.cmds) == 1 {
			fmt.Fprintf(os.Stdout, "   -> %s: %s\n", g.label, g.cmds[0])
		} else {
			fmt.Fprintf(os.Stdout, "   -> %s:\n", g.label)
			for _, cmd := range g.cmds {
				fmt.Fprintf(os.Stdout, "      %s\n", cmd)
			}
		}
	}
}

func exitCodeFromInsights(insights []models.Insight) int {
	code := 0
	for _, ins := range insights {
		switch ins.Level {
		case "CRIT":
			return 2
		case "WARN":
			if code < 1 {
				code = 1
			}
		}
	}
	return code
}

func (r *Renderer) PrintContainerBanner(ctx platform.ContainerContext) {
	if r.mode != output.ModeHuman {
		return
	}
	fmt.Fprintln(os.Stdout, StyleInfo.Render("ℹ️  Running inside a container — showing container limits"))
}

// PrintCorrelations renders the DIAGNOSIS block when the correlation engine
// finds pattern matches. Called between PrintAll and PrintSummary in runHealth.
// No-ops in JSON/YAML/plain modes — correlations are included in JSON output
// separately via RenderJSON if needed in a future pass.
func (r *Renderer) PrintCorrelations(corrs []analysis.Correlation) {
	if len(corrs) == 0 {
		return
	}
	if r.mode == output.ModeJSON || r.mode == output.ModeYAML {
		return
	}

	sep := strings.Repeat("─", 56)
	fmt.Fprintln(os.Stdout, sep)

	if r.mode == output.ModeHuman {
		fmt.Fprintln(os.Stdout, StyleBold.Render("DIAGNOSIS"))
	} else {
		fmt.Fprintln(os.Stdout, "DIAGNOSIS")
	}

	for _, c := range corrs {
		if r.mode == output.ModeHuman {
			style := styleForStatus(c.Level)
			icon := style.Render("▶")
			name := StyleBold.Render(c.Name)
			fmt.Fprintf(os.Stdout, "%s  %s\n", icon, name)
		} else {
			fmt.Fprintf(os.Stdout, "%s: %s\n", c.Level, c.Name)
		}
		fmt.Fprintf(os.Stdout, "   %s\n", c.Summary)
		fmt.Fprintf(os.Stdout, "   → %s\n", c.Action)
	}
}

func inlineHugePages(data interface{}) string {
	var h *models.HugePagesInfo
	if v, ok := data.(*models.HugePagesInfo); ok {
		h = v
	} else if v, ok := data.(models.HugePagesInfo); ok {
		h = &v
	}
	if h == nil {
		return ""
	}
	if h.Configured > 0 {
		return fmt.Sprintf("%d/%d pages used  %.1f GB reserved  THP %s",
			h.Used, h.Configured, h.ReservedGB, h.THPMode)
	}
	if h.THPMode != "" {
		return "THP " + h.THPMode
	}
	return ""
}

func inlineCPUFreq(data interface{}) string {
	var f *models.CPUFreqInfo
	if v, ok := data.(*models.CPUFreqInfo); ok {
		f = v
	} else if v, ok := data.(models.CPUFreqInfo); ok {
		f = &v
	}
	if f == nil || f.Governor == "" {
		return ""
	}
	if f.CurrentMHz > 0 && f.MaxMHz > 0 {
		return fmt.Sprintf("%s  %d/%d MHz", f.Governor, f.CurrentMHz, f.MaxMHz)
	}
	return f.Governor
}

func inlineLaunchd(data interface{}) string {
	var l *models.LaunchdInfo
	if v, ok := data.(*models.LaunchdInfo); ok {
		l = v
	} else if v, ok := data.(models.LaunchdInfo); ok {
		l = &v
	}
	if l == nil || l.Total == 0 {
		return ""
	}
	if len(l.Failed) > 0 {
		return fmt.Sprintf("%d running  %d failed", l.Running, len(l.Failed))
	}
	return fmt.Sprintf("%d running", l.Running)
}

func inlinePackages(data interface{}) string {
	var p *models.PackagesInfo
	if v, ok := data.(*models.PackagesInfo); ok {
		p = v
	} else if v, ok := data.(models.PackagesInfo); ok {
		p = &v
	}
	if p == nil {
		return ""
	}
	if p.SecurityUpdates > 0 || p.CriticalUpdates > 0 || p.ImportantUpdates > 0 {
		return "" // heuristic already shows the warning message
	}
	if p.Checked {
		return "up to date"
	}
	return ""
}
