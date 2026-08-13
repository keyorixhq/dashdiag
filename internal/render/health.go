package render

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

const (
	renderCatCPULoad    = "CPU Load"
	renderCatCPUThermal = "CPU Thermal"
	renderCatMemory     = "Memory"
	renderCatSwap       = "Swap"
	renderCatGPU        = "GPU"
	renderCatIO         = "IO"
	renderCatDrives     = "Drives"
	renderCatDisk       = "Disk"
	renderCatLVM        = "LVM"
	renderCatNetwork    = "Network"
	renderCatSystemd    = "Systemd"
	renderCatProcesses  = "Processes"
	renderCatFDLimits   = "FDLimits"
	renderCatEntropy    = "Entropy"
	renderCatLogs       = "Logs"
	renderCatOOM        = "OOM"
	renderCatIPMI       = "IPMI"
	renderCatBonding    = "Bonding"
	renderCatFirewall   = "Firewall"
	renderCatAuth       = "Auth"
	renderCatAuditd     = "Auditd"
	renderCatPressure   = "Pressure"
	renderCatMultipath  = "Multipath"
	renderCatVMware     = "VMware"
	renderCatVLAN       = "VLAN"
	renderCatSRIOV      = "SRIOV"
	renderCatNspawn     = "Nspawn"
	renderCatLaunchd    = "Launchd"
	renderCatKernelSec  = "KernelSec"
	renderCatIscsi      = "iSCSI"
	renderCatInfiniBand = "InfiniBand"
	renderCatHugePages  = "HugePages"
	renderCatHBA        = "HBA"
	renderCatCPUFreq    = "CPUFreq"
	renderCatContainerd = "Containerd"
	renderCatCloudMeta  = "CloudMeta"
	renderCatCloudInit  = "CloudInit"
	renderCatClock      = "Clock"
	renderCatCeph       = "Ceph"
	renderCatBattery    = "Battery"
	renderCatNUMA       = "NUMA"
	renderCatPackages   = "Packages"
	renderCatOther      = "Other"
)

type Renderer struct{ mode output.OutputMode }

func NewRenderer(mode output.OutputMode) *Renderer { return &Renderer{mode: mode} }

// insightForResult returns the highest-severity insight for a collector result.
// It matches on exact check name or the "Name " prefix (e.g. renderCatIO matches "IO sda").
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
	renderCatCPULoad, renderCatCPUThermal, renderCatMemory, renderCatSwap, renderCatGPU,
	// Storage
	renderCatDisk, renderCatIO, renderCatDrives, renderCatLVM, "RAID", "ZFS", "DRBD",
	// Network
	renderCatNetwork,
	// System
	renderCatSystemd, renderCatProcesses, renderCatFDLimits, renderCatEntropy,
	renderCatClock, renderCatLogs, "Sysctl",
	// Security
	renderCatKernelSec, "Hardening", renderCatPackages,
	// RHEL/Oracle maintenance & patch-effectiveness
	"Kdump", "Tuned", "Kernel", "Ksplice", "ServiceRestart",
	// Platform-specific
	"Subscription", "Snapshots", renderCatBattery, renderCatLaunchd, "PVE",
	renderCatBonding, renderCatIPMI, renderCatOOM, renderCatHBA, renderCatPressure, renderCatMultipath,
	renderCatCeph, renderCatFirewall, renderCatAuth, renderCatCloudMeta, renderCatCloudInit, renderCatAuditd,
	renderCatNUMA, renderCatVLAN, renderCatIscsi, renderCatInfiniBand, renderCatSRIOV, renderCatNspawn,
	renderCatHugePages, renderCatCPUFreq,
	// Optional
	"TLS", "Docker", renderCatContainerd, "K8s", "Hardware",
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

// formatStatusLine renders one row's name+icon+message into a display string,
// applying lipgloss styling in human mode.
func (r *Renderer) formatStatusLine(name, icon, level, msg string) string {
	switch r.mode {
	case output.ModeHuman:
		styledName := StyleBold.Render(name)
		styledIcon := styleForStatus(level).Render(icon)
		if msg != "" {
			return fmt.Sprintf("%s %s  %s", styledName, styledIcon, StyleDim.Render(msg))
		}
		return fmt.Sprintf("%s %s", styledName, styledIcon)
	default:
		if msg != "" {
			return fmt.Sprintf("%s %s  %s", name, icon, msg)
		}
		return fmt.Sprintf("%s %s", name, icon)
	}
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
		fmt.Fprintln(os.Stdout, r.formatStatusLine(name, icon, level, msg))

		if ins != nil && ins.Details != nil {
			r.renderDetails(ins.Details)
		}
	}
}

// PrintAll renders rows from real collector results.
func (r *Renderer) PrintAll(results []runner.Result, insights []models.Insight) {
	for _, res := range sortedResults(results) {
		// Hide rows where the collector signals it has nothing to show on
		// this platform (e.g. Systemd on macOS, KernelSec without SELinux/AppArmor).
		if shouldHideRow(res, insights) {
			continue
		}
		r.printRow(res, insights)
	}
}

// printRow renders one collector's summary line (name, status icon, and either
// its worst insight message or its OK inline data) plus any detail block. Extracted
// from PrintAll so the layered renderer reuses the exact same row formatting.
func (r *Renderer) printRow(res runner.Result, insights []models.Insight) {
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
	// msg is either an Insight.Message (untrusted collector text — same as
	// printInsightGroup) or an inlineData() summary, several of which also
	// surface untrusted collector fields directly (e.g. inlineSessions'
	// session User). Sanitize at this single row-formatting choke point.
	fmt.Fprintln(os.Stdout, r.formatStatusLine(name, icon, level, output.SanitizeControl(msg)))

	if ins != nil && ins.Details != nil && (r.mode == output.ModeHuman || r.mode == output.ModePlain) {
		r.renderDetails(ins.Details)
	}
}

// healthLayer groups collectors by level of abstraction for `--layered` output.
type healthLayer struct {
	title    string
	subtitle string
	hint     string   // optional "zoom in" command shown when a member is present
	hintFor  string   // collector name that triggers hint (e.g. renderCatVMware → dsd vmware)
	members  []string // collector names in this layer
}

// healthLayers is the abstraction stack for `dsd health --layered`: the machine's
// resources, the platform it runs on, then the OS + services on top. Lower layers
// are more root-cause-y, so they print first — a cause reads above its symptoms.
// This is a PRESENTATION grouping only (the --json schema is unchanged); it's a
// flat, deliberately-easy-to-retune table. Any collector not listed here falls
// into a trailing renderCatOther group, so nothing is ever hidden.
var healthLayers = []healthLayer{
	{
		title: "Hardware & storage", subtitle: "your machine's resources & devices",
		members: []string{
			renderCatCPULoad, renderCatCPUThermal, renderCatCPUFreq, "CPUDeep", renderCatMemory, renderCatSwap, renderCatGPU,
			renderCatDisk, "Fstab", "Root FS", renderCatIO, renderCatDrives, renderCatLVM, "RAID", "ZFS", "DRBD",
			renderCatMultipath, renderCatIscsi, renderCatHBA, renderCatCeph, renderCatBattery, renderCatIPMI, renderCatNUMA,
			renderCatInfiniBand, renderCatSRIOV, renderCatHugePages, "Firmware", "Hardware",
		},
	},
	{
		// The virtualization layer — whether this host CONSUMES it (a guest under
		// VMware/AWS/Azure/GCP) or PROVIDES it (a KVM/Proxmox node IS the hypervisor).
		// Both are "the platform," viewed from opposite sides.
		title: "Platform", subtitle: "the hypervisor / cloud platform layer",
		hint: "dsd vmware", hintFor: renderCatVMware,
		members: []string{
			renderCatVMware, "KVMGuest", "ContainerGuest", "AWS", "Azure", "GCP",
			renderCatCloudMeta, renderCatCloudInit, "KVM", "PVE",
		},
	},
	{
		title: "OS & services", subtitle: "Linux configuration & workloads",
		members: []string{
			// Core OS / kernel / config
			renderCatSystemd, "DBus", renderCatProcesses, "Proc", renderCatFDLimits, renderCatEntropy, renderCatClock,
			renderCatLogs, "Sysctl", renderCatKernelSec, "Hardening", renderCatPackages, "Subscription",
			renderCatAuth, renderCatAuditd, "Snapshots", renderCatPressure, renderCatOOM, renderCatNspawn, renderCatLaunchd,
			"Sessions", "PostBoot", "Cron", "Timeline", "CVE", "SteamOS",
			// Networking
			renderCatNetwork, "Networkd", "DNS", "DNS resolver", "NFS",
			"BIND", renderCatFirewall, renderCatBonding, renderCatVLAN, "TLS",
			// Containers / orchestration
			"Docker", renderCatContainerd, "K8s",
			// Service workloads (gate-detected; silent when absent)
			"Services", "ServicesDeep", "Postgres", "MySQL", "Redis", "Memcached",
			"Nginx", "Apache", "HAProxy", "RabbitMQ", "Elasticsearch", "MongoDB",
			"Kafka", "Prometheus", "Alertmanager", "Grafana", "Traefik", "Envoy",
		},
	},
}

// PrintAllLayered renders the same rows as PrintAll, grouped into the abstraction
// stack (Hardware & storage → Platform → OS & services), led by a one-line
// severity tally. Behind `dsd health --layered`; the default output and every
// machine format (--json/--yaml/--report) are untouched.
func (r *Renderer) PrintAllLayered(results []runner.Result, insights []models.Insight) {
	r.printLayeredVerdict(insights)

	sorted := sortedResults(results)
	assigned := make(map[string]bool)

	for _, layer := range healthLayers {
		member := make(map[string]bool, len(layer.members))
		for _, m := range layer.members {
			member[m] = true
		}
		var rows []runner.Result
		present := false
		for _, res := range sorted {
			if !member[res.Name] {
				continue
			}
			assigned[res.Name] = true // claim it so renderCatOther can't, even if hidden
			present = true
			if !shouldHideRow(res, insights) {
				rows = append(rows, res)
			}
		}
		r.printLayerHeader(layer.title, layer.subtitle)
		if len(rows) == 0 {
			none := "bare metal — no hypervisor/cloud layer"
			if layer.title != "Platform" {
				none = "nothing to report"
			}
			r.printLayerNote(none)
			continue
		}
		for _, res := range rows {
			r.printRow(res, insights)
		}
		if layer.hint != "" && present {
			for _, res := range rows {
				if res.Name == layer.hintFor {
					r.printLayerNote("→ full detail: " + layer.hint)
					break
				}
			}
		}
	}

	// Anything unmapped (a new collector not yet placed) surfaces here rather than
	// vanishing — a visible nudge to add it to a layer.
	var other []runner.Result
	for _, res := range sorted {
		if !assigned[res.Name] && !shouldHideRow(res, insights) {
			other = append(other, res)
		}
	}
	if len(other) > 0 {
		r.printLayerHeader(renderCatOther, "unclassified")
		for _, res := range other {
			r.printRow(res, insights)
		}
	}
}

func (r *Renderer) printLayeredVerdict(insights []models.Insight) {
	crit, warn, info := 0, 0, 0
	for _, in := range insights {
		switch in.Level {
		case "CRIT":
			crit++
		case "WARN":
			warn++
		case "INFO":
			info++
		}
	}
	tally := fmt.Sprintf("%d critical · %d warnings · %d info", crit, warn, info)
	fmt.Fprintln(os.Stdout)
	if r.mode != output.ModeHuman {
		fmt.Fprintln(os.Stdout, tally)
		return
	}
	style := StyleOK
	switch {
	case crit > 0:
		style = styleForStatus(levelToStatusKey("CRIT"))
	case warn > 0:
		style = styleForStatus(levelToStatusKey("WARN"))
	}
	fmt.Fprintln(os.Stdout, style.Render(tally))
}

func (r *Renderer) printLayerHeader(title, subtitle string) {
	bar := "━━ " + title
	if subtitle != "" {
		bar += "  ·  " + subtitle
	}
	fmt.Fprintln(os.Stdout)
	if r.mode == output.ModeHuman {
		fmt.Fprintln(os.Stdout, StyleBold.Render(bar))
	} else {
		fmt.Fprintln(os.Stdout, bar)
	}
}

func (r *Renderer) printLayerNote(note string) {
	if r.mode == output.ModeHuman {
		fmt.Fprintln(os.Stdout, "  "+StyleDim.Render(note))
	} else {
		fmt.Fprintln(os.Stdout, "  "+note)
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
	// Check if the collector signals unavailability via an Available field.
	// runner.IsAvailable is the shared definition — baseline.BuildSnapshot uses
	// the same one so --report and live health hide the same rows.
	return !runner.IsAvailable(res.Data)
}

// Follows Option C: ≤2 items shown individually, 3+ shows count + worst.
//
//nolint:cyclop // flat name→function dispatch; splitting would harm readability
func inlineData(res runner.Result) string { //nolint:funlen // NOSONAR — flat dispatch table; CC is entry count, not branch depth
	switch res.Name {
	case renderCatCPULoad:
		return inlineCPULoad(res.Data)
	case renderCatMemory:
		return inlineMemory(res.Data)
	case renderCatSwap:
		return inlineSwap(res.Data)
	case renderCatDisk:
		return diskInline(res.Data)
	case renderCatNetwork:
		return networkInline(res.Data)
	case "Kdump":
		return inlineKdump(res.Data)
	case "Tuned":
		return inlineTuned(res.Data)
	case "Kernel":
		return inlineKernelPatch(res.Data)
	case "Ksplice":
		return inlineKsplice(res.Data)
	case "ServiceRestart":
		return inlineServiceRestart(res.Data)
	case renderCatEntropy:
		return inlineEntropy(res.Data)
	case renderCatFDLimits:
		return inlineFDLimits(res.Data)
	case renderCatIO:
		return inlineIO(res.Data)
	case renderCatKernelSec:
		return inlineKernelSec(res.Data)
	case renderCatClock:
		return inlineClock(res.Data)
	case renderCatLogs:
		return inlineLogs(res.Data)
	case renderCatGPU:
		return inlineGPU(res.Data)
	case renderCatCPUThermal:
		return inlineCPUThermal(res.Data)
	case renderCatBattery:
		return inlineBattery(res.Data)
	case renderCatLaunchd:
		return inlineLaunchd(res.Data)
	case renderCatPackages:
		return inlinePackages(res.Data)
	case "CVE":
		return inlineCVE(res.Data)
	case renderCatDrives:
		return inlineDrives(res.Data)
	case renderCatSystemd:
		return inlineSystemd(res.Data)
	case renderCatProcesses:
		return inlineProcesses(res.Data)
	case renderCatBonding:
		return inlineBonding(res.Data)
	case renderCatOOM:
		return inlineOOM(res.Data)
	case renderCatLVM:
		return inlineLVM(res.Data)
	case "Sessions":
		return inlineSessions(res.Data)
	case renderCatIPMI:
		return inlineIPMI(res.Data)
	case renderCatHBA:
		return inlineHBA(res.Data)
	case renderCatPressure:
		return inlinePressure(res.Data)
	case renderCatMultipath:
		return inlineMultipath(res.Data)
	case renderCatCeph:
		return inlineCeph(res.Data)
	case renderCatFirewall:
		return inlineFirewall(res.Data)
	case renderCatAuth:
		return inlineAuth(res.Data)
	case renderCatCloudMeta:
		return inlineCloudMeta(res.Data)
	case renderCatCloudInit:
		return inlineCloudInit(res.Data)
	case renderCatAuditd:
		return inlineAuditd(res.Data)
	case renderCatNUMA:
		return inlineNUMA(res.Data)
	case renderCatVLAN:
		return inlineVLAN(res.Data)
	case renderCatIscsi:
		return inlineISCSI(res.Data)
	case renderCatInfiniBand:
		return inlineInfiniBand(res.Data)
	case renderCatSRIOV:
		return inlineSRIOV(res.Data)
	case renderCatNspawn:
		return inlineNspawn(res.Data)
	case renderCatHugePages:
		return inlineHugePages(res.Data)
	case renderCatCPUFreq:
		return inlineCPUFreq(res.Data)
	case renderCatContainerd:
		return inlineContainerd(res.Data)
	}
	return ""
}

func inlineCPULoad(data any) string {
	cpu := asCPUInfo(data)
	if cpu == nil {
		return ""
	}
	return fmt.Sprintf("%.0f%%", cpuDisplayPct(cpu))
}

// cpuDisplayPct is the CPU% shown in the grid headline. It prefers the real
// user+sys utilisation (UsagePct, which matches htop) — but that is an
// instantaneous /proc/stat sample, and on a small-core host dsd's own parallel
// collection can briefly load the box and inflate it. The 1-minute load average
// predates this run and is immune, so when it says the box is light yet the
// instantaneous reading is much higher, the reading is unreliable (dsd's
// footprint or a sub-second spike) and we show the load-derived figure instead.
// Busy boxes (load at/above the warn floor) always show the instantaneous value,
// preserving the htop match. This is display-only: the verdict still uses the
// raw UsagePct, so a genuinely busy host is never under-reported into silence.
func cpuDisplayPct(cpu *models.CPUInfo) float64 {
	usage := cpu.UsagePct
	if usage <= 0 {
		return cpu.LoadPct
	}
	// lightLoadFloorPct mirrors the default CPU warn multiplier (0.7); observerGap
	// is the margin by which an instantaneous sample may legitimately exceed the
	// 1-minute average in normal use — a wider gap on an otherwise-light box is
	// measurement noise, not host load.
	const lightLoadFloorPct = 70.0
	const observerGapPct = 25.0
	if cpu.LoadPct < lightLoadFloorPct && usage-cpu.LoadPct > observerGapPct {
		return cpu.LoadPct
	}
	return usage
}

func inlineMemory(data any) string {
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
	// Sub-GB totals (small containers / minimal VMs) floor to "0 GB" under %.0f,
	// producing a broken-looking "0.1/0 GB" — show MB in that range instead.
	if r.TotalGB < 1 {
		return fmt.Sprintf("%.0f/%.0f MB (%.0f%%)", used*1024, r.TotalGB*1024, r.UsedPct)
	}
	return fmt.Sprintf("%.1f/%.0f GB (%.0f%%)", used, r.TotalGB, r.UsedPct)
}

func inlineSwap(data any) string {
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

func inlineEntropy(data any) string {
	var e *models.EntropyInfo
	if v, ok := data.(*models.EntropyInfo); ok {
		e = v
	} else if v, ok := data.(models.EntropyInfo); ok {
		e = &v
	}
	if e == nil || !e.Available || e.EntropyBits <= 0 {
		return ""
	}
	if e.PoolSize > 0 {
		return fmt.Sprintf("%d/%d bits", e.EntropyBits, e.PoolSize)
	}
	return fmt.Sprintf("%d bits", e.EntropyBits)
}

func inlineFDLimits(data any) string {
	var fd *models.FDInfo
	if v, ok := data.(*models.FDInfo); ok {
		fd = v
	} else if v, ok := data.(models.FDInfo); ok {
		fd = &v
	}
	if fd == nil {
		return ""
	}
	// When system limit is effectively unlimited (Linux default ~9.2e18),
	// just show open count + any deleted-but-open files
	if fd.MaxCount == 0 || fd.MaxCount >= 1<<40 {
		s := fmt.Sprintf("%s open", formatCount(fd.OpenCount))
		if fd.DeletedOpenFiles > 0 {
			s += fmt.Sprintf("  %d deleted", fd.DeletedOpenFiles)
		}
		return s
	}
	s := fmt.Sprintf("%.0f%% (%s/%s open)", fd.UsedPct, formatCount(fd.OpenCount), formatCount(fd.MaxCount))
	if fd.DeletedOpenFiles > 0 {
		s += fmt.Sprintf("  %d deleted", fd.DeletedOpenFiles)
	}
	return s
}

func inlineIO(data any) string {
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

func inlineKernelSec(data any) string {
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

func inlineClock(data any) string {
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

func inlineLogs(data any) string {
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

func inlineCPUThermal(data any) string {
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

func inlineBattery(data any) string {
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

func inlineDrives(data any) string {
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
	// Devices whose SMART was never read carry zero-default health fields — they are
	// detected, not verified-healthy. Don't claim "healthy". NVMe: no nvme-cli. SATA:
	// smartctl errored (permission/non-root — validated on pve01) or returned no
	// smart_status (USB/RAID/virtual). Counting only NVMe here let a non-root run,
	// where smartctl fails for every SATA drive, still render "N drives healthy".
	unread := 0
	for _, d := range n.Devices {
		// !SmartRead = nvme-cli absent. NVMeNoRealData = SMART read but all-sentinel
		// (virtual/cloud volume, e.g. AWS EBS — 0-Kelvin temp + all-zero); either way
		// nothing was verified, so it must not render "healthy".
		if !d.SmartRead || analysis.NVMeNoRealData(d) {
			unread++
		}
	}
	for _, d := range n.SATADevices {
		if !d.SmartRead || d.Error != "" {
			unread++
		}
	}
	if total == 1 {
		name := ""
		if len(n.Devices) == 1 {
			name = n.Devices[0].Name
		} else {
			name = n.SATADevices[0].Name
		}
		if unread == 1 {
			return name + "  detected (SMART not read)"
		}
		return name + "  healthy"
	}
	if unread > 0 {
		return fmt.Sprintf("%d drives, %d SMART not read", total, unread)
	}
	return fmt.Sprintf("%d drives  healthy", total)
}

func inlineSystemd(data any) string {
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

func inlineProcesses(data any) string {
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

func inlineBonding(data any) string {
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

func inlineOOM(data any) string {
	var o *models.OOMInfo
	if v, ok := data.(*models.OOMInfo); ok {
		o = v
	} else if v, ok := data.(models.OOMInfo); ok {
		o = &v
	}
	if o == nil || !o.Available {
		return ""
	}
	if o.StatusReason != "" {
		return "not verified (kernel log unreadable)"
	}
	if o.EventsLast24h == 0 {
		return "0 events"
	}
	return fmt.Sprintf("%d event(s) in 24h", o.EventsLast24h)
}

func inlineLVM(data any) string {
	var l *models.LVMInfo
	if v, ok := data.(*models.LVMInfo); ok {
		l = v
	} else if v, ok := data.(models.LVMInfo); ok {
		l = &v
	}
	if l == nil || len(l.VGs) == 0 {
		return ""
	}
	// Count only active VGs (with mounted LVs)
	active := 0
	for _, vg := range l.VGs {
		if vg.HasMountedLV {
			active++
		}
	}
	if active == 0 {
		return fmt.Sprintf("%d VG(s)", len(l.VGs))
	}
	return fmt.Sprintf("%d VG(s)  %d active", len(l.VGs), active)
}

func inlineSessions(data any) string {
	var s *models.SessionsInfo
	if v, ok := data.(*models.SessionsInfo); ok {
		s = v
	} else if v, ok := data.(models.SessionsInfo); ok {
		s = &v
	}
	if s == nil {
		return ""
	}
	if s.TotalCount == 0 {
		return "no active sessions"
	}
	if s.TotalCount == 1 && len(s.Sessions) > 0 {
		return fmt.Sprintf("1 session (%s)", s.Sessions[0].User)
	}
	if s.RemoteCount > 0 {
		return fmt.Sprintf("%d sessions  %d remote", s.TotalCount, s.RemoteCount)
	}
	return fmt.Sprintf("%d sessions", s.TotalCount)
}

func inlineIPMI(data any) string {
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

func inlineHBA(data any) string {
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

func inlinePressure(data any) string {
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

func inlineMultipath(data any) string {
	var m *models.MultipathInfo
	if v, ok := data.(*models.MultipathInfo); ok {
		m = v
	} else if v, ok := data.(models.MultipathInfo); ok {
		m = &v
	}
	if m == nil || !m.Available {
		return ""
	}
	// paths unreadable (both queries failed) — surface it rather than drop the row.
	if m.Status == "error" {
		return "paths unreadable — not verified"
	}
	if len(m.Devices) == 0 {
		return ""
	}
	totalPaths := 0
	for _, d := range m.Devices {
		totalPaths += d.TotalPaths
	}
	return fmt.Sprintf("%d devices  %d paths", len(m.Devices), totalPaths)
}

func inlineCeph(data any) string {
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

func inlineFirewall(data any) string {
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

func inlineAuth(data any) string {
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

func inlineCloudMeta(data any) string {
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

func inlineCloudInit(data any) string {
	var c *models.CloudInitInfo
	if v, ok := data.(*models.CloudInitInfo); ok {
		c = v
	} else if v, ok := data.(models.CloudInitInfo); ok {
		c = &v
	}
	if c == nil || !c.Available {
		return ""
	}
	// Prefer extended_status ("degraded done") when present — it's the richer state.
	s := c.Status
	if c.ExtendedStatus != "" {
		s = c.ExtendedStatus
	}
	if c.Datasource != "" {
		s += "  (" + c.Datasource + ")"
	}
	return s
}

func inlineAuditd(data any) string {
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

func inlineNUMA(data any) string {
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

func inlineVLAN(data any) string {
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

func inlineISCSI(data any) string {
	var i *models.ISCSIInfo
	if v, ok := data.(*models.ISCSIInfo); ok {
		i = v
	} else if v, ok := data.(models.ISCSIInfo); ok {
		i = &v
	}
	if i == nil || !i.Available || len(i.Sessions) == 0 {
		return ""
	}
	// Count actually-LOGGED_IN sessions, not the total — a FAILED/reconnecting session
	// must not read as "logged in" next to a CRIT icon (mirrors inlineHBA online/total).
	loggedIn := 0
	for _, s := range i.Sessions {
		if strings.EqualFold(s.State, "LOGGED_IN") {
			loggedIn++
		}
	}
	if loggedIn == len(i.Sessions) {
		return fmt.Sprintf("%d session(s)  logged in", loggedIn)
	}
	return fmt.Sprintf("%d/%d logged in", loggedIn, len(i.Sessions))
}

func inlineInfiniBand(data any) string {
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

func inlineSRIOV(data any) string {
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

func inlineNspawn(data any) string {
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

func inlineGPU(data any) string {
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
func diskInline(data any) string {
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
func networkInline(data any) string {
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
	// Build set of bond slave interface names — slaves shouldn't be shown as independent NICs
	bondSlaves := map[string]bool{}
	for _, b := range n.Bonds {
		for _, s := range b.Slaves {
			bondSlaves[s.Name] = true
		}
	}
	for _, iface := range n.Interfaces {
		if iface.Up && !bondSlaves[iface.Name] {
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
	// Append bond health summary if any bonds exist
	for _, b := range n.Bonds {
		if b.AllDown {
			ifaceSummary += fmt.Sprintf("  ❌ %s DOWN", b.Name)
		} else if b.Degraded {
			upCount := len(b.Slaves) - b.DownSlaves
			ifaceSummary += fmt.Sprintf("  ⚠️  %s %d/%d slaves", b.Name, upCount, len(b.Slaves))
		}
	}
	return ifaceSummary
}

// ioInline picks the most meaningful IO metric across all devices.
// On Linux: worst await latency (ms). On macOS: current throughput (MB/s).
func ioInline(devices []models.IODeviceInfo) string {
	if len(devices) == 0 {
		return ""
	}

	// Prefer await latency when available (Linux)
	worst := devices[0]
	for _, d := range devices[1:] {
		if d.AwaitMs > worst.AwaitMs {
			worst = d
		}
	}
	if worst.AwaitMs > 0 {
		if len(devices) == 1 {
			return fmt.Sprintf("%.1f ms", worst.AwaitMs)
		}
		return fmt.Sprintf("%.1f ms (%s)", worst.AwaitMs, worst.Name)
	}

	// Fallback: show throughput when latency unavailable (macOS)
	// On macOS, ReadMBps holds total throughput (iostat doesn't split read/write)
	var total float64
	for _, d := range devices {
		total += d.ReadMBps + d.WriteMBps
	}
	if total > 0 {
		return formatMBps(total) + "/s"
	}
	return ""
}

// formatMBps formats bytes-per-second with appropriate unit.
func formatMBps(mbps float64) string {
	if mbps >= 1000 {
		return fmt.Sprintf("%.1f GB", mbps/1024)
	}
	if mbps >= 1 {
		return fmt.Sprintf("%.1f MB", mbps)
	}
	return fmt.Sprintf("%.0f KB", mbps*1024)
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

func asCPUInfo(data any) *models.CPUInfo {
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
		fmt.Fprintf(os.Stdout, "%s%s\n", indent, StyleDim.Render(output.SanitizeControl(d.Title)+":"))
	}

	if len(d.Columns) > 0 && len(d.Rows) > 0 {
		// Sanitize into local copies — Details is largely sourced from
		// journalctl/log_tail content and other subprocess/proc output, which is
		// attacker-influenced and must not carry raw control bytes to the
		// terminal. The underlying model (d) is left untouched so --json/--yaml
		// output keeps the raw values.
		columns := make([]string, len(d.Columns))
		for i, col := range d.Columns {
			columns[i] = output.SanitizeControl(col)
		}
		rows := make([][]string, len(d.Rows))
		for i, row := range d.Rows {
			sanRow := make([]string, len(row))
			for j, cell := range row {
				sanRow[j] = output.SanitizeControl(cell)
			}
			rows[i] = sanRow
		}

		// Compute column widths
		widths := make([]int, len(columns))
		for i, col := range columns {
			widths[i] = len(col)
		}
		for _, row := range rows {
			for i, cell := range row {
				if i < len(widths) && len(cell) > widths[i] {
					widths[i] = len(cell)
				}
			}
		}

		// Header
		var hdr strings.Builder
		hdr.WriteString(indent)
		for i, col := range columns {
			if i > 0 {
				hdr.WriteString("  ")
			}
			fmt.Fprintf(&hdr, "%-*s", widths[i], col)
		}
		fmt.Fprintln(os.Stdout, StyleDim.Render(hdr.String()))

		// Rows
		for _, row := range rows {
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
			for line := range strings.SplitSeq(strings.TrimSpace(tail), "\n") {
				fmt.Fprintf(os.Stdout, "%s%s\n", indent, StyleDim.Render(output.SanitizeControl(line)))
			}
		}
	} else if len(d.KV) > 0 && len(d.Rows) == 0 {
		for k, v := range d.KV {
			fmt.Fprintf(os.Stdout, "%s%s: %s\n", indent, StyleDim.Render(output.SanitizeControl(k)), output.SanitizeControl(v))
		}
	}

	if d.Note != "" {
		fmt.Fprintf(os.Stdout, "%s%s\n", indent, StyleDim.Render("note: "+output.SanitizeControl(d.Note)))
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
		// A "healthy" verdict (no CRIT/WARN) is not the same as "nothing to show" —
		// INFO includes "could not measure" disclosures (e.g. checkMemory's
		// unmeasurable-cgroup case) that must never be silently dropped just because
		// the top-line verdict is clean.
		r.printInsightGroup(infos)
		return exitCodeFromInsights(insights)
	}

	r.printInsightGroup(crits)
	r.printInsightGroup(warns)
	r.printInsightGroup(infos)

	return exitCodeFromInsights(insights)
}

func (r *Renderer) printInsightGroup(ins []models.Insight) {
	for _, i := range ins {
		// Check/Message/Hints routinely embed collector-sourced text that is
		// not trustworthy (process/comm names, cron and journal log lines,
		// subprocess output, sysfs labels, cert fields — see the adversarial
		// review's terminal-injection findings, e.g. internal-collectors-06-02,
		// -08-01, -18-03, -21-02, -21-03, -25-04). Sanitize once here, the
		// single choke point every insight passes through before reaching
		// the terminal, rather than at each of the dozens of analysis call
		// sites that build these strings.
		check := output.SanitizeControl(i.Check)
		msg := output.SanitizeControl(i.Message)
		hints := sanitizeHints(i.Hints)
		if r.mode == output.ModeHuman {
			icon := styleForStatus(i.Level).Render(output.StatusIcon(levelToStatusKey(i.Level), r.mode))
			fmt.Fprintf(os.Stdout, "%s  %s: %s\n", icon, StyleBold.Render(check), msg)
			r.printHints(hints)
		} else {
			fmt.Fprintf(os.Stdout, "%s: %s: %s\n", i.Level, check, msg)
			r.printHintsPlain(hints)
		}
	}
}

// sanitizeHints strips control/escape characters from each hint before
// display. Hints can embed untrusted collector-sourced text (e.g. "last
// error: <raw journal text>", "sample AVC: <raw audit line>"), unlike the
// static "to inspect:"/"to fix:" prefixes printHints/printHintsPlain key off
// of, which are always analysis-authored and untouched by this.
func sanitizeHints(hints []string) []string {
	if len(hints) == 0 {
		return hints
	}
	out := make([]string, len(hints))
	for i, h := range hints {
		out[i] = output.SanitizeControl(h)
	}
	return out
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

	for _, raw := range hints {
		// Hints are largely dsd-authored templates, but some splice in
		// attacker-influenced values (SUID paths, bootnames, comm names, ...) —
		// sanitize before any prefix matching/printing.
		h := output.SanitizeControl(raw)
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

	for _, raw := range hints {
		h := output.SanitizeControl(raw)
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
		// Name/Summary/Action are analysis-constructed strings that can splice in
		// attacker-influenced data (e.g. an OOM-killed process's comm name) — this
		// is the terminal-print boundary, so sanitize here.
		name := output.SanitizeControl(c.Name)
		summary := output.SanitizeControl(c.Summary)
		action := output.SanitizeControl(c.Action)
		if r.mode == output.ModeHuman {
			style := styleForStatus(c.Level)
			icon := style.Render("▶")
			fmt.Fprintf(os.Stdout, "%s  %s\n", icon, StyleBold.Render(name))
		} else {
			fmt.Fprintf(os.Stdout, "%s: %s\n", c.Level, name)
		}
		fmt.Fprintf(os.Stdout, "   %s\n", summary)
		fmt.Fprintf(os.Stdout, "   → %s\n", action)
	}
}

func inlineHugePages(data any) string {
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

func inlineCPUFreq(data any) string {
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

func inlineLaunchd(data any) string {
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

func inlinePackages(data any) string {
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
	// BUG-098: Status is only ever non-empty when the scan did NOT cleanly
	// succeed ("query-failed", "no-security-repo", "stale-metadata", ...).
	// Whitelisting the clean case (rather than blacklisting one bad status)
	// means a future failure status can't fall through here by omission —
	// query-failed/no-security-repo previously did, rendering a scan that
	// timed out or found no repo as a reassuring "up to date".
	if p.Status != "" {
		return "" // heuristic already shows the "could not verify" reason
	}
	if p.Checked {
		return "up to date"
	}
	return ""
}

// inlineCVE returns a one-line summary for the CVE row when it is OK (no
// high-severity or actively-exploited CVEs — those already surface as insights).
func inlineCVE(data any) string {
	var r *models.CVEAllResult
	if v, ok := data.(*models.CVEAllResult); ok {
		r = v
	} else if v, ok := data.(models.CVEAllResult); ok {
		r = &v
	}
	if r == nil {
		return ""
	}
	if r.Total == 0 {
		if r.StatusReason != "" {
			return r.StatusReason
		}
		return "no pending security advisories"
	}
	// Has advisories but none high-severity (else an insight set the row WARN/CRIT).
	return fmt.Sprintf("%d advisory(ies), none high-severity", r.Total)
}

// inlineContainerd returns a one-line summary for a standalone containerd runtime.
// Shows version + namespace/container counts when available.
func inlineContainerd(data any) string {
	d, ok := data.(*models.ContainerdInfo)
	if !ok {
		if v, ok2 := data.(models.ContainerdInfo); ok2 {
			d = &v
		}
	}
	if d == nil || !d.Available {
		return ""
	}
	var parts []string
	if d.Version != "" {
		parts = append(parts, d.Version)
	}
	if len(d.Namespaces) > 0 {
		var nsParts []string
		for _, ns := range d.Namespaces {
			nsParts = append(nsParts, fmt.Sprintf("%s:%d", ns.Name, ns.ContainerCount))
		}
		parts = append(parts, strings.Join(nsParts, " "))
	} else if d.TotalContainers > 0 {
		parts = append(parts, fmt.Sprintf("%d container(s)", d.TotalContainers))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("socket %s", d.SocketPath)
	}
	return strings.Join(parts, "  ")
}
