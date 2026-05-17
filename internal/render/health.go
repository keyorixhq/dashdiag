package render

import (
	"fmt"
	"os"
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

func (r *Renderer) PrintAll(results []runner.Result, insights []models.Insight) {
	for _, res := range results {
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

// inlineData returns a short summary string for a check row when status is OK.
// Follows Option C: ≤2 items shown individually, 3+ shows count + worst.
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
	// Multiple GPUs — ≤2 show both, 3+ show count + hottest
	if len(g.Devices) == 2 {
		var parts []string
		for _, d := range g.Devices {
			s := d.Name
			if d.TempC > 0 {
				s += fmt.Sprintf(" %d°C", d.TempC)
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, "  ")
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

	// Always print timing at the end
	if elapsed > 0 {
		if r.mode == output.ModeHuman {
			fmt.Fprintln(os.Stdout, StyleDim.Render(fmt.Sprintf("done in %.1fs", elapsed.Seconds())))
		} else {
			fmt.Fprintf(os.Stdout, "done in %.1fs\n", elapsed.Seconds())
		}
	}
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
