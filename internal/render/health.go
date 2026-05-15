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
				StyleDim.Render("→"), g.label, g.cmds[0])
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
