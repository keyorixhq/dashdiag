package render

import (
	"fmt"
	"os"
	"strings"

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
	}
}

func (r *Renderer) PrintSummary(insights []models.Insight) int {
	if r.mode == output.ModeJSON {
		return exitCodeFromInsights(insights)
	}

	var crits, warns []models.Insight
	for _, ins := range insights {
		switch ins.Level {
		case "CRIT":
			crits = append(crits, ins)
		case "WARN":
			warns = append(warns, ins)
		}
	}

	sep := strings.Repeat("─", 50)
	fmt.Fprintln(os.Stdout, sep)

	if len(crits)+len(warns) == 0 {
		if r.mode == output.ModeHuman {
			fmt.Fprintln(os.Stdout, StyleOK.Render("✅  All checks passed"))
		} else {
			fmt.Fprintln(os.Stdout, "OK: All checks passed")
		}
		return 0
	}

	r.printInsightGroup(crits)
	r.printInsightGroup(warns)
	return exitCodeFromInsights(insights)
}

func (r *Renderer) printInsightGroup(ins []models.Insight) {
	for _, i := range ins {
		if r.mode == output.ModeHuman {
			icon := styleForStatus(i.Level).Render(output.StatusIcon(levelToStatusKey(i.Level), r.mode))
			fmt.Fprintf(os.Stdout, "%s  %s: %s\n", icon, StyleBold.Render(i.Check), i.Message)
			for _, h := range i.Hints {
				fmt.Fprintf(os.Stdout, "   %s %s\n", StyleDim.Render("→"), h)
			}
		} else {
			fmt.Fprintf(os.Stdout, "%s: %s: %s\n", i.Level, i.Check, i.Message)
			for _, h := range i.Hints {
				fmt.Fprintf(os.Stdout, "   -> %s\n", h)
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
