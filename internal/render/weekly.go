package render

import (
	"fmt"
	"os"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/tips"
)

func RenderWeekly(state *tips.State, period string) string {
	if state.TotalRuns < 7 {
		return "ℹ️  Not enough data yet. Run dsd health for 7+ days to see your weekly report."
	}

	hostname, _ := os.Hostname()
	avg := float64(state.TotalRuns) / 7.0
	timeSaved := state.TotalRuns

	const width = 45
	border := strings.Repeat("═", width)

	title := centerPad(fmt.Sprintf("DashDiag %s Report — %s", capitalize(period), hostname), width)
	runsLine := padRight(fmt.Sprintf(" Checks run:       %-4d  (%.1f / day avg)", state.TotalRuns, avg), width)
	issuesLine := padRight(fmt.Sprintf(" Issues detected:  %-4d", state.ErrorExits), width)
	timeLine := padRight(fmt.Sprintf(" Time saved:       ~%d minutes", timeSaved), width)

	lines := []string{
		"╔" + border + "╗",
		"║" + title + "║",
		"╠" + border + "╣",
		"║" + runsLine + "║",
		"║" + issuesLine + "║",
		"║" + timeLine + "║",
		"╚" + border + "╝",
		"",
		"💡 See 90-day history: dashdiag.sh/teams",
	}

	return strings.Join(lines, "\n")
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func centerPad(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	pad := (width - len(s)) / 2
	right := width - pad - len(s)
	return strings.Repeat(" ", pad) + s + strings.Repeat(" ", right)
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}
