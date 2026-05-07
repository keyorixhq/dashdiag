package output

import "github.com/charmbracelet/lipgloss"

var dimStyle = lipgloss.NewStyle().Faint(true)

func ProLabel(tier string, mode OutputMode) string {
	label := "  ◆ " + tier
	switch mode {
	case ModeJSON, ModeYAML:
		return ""
	case ModePlain, ModeReport:
		return "  [" + tier + "]"
	default: // ModeHuman
		return dimStyle.Render(label)
	}
}
