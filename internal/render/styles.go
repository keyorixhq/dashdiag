package render

import "github.com/charmbracelet/lipgloss"

var (
	StyleOK   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#2E7D32", Dark: "#66BB6A"})
	StyleWarn = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#E65100", Dark: "#FFB74D"})
	StyleCrit = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#B71C1C", Dark: "#EF5350"})
	StyleInfo = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#1565C0", Dark: "#64B5F6"})
	StyleDim  = lipgloss.NewStyle().Faint(true)
	StyleBold = lipgloss.NewStyle().Bold(true)
	StyleBox  = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.AdaptiveColor{Light: "#BDBDBD", Dark: "#424242"}).
			Padding(0, 1)
)

func styleForStatus(status string) lipgloss.Style {
	switch status {
	case "CRIT":
		return StyleCrit
	case "WARN":
		return StyleWarn
	case "INFO":
		return StyleInfo
	default:
		return StyleOK
	}
}
