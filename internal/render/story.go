package render

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
)

// RenderStory narrates system health — uses history if available, single point otherwise.
func RenderStory(insights []models.Insight, snap *baseline.Snapshot) string {
	history, err := baseline.LoadHistory(48)
	if err == nil && len(history) >= 2 {
		return RenderStoryFromHistory(history)
	}
	return renderStorySinglePoint(insights, snap)
}

// RenderStoryFromHistory narrates across multiple baseline snapshots.
func RenderStoryFromHistory(history []*baseline.Snapshot) string {
	return renderStoryFromHistory(history)
}

// renderStorySinglePoint is the fallback when no history exists yet.
func renderStorySinglePoint(insights []models.Insight, snap *baseline.Snapshot) string {
	ts := snap.Timestamp.Local().Format("15:04 02.01.2006")
	active := activeInsights(insights)
	if len(active) == 0 {
		return fmt.Sprintf("System health at %s on %s — all %d checks passed.",
			ts, snap.Hostname, len(snap.Checks))
	}
	var lines []string
	for _, ins := range active {
		lines = append(lines, fmt.Sprintf("  %s: %s", ins.Check, ins.Message))
	}
	return fmt.Sprintf("System health at %s on %s:\n%s",
		ts, snap.Hostname, strings.Join(lines, "\n"))
}

// renderStoryFromHistory narrates across multiple baseline snapshots.
func renderStoryFromHistory(history []*baseline.Snapshot) string {
	if len(history) == 0 {
		return "No baseline history found. Run dsd health a few times to build history."
	}

	first := history[0]
	last := history[len(history)-1]
	start := first.Timestamp.Local().Format("15:04 02.01.2006")
	end := last.Timestamp.Local().Format("15:04 02.01.2006")
	hostname := last.Hostname
	n := len(history)

	// Track events: when each check changed status
	type event struct {
		ts      string
		check   string
		from    string
		to      string
		message string
	}
	var events []event
	prevStatus := make(map[string]string)
	prevMsg := make(map[string]string)

	// Seed from first snapshot
	for _, c := range first.Checks {
		prevStatus[c.Name] = c.Status
		prevMsg[c.Name] = c.Value
	}

	// Walk history looking for status changes
	for _, snap := range history[1:] {
		ts := snap.Timestamp.Local().Format("15:04 02.01.2006")
		for _, c := range snap.Checks {
			prev := prevStatus[c.Name]
			if prev != "" && prev != c.Status {
				msg := c.Value
				if c.Name == "Processes" && (c.Status == "WARN" || c.Status == "CRIT") {
					if offender := extractZombieOffender(c.Raw); offender != "" {
						msg = fmt.Sprintf("%s (offender: %s)", msg, offender)
					}
				}
				events = append(events, event{
					ts:      ts,
					check:   c.Name,
					from:    prev,
					to:      c.Status,
					message: msg,
				})
			}
			prevStatus[c.Name] = c.Status
			prevMsg[c.Name] = c.Value
		}
	}

	// Current state of last snapshot
	var currentIssues []string
	for _, c := range last.Checks {
		if c.Status == "WARN" || c.Status == "CRIT" {
			currentIssues = append(currentIssues, fmt.Sprintf("  %s: %s", c.Name, c.Value))
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("System health — %d snapshots — %s to %s on %s\n",
		n, start, end, hostname))
	sb.WriteString(strings.Repeat("─", 56) + "\n")

	if len(events) == 0 && len(currentIssues) == 0 {
		sb.WriteString("All checks remained healthy throughout this period.")
		return sb.String()
	}

	if len(events) > 0 {
		sb.WriteString("\nEvents:\n")
		for _, e := range events {
			arrow := degradeArrow(e.from, e.to)
			if e.message != "" {
				sb.WriteString(fmt.Sprintf("  %s  %s %s %s — %s\n", e.ts, e.check, arrow, e.to, e.message))
			} else {
				sb.WriteString(fmt.Sprintf("  %s  %s %s %s\n", e.ts, e.check, arrow, e.to))
			}
		}
	}

	if len(currentIssues) > 0 {
		sb.WriteString("\nCurrent issues:\n")
		for _, issue := range currentIssues {
			sb.WriteString(issue + "\n")
		}
	} else if len(events) > 0 {
		sb.WriteString("\nAll checks currently healthy.\n")
	}

	return strings.TrimRight(sb.String(), "\n")
}

func degradeArrow(from, to string) string {
	order := map[string]int{"OK": 0, "INFO": 0, "WARN": 1, "CRIT": 2}
	if order[to] > order[from] {
		return "↓"
	}
	return "↑"
}

func activeInsights(insights []models.Insight) []models.Insight {
	seen := make(map[string]models.Insight)
	for _, ins := range insights {
		if ins.Level != "WARN" && ins.Level != "CRIT" {
			continue
		}
		if prev, ok := seen[ins.Check]; !ok || severityOrder(ins.Level) > severityOrder(prev.Level) {
			seen[ins.Check] = ins
		}
	}
	out := make([]models.Insight, 0, len(seen))
	for _, ins := range seen {
		out = append(out, ins)
	}
	return out
}

func severityOrder(level string) int {
	switch level {
	case "CRIT":
		return 2
	case "WARN":
		return 1
	default:
		return 0
	}
}

// extractZombieOffender pulls the parent process name from the raw ProcessInfo
// stored in a baseline snapshot. Raw arrives as map[string]interface{} after
// JSON round-trip.
func extractZombieOffender(raw any) string {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return ""
	}
	procs, ok := m["zombie_procs"].([]interface{})
	if !ok || len(procs) == 0 {
		return ""
	}
	seen := make(map[string]bool)
	var names []string
	for _, p := range procs {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := pm["parent_name"].(string)
		if name == "" {
			continue
		}
		if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
			name = name[idx+1:]
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return strings.Join(names, ", ")
}
