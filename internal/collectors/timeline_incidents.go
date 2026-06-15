package collectors

import "github.com/keyorixhq/dashdiag/internal/models"

// incidentGapSec is the quiet gap that separates one incident from the next:
// events more than this many seconds apart are treated as unrelated incidents.
// Two minutes captures a typical crash-restart-cascade burst without merging
// unrelated blips that happen to share the same window.
const incidentGapSec int64 = 120

func timelineLevelRank(level string) int {
	switch level {
	case "CRIT":
		return 3
	case "WARN":
		return 2
	default:
		return 1
	}
}

// GroupIncidents clusters time-sorted events into incidents: a new incident
// starts whenever the gap from the previous event exceeds gapSec. Each incident
// is headlined by its worst event so the operator reads "what happened" instead
// of scanning every line. Input is assumed sorted ascending by TimestampUnix
// (the timeline collector sorts before calling this).
func GroupIncidents(events []models.TimelineEvent, gapSec int64) []models.TimelineIncident {
	if len(events) == 0 {
		return nil
	}
	var incidents []models.TimelineIncident
	start := 0
	for i := 1; i <= len(events); i++ {
		if i == len(events) || events[i].TimestampUnix-events[i-1].TimestampUnix > gapSec {
			incidents = append(incidents, buildIncident(events[start:i]))
			start = i
		}
	}
	return incidents
}

func buildIncident(evs []models.TimelineEvent) models.TimelineIncident {
	worst := "INFO"
	var headline models.TimelineEvent
	total := 0
	units := map[string]bool{}
	for _, e := range evs {
		c := e.Count
		if c == 0 {
			c = 1
		}
		total += c
		if e.Unit != "" {
			units[e.Unit] = true
		}
		if timelineLevelRank(e.Level) > timelineLevelRank(worst) {
			worst = e.Level
			headline = e
		}
	}
	if headline.Message == "" { // all same level — lead with the first event
		headline = evs[0]
	}
	summary := headline.Message
	if headline.Unit != "" {
		summary = headline.Unit + ": " + summary
	}
	return models.TimelineIncident{
		StartUnix:   evs[0].TimestampUnix,
		EndUnix:     evs[len(evs)-1].TimestampUnix,
		StartStr:    evs[0].TimeStr,
		DurationSec: evs[len(evs)-1].TimestampUnix - evs[0].TimestampUnix,
		Level:       worst,
		Summary:     summary,
		EventCount:  total,
		Sources:     len(units),
	}
}
