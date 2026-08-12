package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckOOMIsCrit guards that an OOM kill in the 24h window is CRIT, matching
// the logs path's 1h-window CRIT — otherwise a kill 60+ minutes ago would only
// WARN and dsd would exit 1 instead of 2.
func TestCheckOOMIsCrit(t *testing.T) {
	t.Parallel()
	got := checkOOM(models.OOMInfo{
		EventsLast24h: 2,
		RecentEvents:  []models.OOMEvent{{Process: "java"}, {Process: "java"}},
	})
	if len(got) != 1 {
		t.Fatalf("insight count: got %d, want 1", len(got))
	}
	if got[0].Level != "CRIT" {
		t.Errorf("level: got %q, want CRIT", got[0].Level)
	}
}

// TestCheckOOMSilentWhenNone confirms no insight when there were no OOM events.
func TestCheckOOMSilentWhenNone(t *testing.T) {
	t.Parallel()
	if got := checkOOM(models.OOMInfo{EventsLast24h: 0}); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

// TestCheckOOM_EventsCountUnverified is the regression guard for
// internal-collectors-25-05: a scanner error mid-parse must disclose INFO
// even when EventsLast24h reads 0 (the truncation may have dropped every
// remaining event), and must NOT suppress a real CRIT when some events were
// still parsed before the truncation point.
func TestCheckOOM_EventsCountUnverified(t *testing.T) {
	t.Parallel()
	zero := checkOOM(models.OOMInfo{EventsLast24h: 0, EventsCountUnverified: true})
	if len(zero) != 1 || zero[0].Level != "INFO" || !strings.Contains(zero[0].Message, "may be incomplete") {
		t.Errorf("zero-count truncated = %+v, want one INFO mentioning 'may be incomplete'", zero)
	}

	withEvents := checkOOM(models.OOMInfo{
		EventsLast24h:         1,
		RecentEvents:          []models.OOMEvent{{Process: "java"}},
		EventsCountUnverified: true,
	})
	var sawInfo, sawCrit bool
	for _, ins := range withEvents {
		switch ins.Level {
		case "INFO":
			sawInfo = true
		case "CRIT":
			sawCrit = true
		}
	}
	if !sawInfo || !sawCrit {
		t.Errorf("truncated-but-nonzero = %+v, want both the INFO caveat AND the CRIT for the parsed event", withEvents)
	}
}
