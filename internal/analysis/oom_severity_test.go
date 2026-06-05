package analysis

import (
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
