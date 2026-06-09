package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/output"
)

// The Team-mode waitlist nudge must be tasteful: only on genuine multi-host runs,
// and fully suppressible. It must never appear for a single host or when silenced.
func TestFleetWaitlistNudge(t *testing.T) {
	// Single host → never nudge (not a "team" signal).
	t.Setenv("DSD_NO_NUDGE", "")
	t.Setenv("DSD_NO_UPDATE_CHECK", "")
	if got := fleetWaitlistNudge(output.ModeHuman, 1); got != "" {
		t.Errorf("single host should not nudge, got %q", got)
	}

	// Multi-host, not silenced → nudge with the waitlist URL.
	got := fleetWaitlistNudge(output.ModeHuman, 4)
	if !strings.Contains(got, "dashdiag.sh/plans") || !strings.Contains(got, "waitlist") {
		t.Errorf("multi-host nudge should point to the waitlist, got %q", got)
	}

	// Silenced by either env → no nudge even on a multi-host run.
	t.Setenv("DSD_NO_NUDGE", "1")
	if got := fleetWaitlistNudge(output.ModeHuman, 4); got != "" {
		t.Errorf("DSD_NO_NUDGE must silence the nudge, got %q", got)
	}
	t.Setenv("DSD_NO_NUDGE", "")
	t.Setenv("DSD_NO_UPDATE_CHECK", "1")
	if got := fleetWaitlistNudge(output.ModeHuman, 4); got != "" {
		t.Errorf("DSD_NO_UPDATE_CHECK must also silence the nudge, got %q", got)
	}
}
