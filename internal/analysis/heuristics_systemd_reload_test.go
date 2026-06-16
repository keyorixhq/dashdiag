package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckSystemdNeedsDaemonReload verifies that units with files changed on
// disk but not reloaded surface as a WARN in dsd health (folded in from the same
// signal dsd services deep shows), and that a clean host emits nothing for it.
func TestCheckSystemdNeedsDaemonReload(t *testing.T) {
	got := checkSystemd(models.SystemdInfo{
		Available:         true,
		NeedsDaemonReload: []string{"nginx.service", "myapp.service"},
	})
	if !insightWithMsg(got, "WARN", "pending reload") {
		t.Errorf("units pending daemon-reload should WARN, got %+v", got)
	}

	clean := checkSystemd(models.SystemdInfo{Available: true})
	if insightWithMsg(clean, "WARN", "pending reload") {
		t.Errorf("no pending-reload units should not WARN, got %+v", clean)
	}
}

// TestCheckSystemdFailedUnitsUnknown guards the false-OK fix: when the
// failed-unit query did not run, the row must say so (INFO unverified) instead
// of staying silently green; when it did run and found nothing, it must stay
// silent (no false-alarm on a genuinely clean host).
func TestCheckSystemdFailedUnitsUnknown(t *testing.T) {
	unknown := checkSystemd(models.SystemdInfo{Available: true, FailedUnitsUnknown: true})
	if !insightWithMsg(unknown, "INFO", "could not list failed units") {
		t.Errorf("unverified failed-unit query should emit INFO, got %+v", unknown)
	}

	clean := checkSystemd(models.SystemdInfo{Available: true})
	if insightWithMsg(clean, "INFO", "could not list failed units") {
		t.Errorf("a successful empty failed-unit query must stay silent, got %+v", clean)
	}
}
