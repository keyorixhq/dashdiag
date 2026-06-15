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
