package collectors

import "testing"

// TestISCSICollectorNameStable guards against the per-platform Name() drift that
// shipped "iSCSI" on Linux but "ISCSI" on other platforms. A collector's name is
// keyed on by the render inline dispatch, insight-to-row matching, and the
// drilldown engine, so it must be identical on every platform. This test has no
// build constraint, so it runs against whichever variant compiles (Linux in CI's
// ubuntu runners, the stub on macOS).
func TestISCSICollectorNameStable(t *testing.T) {
	if got := NewISCSICollector().Name(); got != "iSCSI" {
		t.Errorf("ISCSICollector.Name() = %q, want %q (must match on every platform)", got, "iSCSI")
	}
}
