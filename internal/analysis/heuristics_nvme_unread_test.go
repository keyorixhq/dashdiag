package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestNVMeUnreadReasonMessages verifies the SMART-unread INFO names the correct
// cause + remediation per SmartUnreadReason, instead of always blaming a missing
// nvme-cli (the false-reason bug found on a SLES 16 arm64 EC2 box where nvme-cli
// was installed but the non-root read needed root).
func TestNVMeUnreadReasonMessages(t *testing.T) {
	cases := []struct {
		name      string
		reason    string
		wantMsg   string
		wantNotIn string
	}{
		{"needs_root names privilege, not a missing tool", "needs_root", "needs root", "nvme-cli not installed"},
		{"tool_absent names the missing package", "tool_absent", "nvme-cli not installed", ""},
		{"empty reason keeps the historical absent message", "", "nvme-cli not installed", ""},
		{"error names a genuine read failure", "error", "nvme smart-log failed", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := models.NVMeInfo{Devices: []models.NVMeDevice{
				{Name: "/dev/nvme0", SmartRead: false, SmartUnreadReason: tc.reason},
			}}
			got := checkNVMe(info)
			if !insightWithMsg(got, "INFO", tc.wantMsg) {
				t.Errorf("expected INFO containing %q, got %+v", tc.wantMsg, got)
			}
			if tc.wantNotIn != "" && insightWithMsg(got, "INFO", tc.wantNotIn) {
				t.Errorf("message must NOT contain %q for reason %q, got %+v", tc.wantNotIn, tc.reason, got)
			}
		})
	}
}

// TestSMARTNoRealTelemetry covers the virtual/cloud-volume detection used by the
// standalone `dsd disk` view (Finding B): an EBS-style PASSED-but-all-sentinel
// SMART must be recognized as "no real telemetry", while a genuine drive (real
// temperature / spare) must not.
func TestSMARTNoRealTelemetry(t *testing.T) {
	// AWS EBS signature: -H PASSED, -A all not-reported sentinels (temp "-" → 0).
	ebs := models.SMARTInfo{Healthy: true}
	if !ebs.NoRealTelemetry() {
		t.Errorf("EBS all-sentinel SMART should be NoRealTelemetry")
	}
	// A real (even brand-new) drive reports a temperature and spare → not virtual.
	realNew := models.SMARTInfo{Healthy: true, Temperature: 31, AvailableSpare: 100}
	if realNew.NoRealTelemetry() {
		t.Errorf("real drive with temp/spare must not be flagged as virtual: %+v", realNew)
	}
	// A worn but real drive likewise has telemetry.
	realWorn := models.SMARTInfo{Healthy: true, Temperature: 45, AvailableSpare: 80, PercentUsed: 60, PowerOnHours: 12000}
	if realWorn.NoRealTelemetry() {
		t.Errorf("real worn drive must not be flagged as virtual: %+v", realWorn)
	}
	// A failing drive (not Healthy) is never "no telemetry" — it has a real verdict.
	failing := models.SMARTInfo{Healthy: false}
	if failing.NoRealTelemetry() {
		t.Errorf("unhealthy drive must not be treated as no-telemetry")
	}
}
