package render

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestGuestReportHTML(t *testing.T) {
	blocks := []GuestReportBlock{
		{Title: "Your instance — you can fix these", Issues: []models.Insight{
			{Level: "WARN", Message: "IMDSv1 is enabled <unsafe>", Hints: []string{"to fix: enforce IMDSv2"}},
		}},
		{Title: "AWS-imposed limits — evidence to share with AWS support", Issues: nil},
	}
	out := GuestReportHTML("🟧 EC2 guest — m5.large", "ip-10-0-0-1", "2026-06-29 10:00 UTC", blocks, "warn", "1 issue(s) found")

	for _, want := range []string{
		"<!DOCTYPE html>", "EC2 guest — m5.large", "Your instance — you can fix these",
		"AWS-imposed limits", "to fix: enforce IMDSv2", "nothing flagged", `class="verdict warn"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
	}
	// HTML-escaped (no raw angle brackets from the message leak into markup).
	if strings.Contains(out, "IMDSv1 is enabled <unsafe>") {
		t.Error("message not HTML-escaped")
	}
	if !strings.Contains(out, "&lt;unsafe&gt;") {
		t.Error("expected escaped message")
	}
	// Self-contained: no external script/style/img references.
	if strings.Contains(out, "<script src") || strings.Contains(out, "<link ") || strings.Contains(out, "<img ") {
		t.Error("report must be self-contained (no external assets)")
	}
}

// TestVerdictClass covers all three levels plus the default fallback for an
// unrecognized/empty level, and confirms matching is case-insensitive.
func TestVerdictClass(t *testing.T) {
	t.Parallel()
	cases := []struct{ level, want string }{
		{"crit", "crit"},
		{"CRIT", "crit"},
		{"warn", "warn"},
		{"WARN", "warn"},
		{"ok", "ok"},
		{"", "ok"},
		{"unknown", "ok"},
	}
	for _, tc := range cases {
		if got := verdictClass(tc.level); got != tc.want {
			t.Errorf("verdictClass(%q) = %q, want %q", tc.level, got, tc.want)
		}
	}
}

// TestGuestFooterHTMLBranded covers the branded-footer branch (guestFooterHTML)
// — a company set via SetBrand credits it instead of the default dsd footer.
func TestGuestFooterHTMLBranded(t *testing.T) {
	resetBrand(t)
	SetBrand(Brand{Company: "Acme <script> Co"})
	got := guestFooterHTML()
	if !strings.Contains(got, "Prepared by") || !strings.Contains(got, "powered by") {
		t.Errorf("branded footer missing expected copy, got %q", got)
	}
	if strings.Contains(got, "<script>") {
		t.Errorf("company name must be HTML-escaped in footer, got %q", got)
	}

	SetBrand(Brand{})
	unbranded := guestFooterHTML()
	if strings.Contains(unbranded, "Prepared by") {
		t.Errorf("unbranded footer should not credit a company, got %q", unbranded)
	}
}
