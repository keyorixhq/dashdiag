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
