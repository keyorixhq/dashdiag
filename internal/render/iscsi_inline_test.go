package render

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// inlineISCSI must not label a failed/reconnecting session as "logged in" — that
// contradicts the CRIT verdict checkISCSI raises on FailedCount>0 (the sibling of
// the inlineHBA online/total fix).
func TestInlineISCSI_FailedSessionNotAllLoggedIn(t *testing.T) {
	mixed := &models.ISCSIInfo{Available: true, Sessions: []models.ISCSISession{
		{State: "LOGGED_IN"}, {State: "FAILED"},
	}}
	got := inlineISCSI(mixed)
	if !strings.Contains(got, "1/2 logged in") {
		t.Errorf("a failed session must render as N/total, got %q", got)
	}

	allUp := &models.ISCSIInfo{Available: true, Sessions: []models.ISCSISession{
		{State: "LOGGED_IN"}, {State: "LOGGED_IN"},
	}}
	if got := inlineISCSI(allUp); !strings.Contains(got, "2 session(s)  logged in") {
		t.Errorf("all-logged-in keeps the original phrasing, got %q", got)
	}
}
