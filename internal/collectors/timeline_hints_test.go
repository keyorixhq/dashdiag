//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestMatchHint guards the substring-match lookup: a message-only match, a
// unit-constrained rule (must match both message and unit substrings), a
// unit-constrained rule with the wrong unit (no match despite the message
// matching), and no match at all.
func TestMatchHint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		unit    string
		message string
		want    bool
	}{
		{
			name:    "message-only match, case-insensitive",
			unit:    "some.service",
			message: "kernel: NO BUFFER SPACE AVAILABLE on veth123",
			want:    true,
		},
		{
			name:    "unit-constrained rule matches both message and unit",
			unit:    "systemd-udevd",
			message: "Failed to get link information for veth123",
			want:    true,
		},
		{
			name:    "unit-constrained rule: message matches but unit does not",
			unit:    "some-other.service",
			message: "Failed to get link information for veth123",
			want:    false,
		},
		{
			name:    "no rule matches",
			unit:    "some.service",
			message: "completely unrelated log line",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := matchHint(tt.unit, tt.message)
			if tt.want && got == nil {
				t.Fatalf("matchHint(%q, %q) = nil, want a hint", tt.unit, tt.message)
			}
			if !tt.want && got != nil {
				t.Fatalf("matchHint(%q, %q) = %+v, want nil", tt.unit, tt.message, got)
			}
		})
	}
}

// TestAnnotateHints guards the events-walking wrapper: each event gets its
// Hint field populated (or left nil) independently based on its own
// unit/message.
func TestAnnotateHints(t *testing.T) {
	t.Parallel()
	events := []models.TimelineEvent{
		{Unit: "some.service", Message: "no buffer space available"},
		{Unit: "some.service", Message: "nothing interesting here"},
	}
	got := annotateHints(events)
	if got[0].Hint == nil {
		t.Error("event 0 should have received a hint")
	}
	if got[1].Hint != nil {
		t.Errorf("event 1 should have no hint, got %+v", got[1].Hint)
	}
}
