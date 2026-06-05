//go:build linux

package collectors

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Characterization tests for the timeline collector's pure parsers. The timeline
// runs on every `dsd health` (and `dsd timeline`), and these parsers chew on
// format-fragile dmesg/journal/sar output — exactly the surface the BUG-024..035
// parser-hardening wave touched. No external commands or filesystem access.
//
// Timestamps are asserted via TimestampUnix (time.Parse uses UTC when the layout
// carries no zone, and time.Unix(sec,0).Unix()==sec), so results are independent
// of the test host's timezone. The tz-sensitive TimeStr field is not asserted.

func TestParseJournalLine_Levels(t *testing.T) {
	// PRIORITY <= 3 is CRIT (emerg/alert/crit/err), 4+ is WARN.
	tests := []struct {
		name      string
		priority  string
		wantLevel string
	}{
		{"emerg", "0", "CRIT"},
		{"err", "3", "CRIT"},
		{"warning", "4", "WARN"},
		{"notice", "5", "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := `{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"` + tt.priority +
				`","_SYSTEMD_UNIT":"k3s.service","MESSAGE":"something happened"}`
			ev := parseJournalLine(line)
			if ev == nil {
				t.Fatal("expected event, got nil")
			}
			if ev.Level != tt.wantLevel {
				t.Errorf("Level = %q, want %q", ev.Level, tt.wantLevel)
			}
			if ev.TimestampUnix != 1_700_000_000 {
				t.Errorf("TimestampUnix = %d, want 1700000000", ev.TimestampUnix)
			}
			if ev.Source != "journal" {
				t.Errorf("Source = %q, want journal", ev.Source)
			}
			if ev.Unit != "k3s" { // .service suffix stripped
				t.Errorf("Unit = %q, want k3s", ev.Unit)
			}
		})
	}
}

func TestParseJournalLine_UnitFallback(t *testing.T) {
	// Unit precedence: _SYSTEMD_UNIT -> SYSLOG_IDENTIFIER -> _COMM.
	tests := []struct {
		name string
		json string
		want string
	}{
		{"systemd unit wins", `{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"4","_SYSTEMD_UNIT":"nginx.service","SYSLOG_IDENTIFIER":"nginx","_COMM":"nginx","MESSAGE":"m"}`, "nginx"},
		{"syslog id fallback", `{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"4","SYSLOG_IDENTIFIER":"kernel","MESSAGE":"m"}`, "kernel"},
		{"comm fallback", `{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"4","_COMM":"dockerd","MESSAGE":"m"}`, "dockerd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := parseJournalLine(tt.json)
			if ev == nil {
				t.Fatal("expected event, got nil")
			}
			if ev.Unit != tt.want {
				t.Errorf("Unit = %q, want %q", ev.Unit, tt.want)
			}
		})
	}
}

func TestParseJournalLine_NoiseAndInvalid(t *testing.T) {
	// Noisy units/messages and malformed JSON return nil.
	noise := []string{
		`{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"4","_SYSTEMD_UNIT":"sshd.service","MESSAGE":"accepted"}`,
		`{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"4","_SYSTEMD_UNIT":"app.service","MESSAGE":"pam_unix(sudo) session opened"}`,
		`{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"4","_SYSTEMD_UNIT":"libpod-abc123.scope","MESSAGE":"m"}`,
		`not valid json`,
		``,
	}
	for _, line := range noise {
		if ev := parseJournalLine(line); ev != nil {
			t.Errorf("parseJournalLine(%q) = %+v, want nil", line, ev)
		}
	}
}

func TestParseJournalLine_MessageTruncation(t *testing.T) {
	long := strings.Repeat("x", 200)
	line := `{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"4","_SYSTEMD_UNIT":"app.service","MESSAGE":"` + long + `"}`
	ev := parseJournalLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if !strings.HasSuffix(ev.Message, "…") {
		t.Errorf("long message should be truncated with ellipsis, got %q", ev.Message)
	}
	// 140 runes + the ellipsis rune.
	if got := len([]rune(ev.Message)); got != 141 {
		t.Errorf("truncated message rune length = %d, want 141", got)
	}
}

func TestParseDmesgLine(t *testing.T) {
	epoch := time.Unix(0, 0) // everything is after epoch
	tests := []struct {
		name      string
		line      string
		wantNil   bool
		wantLevel string
		wantUnit  string
	}{
		{
			name:      "ext4 error is CRIT",
			line:      "[Wed Jun  4 10:30:00 2025] EXT4-fs (sda1): error reading block",
			wantLevel: "CRIT", wantUnit: "EXT4-fs",
		},
		{
			name:      "two-digit day, warn",
			line:      "[Wed Jun 04 10:30:00 2025] usb 1-1: device descriptor read",
			wantLevel: "WARN", wantUnit: "usb 1-1",
		},
		{
			// GAP: the CRIT keyword list matches literal "oom", but the kernel OOM
			// killer prints "Out of memory: Killed process ...". So a genuine OOM-kill
			// line is classified WARN here, not CRIT. Pinned; worth a follow-up.
			name:      "kernel OOM line is only WARN (keyword gap)",
			line:      "[Wed Jun  4 10:30:00 2025] Out of memory: Killed process 123",
			wantLevel: "WARN",
		},
		{
			name:      "explicit oom-killer mention is CRIT",
			line:      "[Wed Jun  4 10:30:00 2025] oom-killer: gfp_mask=0x100",
			wantLevel: "CRIT",
		},
		{"no bracket", "kernel: just a message", true, "", ""},
		{"no closing bracket", "[Wed Jun  4 10:30:00 2025 missing", true, "", ""},
		{"bad timestamp", "[not a timestamp] some message", true, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := parseDmesgLine(tt.line, epoch)
			if tt.wantNil {
				if ev != nil {
					t.Fatalf("expected nil, got %+v", ev)
				}
				return
			}
			if ev == nil {
				t.Fatal("expected event, got nil")
			}
			if ev.Level != tt.wantLevel {
				t.Errorf("Level = %q, want %q", ev.Level, tt.wantLevel)
			}
			if tt.wantUnit != "" && ev.Unit != tt.wantUnit {
				t.Errorf("Unit = %q, want %q", ev.Unit, tt.wantUnit)
			}
			if ev.Source != "dmesg" {
				t.Errorf("Source = %q, want dmesg", ev.Source)
			}
		})
	}
}

func TestParseDmesgLine_BeforeSince(t *testing.T) {
	// Events older than the window are dropped.
	future := time.Unix(4_000_000_000, 0) // year 2096
	ev := parseDmesgLine("[Wed Jun  4 10:30:00 2025] EXT4-fs: error", future)
	if ev != nil {
		t.Errorf("event before 'since' should be dropped, got %+v", ev)
	}
}

func TestExtractKernelSubsystem(t *testing.T) {
	tests := []struct {
		msg  string
		want string
	}{
		{"EXT4-fs (sda1): warning on mount", "EXT4-fs"},    // hyphenated before paren
		{"CPU0: Core temperature above threshold", "CPU0"}, // all-caps before colon
		// QUIRK: a lowercase subsystem fails the all-caps/hyphen heuristic and falls
		// through to Fields()[0], which keeps the trailing colon ("audit:" not "audit").
		{"audit: type=1400 denied", "audit:"},
		{"EXT4-fs no punctuation here", "EXT4-fs"}, // no :/( -> first field
		{"x", "kernel"}, // too short -> default
		{"", "kernel"},  // empty -> default
	}
	for _, tt := range tests {
		if got := extractKernelSubsystem(tt.msg); got != tt.want {
			t.Errorf("extractKernelSubsystem(%q) = %q, want %q", tt.msg, got, tt.want)
		}
	}
}

func TestParseSarLoadLine(t *testing.T) {
	today := "2026-06-05"
	tests := []struct {
		name    string
		line    string
		wantNil bool
		l1      float64
		l5      float64
		l15     float64
	}{
		{
			name: "valid sar -q line",
			line: "10:30:01        0       225      0.08      0.06      0.05         0",
			l1:   0.08, l5: 0.06, l15: 0.05,
		},
		{"too few fields", "10:30:01 0 225 0.08", true, 0, 0, 0},
		{"summary line not a time", "Average:        0       225      0.08      0.06      0.05         0", true, 0, 0, 0},
		{"non-float load", "10:30:01        0       225      x      y      z         0", true, 0, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ls := parseSarLoadLine(tt.line, today)
			if tt.wantNil {
				if ls != nil {
					t.Fatalf("expected nil, got %+v", ls)
				}
				return
			}
			if ls == nil {
				t.Fatal("expected LoadSpike, got nil")
			}
			if ls.Load1 != tt.l1 || ls.Load5 != tt.l5 || ls.Load15 != tt.l15 {
				t.Errorf("loads = %v/%v/%v, want %v/%v/%v", ls.Load1, ls.Load5, ls.Load15, tt.l1, tt.l5, tt.l15)
			}
			if ls.TimeStr != "10:30:01" {
				t.Errorf("TimeStr = %q, want 10:30:01", ls.TimeStr)
			}
		})
	}
}

func TestStripServiceSuffix(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"k3s.service", "k3s"},
		{"user-1000.slice", "user-1000"},
		{"session-3.scope", "session-3"},
		{"plain", "plain"},
	}
	for _, tt := range tests {
		if got := stripServiceSuffix(tt.in); got != tt.want {
			t.Errorf("stripServiceSuffix(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsNoisyJournalEntry(t *testing.T) {
	tests := []struct {
		unit string
		msg  string
		want bool
	}{
		{"sshd.service", "accepted publickey", true},
		{"app.service", "pam_unix(sudo) opened", true},
		{"libpod-abc.scope", "container exited", true},
		{"audit", "type=1400", true},
		{"nginx.service", "upstream timed out", false},
		{"k3s.service", "node ready", false},
	}
	for _, tt := range tests {
		if got := isNoisyJournalEntry(tt.unit, tt.msg); got != tt.want {
			t.Errorf("isNoisyJournalEntry(%q, %q) = %v, want %v", tt.unit, tt.msg, got, tt.want)
		}
	}
}

func TestDeduplicateEvents(t *testing.T) {
	base := int64(1_700_000_000) // some minute boundary-ish
	events := []models.TimelineEvent{
		{TimestampUnix: base, Level: "CRIT", Unit: "k3s", Message: "node not ready"},
		{TimestampUnix: base + 10, Level: "CRIT", Unit: "k3s", Message: "node not ready"},  // same minute -> merged
		{TimestampUnix: base + 120, Level: "CRIT", Unit: "k3s", Message: "node not ready"}, // +2min -> separate
		{TimestampUnix: base, Level: "WARN", Unit: "k3s", Message: "node not ready"},       // different level -> separate
	}
	got := deduplicateEvents(events)
	if len(got) != 3 {
		t.Fatalf("got %d deduplicated events, want 3: %+v", len(got), got)
	}
	if got[0].Count != 2 {
		t.Errorf("first group Count = %d, want 2 (two same-minute CRITs)", got[0].Count)
	}
}
