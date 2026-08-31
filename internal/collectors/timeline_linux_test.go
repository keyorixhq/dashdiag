//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// Characterization tests for the timeline collector's pure parsers. The timeline
// runs on every `dsd health` (and `dsd timeline`), and these parsers chew on
// format-fragile dmesg/journal/sar output — exactly the surface the BUG-024..035
// parser-hardening wave touched. No external commands or filesystem access.
//
// Timestamps are asserted via TimestampUnix, an absolute instant, so results
// don't depend on the test process's own timezone (unlike the tz-sensitive
// TimeStr display field, not asserted here). This is now true BECAUSE the
// dmesg parser requires an explicit offset in its input (--time-format=iso)
// rather than because Go defaults an offset-less layout to UTC — that
// default was the bug (C3): it silently treated the LOCAL time dmesg -T
// printed as if it were already UTC, correct only by coincidence on a
// UTC-local host. See TestParseDmesgLine_ChronologicalInterleavingUnderNonUTCTZ
// (timeline_linux_tz_test.go) for the direct demonstration.

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
		`{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"4","_SYSTEMD_UNIT":"libpod-abc123.scope","MESSAGE":"m"}`,
		`not valid json`,
		``,
	}
	for _, line := range noise {
		if ev := parseJournalLine(line); ev != nil {
			t.Errorf("parseJournalLine(%q) = %+v, want nil", line, ev)
		}
	}

	// internal-collectors-33-04 regression: a genuinely unrelated unit whose
	// message merely mentions a noisy substring ("pam_unix(sudo") must NOT be
	// dropped — only unit IDENTITY drives suppression now, never message text.
	line := `{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"4","_SYSTEMD_UNIT":"app.service","MESSAGE":"pam_unix(sudo) session opened"}`
	ev := parseJournalLine(line)
	if ev == nil {
		t.Fatalf("parseJournalLine(%q) = nil, want a surfaced event (unit is not noisy, only msg mentions a noisy substring)", line)
	}
	if ev.Unit != "app" {
		t.Errorf("Unit = %q, want %q", ev.Unit, "app")
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

// A missing or unparseable PRIORITY must NOT default to CRIT — that would inflate
// the timeline's CRIT count and verdict. The journalctl filter already bounds
// these to <= warning, so the safe default is WARN.
func TestParseJournalLine_PriorityDefaultsToWarn(t *testing.T) {
	for _, prio := range []string{"", "  ", "notanumber"} {
		line := `{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"` + prio +
			`","_SYSTEMD_UNIT":"app.service","MESSAGE":"something"}`
		ev := parseJournalLine(line)
		if ev == nil {
			t.Fatalf("priority %q: expected event, got nil", prio)
		}
		if ev.Level != "WARN" {
			t.Errorf("priority %q: Level = %q, want WARN (must not default to CRIT)", prio, ev.Level)
		}
	}
}

// journald renders a MESSAGE with non-UTF-8 content as a JSON array of byte
// integers. The event must still be parsed (decoded to text), not silently
// dropped because the field isn't a JSON string.
func TestParseJournalLine_MessageAsByteArray(t *testing.T) {
	// "hi" as a byte array, plus a high byte (0xff) that isn't valid UTF-8.
	line := `{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"3","_SYSTEMD_UNIT":"app.service","MESSAGE":[104,105,255]}`
	ev := parseJournalLine(line)
	if ev == nil {
		t.Fatal("event with array MESSAGE must not be dropped")
	}
	if !strings.HasPrefix(ev.Message, "hi") {
		t.Errorf("decoded message = %q, want prefix %q", ev.Message, "hi")
	}
}

// Truncation must cut on a rune boundary so it never emits invalid UTF-8.
func TestParseJournalLine_TruncationIsRuneSafe(t *testing.T) {
	long := strings.Repeat("世", 200) // 3 bytes each — byte-slicing would split a rune
	line := `{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"4","_SYSTEMD_UNIT":"app.service","MESSAGE":"` + long + `"}`
	ev := parseJournalLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if !utf8.ValidString(ev.Message) {
		t.Errorf("truncated message is not valid UTF-8: %q", ev.Message)
	}
	if got := len([]rune(ev.Message)); got != 141 { // 140 runes + ellipsis
		t.Errorf("rune length = %d, want 141", got)
	}
}

// TestDecodeJournalMessage covers decodeJournalMessage's branches directly:
// empty input, a plain JSON string, the byte-array fallback, and the final
// "neither shape parses" fallback (both Unmarshal attempts fail).
func TestDecodeJournalMessage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  json.RawMessage
		want string
	}{
		{"empty raw message", nil, ""},
		{"plain JSON string", json.RawMessage(`"hello"`), "hello"},
		{"byte array form", json.RawMessage(`[104,105]`), "hi"},
		{"neither string nor byte array", json.RawMessage(`{"nested":"object"}`), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := decodeJournalMessage(tt.raw); got != tt.want {
				t.Errorf("decodeJournalMessage(%s) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// TestDecodeJournalMessage_ByteArrayCapped is the regression test for
// internal-collectors-33-01: a byte-array MESSAGE field far larger than any
// truncated display could ever need must not allocate proportionally to its
// claimed length — decodeJournalMessage must stop at maxJournalByteArrayLen
// instead of building a []int/[]byte sized to the whole input.
func TestDecodeJournalMessage_ByteArrayCapped(t *testing.T) {
	t.Parallel()
	const n = 200_000 // far past the 4096-element cap
	var b strings.Builder
	b.WriteByte('[')
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa('a' + i%26))
	}
	b.WriteByte(']')

	got := decodeJournalMessage(json.RawMessage(b.String()))
	if len(got) != 4096 {
		t.Errorf("decodeJournalMessage returned %d bytes, want exactly the 4096-element cap", len(got))
	}
	if got[:2] != "ab" {
		t.Errorf("expected the capped result to start with the real leading bytes, got %q", got[:10])
	}
}

// C3: dmesg lines now come in the primary `-x --time-format=iso` shape
// ("kern  :err   : 2025-06-04T10:30:00.000000+0000 message") — an explicit
// UTC offset dmesg computes itself, correct regardless of this test
// process's own timezone — rather than the old `-T` ctime-bracket shape
// ("kern  :err   : [Wed Jun  4 10:30:00 2025] message"), which carried no
// offset at all and silently parsed as UTC regardless of what the text
// actually represented. See TestParseDmesgLine_ChronologicalInterleavingUnderNonUTCTZ
// (timeline_linux_tz_test.go) for the direct demonstration of that bug and
// TestParseDmesgLine_MonotonicFallback below for the busybox/no-flags shape.
func TestParseDmesgLine(t *testing.T) {
	epoch := time.Unix(0, 0)    // everything is after epoch
	bootTime := time.Unix(0, 0) // unused by the ISO path this test exercises
	tests := []struct {
		name      string
		line      string
		wantNil   bool
		wantLevel string
		wantUnit  string
	}{
		{
			// kernel err level → CRIT (the `dmesg -x` decoded prefix drives severity).
			name:      "ext4 error (err level) is CRIT",
			line:      "kern  :err   : 2025-06-04T10:30:00.000000+0000 EXT4-fs (sda1): error reading block",
			wantLevel: "CRIT", wantUnit: "EXT4-fs",
		},
		{
			// The bug fix: a warn-level message containing "failed"/"error" must stay
			// WARN, not get keyword-escalated to CRIT (regulatory.db is benign noise).
			name:      "warn-level 'failed' stays WARN (not keyword-escalated)",
			line:      "kern  :warn  : 2025-06-04T10:30:00.000000+0000 regulatory: Direct firmware load for regulatory.db failed with error -2",
			wantLevel: "WARN",
		},
		{
			// Benign-by-platform err: arm64/ACPI cloud guests log this at err on every
			// boot (no device-tree). Must downgrade to INFO, not a timeline CRIT.
			name:      "arm64 of_root PCI err is benign → INFO",
			line:      "kern  :err   : 2025-06-04T10:30:00.000000+0000 PCI: OF: of_root node is NULL, cannot create PCI host bridge node",
			wantLevel: "INFO",
		},
		{
			// Benign-by-platform err: VMs/boards log the PIIX4 SMBus base-address
			// message at err on every boot (unset by firmware). Downgrade to INFO.
			name:      "PIIX4 SMBus uninitialized err is benign → INFO",
			line:      "kern  :err   : 2025-06-04T10:30:00.000000+0000 piix4_smbus 0000:00:07.3: SMBus base address uninitialized - upgrade BIOS or use force_addr=0xaddr",
			wantLevel: "INFO",
		},
		{
			// Benign-by-environment err: systemd-nsresourced logs this at err in any
			// container (no securityfs mount) and on minimal hosts; BPF LSM is optional.
			name:      "bpf-lsm securityfs err is benign → INFO",
			line:      "kern  :err   : 2025-06-04T10:30:00.000000+0000 systemd-nsresourced[123]: bpf-lsm support not available, as securityfs is not mounted.",
			wantLevel: "INFO",
		},
		{
			// Guard: a real PCI err (not on the benign list) still CRITs.
			name:      "real PCI err stays CRIT",
			line:      "kern  :err   : 2025-06-04T10:30:00.000000+0000 PCI: Fatal: bus configuration error",
			wantLevel: "CRIT",
		},
		{
			// internal-collectors-33-02: a message containing a genuine catastrophe
			// keyword ("panic") ALONGSIDE a benign-substring match must stay CRIT —
			// the catastrophe-keyword escalation must win over the benign downgrade,
			// not the other way around, even though isBenignKernelErr also matches.
			name:      "catastrophe keyword co-occurring with a benign substring stays CRIT",
			line:      "kern  :warn  : 2025-06-04T10:30:00.000000+0000 kernel panic - smbus base address uninitialized triggered watchdog reset",
			wantLevel: "CRIT",
		},
		{
			// A nonzero UTC offset (not just +0000) must parse correctly — the
			// whole point of the fix (C3).
			name:      "non-UTC offset in the timestamp itself",
			line:      "kern  :warn  : 2025-06-04T03:30:00.000000-0700 usb 1-1: device descriptor read",
			wantLevel: "WARN", wantUnit: "usb 1-1",
		},
		{
			// Catastrophe keyword overrides upward even at warn level: the OOM killer
			// header has no literal "oom" token, so "out of memory" catches it.
			name:      "kernel OOM line is CRIT even at warn level",
			line:      "kern  :warn  : 2025-06-04T10:30:00.000000+0000 Out of memory: Killed process 123",
			wantLevel: "CRIT",
		},
		{
			name:      "explicit oom-killer mention is CRIT",
			line:      "kern  :warn  : 2025-06-04T10:30:00.000000+0000 oom-killer: gfp_mask=0x100",
			wantLevel: "CRIT",
		},
		{"no facility:level separator", "kernel just a message with no colon-space", true, "", ""},
		{"malformed timestamp", "kern  :err   : not-a-timestamp some message", true, "", ""},
		{"empty line", "", true, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := parseDmesgLine(tt.line, epoch, bootTime)
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

// TestParseDmesgLine_MonotonicFallback covers the fallback bare-`dmesg`
// shape (busybox, or a util-linux predating --time-format=iso): a raw
// monotonic offset with no facility:level decoding, anchored to bootTime.
func TestParseDmesgLine_MonotonicFallback(t *testing.T) {
	epoch := time.Unix(0, 0)
	bootTime := time.Date(2025, 6, 4, 8, 0, 0, 0, time.UTC) // host booted 08:00 UTC

	t.Run("offset anchored to boot time", func(t *testing.T) {
		// 9000s after boot (08:00 UTC) = 10:30:00 UTC.
		ev := parseDmesgLine("[ 9000.123456] EXT4-fs (sda1): error reading block", epoch, bootTime)
		if ev == nil {
			t.Fatal("expected event, got nil")
		}
		want := time.Date(2025, 6, 4, 10, 30, 0, 0, time.UTC).Unix()
		if ev.TimestampUnix != want {
			t.Errorf("TimestampUnix = %d, want %d", ev.TimestampUnix, want)
		}
		// No facility:level decoding available in this shape — severity
		// falls back to WARN (no catastrophe keyword present here).
		if ev.Level != "WARN" {
			t.Errorf("Level = %q, want WARN (no -x decoding in the fallback shape)", ev.Level)
		}
	})

	t.Run("catastrophe keyword still escalates with no facility:level available", func(t *testing.T) {
		ev := parseDmesgLine("[ 9000.123456] Out of memory: Killed process 123", epoch, bootTime)
		if ev == nil || ev.Level != "CRIT" {
			t.Errorf("got %+v, want a CRIT event", ev)
		}
	})

	t.Run("malformed offset is nil", func(t *testing.T) {
		if ev := parseDmesgLine("[not-a-number] message", epoch, bootTime); ev != nil {
			t.Errorf("expected nil, got %+v", ev)
		}
	})

	t.Run("no closing bracket is nil", func(t *testing.T) {
		if ev := parseDmesgLine("[9000.123456 missing bracket", epoch, bootTime); ev != nil {
			t.Errorf("expected nil, got %+v", ev)
		}
	})
}

func TestParseDmesgLine_BeforeSince(t *testing.T) {
	// Events older than the window are dropped — both shapes.
	future := time.Unix(4_000_000_000, 0) // year 2096
	bootTime := time.Unix(0, 0)

	t.Run("ISO shape", func(t *testing.T) {
		ev := parseDmesgLine("kern  :err   : 2025-06-04T10:30:00.000000+0000 EXT4-fs: error", future, bootTime)
		if ev != nil {
			t.Errorf("event before 'since' should be dropped, got %+v", ev)
		}
	})

	t.Run("monotonic fallback shape", func(t *testing.T) {
		ev := parseDmesgLine("[ 9000.123456] EXT4-fs: error", future, bootTime)
		if ev != nil {
			t.Errorf("event before 'since' should be dropped, got %+v", ev)
		}
	})
}

func TestExtractKernelSubsystem(t *testing.T) {
	tests := []struct {
		msg  string
		want string
	}{
		{"EXT4-fs (sda1): warning on mount", "EXT4-fs"},    // hyphenated before paren
		{"CPU0: Core temperature above threshold", "CPU0"}, // all-caps before colon
		{"audit: type=1400 denied", "audit"},               // lowercase before colon -> colon stripped
		{"EXT4-fs no punctuation here", "EXT4-fs"},         // no :/( -> first field
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
		name string
		unit string
		msg  string
		want bool
	}{
		{"sshd unit is noise", "sshd.service", "accepted publickey", true},
		{"auditd unit is noise", "auditd.service", "type=1400", true},
		{"bare audit syslog id is noise", "audit", "type=1400", true},
		{"setroubleshoot unit is noise", "setroubleshootd", "SELinux is preventing", true},
		{"sudo syslog id is noise", "sudo", "session opened for user root", true},
		{"libpod scope unit is noise", "libpod-abc.scope", "container exited", true},
		{"libpod message prefix is noise", "cron.service", "libpod-abc exited", true},
		{"unrelated unit is not noise", "nginx.service", "upstream timed out", false},
		{"healthy unit is not noise", "k3s.service", "node ready", false},
		// internal-collectors-33-04 regression: a genuinely unrelated CRIT/WARN
		// must never be discarded merely because its free-text message happens
		// to contain a noisy substring. Before the fix, msg was matched against
		// the same noisy list as unit, so this entry (unit "app.service") was
		// silently dropped just because its message mentions "pam_unix(sudo".
		{"unrelated unit mentioning pam_unix in msg is not noise", "app.service", "pam_unix(sudo) opened", false},
		{"unrelated unit mentioning sudo in msg is not noise", "app.service", "user ran sudo to escalate", false},
		{"unrelated unit mentioning audit in msg is not noise", "app.service", "failed audit of config", false},
		{"unrelated unit mentioning sshd in msg is not noise", "app.service", "sshd restarted unexpectedly", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isNoisyJournalEntry(tt.unit, tt.msg); got != tt.want {
				t.Errorf("isNoisyJournalEntry(%q, %q) = %v, want %v", tt.unit, tt.msg, got, tt.want)
			}
		})
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

// ── constructor / interface methods ──────────────────────────────────────────

func TestNewTimelineCollector(t *testing.T) {
	tests := []struct {
		hours int
		want  int
	}{
		{0, 1},
		{-5, 1},
		{3, 3},
	}
	for _, tt := range tests {
		c := NewTimelineCollector(tt.hours)
		if c.WindowHours != tt.want {
			t.Errorf("NewTimelineCollector(%d).WindowHours = %d, want %d", tt.hours, c.WindowHours, tt.want)
		}
	}
}

func TestTimelineCollector_NameAndTimeout(t *testing.T) {
	c := NewTimelineCollector(1)
	if c.Name() != "Timeline" {
		t.Errorf("Name() = %q, want Timeline", c.Name())
	}
	if c.Timeout() != 20*time.Second {
		t.Errorf("Timeout() = %v, want 20s", c.Timeout())
	}
}

// ── Collect (integration) ────────────────────────────────────────────────────

// Both journalctl and dmesg are left unseeded so Replay.Run returns
// ErrNotRecorded for either regardless of the dynamic --since args Collect
// builds from time.Now() — this exercises the SourcesUnavailable branch
// deterministically without racing against Collect's internal clock read.
func TestTimelineCollector_Collect_SourcesUnavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/loadavg", []byte("0.10 0.20 0.30 1/200 999\n"))
		// sar is also left unseeded -> collectSarLoad returns nil, current load still included.
	})
	c := NewTimelineCollector(2)
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := result.(*models.TimelineInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.TimelineInfo", result)
	}
	if !info.SourcesUnavailable {
		t.Error("expected SourcesUnavailable=true when both journalctl and dmesg fail")
	}
	if info.WindowHours != 2 {
		t.Errorf("WindowHours = %d, want 2", info.WindowHours)
	}
	if len(info.Events) != 0 {
		t.Errorf("Events = %+v, want empty", info.Events)
	}
	if len(info.LoadSpikes) != 1 {
		t.Errorf("LoadSpikes = %+v, want 1 entry (current load)", info.LoadSpikes)
	}
	if info.CritCount != 0 || info.WarnCount != 0 {
		t.Errorf("CritCount/WarnCount = %d/%d, want 0/0", info.CritCount, info.WarnCount)
	}
}

// TestTimelineCollector_Collect_TallyAndSort covers the branches
// TestTimelineCollector_Collect_SourcesUnavailable's empty-events run cannot
// reach: the sort.Slice comparator actually invoked across >1 event, and the
// CRIT/WARN tally loop's switch-case bodies (both need at least one real
// event of each level to execute).
func TestTimelineCollector_Collect_TallyAndSort(t *testing.T) {
	since := time.Now().Add(-2 * time.Hour)
	// Two journal lines deliberately OUT of chronological order in the raw
	// feed, so the sort.Slice comparator has real work to do. PRIORITY 2=crit
	// (-> CRIT), PRIORITY 4=warning (-> WARN).
	lines := strings.Join([]string{
		`{"__REALTIME_TIMESTAMP":"1700000300000000","PRIORITY":"4","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"upstream timeout"}`,
		`{"__REALTIME_TIMESTAMP":"1700000100000000","PRIORITY":"2","_SYSTEMD_UNIT":"k3s.service","MESSAGE":"node not ready"}`,
	}, "\n")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/loadavg", []byte("0.10 0.20 0.30 1/200 999\n"))
		b.PutCmd("journalctl", []string{"--no-pager", "--output=json",
			"--since", since.Format("2006-01-02 15:04:05"), "--priority=warning"}, lines, 0)
		b.PutCmdNotFound("dmesg", []string{"-x", "--time-format", "iso", "--level=err,warn,crit,emerg,alert"})
		b.PutCmdNotFound("dmesg", nil)
	})
	c := NewTimelineCollector(2)
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := result.(*models.TimelineInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.TimelineInfo", result)
	}
	if len(info.Events) != 2 {
		t.Fatalf("expected 2 events, got %+v", info.Events)
	}
	// Sorted chronologically: the 1700000100 (k3s, CRIT) event must come first.
	// (parseJournalLine stores the unit with its .service suffix stripped.)
	if info.Events[0].Unit != "k3s" {
		t.Errorf("Events[0].Unit = %q, want k3s (chronological sort)", info.Events[0].Unit)
	}
	if info.CritCount != 1 || info.WarnCount != 1 {
		t.Errorf("CritCount/WarnCount = %d/%d, want 1/1", info.CritCount, info.WarnCount)
	}
}

// TestTimelineCollector_Collect_CapAt200 covers the "len(info.Events) > 200 ->
// filterTopEvents" truncation branch inside Collect: 250 distinct (never
// deduplicated) warning events must be capped down to 200 in the final
// result.
func TestTimelineCollector_Collect_CapAt200(t *testing.T) {
	since := time.Now().Add(-2 * time.Hour)
	tsUsec := int64(1_700_000_000_000_000)
	lines := make([]string, 0, 250)
	for i := range 250 {
		// Distinct message per line defeats deduplicateEvents' msgPrefix key,
		// so all 250 survive dedup and reach the 200-cap truncation.
		lines = append(lines, fmt.Sprintf(
			`{"__REALTIME_TIMESTAMP":"%d","PRIORITY":"4","_SYSTEMD_UNIT":"app.service","MESSAGE":"distinct message number %d"}`,
			tsUsec, i))
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/loadavg", []byte("0.10 0.20 0.30 1/200 999\n"))
		b.PutCmd("journalctl", []string{"--no-pager", "--output=json",
			"--since", since.Format("2006-01-02 15:04:05"), "--priority=warning"}, strings.Join(lines, "\n"), 0)
		b.PutCmdNotFound("dmesg", []string{"-x", "--time-format", "iso", "--level=err,warn,crit,emerg,alert"})
		b.PutCmdNotFound("dmesg", nil)
	})
	c := NewTimelineCollector(2)
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := result.(*models.TimelineInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.TimelineInfo", result)
	}
	if len(info.Events) != 200 {
		t.Errorf("len(Events) = %d, want 200 (capped from 250)", len(info.Events))
	}
}

// ── collectJournalEvents ──────────────────────────────────────────────────────

func TestCollectJournalEvents(t *testing.T) {
	since := time.Unix(1_700_000_000, 0).UTC()
	sinceStr := since.Format("2006-01-02 15:04:05")
	lines := strings.Join([]string{
		`{"__REALTIME_TIMESTAMP":"1700000100000000","PRIORITY":"3","_SYSTEMD_UNIT":"k3s.service","MESSAGE":"node not ready"}`,
		`{"__REALTIME_TIMESTAMP":"1700000200000000","PRIORITY":"4","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"upstream timeout"}`,
		`{"__REALTIME_TIMESTAMP":"1700000300000000","PRIORITY":"4","_SYSTEMD_UNIT":"sshd.service","MESSAGE":"accepted publickey"}`, // noisy, filtered
	}, "\n")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"--no-pager", "--output=json", "--since", sinceStr, "--priority=warning"}, lines, 0)
	})
	events, err := collectJournalEvents(context.Background(), since)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (noisy sshd line filtered): %+v", len(events), events)
	}
}

func TestCollectJournalEvents_CommandUnavailable(t *testing.T) {
	since := time.Unix(1_700_000_000, 0).UTC()
	withFixtureSource(t, func(b *source.Bundle) {})
	events, err := collectJournalEvents(context.Background(), since)
	if err == nil {
		t.Fatal("expected error when journalctl is unavailable")
	}
	if events != nil {
		t.Errorf("expected nil events on error, got %+v", events)
	}
}

func TestCollectJournalEvents_CapAt500(t *testing.T) {
	since := time.Unix(1_700_000_000, 0).UTC()
	sinceStr := since.Format("2006-01-02 15:04:05")
	lines := make([]string, 0, 600)
	for range 600 {
		lines = append(lines, `{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"4","_SYSTEMD_UNIT":"app.service","MESSAGE":"m"}`)
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"--no-pager", "--output=json", "--since", sinceStr, "--priority=warning"}, strings.Join(lines, "\n"), 0)
	})
	events, err := collectJournalEvents(context.Background(), since)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 500 {
		t.Errorf("got %d events, want 500 (capped)", len(events))
	}
}

// ── collectDmesgEvents ────────────────────────────────────────────────────────

func TestCollectDmesgEvents(t *testing.T) {
	since := time.Unix(0, 0)
	out := strings.Join([]string{
		"kern  :err   : 2025-06-04T10:30:00.000000+0000 EXT4-fs (sda1): error reading block",
		"kern  :warn  : 2025-06-04T10:30:00.000000+0000 usb 1-1: device descriptor read",
	}, "\n")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dmesg", []string{"-x", "--time-format", "iso", "--level=err,warn,crit,emerg,alert"}, out, 0)
	})
	events, err := collectDmesgEvents(context.Background(), since)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(events), events)
	}
}

// TestCollectDmesgEvents_PlainFallback is C3's stated fallback: a dmesg
// build supporting neither -x nor --time-format (busybox — Alpine and other
// non-systemd hosts) errors on the primary invocation; collectDmesgEvents
// must retry with the bare, always-supported form and still surface real
// events, anchored to bootTime via /proc/uptime rather than dropped.
func TestCollectDmesgEvents_PlainFallback(t *testing.T) {
	since := time.Unix(0, 0)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/uptime", []byte("9000.00 8000.00\n")) // boot 9000s ago
		b.PutCmdNotFound("dmesg", []string{"-x", "--time-format", "iso", "--level=err,warn,crit,emerg,alert"})
		b.PutCmd("dmesg", nil, "[ 100.000000] EXT4-fs (sda1): error reading block\n", 0)
	})
	events, err := collectDmesgEvents(context.Background(), since)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	if events[0].Source != "dmesg" || events[0].Unit != "EXT4-fs" {
		t.Errorf("got %+v, want an EXT4-fs dmesg event", events[0])
	}
}

func TestCollectDmesgEvents_CommandUnavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	events, err := collectDmesgEvents(context.Background(), time.Unix(0, 0))
	if err == nil {
		t.Fatal("expected error when dmesg is unavailable")
	}
	if events != nil {
		t.Errorf("expected nil events on error, got %+v", events)
	}
}

// ── load spikes ───────────────────────────────────────────────────────────────

func TestCurrentLoadSpike(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/loadavg", []byte("0.52 0.58 0.59 2/456 12345\n"))
	})
	spike := currentLoadSpike()
	if spike == nil {
		t.Fatal("expected a load spike, got nil")
	}
	if spike.Load1 != 0.52 || spike.Load5 != 0.58 || spike.Load15 != 0.59 {
		t.Errorf("loads = %v/%v/%v, want 0.52/0.58/0.59", spike.Load1, spike.Load5, spike.Load15)
	}
}

func TestCurrentLoadSpike_FileMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if spike := currentLoadSpike(); spike != nil {
		t.Errorf("expected nil when /proc/loadavg is unreadable, got %+v", spike)
	}
}

func TestCurrentLoadSpike_TooFewFields(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/loadavg", []byte("0.52 0.58\n"))
	})
	if spike := currentLoadSpike(); spike != nil {
		t.Errorf("expected nil with too few fields, got %+v", spike)
	}
}

func TestCollectSarLoad(t *testing.T) {
	since := time.Unix(1_700_000_000, 0).UTC()
	out := "10:30:01        0       225      0.08      0.06      0.05         0\n"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("sar", []string{"-q", "-s", since.Format("15:04:00")}, out, 0)
	})
	spikes := collectSarLoad(context.Background(), since)
	if len(spikes) != 1 {
		t.Fatalf("got %d spikes, want 1: %+v", len(spikes), spikes)
	}
	if spikes[0].Load1 != 0.08 {
		t.Errorf("Load1 = %v, want 0.08", spikes[0].Load1)
	}
}

func TestCollectSarLoad_NotInstalled(t *testing.T) {
	since := time.Unix(1_700_000_000, 0).UTC()
	withFixtureSource(t, func(b *source.Bundle) {})
	spikes := collectSarLoad(context.Background(), since)
	if spikes != nil {
		t.Errorf("expected nil spikes when sar unavailable, got %+v", spikes)
	}
}

func TestCollectLoadSpikes(t *testing.T) {
	since := time.Unix(1_700_000_000, 0).UTC()
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/loadavg", []byte("0.10 0.20 0.30 1/200 999\n"))
		// sar left unseeded -> collectSarLoad returns nil, current load still included.
	})
	spikes := collectLoadSpikes(context.Background(), since)
	if len(spikes) != 1 {
		t.Fatalf("got %d spikes, want 1 (current only, sar unavailable): %+v", len(spikes), spikes)
	}
}

// ── filterTopEvents ───────────────────────────────────────────────────────────

func TestFilterTopEvents(t *testing.T) {
	events := []models.TimelineEvent{
		{TimestampUnix: 1, Level: "WARN", Message: "w1"},
		{TimestampUnix: 2, Level: "CRIT", Message: "c1"},
		{TimestampUnix: 3, Level: "WARN", Message: "w2"},
		{TimestampUnix: 4, Level: "CRIT", Message: "c2"},
		{TimestampUnix: 5, Level: "WARN", Message: "w3"},
	}
	got := filterTopEvents(events, 3)
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3 (cap): %+v", len(got), got)
	}
	// Both CRITs plus the most recent WARN (w3, ts=5), sorted chronologically.
	want := []int64{2, 4, 5}
	for i, ts := range want {
		if got[i].TimestampUnix != ts {
			t.Errorf("got[%d].TimestampUnix = %d, want %d (full result: %+v)", i, got[i].TimestampUnix, ts, got)
		}
	}
}

func TestFilterTopEvents_MoreCritsThanCap(t *testing.T) {
	events := []models.TimelineEvent{
		{TimestampUnix: 1, Level: "CRIT"},
		{TimestampUnix: 2, Level: "CRIT"},
		{TimestampUnix: 3, Level: "CRIT"},
		{TimestampUnix: 4, Level: "WARN"},
	}
	got := filterTopEvents(events, 2)
	// remaining = 2-3 = -1 -> no warns added; all CRITs kept even over cap.
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3 (all CRITs kept even over cap): %+v", len(got), got)
	}
	for _, e := range got {
		if e.Level != "CRIT" {
			t.Errorf("unexpected non-CRIT in result: %+v", e)
		}
	}
}

func TestFilterTopEvents_NoCrits(t *testing.T) {
	events := []models.TimelineEvent{
		{TimestampUnix: 1, Level: "WARN"},
		{TimestampUnix: 2, Level: "WARN"},
		{TimestampUnix: 3, Level: "WARN"},
	}
	got := filterTopEvents(events, 2)
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}
	// Most recent 2 warns: ts 2 and 3.
	if got[0].TimestampUnix != 2 || got[1].TimestampUnix != 3 {
		t.Errorf("got = %+v, want ts 2,3 (most recent warns)", got)
	}
}

// TestFilterTopEvents_StartClampedToZero exercises the start<0 branch: when
// there are fewer warns than the remaining capacity, start is clamped to 0 so
// all warns are included (line 571-573).
func TestFilterTopEvents_StartClampedToZero(t *testing.T) {
	t.Parallel()
	// cap=10, crits=1, warns=2: remaining=9 > len(warns)=2 → start=2-9=-7 < 0 → clamped to 0
	events := []models.TimelineEvent{
		{TimestampUnix: 1, Level: "CRIT"},
		{TimestampUnix: 2, Level: "WARN"},
		{TimestampUnix: 3, Level: "WARN"},
	}
	got := filterTopEvents(events, 10)
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3 (all crits+warns fit within cap)", len(got))
	}
}

// TestCollectJournalEvents_EmptyLineInOutput covers the `if line == "" { continue }`
// guard (line 133-134): journalctl output with a blank line between two valid JSON
// entries must not panic or produce a nil event.
func TestCollectJournalEvents_EmptyLineInOutput(t *testing.T) {
	since := time.Unix(1_700_000_000, 0).UTC()
	sinceStr := since.Format("2006-01-02 15:04:05")
	line1 := `{"__REALTIME_TIMESTAMP":"1700000100000000","PRIORITY":"4","_SYSTEMD_UNIT":"app.service","MESSAGE":"first"}`
	line2 := `{"__REALTIME_TIMESTAMP":"1700000200000000","PRIORITY":"4","_SYSTEMD_UNIT":"app.service","MESSAGE":"second"}`
	// "\n\n" produces an empty string in the middle after strings.Split.
	output := line1 + "\n\n" + line2
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{"--no-pager", "--output=json", "--since", sinceStr, "--priority=warning"}, output, 0)
	})
	events, err := collectJournalEvents(context.Background(), since)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (empty line between entries must be skipped)", len(events))
	}
}

// TestParseJournalLine_BenignKernelErrDowngraded covers line 190-192: a journal
// entry that is CRIT by priority but whose message matches a known benign kernel
// pattern must be downgraded to INFO.
func TestParseJournalLine_BenignKernelErrDowngraded(t *testing.T) {
	t.Parallel()
	line := `{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"3","_SYSTEMD_UNIT":"kernel","MESSAGE":"of_root node is null, cannot create root phandle"}`
	ev := parseJournalLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Level != "INFO" {
		t.Errorf("Level = %q, want INFO (benign kernel err must be downgraded from CRIT)", ev.Level)
	}
}

// TestParseJournalLine_CatastropheKeywordWinsOverBenignDowngrade is the
// regression test for internal-collectors-33-02: parseJournalLine previously
// downgraded ANY CRIT entry containing a benign substring to INFO
// unconditionally — including a message that also contains a genuine
// catastrophe keyword (e.g. "panic"). Mirrors parseDmesgLine's existing
// !catastrophe-gated test: the catastrophe keyword must win, never get
// silently swallowed by the benign-substring downgrade just because
// isBenignKernelErr also happens to match.
func TestParseJournalLine_CatastropheKeywordWinsOverBenignDowngrade(t *testing.T) {
	t.Parallel()
	line := `{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"3","_SYSTEMD_UNIT":"kernel","MESSAGE":"kernel panic - smbus base address uninitialized triggered watchdog reset"}`
	ev := parseJournalLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Level != "CRIT" {
		t.Errorf("Level = %q, want CRIT — a catastrophe keyword co-occurring with a benign substring must stay CRIT, not get downgraded to INFO", ev.Level)
	}
}

// TestDeduplicateEvents_LongMessage covers line 271-273: messages longer than 40
// chars are truncated to a 40-char prefix for the dedup key.  Two events with the
// same long message must collapse into a single entry with Count==2.
func TestDeduplicateEvents_LongMessage(t *testing.T) {
	t.Parallel()
	msg := strings.Repeat("x", 50) // > 40 chars → triggers the truncation branch
	events := []models.TimelineEvent{
		{Level: "WARN", TimestampUnix: 100, Unit: "svc", Message: msg},
		{Level: "WARN", TimestampUnix: 115, Unit: "svc", Message: msg}, // same minute (100/60 == 115/60 == 1)
	}
	result := deduplicateEvents(events)
	if len(result) != 1 {
		t.Fatalf("got %d events after dedup, want 1 (identical 40-char prefixes must collapse)", len(result))
	}
	if result[0].Count != 2 {
		t.Errorf("Count = %d, want 2", result[0].Count)
	}
}

// TestCollectDmesgEvents_CapAt500 covers line 324-325: more than 500 parseable
// dmesg lines must be capped at exactly 500 events.
func TestCollectDmesgEvents_CapAt500(t *testing.T) {
	since := time.Unix(0, 0)
	line := "kern  :err   : 2025-06-04T10:30:00.000000+0000 repeated error message"
	lines := make([]string, 600)
	for i := range lines {
		lines[i] = line
	}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("dmesg", []string{"-x", "--time-format", "iso", "--level=err,warn,crit,emerg,alert"}, strings.Join(lines, "\n"), 0)
	})
	events, err := collectDmesgEvents(context.Background(), since)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 500 {
		t.Errorf("got %d events, want 500 (capped at 500)", len(events))
	}
}
