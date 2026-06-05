//go:build linux

package collectors

import "testing"

// Characterization tests for more pure parsers: network interface filtering and
// CAP_NET_RAW / ping-group-range parsing (network_quick.go), the kernel-log
// process-name extractors and systemd-time parser (logs_linux.go), and the
// package-count integer extractor (packages_linux.go).

func TestParseJSONInt(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{`"available": 42,`, 42},
		{`"count": 7`, 7},
		{`no colon here`, 0},
		{`"zero": 0`, 0},
	}
	for _, tt := range tests {
		if got := parseJSONInt(tt.in); got != tt.want {
			t.Errorf("parseJSONInt(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestExtractParenthesized(t *testing.T) {
	if got := extractParenthesized("Out of memory: Kill process 1234 (nginx) score 900"); got != "nginx" {
		t.Errorf("extractParenthesized = %q, want nginx", got)
	}
	if got := extractParenthesized("no parens here"); got != "" {
		t.Errorf("extractParenthesized without parens = %q, want empty", got)
	}
}

func TestExtractBracketProc(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"nginx[1234]: segfault at 0", "nginx"},
		{"/usr/sbin/sshd[99]: error", "sshd"}, // leading path stripped
		{"no bracket here", ""},
	}
	for _, tt := range tests {
		if got := extractBracketProc(tt.in); got != tt.want {
			t.Errorf("extractBracketProc(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseSystemdTime(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"5min", 300},
		{"2m", 120},
		{"1h", 3600},
		{"30s", 30},
		{"45", 45}, // bare number = seconds
	}
	for _, tt := range tests {
		if got := parseSystemdTime(tt.in); got != tt.want {
			t.Errorf("parseSystemdTime(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestLogMessageKey(t *testing.T) {
	// Drops the first 3 whitespace fields and keeps the rest. For a
	// "Mon D HH:MM:SS" stamp (3 tokens) the host is therefore retained.
	if got := logMessageKey("Jun 1 12:00:00 myhost kernel: out of memory"); got != "myhost kernel: out of memory" {
		t.Errorf("logMessageKey = %q", got)
	}
	// A line with <= 3 fields is returned verbatim.
	if got := logMessageKey("short line"); got != "short line" {
		t.Errorf("logMessageKey (short) = %q", got)
	}
}
