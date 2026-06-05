//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Characterization tests for the BIND collector's parsers. bindParseZoneFile is
// exercised against a real temp named.conf (the only filesystem touch); the rest
// are pure string functions.

func TestBindParseZoneFile(t *testing.T) {
	dir := t.TempDir()
	included := filepath.Join(dir, "included.conf")
	if err := os.WriteFile(included, []byte(`zone "extra.org" {
    type master;
    file "/zones/extra.db";
};
`), 0o600); err != nil {
		t.Fatal(err)
	}

	main := filepath.Join(dir, "named.conf")
	cfg := `// main config — comment line ignored
zone "good.com" {
    type master;
    file "/zones/good.db";
};
zone "cache" {
    type hint;            // hint zones are not checkable, skipped
    file "/zones/root.hint";
};
zone "fwd.com" {
    type forward;         // forward zones skipped too
    file "/zones/fwd.db";
};
include "` + included + `";
`
	if err := os.WriteFile(main, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	zones := bindParseZones(main)

	// Expect: good.com (master) + extra.org (from include). hint/forward skipped.
	if len(zones) != 2 {
		t.Fatalf("got %d zones, want 2: %+v", len(zones), zones)
	}
	byName := map[string]string{}
	for _, z := range zones {
		byName[z.name] = z.file
	}
	if byName["good.com"] != "/zones/good.db" {
		t.Errorf("good.com file = %q, want /zones/good.db", byName["good.com"])
	}
	if byName["extra.org"] != "/zones/extra.db" {
		t.Errorf("extra.org file = %q, want /zones/extra.db (include not followed?)", byName["extra.org"])
	}
	if _, ok := byName["cache"]; ok {
		t.Error("hint zone 'cache' should have been skipped")
	}
	if _, ok := byName["fwd.com"]; ok {
		t.Error("forward zone 'fwd.com' should have been skipped")
	}
}

func TestBindParseZoneFile_Missing(t *testing.T) {
	if zones := bindParseZones("/nonexistent/named.conf"); zones != nil {
		t.Errorf("missing file should yield nil, got %+v", zones)
	}
}

func TestBindExtractZoneError(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want string
	}{
		{
			name: "error line extracted",
			out:  "loading \"example.com\"\nzone example.com/IN: NS 'ns1' has no address\nerror: zone example.com/IN: loading from master file failed",
			want: "error: zone example.com/IN: loading from master file failed",
		},
		{
			name: "no TTL line extracted",
			out:  "zone example.com/IN: no TTL specified; using SOA MINTTL",
			want: "zone example.com/IN: no TTL specified; using SOA MINTTL",
		},
		{
			name: "no error keyword returns trimmed output",
			out:  "  zone example.com/IN: loaded serial 42\nOK  ",
			want: "zone example.com/IN: loaded serial 42\nOK",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bindExtractZoneError(tt.out); got != tt.want {
				t.Errorf("bindExtractZoneError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBindExtractZoneError_Truncates(t *testing.T) {
	long := "error: " + strings.Repeat("x", 200)
	got := bindExtractZoneError(long)
	if !strings.HasSuffix(got, "…") || len([]rune(got)) != 151 {
		t.Errorf("expected truncation to 150 runes + ellipsis, got %d runes", len([]rune(got)))
	}
}

func TestBindCalcUptime(t *testing.T) {
	// Malformed inputs return "".
	if got := bindCalcUptime("no colon no date"); got != "" {
		t.Errorf("line without colon should yield empty, got %q", got)
	}
	if got := bindCalcUptime("boot time: not a real date"); got != "" {
		t.Errorf("unparseable date should yield empty, got %q", got)
	}
	// A clearly-past boot time yields a non-empty day-granularity string.
	got := bindCalcUptime("boot time: Mon, 19 May 2025 13:17:03 GMT")
	if got == "" || !strings.Contains(got, "d") {
		t.Errorf("past boot time should yield a 'Xd ...' uptime, got %q", got)
	}
}

func TestBindFmt(t *testing.T) {
	tests := []struct {
		n    int
		unit string
		want string
	}{
		{0, "d", ""}, // zero is omitted
		{5, "d", "5d"},
		{12, "h", "12h"},
	}
	for _, tt := range tests {
		if got := bindFmt(tt.n, tt.unit); got != tt.want {
			t.Errorf("bindFmt(%d, %q) = %q, want %q", tt.n, tt.unit, got, tt.want)
		}
	}
}
