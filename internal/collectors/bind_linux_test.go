//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
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

// TestBindParseZoneFile_DepthGuard guards the circular-include protection:
// depth > 5 must bail with nil rather than recursing forever. Constructed by
// calling bindParseZoneFile directly with depth=6 (an actually-circular
// include chain would take 6 real files to reach this — the guard itself is
// what's under test here, not the recursion machinery).
func TestBindParseZoneFile_DepthGuard(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "named.conf")
	if err := os.WriteFile(main, []byte(`zone "x" { type master; file "/zones/x.db"; };`), 0o600); err != nil {
		t.Fatal(err)
	}
	if zones := bindParseZoneFile(main, 6); zones != nil {
		t.Errorf("depth > 5 should short-circuit to nil, got %+v", zones)
	}
}

// TestBindParseZoneFile_GlobalOptionsSkipped guards the "!zb.active" continue
// branch: a top-level options/logging block that sits OUTSIDE any zone
// declaration (very common in a real named.conf) must be ignored entirely,
// not mistaken for zone content.
func TestBindParseZoneFile_GlobalOptionsSkipped(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "named.conf")
	cfg := `options {
    directory "/var/named";
    file "/should/not/become/a/zone.db";
};
zone "real.com" {
    type master;
    file "/zones/real.db";
};
`
	if err := os.WriteFile(main, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	zones := bindParseZones(main)
	if len(zones) != 1 || zones[0].name != "real.com" || zones[0].file != "/zones/real.db" {
		t.Errorf("expected only the real.com zone (global options block ignored), got %+v", zones)
	}
}

// TestBindParseZoneFile_IncludeCap guards the 20-zone cap after following an
// include: once 20 zones have been collected, parsing must stop early and
// return immediately rather than continuing to scan for more.
func TestBindParseZoneFile_IncludeCap(t *testing.T) {
	dir := t.TempDir()

	// The included file alone defines 21 zones — more than the cap.
	included := filepath.Join(dir, "included.conf")
	var includedCfg strings.Builder
	for i := range 21 {
		fmt.Fprintf(&includedCfg, `zone "z%c.com" { type master; file "/zones/z%c.db"; };`+"\n", 'a'+i, 'a'+i)
	}
	if err := os.WriteFile(included, []byte(includedCfg.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	main := filepath.Join(dir, "named.conf")
	cfg := `include "` + included + `";
zone "never-reached.com" {
    type master;
    file "/zones/never.db";
};
`
	if err := os.WriteFile(main, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	zones := bindParseZones(main)
	if len(zones) != 20 {
		t.Fatalf("expected the result capped at 20 zones, got %d: %+v", len(zones), zones)
	}
	for _, z := range zones {
		if z.name == "never-reached.com" {
			t.Error("parsing should have stopped at the cap before reaching the zone after the include")
		}
	}
}

// TestBindParseZoneFile_FileDirectiveCap guards the OTHER 20-zone cap site: the
// one hit while appending zones found via the "file" directive directly in the
// SAME file being scanned (as opposed to TestBindParseZoneFile_IncludeCap,
// which hits the cap after an include's recursive append).
func TestBindParseZoneFile_FileDirectiveCap(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "named.conf")
	var cfg strings.Builder
	for i := range 21 {
		fmt.Fprintf(&cfg, `zone "z%c.com" { type master; file "/zones/z%c.db"; };`+"\n", 'a'+i, 'a'+i)
	}
	if err := os.WriteFile(main, []byte(cfg.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	zones := bindParseZones(main)
	if len(zones) != 20 {
		t.Fatalf("expected the result capped at 20 zones, got %d: %+v", len(zones), zones)
	}
}

// ── resolveZoneFilePath ──────────────────────────────────────────────────────

func TestResolveZoneFilePath_AbsoluteUnchanged(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := resolveZoneFilePath("/zones/good.db"); got != "/zones/good.db" {
		t.Errorf("resolveZoneFilePath(absolute) = %q, want unchanged", got)
	}
}

func TestResolveZoneFilePath_FoundUnderVarNamed(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/var/named/good.db", source.FileMeta{})
	})
	if got := resolveZoneFilePath("good.db"); got != "/var/named/good.db" {
		t.Errorf("resolveZoneFilePath(good.db) = %q, want /var/named/good.db", got)
	}
}

func TestResolveZoneFilePath_FoundUnderEtcBind(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/etc/bind/db.example", source.FileMeta{})
	})
	if got := resolveZoneFilePath("db.example"); got != "/etc/bind/db.example" {
		t.Errorf("resolveZoneFilePath(db.example) = %q, want /etc/bind/db.example", got)
	}
}

func TestResolveZoneFilePath_NotFoundAnywhere(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {}) // neither base dir has the file
	if got := resolveZoneFilePath("missing.db"); got != "missing.db" {
		t.Errorf("resolveZoneFilePath(missing.db) = %q, want the unresolved relative path unchanged", got)
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

// TestIsBindProcess pins the process-owner matching used to confirm a :53
// listener is actually named, not some other daemon.
func TestIsBindProcess(t *testing.T) {
	yes := []string{
		`tcp   LISTEN 0 10 0.0.0.0:53 0.0.0.0:* users:(("named",pid=1234,fd=20))`,
		`tcp   LISTEN 0 10 0.0.0.0:53 0.0.0.0:* users:(("bind9",pid=1234,fd=20))`,
	}
	for _, line := range yes {
		if !isBindProcess(line) {
			t.Errorf("isBindProcess(%q) = false, want true", line)
		}
	}
	no := []string{
		`tcp   LISTEN 0 10 127.0.0.53:53 0.0.0.0:* users:(("systemd-resolve",pid=900,fd=12))`,
		`udp   UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("dnsmasq",pid=555,fd=6))`,
		`tcp   LISTEN 0 10 0.0.0.0:53 0.0.0.0:*`, // no -p info at all
	}
	for _, line := range no {
		if isBindProcess(line) {
			t.Errorf("isBindProcess(%q) = true, want false", line)
		}
	}
}

// TestBindCheckPorts_OtherDaemonOnPort53 is a regression guard: bindCheckPorts
// used to credit ANY process holding :53 as "named is listening", so a host
// where systemd-resolved (or dnsmasq) also happens to be on :53 while named
// genuinely failed to bind would suppress the "named running but not
// listening" WARN — exactly the misconfiguration the check exists to catch.
func TestBindCheckPorts_OtherDaemonOnPort53(t *testing.T) {
	const ssOut = `tcp   LISTEN 0 10 127.0.0.53:53 0.0.0.0:* users:(("systemd-resolve",pid=900,fd=12))
udp   UNCONN 0 0 127.0.0.53:53 0.0.0.0:* users:(("systemd-resolve",pid=900,fd=13))
`
	prev := SetSource(source.Live{Exec: func(_ context.Context, name string, _ ...string) (source.Result, error) {
		if name == "ss" {
			return source.Result{Stdout: []byte(ssOut)}, nil
		}
		return source.Result{}, nil
	}})
	defer SetSource(prev)

	var info models.BINDInfo
	bindCheckPorts(context.Background(), &info)
	if !info.PortsChecked {
		t.Fatal("PortsChecked should be true — ss succeeded")
	}
	if info.Port53TCP || info.Port53UDP {
		t.Errorf("Port53TCP=%v Port53UDP=%v, want both false — :53 is held by systemd-resolved, not named",
			info.Port53TCP, info.Port53UDP)
	}
}

// TestBindCheckPorts_NamedListening confirms the positive case still works:
// named itself holding :53 must still be credited.
func TestBindCheckPorts_NamedListening(t *testing.T) {
	const ssOut = `tcp   LISTEN 0 10 0.0.0.0:53 0.0.0.0:* users:(("named",pid=1234,fd=20))
udp   UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("named",pid=1234,fd=21))
`
	prev := SetSource(source.Live{Exec: func(_ context.Context, name string, _ ...string) (source.Result, error) {
		if name == "ss" {
			return source.Result{Stdout: []byte(ssOut)}, nil
		}
		return source.Result{}, nil
	}})
	defer SetSource(prev)

	var info models.BINDInfo
	bindCheckPorts(context.Background(), &info)
	if !info.Port53TCP || !info.Port53UDP {
		t.Errorf("Port53TCP=%v Port53UDP=%v, want both true — named is listening", info.Port53TCP, info.Port53UDP)
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
