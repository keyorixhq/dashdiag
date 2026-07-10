//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestBINDCollectorIdentity(t *testing.T) {
	c := NewBINDCollector()
	if c == nil {
		t.Fatal("NewBINDCollector returned nil")
	}
	if c.Name() != "BIND" {
		t.Errorf("Name() = %q, want BIND", c.Name())
	}
	if c.Timeout() != 15*time.Second {
		t.Errorf("Timeout() = %v, want 15s", c.Timeout())
	}
}

func TestBindServiceActive_SystemdUnit(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "named"}, "active\n", 0)
	})
	if !bindServiceActive(context.Background()) {
		t.Error("bindServiceActive() = false, want true")
	}
}

func TestBindServiceActive_ProcessFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "named"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "bind9"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "named-sdb"}, "inactive\n", 3)
		b.PutDir("/proc", []string{"50"})
		b.PutDir("/proc/50", []string{"comm"})
		b.PutFile("/proc/50/comm", []byte("named\n"))
	})
	if !bindServiceActive(context.Background()) {
		t.Error("bindServiceActive() = false, want true (process fallback)")
	}
}

func TestBindServiceActive_NotRunning(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"is-active", "named"})
		b.PutCmdNotFound("systemctl", []string{"is-active", "bind9"})
		b.PutCmdNotFound("systemctl", []string{"is-active", "named-sdb"})
		b.PutDir("/proc", []string{})
	})
	if bindServiceActive(context.Background()) {
		t.Error("bindServiceActive() = true, want false")
	}
}

func TestBindDetect_ByProcess(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc", []string{"60"})
		b.PutDir("/proc/60", []string{"comm"})
		b.PutFile("/proc/60/comm", []byte("named\n"))
	})
	if !bindDetect() {
		t.Error("bindDetect() = false, want true")
	}
}

func TestBindDetect_BySystemctlFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc", []string{})
		b.PutCmd("systemctl", []string{"is-active", "--quiet", "named"}, "", 0)
	})
	if !bindDetect() {
		t.Error("bindDetect() = false, want true (systemctl fallback)")
	}
}

func TestBindDetect_NotRunning(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc", []string{})
		b.PutCmd("systemctl", []string{"is-active", "--quiet", "named"}, "", 3)
	})
	if bindDetect() {
		t.Error("bindDetect() = true, want false")
	}
}

func TestBindConfigPath_RHEL(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/etc/named.conf", source.FileMeta{})
	})
	if got := bindConfigPath(); got != "/etc/named.conf" {
		t.Errorf("bindConfigPath() = %q, want /etc/named.conf", got)
	}
}

func TestBindConfigPath_Debian(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/etc/bind/named.conf", source.FileMeta{})
	})
	if got := bindConfigPath(); got != "/etc/bind/named.conf" {
		t.Errorf("bindConfigPath() = %q, want /etc/bind/named.conf", got)
	}
}

func TestBindConfigPath_NotFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := bindConfigPath(); got != "" {
		t.Errorf("bindConfigPath() = %q, want empty", got)
	}
}

func TestBindCheckConfig_NoConfigFile(t *testing.T) {
	info := &models.BINDInfo{}
	bindCheckConfig(context.Background(), info)
	if info.ConfigOK || info.ConfigError != "named.conf not found" {
		t.Errorf("ConfigOK=%v ConfigError=%q, want false/'named.conf not found'", info.ConfigOK, info.ConfigError)
	}
}

func TestBindCheckConfig_Clean(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("named-checkconf", []string{"/etc/named.conf"}, "", 0)
	})
	info := &models.BINDInfo{ConfigFile: "/etc/named.conf"}
	bindCheckConfig(context.Background(), info)
	if !info.ConfigOK || info.ConfigError != "" {
		t.Errorf("ConfigOK=%v ConfigError=%q, want true/empty", info.ConfigOK, info.ConfigError)
	}
}

// TestBindCheckConfig_Errors pins the fix for a real bug: bindCheckConfig used
// to call runCmd, which discards stdout entirely on a non-zero exit — so any
// actual named-checkconf diagnostic was always replaced by the generic
// "named-checkconf exited 1" with no actionable detail. Fixed by switching to
// runCmdCombined, which preserves stdout+stderr regardless of exit code.
func TestBindCheckConfig_Errors(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("named-checkconf", []string{"/etc/named.conf"}, "/etc/named.conf:12: unknown option 'foo'\n", 1)
	})
	info := &models.BINDInfo{ConfigFile: "/etc/named.conf"}
	bindCheckConfig(context.Background(), info)
	if info.ConfigOK {
		t.Error("ConfigOK = true, want false")
	}
	if info.ConfigError != "/etc/named.conf:12: unknown option 'foo'" {
		t.Errorf("ConfigError = %q, want the real named-checkconf diagnostic, not a generic exit-code message", info.ConfigError)
	}
}

// TestBindCheckConfig_ErrorsWithNoOutput covers the case where named-checkconf
// fails but produces no diagnostic text at all (e.g. killed by a signal) — the
// generic err.Error() fallback must still kick in.
func TestBindCheckConfig_ErrorsWithNoOutput(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("named-checkconf", []string{"/etc/named.conf"}, "", 1)
	})
	info := &models.BINDInfo{ConfigFile: "/etc/named.conf"}
	bindCheckConfig(context.Background(), info)
	if info.ConfigOK || info.ConfigError == "" {
		t.Errorf("ConfigOK=%v ConfigError=%q, want false/non-empty (fallback to the generic error)", info.ConfigOK, info.ConfigError)
	}
}

func TestBindQueryTest_DigMissing(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"dig": false}, func(b *source.Bundle) {})
	info := &models.BINDInfo{}
	bindQueryTest(context.Background(), info)
	if info.QueryTested {
		t.Error("QueryTested = true, want false when dig is absent")
	}
}

func TestBindQueryTest_Success(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"dig": true}, func(b *source.Bundle) {
		b.PutCmd("dig", []string{"@127.0.0.1", "localhost", "A", "+time=2", "+tries=1", "+noall", "+answer"},
			"localhost.\t\t60\tIN\tA\t127.0.0.1\n", 0)
	})
	info := &models.BINDInfo{}
	bindQueryTest(context.Background(), info)
	if !info.QueryTested || !info.QueryOK {
		t.Errorf("QueryTested=%v QueryOK=%v, want both true", info.QueryTested, info.QueryOK)
	}
}

func TestBindQueryTest_Fails(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"dig": true}, func(b *source.Bundle) {
		b.PutCmd("dig", []string{"@127.0.0.1", "localhost", "A", "+time=2", "+tries=1", "+noall", "+answer"}, "", 1)
	})
	info := &models.BINDInfo{}
	bindQueryTest(context.Background(), info)
	if !info.QueryTested {
		t.Error("QueryTested = false, want true (dig is present)")
	}
	if info.QueryOK {
		t.Error("QueryOK = true, want false (dig failed)")
	}
}

func TestBindCheckZones_MixedResults(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("named-checkzone", []string{"example.com", "/etc/bind/db.example.com"}, "zone example.com/IN: loaded serial 1\nOK\n", 0)
		b.PutCmd("named-checkzone", []string{"broken.com", "/etc/bind/db.broken.com"}, "zone broken.com/IN: not loaded due to errors.\ndns_zone_load: broken.com/IN: NS 'ns1.broken.com' has no address records (A or AAAA)\n", 1)
	})
	info := &models.BINDInfo{}
	zones := []namedZone{
		{name: "example.com", file: "/etc/bind/db.example.com"},
		{name: "broken.com", file: "/etc/bind/db.broken.com"},
		{name: "empty.com", file: ""}, // no file directive -> skipped
	}
	bindCheckZones(context.Background(), info, zones)
	if len(info.Zones) != 2 {
		t.Fatalf("Zones = %+v, want 2 (empty-file zone skipped)", info.Zones)
	}
	if !info.Zones[0].OK {
		t.Errorf("Zones[0] = %+v, want OK=true", info.Zones[0])
	}
	if info.Zones[1].OK || info.Zones[1].Error == "" {
		t.Errorf("Zones[1] = %+v, want OK=false with an error message", info.Zones[1])
	}
	if info.ZonesFailed != 1 {
		t.Errorf("ZonesFailed = %d, want 1", info.ZonesFailed)
	}
}

func TestBindRNCDStatus_Available(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("rndc", []string{"status"},
			"version: BIND 9.18.33 (Extended Support Version) <id:abcdef>\n"+
				"boot time: Mon, 01 Jun 2026 00:00:00 GMT\n"+
				"queries: 12345\n", 0)
	})
	info := &models.BINDInfo{}
	bindRNCDStatus(context.Background(), info)
	if !info.RNCDAvailable {
		t.Fatal("RNCDAvailable = false, want true")
	}
	if info.Version != "9.18.33" {
		t.Errorf("Version = %q, want 9.18.33", info.Version)
	}
	if info.QueryCount != 12345 {
		t.Errorf("QueryCount = %d, want 12345", info.QueryCount)
	}
	if info.Uptime == "" {
		t.Error("Uptime = \"\", want a non-empty duration string")
	}
}

func TestBindRNCDStatus_Unavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("rndc", []string{"status"})
	})
	info := &models.BINDInfo{}
	bindRNCDStatus(context.Background(), info)
	if info.RNCDAvailable {
		t.Error("RNCDAvailable = true, want false")
	}
}

// TestBINDCollector_Collect_NotDetected verifies the gate: when no BIND daemon
// is running, Collect() returns (nil, nil) — the section is omitted entirely.
func TestBINDCollector_Collect_NotDetected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc", []string{})
		b.PutCmd("systemctl", []string{"is-active", "--quiet", "named"}, "", 3)
	})
	c := NewBINDCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("Collect() = %+v, want nil when BIND is not detected", raw)
	}
}

// TestBINDCollector_Collect_FullHappyPath drives the entire Collect() pipeline
// once BIND is detected: service active, config valid, ports listening, a
// successful live query, one valid zone, and rndc status.
func TestBINDCollector_Collect_FullHappyPath(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"dig": true}, func(b *source.Bundle) {
		b.PutDir("/proc", []string{"70"})
		b.PutDir("/proc/70", []string{"comm"})
		b.PutFile("/proc/70/comm", []byte("named\n"))

		b.PutCmd("systemctl", []string{"is-active", "named"}, "active\n", 0)

		b.PutStat("/etc/named.conf", source.FileMeta{})
		b.PutFile("/etc/named.conf", []byte(`zone "example.com" {
    type master;
    file "/etc/bind/db.example.com";
};
`))
		b.PutCmd("named-checkconf", []string{"/etc/named.conf"}, "", 0)

		b.PutCmd("ss", []string{"-tulpn"},
			`tcp   LISTEN 0 10 0.0.0.0:53 0.0.0.0:* users:(("named",pid=70,fd=20))`+"\n"+
				`udp   UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("named",pid=70,fd=21))`+"\n", 0)

		b.PutCmd("dig", []string{"@127.0.0.1", "localhost", "A", "+time=2", "+tries=1", "+noall", "+answer"},
			"localhost.\t\t60\tIN\tA\t127.0.0.1\n", 0)

		b.PutCmd("named-checkzone", []string{"example.com", "/etc/bind/db.example.com"}, "OK\n", 0)

		b.PutCmd("rndc", []string{"status"}, "version: BIND 9.18.33\nqueries: 99\n", 0)
	})

	c := NewBINDCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.BINDInfo)

	if !info.Detected || !info.ServiceActive {
		t.Errorf("Detected=%v ServiceActive=%v, want both true", info.Detected, info.ServiceActive)
	}
	if info.ConfigFile != "/etc/named.conf" || !info.ConfigOK {
		t.Errorf("ConfigFile=%q ConfigOK=%v, unexpected", info.ConfigFile, info.ConfigOK)
	}
	if !info.PortsChecked || !info.Port53TCP || !info.Port53UDP {
		t.Errorf("PortsChecked=%v Port53TCP=%v Port53UDP=%v, want all true", info.PortsChecked, info.Port53TCP, info.Port53UDP)
	}
	if !info.QueryTested || !info.QueryOK {
		t.Errorf("QueryTested=%v QueryOK=%v, want both true", info.QueryTested, info.QueryOK)
	}
	if len(info.Zones) != 1 || !info.Zones[0].OK || info.ZonesFailed != 0 {
		t.Errorf("Zones=%+v ZonesFailed=%d, want 1 OK zone, 0 failed", info.Zones, info.ZonesFailed)
	}
	if !info.RNCDAvailable || info.Version != "9.18.33" || info.QueryCount != 99 {
		t.Errorf("RNCDAvailable=%v Version=%q QueryCount=%d, unexpected", info.RNCDAvailable, info.Version, info.QueryCount)
	}
}
