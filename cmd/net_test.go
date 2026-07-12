package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestBandLabel(t *testing.T) {
	cases := []struct {
		ghz  float64
		want string
	}{
		{2.4, "2.4GHz"},
		{5, "5GHz"},
		{6, "6GHz"},
		{3.7, "unknown"},
	}
	for _, c := range cases {
		if got := bandLabel(c.ghz); got != c.want {
			t.Errorf("bandLabel(%v) = %q, want %q", c.ghz, got, c.want)
		}
	}
}

func TestIconBand(t *testing.T) {
	// 2.4GHz is flagged (crowded/legacy band); 5/6GHz are not.
	if got := iconBand(2.4); got != "⚠️ " {
		t.Errorf("iconBand(2.4) = %q, want warn", got)
	}
	if got := iconBand(5); got != "✅" {
		t.Errorf("iconBand(5) = %q, want ok", got)
	}
}

func TestIconWidth(t *testing.T) {
	// A 20MHz channel width is the flagged case (narrow/legacy); wider is fine.
	if got := iconWidth(20); got != "⚠️ " {
		t.Errorf("iconWidth(20) = %q, want warn", got)
	}
	if got := iconWidth(80); got != "✅" {
		t.Errorf("iconWidth(80) = %q, want ok", got)
	}
}

func TestIconSignal(t *testing.T) {
	cases := []struct {
		dbm  int
		want string
	}{
		{-50, "✅"},
		{-65, "⚠️ "},
		{-70, "⚠️ "},
		{-76, "❌"},
	}
	for _, c := range cases {
		if got := iconSignal(c.dbm); got != c.want {
			t.Errorf("iconSignal(%d) = %q, want %q", c.dbm, got, c.want)
		}
	}
}

// TestCountSteamOSWifiIssues exercises every independent concern branch — a
// nil profile (non-SteamOS host) must count 0, and each condition (backend
// conflict, SSID conflict, slow CDN DNS, and — only when connected — 2.4GHz
// band / narrow width / weak signal) must count exactly once.
func TestCountSteamOSWifiIssues(t *testing.T) {
	t.Parallel()
	if got := countSteamOSWifiIssues(nil); got != 0 {
		t.Errorf("nil profile should count 0 issues, got %d", got)
	}
	cases := []struct {
		name string
		w    models.SteamOSWifi
		want int
	}{
		{"clean disconnected", models.SteamOSWifi{}, 0},
		{"both backends", models.SteamOSWifi{BothBackends: true}, 1},
		{"ssid conflict", models.SteamOSWifi{SSIDConflict: true}, 1},
		{"slow cdn dns", models.SteamOSWifi{CDNDNSKnown: true, CDNDNSms: 800}, 1},
		{"fast cdn dns not counted", models.SteamOSWifi{CDNDNSKnown: true, CDNDNSms: 50}, 0},
		{"2.4GHz band while connected", models.SteamOSWifi{Connected: true, BandGHz: 2.4}, 1},
		{"5GHz band while connected", models.SteamOSWifi{Connected: true, BandGHz: 5}, 0},
		{"narrow width while connected", models.SteamOSWifi{Connected: true, WidthMHz: 20}, 1},
		{"weak signal while connected", models.SteamOSWifi{Connected: true, SignalDBm: -70}, 1},
		{"2.4GHz band while NOT connected doesn't count", models.SteamOSWifi{Connected: false, BandGHz: 2.4}, 0},
		{"everything wrong at once", models.SteamOSWifi{
			BothBackends: true, SSIDConflict: true, CDNDNSKnown: true, CDNDNSms: 900,
			Connected: true, BandGHz: 2.4, WidthMHz: 20, SignalDBm: -80,
		}, 6},
	}
	for _, c := range cases {
		if got := countSteamOSWifiIssues(&c.w); got != c.want {
			t.Errorf("%s: countSteamOSWifiIssues = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestIsUSBSlave guards the fallback path — an unreadable/nonexistent sysfs
// link (typical in a container or for a nonexistent interface) must read
// false, not panic.
func TestIsUSBSlave(t *testing.T) {
	t.Parallel()
	if isUSBSlave("nonexistent-iface-xyz") {
		t.Error("a nonexistent interface should not be reported as a USB slave")
	}
}

// TestTCPCounterIsIssue pins which DeepTCPCounterLevel outputs count toward
// the `dsd net` summary tally — only WARN/CRIT are issues; INFO/"" are context.
func TestTCPCounterIsIssue(t *testing.T) {
	t.Parallel()
	cases := []struct {
		level string
		want  bool
	}{
		{"WARN", true}, {"CRIT", true}, {"INFO", false}, {"", false},
	}
	for _, c := range cases {
		if got := tcpCounterIsIssue(c.level); got != c.want {
			t.Errorf("tcpCounterIsIssue(%q) = %v, want %v", c.level, got, c.want)
		}
	}
}

// TestRunNet exercises runNet's real (read-only) collector wiring in --plain
// and --json mode (non-deep, to keep the test fast — deep-mode's extra
// NFS/BIND/resolver/networkd collectors are exercised via their own direct
// renderer tests elsewhere in this package). Same real-I/O precedent as
// cpu_report_test.go / hardware_test.go.
func TestRunNet(t *testing.T) {
	plainCmd := newBareCloudCmd()
	plainCmd.SetContext(context.Background())
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runNet(plainCmd, nil); err != nil {
			t.Fatalf("runNet (plain): %v", err)
		}
	})
	if !strings.Contains(plainOut, "Interfaces") {
		t.Errorf("plain mode should render the interfaces section, got: %q", plainOut)
	}

	jsonCmd := newBareCloudCmd()
	jsonCmd.SetContext(context.Background())
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runNet(jsonCmd, nil); err != nil {
			t.Fatalf("runNet (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, `"network"`) {
		t.Errorf("json mode should emit a top-level network key, got: %q", jsonOut)
	}
}

// TestRunNetDNS exercises runNetDNS's real (read-only) collector wiring. It
// reads flags off cmd.Parent() (it's wired as `dsd net dns`), so the test
// constructs a parent/child cobra relationship the way root.go does.
func TestRunNetDNS(t *testing.T) {
	parent := newBareCloudCmd()
	child := &cobra.Command{}
	parent.AddCommand(child)
	child.SetContext(context.Background())
	_ = parent.Flags().Set("plain", "true")

	out := captureStdout(t, func() {
		if err := runNetDNS(child, nil); err != nil {
			t.Fatalf("runNetDNS (plain): %v", err)
		}
	})
	if out == "" {
		t.Error("runNetDNS (plain) produced no output")
	}

	jsonParent := newBareCloudCmd()
	jsonChild := &cobra.Command{}
	jsonParent.AddCommand(jsonChild)
	jsonChild.SetContext(context.Background())
	_ = jsonParent.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runNetDNS(jsonChild, nil); err != nil {
			t.Fatalf("runNetDNS (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, "{") {
		t.Errorf("json mode should emit JSON, got: %q", jsonOut)
	}
}
