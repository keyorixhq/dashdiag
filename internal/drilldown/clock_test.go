package drilldown

import (
	"context"
	"testing"
)

func TestParseChronyTracking(t *testing.T) {
	t.Parallel()
	const sample = `Reference ID    : C0A80101 (router.local)
Stratum         : 3
Ref time (UTC)  : Mon Jul 07 12:00:00 2026
System time     : 0.000012345 seconds fast of NTP time
Leap status     : Normal
`
	got := parseChronyTracking(sample)
	if got.Type != tableKV || got.Title != "chronyc tracking" {
		t.Fatalf("unexpected shape: %+v", got)
	}
	want := map[string]string{
		"Reference ID": "C0A80101 (router.local)",
		"Stratum":      "3",
		"Leap status":  "Normal",
	}
	for k, v := range want {
		if got.KV[k] != v {
			t.Errorf("KV[%q] = %q, want %q", k, got.KV[k], v)
		}
	}
}

func TestParseChronyTracking_EmptyInput(t *testing.T) {
	t.Parallel()
	got := parseChronyTracking("")
	if len(got.KV) != 0 {
		t.Errorf("expected empty KV for empty input, got %+v", got.KV)
	}
}

func TestParseChronyTracking_MalformedLinesIgnored(t *testing.T) {
	t.Parallel()
	got := parseChronyTracking("no colon here\nStratum : 2\n : empty key\nTrailing:  \n")
	if len(got.KV) != 1 || got.KV["Stratum"] != "2" {
		t.Errorf("expected only well-formed non-empty key/value pairs, got %+v", got.KV)
	}
}

func TestParseTimedatectl(t *testing.T) {
	t.Parallel()
	const sample = `Local time=Mon 2026-07-07 12:00:00 UTC
Universal time=Mon 2026-07-07 12:00:00 UTC
NTP service=active
System clock synchronized=yes
`
	got := parseTimedatectl(sample)
	if got.Type != tableKV || got.Title != "timedatectl status" {
		t.Fatalf("unexpected shape: %+v", got)
	}
	want := map[string]string{
		"NTP service":               "active",
		"System clock synchronized": "yes",
	}
	for k, v := range want {
		if got.KV[k] != v {
			t.Errorf("KV[%q] = %q, want %q", k, got.KV[k], v)
		}
	}
}

func TestParseTimedatectl_EmptyInput(t *testing.T) {
	t.Parallel()
	got := parseTimedatectl("")
	if len(got.KV) != 0 {
		t.Errorf("expected empty KV for empty input, got %+v", got.KV)
	}
}

// TestClockTracking_RealDispatch exercises the exported GOOS-switch
// dispatcher directly (real, uncancelled context, real runCmd — not swapped)
// — see the equivalent comment on TestTopProcessesByCPU_RealProc in
// cpu_test.go for the general rationale. On Linux this calls through to
// clockTrackingLinux, which is already covered in detail below via
// swapRunCmd; here it just proves ClockTracking itself doesn't panic/error
// when neither chronyc nor timedatectl is installed (the golang:1.26 test
// image has neither, so this exercises the graceful nil,nil degrade path).
// Must not run with t.Parallel() — see swapRunCmd's doc comment; this test
// doesn't swap runCmd itself, but it shares the package-level var with the
// serial group below and must stay ordered with it.
func TestClockTracking_RealDispatch(t *testing.T) {
	got, err := ClockTracking(context.Background())
	if err != nil {
		t.Fatalf("ClockTracking: %v", err)
	}
	if got != nil && got.Type != tableKV {
		t.Errorf("unexpected shape: %+v", got)
	}
}

// clockTrackingLinux/clockTrackingMac shell out via runCmd, which is a
// swappable package var for exactly this reason. No t.Parallel() in this
// group — see swapRunCmd's doc comment.

func TestClockTrackingLinux_ChronycSucceeds(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name == "chronyc" {
			return "Stratum         : 3\n", nil
		}
		t.Fatalf("unexpected command: %s %v (timedatectl fallback should not run)", name, args)
		return "", nil
	})

	got, err := clockTrackingLinux(context.Background())
	if err != nil {
		t.Fatalf("clockTrackingLinux: %v", err)
	}
	if got.Title != "chronyc tracking" || got.KV["Stratum"] != "3" {
		t.Errorf("unexpected result: %+v", got)
	}
}

func TestClockTrackingLinux_FallsBackToTimedatectl(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		switch name {
		case "chronyc":
			return "", errNotFound
		case "timedatectl":
			return "NTP service=active\n", nil
		default:
			t.Fatalf("unexpected command: %s %v", name, args)
			return "", nil
		}
	})

	got, err := clockTrackingLinux(context.Background())
	if err != nil {
		t.Fatalf("clockTrackingLinux: %v", err)
	}
	if got.Title != "timedatectl status" || got.KV["NTP service"] != "active" {
		t.Errorf("unexpected result: %+v", got)
	}
}

func TestClockTrackingLinux_NoToolingAvailable(t *testing.T) {
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		return "", errNotFound
	})

	got, err := clockTrackingLinux(context.Background())
	if got != nil || err != nil {
		t.Errorf("clockTrackingLinux() = (%+v, %v), want (nil, nil) when neither tool is available", got, err)
	}
}

func TestClockTrackingMac_TimedRunningWithSNTP(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		switch name {
		case "pgrep":
			return "4242\n", nil
		case "sntp":
			return "2026-07-08 12:00:00.000000 (+0000) +0.000123 +/- 0.001 host stratum 2\n", nil
		default:
			t.Fatalf("unexpected command: %s %v", name, args)
			return "", nil
		}
	})

	got, err := clockTrackingMac(context.Background())
	if err != nil {
		t.Fatalf("clockTrackingMac: %v", err)
	}
	if got.KV["timed_running"] != "yes" || got.KV["timed_pid"] != "4242" {
		t.Errorf("unexpected result: %+v", got.KV)
	}
	if got.KV["sntp_result"] == "" {
		t.Error("expected sntp_result to be populated from the stratum line")
	}
}

// TestClockTrackingMac_DSD_OFFLINE_SkipsSNTP is a regression guard for
// internal-drilldown-01-05: clockTrackingMac used to unconditionally run
// `sntp -t 1 time.apple.com` -- a real outbound UDP query to Apple's time
// servers -- whenever a Clock WARN/CRIT insight is drilled down on macOS,
// with no opt-out. Under DSD_OFFLINE, sntp must never be invoked at all:
// swapRunCmd's default branch calls t.Fatalf on any command other than
// pgrep, so this fails loudly (not just via a missing kv entry) if the gate
// is ever removed or bypassed.
func TestClockTrackingMac_DSD_OFFLINE_SkipsSNTP(t *testing.T) {
	t.Setenv("DSD_OFFLINE", "1")
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		switch name {
		case "pgrep":
			return "4242\n", nil
		default:
			t.Fatalf("unexpected command under DSD_OFFLINE: %s %v (sntp must not run)", name, args)
			return "", nil
		}
	})

	got, err := clockTrackingMac(context.Background())
	if err != nil {
		t.Fatalf("clockTrackingMac: %v", err)
	}
	if got.KV["timed_running"] != "yes" {
		t.Errorf("local (non-network) checks must still run under DSD_OFFLINE, got %+v", got.KV)
	}
	if _, ok := got.KV["sntp_result"]; ok {
		t.Errorf("expected no sntp_result under DSD_OFFLINE, got %+v", got.KV)
	}
}

func TestClockTrackingMac_TimedNotRunning(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		switch name {
		case "pgrep":
			return "", errNotFound
		case "sntp":
			return "", errNotFound
		default:
			t.Fatalf("unexpected command: %s %v", name, args)
			return "", nil
		}
	})

	got, err := clockTrackingMac(context.Background())
	if err != nil {
		t.Fatalf("clockTrackingMac: %v", err)
	}
	if got.KV["timed_running"] != "no" {
		t.Errorf("expected timed_running=no, got %+v", got.KV)
	}
	if _, ok := got.KV["sntp_result"]; ok {
		t.Errorf("expected no sntp_result when sntp fails, got %+v", got.KV)
	}
}
