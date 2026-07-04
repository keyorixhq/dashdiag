package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for steamos.go's report renderers — plain data structs,
// no live I/O. No t.Parallel() (corrupts captureStdout's shared os.Stdout
// swap).

func TestOrDash(t *testing.T) {
	if got := orDash(""); got != "—" {
		t.Errorf("orDash(\"\") = %q, want —", got)
	}
	if got := orDash("A"); got != "A" {
		t.Errorf("orDash(A) = %q, want A", got)
	}
}

func TestPrintSteamOSReportNotDetected(t *testing.T) {
	out := captureStdout(t, func() { printSteamOSReport(&models.SteamOSInfo{Detected: false}, 0, output.ModePlain) })
	if !strings.Contains(out, "Not a SteamOS") {
		t.Errorf("undetected SteamOS should say so, got:\n%s", out)
	}
	if strings.Contains(out, "SteamOS healthy") {
		t.Errorf("undetected SteamOS must not read healthy, got:\n%s", out)
	}
}

func TestPrintSteamOSSystemReadonly(t *testing.T) {
	cases := []struct {
		name string
		info models.SteamOSInfo
		want string
	}{
		{"unknown", models.SteamOSInfo{}, "status unavailable"},
		{"enabled", models.SteamOSInfo{ReadonlyKnown: true, ReadonlyEnabled: true}, "enabled (rootfs protected)"},
		{"disabled", models.SteamOSInfo{ReadonlyKnown: true, ReadonlyEnabled: false}, "DISABLED"},
	}
	for _, c := range cases {
		out := captureStdout(t, func() { printSteamOSSystem(&c.info, output.ModePlain) })
		if !strings.Contains(out, c.want) {
			t.Errorf("%s: printSteamOSSystem output missing %q, got:\n%s", c.name, c.want, out)
		}
	}
}

func TestPrintSteamOSDevice(t *testing.T) {
	// No DMI at all: section suppressed entirely.
	if out := captureStdout(t, func() { printSteamOSDevice(&models.SteamOSInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("no device info should print nothing, got:\n%s", out)
	}

	unrecognised := captureStdout(t, func() {
		printSteamOSDevice(&models.SteamOSInfo{DeviceName: "Unknown Handheld", DeviceProductRaw: "Foo123", DeviceRecognised: false}, output.ModePlain)
	})
	if !strings.Contains(unrecognised, "unrecognised") {
		t.Errorf("an unrecognised device should say so, got:\n%s", unrecognised)
	}

	secureBootOn := true
	sbEnabled := captureStdout(t, func() {
		printSteamOSDevice(&models.SteamOSInfo{DeviceName: "x", SecureBootApplicable: true, SecureBootEnabled: &secureBootOn}, output.ModePlain)
	})
	if !strings.Contains(sbEnabled, "WARN") {
		t.Errorf("Secure Boot enabled should render WARN (blocks USB recovery), got:\n%s", sbEnabled)
	}
}

func TestPrintSteamOSRAUC(t *testing.T) {
	unavailable := captureStdout(t, func() { printSteamOSRAUC(&models.SteamOSInfo{RAUCAvailable: false}, output.ModePlain) })
	if !strings.Contains(unavailable, "unavailable") {
		t.Errorf("no rauc should say unavailable, got:\n%s", unavailable)
	}

	badInactive := captureStdout(t, func() {
		printSteamOSRAUC(&models.SteamOSInfo{
			RAUCAvailable: true, RAUCBootedSlot: "A", RAUCBootedStatus: "good",
			RAUCInactiveSlot: "B", RAUCInactiveStatus: "bad",
		}, output.ModePlain)
	})
	if !strings.Contains(badInactive, "no rollback available") {
		t.Errorf("a bad inactive slot must warn no rollback is available, got:\n%s", badInactive)
	}
}

func TestPrintSteamOSSession(t *testing.T) {
	crashed := captureStdout(t, func() {
		printSteamOSSession(&models.SteamOSInfo{SessionMode: "gamemode", GamescopeActive: false}, output.ModePlain)
	})
	if !strings.Contains(crashed, "session likely crashed") {
		t.Errorf("Game Mode with gamescope inactive should flag a likely crash, got:\n%s", crashed)
	}

	fine := captureStdout(t, func() {
		printSteamOSSession(&models.SteamOSInfo{SessionMode: "gamemode", GamescopeActive: true}, output.ModePlain)
	})
	if strings.Contains(fine, "crashed") {
		t.Errorf("Game Mode with gamescope active should not flag a crash, got:\n%s", fine)
	}
}

func TestPrintSteamOSStorage(t *testing.T) {
	out := captureStdout(t, func() {
		printSteamOSStorage(&models.SteamOSInfo{VarUsedPct: 90, HomeUsedPct: 96}, output.ModePlain)
	})
	if strings.Count(out, "CRIT") != 2 {
		t.Errorf("var>=85 and home>=95 should each render CRIT, got:\n%s", out)
	}
}

func TestPrintSteamOSNetwork(t *testing.T) {
	unreachable := captureStdout(t, func() {
		printSteamOSNetwork(&models.SteamOSInfo{UpdateServerKnown: true, UpdateServerReachable: false}, output.ModePlain)
	})
	if !strings.Contains(unreachable, "unreachable") {
		t.Errorf("an unreachable update server should say so, got:\n%s", unreachable)
	}

	notTested := captureStdout(t, func() {
		printSteamOSNetwork(&models.SteamOSInfo{UpdateServerKnown: false}, output.ModePlain)
	})
	if !strings.Contains(notTested, "not tested") {
		t.Errorf("an untested update server must not claim reachable/unreachable, got:\n%s", notTested)
	}
}

func TestPrintSteamOSRemotePlay(t *testing.T) {
	if out := captureStdout(t, func() { printSteamOSRemotePlay(&models.SteamOSInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("nil RemotePlay should print nothing, got:\n%s", out)
	}

	unbound := captureStdout(t, func() {
		printSteamOSRemotePlay(&models.SteamOSInfo{RemotePlay: &models.SteamOSRemotePlay{
			Ports: []models.RemotePlayPort{{Protocol: "udp", Port: 27031, Bound: false, Optional: false}},
		}}, output.ModePlain)
	})
	if !strings.Contains(unbound, "CRIT") {
		t.Errorf("a required (non-optional) unbound port should render CRIT, got:\n%s", unbound)
	}

	// An optional (VR) unbound port must NOT read as a fault — only INFO.
	optionalUnbound := captureStdout(t, func() {
		printSteamOSRemotePlay(&models.SteamOSInfo{RemotePlay: &models.SteamOSRemotePlay{
			Ports: []models.RemotePlayPort{{Protocol: "udp", Port: 27038, Bound: false, Optional: true}},
		}}, output.ModePlain)
	})
	if strings.Contains(optionalUnbound, "CRIT") {
		t.Errorf("an optional unbound VR port must not render CRIT, got:\n%s", optionalUnbound)
	}
	if !strings.Contains(optionalUnbound, "optional") {
		t.Errorf("an optional unbound port should say so, got:\n%s", optionalUnbound)
	}

	isolation := captureStdout(t, func() {
		printSteamOSRemotePlay(&models.SteamOSInfo{RemotePlay: &models.SteamOSRemotePlay{
			ARPChecked: true, APIsolationSuspected: true,
		}}, output.ModePlain)
	})
	if !strings.Contains(isolation, "AP client isolation") {
		t.Errorf("suspected AP isolation should be called out, got:\n%s", isolation)
	}
}

func TestPrintSteamOSDeep(t *testing.T) {
	out := captureStdout(t, func() {
		printSteamOSDeep(&models.SteamOSInfo{FlatpakAppCount: 5, FlatpakDataGB: 25, BIOSVersion: "F7A0113"}, output.ModePlain)
	})
	if !strings.Contains(out, "WARN") {
		t.Errorf("25GB of flatpak data (>20GB threshold) should render WARN, got:\n%s", out)
	}
	if !strings.Contains(out, "F7A0113") {
		t.Errorf("BIOS version should be shown, got:\n%s", out)
	}
}

// TestSteamOSConcernCount pins the WARN/CRIT tally feeding the summary line and
// exit code — each independent condition tested so a future field that stops
// being wired in doesn't silently vanish (the cmd verdict tally drift class).
func TestSteamOSConcernCount(t *testing.T) {
	if got := steamOSConcernCount(&models.SteamOSInfo{}); got != 0 {
		t.Errorf("a clean info should have 0 concerns, got %d", got)
	}

	cases := []struct {
		name string
		info models.SteamOSInfo
	}{
		{"rauc booted bad", models.SteamOSInfo{RAUCAvailable: true, RAUCBootedStatus: "bad"}},
		{"rauc inactive bad", models.SteamOSInfo{RAUCAvailable: true, RAUCInactiveStatus: "bad"}},
		{"readonly disabled", models.SteamOSInfo{ReadonlyKnown: true, ReadonlyEnabled: false}},
		{"channel config missing", models.SteamOSInfo{ChannelConfigMissing: true}},
		{"gamescope crashed", models.SteamOSInfo{SessionMode: "gamemode", GamescopeActive: false}},
		{"var full", models.SteamOSInfo{VarUsedPct: 70}},
		{"home full", models.SteamOSInfo{HomeUsedPct: 85}},
		{"update server unreachable", models.SteamOSInfo{UpdateServerKnown: true, UpdateServerReachable: false}},
		{"flatpak data large", models.SteamOSInfo{FlatpakDataGB: 21}},
	}
	for _, c := range cases {
		if got := steamOSConcernCount(&c.info); got != 1 {
			t.Errorf("%s: steamOSConcernCount = %d, want 1", c.name, got)
		}
	}

	secureBootOn := true
	if got := steamOSConcernCount(&models.SteamOSInfo{SecureBootApplicable: true, SecureBootEnabled: &secureBootOn}); got != 1 {
		t.Errorf("Secure Boot enabled (applicable) should count as 1 concern, got %d", got)
	}

	remotePlayIssues := &models.SteamOSInfo{RemotePlay: &models.SteamOSRemotePlay{
		Ports:            []models.RemotePlayPort{{Bound: false, Optional: false}},
		FirewallBlocking: true,
		ARPChecked:       true, APIsolationSuspected: true,
	}}
	if got := steamOSConcernCount(remotePlayIssues); got != 3 {
		t.Errorf("unbound port + firewall blocking + AP isolation should each count, got %d, want 3", got)
	}
}
