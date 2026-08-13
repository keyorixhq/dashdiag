package cmd

import (
	"context"
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

// TestPrintSteamOSSystemVersionAndChannel covers the version/channel/BuildID
// identity line's fallback and populated branches, plus the
// ChannelConfigMissing WARN, none exercised by the readonly-focused table above.
func TestPrintSteamOSSystemVersionAndChannel(t *testing.T) {
	fallback := captureStdout(t, func() {
		printSteamOSSystem(&models.SteamOSInfo{}, output.ModePlain)
	})
	if !strings.Contains(fallback, "SteamOS unknown") || !strings.Contains(fallback, "unknown channel") {
		t.Errorf("no version/channel set should fall back to 'unknown', got:\n%s", fallback)
	}

	populated := captureStdout(t, func() {
		printSteamOSSystem(&models.SteamOSInfo{Version: "3.6.19", Channel: "stable", BuildID: "20240611.1"}, output.ModePlain)
	})
	if !strings.Contains(populated, "SteamOS 3.6.19") || !strings.Contains(populated, "stable channel") {
		t.Errorf("a set version/channel should be shown, got:\n%s", populated)
	}
	if !strings.Contains(populated, "BUILD_ID: 20240611.1") {
		t.Errorf("a set BuildID should be shown, got:\n%s", populated)
	}

	missingConfig := captureStdout(t, func() {
		printSteamOSSystem(&models.SteamOSInfo{ChannelConfigMissing: true}, output.ModePlain)
	})
	if !strings.Contains(missingConfig, "client.conf missing") {
		t.Errorf("a missing channel config should warn, got:\n%s", missingConfig)
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

	reachable := captureStdout(t, func() {
		printSteamOSNetwork(&models.SteamOSInfo{UpdateServerKnown: true, UpdateServerReachable: true, UpdateServerLatencyMs: 42}, output.ModePlain)
	})
	if !strings.Contains(reachable, "reachable (42ms)") {
		t.Errorf("a reachable update server should show its latency, got:\n%s", reachable)
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

	// A bound port with no Process name reported falls back to the bare "bound"
	// label — distinct from the process+PID case in
	// TestPrintSteamOSRemotePlayBoundAndFirewall.
	boundNoProcess := captureStdout(t, func() {
		printSteamOSRemotePlay(&models.SteamOSInfo{RemotePlay: &models.SteamOSRemotePlay{
			Ports: []models.RemotePlayPort{{Protocol: "udp", Port: 27036, Bound: true}},
		}}, output.ModePlain)
	})
	if !strings.Contains(boundNoProcess, "bound") {
		t.Errorf("a bound port with no process name should say 'bound', got:\n%s", boundNoProcess)
	}

	// ARP checked, no isolation suspected: the healthy default branch showing
	// the peer count — distinct from both the "not checked" and "isolation
	// suspected" cases above.
	peersVisible := captureStdout(t, func() {
		printSteamOSRemotePlay(&models.SteamOSInfo{RemotePlay: &models.SteamOSRemotePlay{
			ARPChecked: true, APIsolationSuspected: false, LANPeersVisible: 3,
		}}, output.ModePlain)
	})
	if !strings.Contains(peersVisible, "3 peer(s) in ARP cache") {
		t.Errorf("visible LAN peers should show the count, got:\n%s", peersVisible)
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

// TestPrintSteamOSReportDispatch covers printSteamOSReport's top-level
// healthy branch and the --deep dispatch (the not-detected branch is already
// covered by TestPrintSteamOSReportNotDetected).
func TestPrintSteamOSReportDispatch(t *testing.T) {
	healthy := captureStdout(t, func() {
		printSteamOSReport(&models.SteamOSInfo{Detected: true}, 0, output.ModePlain)
	})
	if !strings.Contains(healthy, "SteamOS healthy") {
		t.Errorf("no concerns should read healthy, got:\n%s", healthy)
	}

	deep := captureStdout(t, func() {
		printSteamOSReport(&models.SteamOSInfo{Detected: true, Deep: true, BIOSVersion: "F7A0113"}, 0, output.ModePlain)
	})
	if !strings.Contains(deep, "F7A0113") {
		t.Errorf("Deep=true should render the [Deep] section, got:\n%s", deep)
	}

	// A genuine concern (rootfs writable) must surface the WARN summary line
	// through the top-level dispatcher — not just via steamOSConcernCount
	// itself (already pinned by TestSteamOSConcernCount).
	concerning := captureStdout(t, func() {
		printSteamOSReport(&models.SteamOSInfo{Detected: true, ReadonlyKnown: true, ReadonlyEnabled: false}, 0, output.ModePlain)
	})
	if !strings.Contains(concerning, "SteamOS concern(s) found") {
		t.Errorf("a genuine concern should surface the warn summary, got:\n%s", concerning)
	}
}

// TestPrintSteamOSDeviceRecognisedAndSecureBoot covers the recognised-device
// and Secure-Boot-disabled/unknown branches that TestPrintSteamOSDevice
// doesn't reach.
func TestPrintSteamOSDeviceRecognisedAndSecureBoot(t *testing.T) {
	recognised := captureStdout(t, func() {
		printSteamOSDevice(&models.SteamOSInfo{DeviceName: "Steam Deck", DeviceProductRaw: "Jupiter", DeviceRecognised: true}, output.ModePlain)
	})
	if !strings.Contains(recognised, "Steam Deck") || strings.Contains(recognised, "unrecognised") {
		t.Errorf("a recognised device should be shown without the unrecognised caveat, got:\n%s", recognised)
	}

	sbOff := false
	sbDisabled := captureStdout(t, func() {
		printSteamOSDevice(&models.SteamOSInfo{DeviceName: "x", SecureBootApplicable: true, SecureBootEnabled: &sbOff}, output.ModePlain)
	})
	if !strings.Contains(sbDisabled, "disabled") {
		t.Errorf("Secure Boot explicitly disabled should say so, got:\n%s", sbDisabled)
	}

	sbUnknown := captureStdout(t, func() {
		printSteamOSDevice(&models.SteamOSInfo{DeviceName: "x", SecureBootApplicable: true, SecureBootEnabled: nil}, output.ModePlain)
	})
	if !strings.Contains(sbUnknown, "EFI not available") {
		t.Errorf("a nil SecureBootEnabled (EFI unavailable) should say so, got:\n%s", sbUnknown)
	}
}

// TestPrintSteamOSSessionUnknownMode covers the empty-SessionMode fallback.
func TestPrintSteamOSSessionUnknownMode(t *testing.T) {
	out := captureStdout(t, func() { printSteamOSSession(&models.SteamOSInfo{}, output.ModePlain) })
	if !strings.Contains(out, "unknown") {
		t.Errorf("an empty session mode should read unknown, got:\n%s", out)
	}
}

// TestPrintSteamOSRemotePlayBoundAndFirewall covers the bound-port-with-process
// branch and the firewall-known/blocking and firewall-clean branches.
func TestPrintSteamOSRemotePlayBoundAndFirewall(t *testing.T) {
	bound := captureStdout(t, func() {
		printSteamOSRemotePlay(&models.SteamOSInfo{RemotePlay: &models.SteamOSRemotePlay{
			Ports:         []models.RemotePlayPort{{Protocol: "udp", Port: 27036, Bound: true, Process: "steam", PID: 4242}},
			FirewallKnown: true, FirewallBlocking: false,
		}}, output.ModePlain)
	})
	if !strings.Contains(bound, "steam (PID 4242)") {
		t.Errorf("a bound port with a process+PID should show both, got:\n%s", bound)
	}
	if !strings.Contains(bound, "no blocking rules found") {
		t.Errorf("a known, non-blocking firewall should say so, got:\n%s", bound)
	}

	blocking := captureStdout(t, func() {
		printSteamOSRemotePlay(&models.SteamOSInfo{RemotePlay: &models.SteamOSRemotePlay{
			FirewallKnown: true, FirewallBlocking: true,
		}}, output.ModePlain)
	})
	if !strings.Contains(blocking, "may block a Remote Play port") {
		t.Errorf("a blocking firewall should warn, got:\n%s", blocking)
	}
}

// TestPrintSteamOSRemotePlaySanitizesControlChars guards against
// terminal-escape injection via the process name bound to a Remote Play
// port, parsed from `ss` output (ultimately /proc/<pid>/comm) — fully
// attacker-controlled by any unprivileged local user. See cmd-12-02.
func TestPrintSteamOSRemotePlaySanitizesControlChars(t *testing.T) {
	const esc = "\x1b[2J"
	out := captureStdout(t, func() {
		printSteamOSRemotePlay(&models.SteamOSInfo{RemotePlay: &models.SteamOSRemotePlay{
			Ports:         []models.RemotePlayPort{{Protocol: "udp", Port: 27036, Bound: true, Process: "evil" + esc + "proc", PID: 1}},
			FirewallKnown: true,
		}}, output.ModePlain)
	})
	if strings.Contains(out, esc) {
		t.Errorf("printSteamOSRemotePlay must strip terminal escape sequences from process names, got:\n%q", out)
	}
}

// TestPrintSteamOSDeepExtras covers the Proton/GamescopeErrors/RAUCLastLog
// branches of printSteamOSDeep, which TestPrintSteamOSDeep doesn't reach.
func TestPrintSteamOSDeepExtras(t *testing.T) {
	out := captureStdout(t, func() {
		printSteamOSDeep(&models.SteamOSInfo{
			ProtonPrefixCount: 5, CompatDataGB: 12.5,
			GamescopeErrors: []string{"failed to init vulkan"},
			RAUCLastLog:     "slot A: marked good",
		}, output.ModePlain)
	})
	if !strings.Contains(out, "Proton prefixes: 5") || !strings.Contains(out, "12.5 GB") {
		t.Errorf("Proton prefix count and compatdata size should be shown, got:\n%s", out)
	}
	if !strings.Contains(out, "failed to init vulkan") {
		t.Errorf("gamescope errors should be listed, got:\n%s", out)
	}
	if !strings.Contains(out, "slot A: marked good") {
		t.Errorf("the last RAUC log line should be shown, got:\n%s", out)
	}
}

// TestRunSteamOS exercises runSteamOS's real (read-only) collector wiring in
// --plain and --json mode. This test host is not a SteamOS system, so both
// should render the "not detected" report without error — the same real-I/O
// precedent as cpu_report_test.go / hardware_test.go.
func TestRunSteamOS(t *testing.T) {
	plainCmd := newBareCloudCmd()
	plainCmd.SetContext(context.Background())
	_ = plainCmd.Flags().Set("plain", "true")
	plainOut := captureStdout(t, func() {
		if err := runSteamOS(plainCmd, nil); err != nil {
			t.Fatalf("runSteamOS (plain): %v", err)
		}
	})
	if !strings.Contains(plainOut, "SteamOS") {
		t.Errorf("plain mode should mention SteamOS, got: %q", plainOut)
	}

	jsonCmd := newBareCloudCmd()
	jsonCmd.SetContext(context.Background())
	_ = jsonCmd.Flags().Set("json", "true")
	jsonOut := captureStdout(t, func() {
		if err := runSteamOS(jsonCmd, nil); err != nil {
			t.Fatalf("runSteamOS (json): %v", err)
		}
	})
	if !strings.Contains(jsonOut, "{") {
		t.Errorf("json mode should emit JSON, got: %q", jsonOut)
	}
}
