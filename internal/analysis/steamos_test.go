package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func steamLevels(insights []models.Insight) map[string]int {
	m := map[string]int{}
	for _, i := range insights {
		m[i.Level]++
	}
	return m
}

func TestCheckSteamOSQuietWhenNotDetected(t *testing.T) {
	if got := checkSteamOS(models.SteamOSInfo{Detected: false}); len(got) != 0 {
		t.Errorf("expected no insights when not SteamOS, got %v", got)
	}
}

func TestCheckSteamOSHealthy(t *testing.T) {
	info := models.SteamOSInfo{
		Detected:         true,
		RAUCAvailable:    true,
		RAUCBootedStatus: "good", RAUCInactiveStatus: "good",
		ReadonlyKnown: true, ReadonlyEnabled: true,
		Channel: "stable", SessionMode: "gamemode", GamescopeActive: true,
		VarUsedPct: 30, HomeUsedPct: 24,
		UpdateServerKnown: true, UpdateServerReachable: true,
	}
	if got := checkSteamOS(info); len(got) != 0 {
		t.Errorf("healthy deck should produce no insights, got %v", got)
	}
}

func TestCheckSteamOSBadBootedSlotIsCrit(t *testing.T) {
	info := models.SteamOSInfo{
		Detected: true, RAUCAvailable: true,
		RAUCBootedSlot: "A", RAUCBootedStatus: "bad",
		ReadonlyKnown: true, ReadonlyEnabled: true,
	}
	got := checkSteamOS(info)
	if steamLevels(got)["CRIT"] == 0 {
		t.Fatalf("bad booted slot must be CRIT, got %v", got)
	}
	if !strings.Contains(got[0].Message, "updates will not install") {
		t.Errorf("unexpected message: %q", got[0].Message)
	}
}

func TestCheckSteamOSBadInactiveSlotIsWarn(t *testing.T) {
	info := models.SteamOSInfo{
		Detected: true, RAUCAvailable: true,
		RAUCBootedSlot: "A", RAUCBootedStatus: "good",
		RAUCInactiveSlot: "B", RAUCInactiveStatus: "bad",
		ReadonlyKnown: true, ReadonlyEnabled: true,
	}
	lv := steamLevels(checkSteamOS(info))
	if lv["WARN"] == 0 || lv["CRIT"] != 0 {
		t.Errorf("bad inactive slot should be WARN only, got %v", lv)
	}
}

func TestCheckSteamOSReadonlyDisabledIsCrit(t *testing.T) {
	info := models.SteamOSInfo{Detected: true, ReadonlyKnown: true, ReadonlyEnabled: false}
	if steamLevels(checkSteamOS(info))["CRIT"] == 0 {
		t.Error("disabled steamos-readonly must be CRIT")
	}
}

func TestCheckSteamOSReadonlyUnknownStaysQuiet(t *testing.T) {
	// ReadonlyKnown=false means the command could not run — don't assert "writable".
	info := models.SteamOSInfo{Detected: true, ReadonlyKnown: false}
	for _, i := range checkSteamOS(info) {
		if strings.Contains(i.Message, "readonly") || strings.Contains(i.Message, "writable") {
			t.Errorf("should not emit a readonly verdict when status unknown: %q", i.Message)
		}
	}
}

func TestCheckSteamOSStuckGameModeIsCrit(t *testing.T) {
	info := models.SteamOSInfo{Detected: true, SessionMode: "gamemode", GamescopeActive: false}
	if steamLevels(checkSteamOS(info))["CRIT"] == 0 {
		t.Error("Game Mode with inactive gamescope must be CRIT")
	}
}

func TestCheckSteamOSVarThresholds(t *testing.T) {
	warn := checkSteamOS(models.SteamOSInfo{Detected: true, VarUsedPct: 75})
	if steamLevels(warn)["WARN"] == 0 {
		t.Error("/var at 75% should WARN")
	}
	crit := checkSteamOS(models.SteamOSInfo{Detected: true, VarUsedPct: 90})
	if steamLevels(crit)["CRIT"] == 0 {
		t.Error("/var at 90% should CRIT")
	}
}

func TestCheckSteamOSUpdateServerUnreachableIsWarn(t *testing.T) {
	info := models.SteamOSInfo{Detected: true, UpdateServerKnown: true, UpdateServerReachable: false}
	if steamLevels(checkSteamOS(info))["WARN"] == 0 {
		t.Error("unreachable update server should WARN")
	}
}

func TestCheckSteamOSUnrecognisedDeviceIsInfo(t *testing.T) {
	info := models.SteamOSInfo{Detected: true, DeviceProductRaw: "OEMDEVICE", DeviceRecognised: false}
	lv := steamLevels(checkSteamOS(info))
	if lv["INFO"] == 0 || lv["WARN"] != 0 || lv["CRIT"] != 0 {
		t.Errorf("unrecognised device should be INFO only, got %v", lv)
	}
}

func TestCheckSteamOSSecureBootEnabledIsWarn(t *testing.T) {
	enabled := true
	info := models.SteamOSInfo{
		Detected: true, DeviceProductRaw: "ROG Ally RC71L", DeviceRecognised: true,
		SecureBootApplicable: true, SecureBootEnabled: &enabled,
	}
	if steamLevels(checkSteamOS(info))["WARN"] == 0 {
		t.Error("Secure Boot enabled on non-Deck should WARN")
	}
}

func TestCheckSteamOSRemotePlayUnboundPortsWarn(t *testing.T) {
	info := models.SteamOSInfo{Detected: true, RemotePlay: &models.SteamOSRemotePlay{
		Ports: []models.RemotePlayPort{
			{Protocol: "udp", Port: 27031, Bound: false},
			{Protocol: "tcp", Port: 27036, Bound: false},
		},
	}}
	if steamLevels(checkSteamOS(info))["WARN"] == 0 {
		t.Error("unbound primary Remote Play ports should WARN")
	}
}

func TestCheckSteamOSRemotePlayVRUnboundIsQuiet(t *testing.T) {
	// All primary bound, only optional VR ports unbound → no WARN.
	info := models.SteamOSInfo{Detected: true, RemotePlay: &models.SteamOSRemotePlay{
		Ports: []models.RemotePlayPort{
			{Protocol: "udp", Port: 27031, Bound: true},
			{Protocol: "udp", Port: 27036, Bound: true},
			{Protocol: "tcp", Port: 27036, Bound: true},
			{Protocol: "tcp", Port: 27037, Bound: true},
			{Protocol: "udp", Port: 10400, Optional: true, Bound: false},
		},
		FirewallKnown: true,
	}}
	if got := checkSteamOS(info); len(got) != 0 {
		t.Errorf("all primary bound + only VR unbound should be quiet, got %v", got)
	}
}

func TestCheckSteamOSRemotePlayAPIsolationWarn(t *testing.T) {
	allBound := []models.RemotePlayPort{
		{Protocol: "udp", Port: 27031, Bound: true},
		{Protocol: "udp", Port: 27036, Bound: true},
		{Protocol: "tcp", Port: 27036, Bound: true},
		{Protocol: "tcp", Port: 27037, Bound: true},
	}
	info := models.SteamOSInfo{Detected: true, RemotePlay: &models.SteamOSRemotePlay{
		Ports: allBound, FirewallKnown: true, ARPChecked: true, APIsolationSuspected: true,
	}}
	if steamLevels(checkSteamOS(info))["WARN"] == 0 {
		t.Error("suspected AP isolation should WARN")
	}
}

func TestCheckSteamOSRemotePlayNotCheckedQuiet(t *testing.T) {
	// ARPChecked=false (recent boot) must not produce an isolation warning.
	allBound := []models.RemotePlayPort{
		{Protocol: "udp", Port: 27031, Bound: true},
		{Protocol: "udp", Port: 27036, Bound: true},
		{Protocol: "tcp", Port: 27036, Bound: true},
		{Protocol: "tcp", Port: 27037, Bound: true},
	}
	info := models.SteamOSInfo{Detected: true, RemotePlay: &models.SteamOSRemotePlay{
		Ports: allBound, FirewallKnown: true, ARPChecked: false, APIsolationSuspected: true,
	}}
	for _, i := range checkSteamOS(info) {
		if strings.Contains(i.Message, "isolation") {
			t.Errorf("must not warn on isolation when ARPChecked=false: %q", i.Message)
		}
	}
}

func TestCheckSteamOSSecureBootSuppressedOnDeck(t *testing.T) {
	// Steam Deck: SecureBootApplicable=false → never warn even if a stray value is set.
	enabled := true
	info := models.SteamOSInfo{Detected: true, SecureBootApplicable: false, SecureBootEnabled: &enabled}
	for _, i := range checkSteamOS(info) {
		if strings.Contains(i.Message, "Secure Boot") {
			t.Errorf("Secure Boot must be suppressed on Steam Deck, got %q", i.Message)
		}
	}
}

// ── checkSteamOSDisk (Spec 19) ────────────────────────────────────────────

func TestCheckSteamOSDiskShaderCacheThresholds(t *testing.T) {
	if steamLevels(checkSteamOSDisk(&models.SteamOSDisk{ShaderCacheGB: 14}))["WARN"] == 0 {
		t.Error("14GB shader cache should WARN")
	}
	if steamLevels(checkSteamOSDisk(&models.SteamOSDisk{ShaderCacheGB: 35}))["CRIT"] == 0 {
		t.Error("35GB shader cache should CRIT")
	}
}

func TestCheckSteamOSDiskBrokenBindMountWarn(t *testing.T) {
	d := &models.SteamOSDisk{BindMounts: []models.SteamOSBindMount{
		{Path: "/opt", Target: "/home/.steamos/offload/opt", OK: true},
		{Path: "/root", Target: "/home/.steamos/offload/root", OK: false},
	}}
	if steamLevels(checkSteamOSDisk(d))["WARN"] == 0 {
		t.Error("broken bind mount should WARN")
	}
}

func TestCheckSteamOSDiskHealthyQuiet(t *testing.T) {
	d := &models.SteamOSDisk{
		ShaderCacheGB: 3,
		BindMounts: []models.SteamOSBindMount{
			{Path: "/opt", OK: true}, {Path: "/root", OK: true},
		},
	}
	if got := checkSteamOSDisk(d); len(got) != 0 {
		t.Errorf("healthy SteamOS disk should be quiet, got %v", got)
	}
}

// ── checkSteamOSWifi (Spec 20 + 22B) ──────────────────────────────────────

func TestCheckSteamOSWifiBothBackendsWarn(t *testing.T) {
	if steamLevels(checkSteamOSWifi(&models.SteamOSWifi{BothBackends: true}))["WARN"] == 0 {
		t.Error("both backends active should WARN")
	}
}

func TestCheckSteamOSWifiDevModeInfo(t *testing.T) {
	lv := steamLevels(checkSteamOSWifi(&models.SteamOSWifi{DevMode: true}))
	if lv["INFO"] == 0 || lv["WARN"] != 0 {
		t.Errorf("dev-mode backend should be INFO only, got %v", lv)
	}
}

func TestCheckSteamOSWifiSSIDConflictWarn(t *testing.T) {
	if steamLevels(checkSteamOSWifi(&models.SteamOSWifi{SSIDConflict: true, ConflictSSID: "Home"}))["WARN"] == 0 {
		t.Error("SSID conflict should WARN")
	}
}

func TestCheckSteamOSWifiSlowDNSWarn(t *testing.T) {
	if steamLevels(checkSteamOSWifi(&models.SteamOSWifi{CDNDNSKnown: true, CDNDNSms: 680}))["WARN"] == 0 {
		t.Error("slow CDN DNS should WARN")
	}
	if got := checkSteamOSWifi(&models.SteamOSWifi{CDNDNSKnown: true, CDNDNSms: 40}); len(got) != 0 {
		t.Errorf("fast DNS should be quiet, got %v", got)
	}
}

func TestCheckSteamOSWifiQualityProfile(t *testing.T) {
	// 2.4GHz + 20MHz width + marginal signal → multiple WARNs, no CRIT.
	w := &models.SteamOSWifi{Connected: true, BandGHz: 2.4, Channel: 6, WidthMHz: 20, SignalDBm: -70}
	lv := steamLevels(checkSteamOSWifi(w))
	if lv["WARN"] < 3 || lv["CRIT"] != 0 {
		t.Errorf("expected >=3 WARN, 0 CRIT, got %v", lv)
	}
	// Channel 6 is non-overlapping → no extra channel warn beyond the band warn.
	w2 := &models.SteamOSWifi{Connected: true, BandGHz: 2.4, Channel: 3, WidthMHz: 80, SignalDBm: -50}
	if steamLevels(checkSteamOSWifi(w2))["WARN"] < 2 {
		t.Error("2.4GHz on overlapping channel 3 should add a channel WARN")
	}
}

func TestCheckSteamOSWifiWeakSignalCrit(t *testing.T) {
	w := &models.SteamOSWifi{Connected: true, BandGHz: 5, WidthMHz: 80, SignalDBm: -80}
	if steamLevels(checkSteamOSWifi(w))["CRIT"] == 0 {
		t.Error("signal < -75 dBm should be CRIT")
	}
}

func TestCheckSteamOSWifiHealthy5GHzQuiet(t *testing.T) {
	w := &models.SteamOSWifi{
		Backend: "iwd", CDNDNSKnown: true, CDNDNSms: 30,
		Connected: true, BandGHz: 5, Channel: 149, WidthMHz: 80, SignalDBm: -52,
	}
	if got := checkSteamOSWifi(w); len(got) != 0 {
		t.Errorf("healthy 5GHz link should be quiet, got %v", got)
	}
}

func TestCheckSteamOSWifiNotConnectedQuiet(t *testing.T) {
	// Disconnected: no quality WARN even with bad-looking zero values.
	w := &models.SteamOSWifi{Backend: "iwd", CDNDNSKnown: true, CDNDNSms: 30, Connected: false}
	if got := checkSteamOSWifi(w); len(got) != 0 {
		t.Errorf("disconnected Wi-Fi should be quiet, got %v", got)
	}
}
