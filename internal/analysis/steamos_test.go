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
		WifiBackend: "iwd", UpdateServerKnown: true, UpdateServerReachable: true,
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
