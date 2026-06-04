package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestParseSteamOSChannel(t *testing.T) {
	cases := []struct {
		name      string
		content   string
		wantRaw   string
		wantLabel string
	}{
		{"variant rel", "[Server]\nVariant = rel\n", "rel", "stable"},
		{"variant beta", "Variant=beta", "beta", "beta"},
		{"channel key", "Channel = main\n", "main", "main"},
		{"bc", "Variant = bc", "bc", "beta-candidate"},
		{"unknown passes through", "Variant = experimental", "experimental", "experimental"},
		{"absent", "[Server]\nMetaUrl = https://...\n", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, label := parseSteamOSChannel(tc.content)
			if raw != tc.wantRaw || label != tc.wantLabel {
				t.Errorf("got (%q,%q), want (%q,%q)", raw, label, tc.wantRaw, tc.wantLabel)
			}
		})
	}
}

func TestOSReleaseValue(t *testing.T) {
	content := `NAME="SteamOS"
VERSION_ID="3.7.13"
BUILD_ID=20250501.1
VARIANT_ID=steamdeck`
	if got := osReleaseValue(content, "BUILD_ID"); got != "20250501.1" {
		t.Errorf("BUILD_ID: got %q", got)
	}
	if got := osReleaseValue(content, "VERSION_ID"); got != "3.7.13" {
		t.Errorf("VERSION_ID: got %q (quotes should be stripped)", got)
	}
	if got := osReleaseValue(content, "MISSING"); got != "" {
		t.Errorf("missing key: got %q, want empty", got)
	}
}

func TestApplyRAUCJSON(t *testing.T) {
	out := `{
  "booted": "rootfs.0",
  "slots": [
    {"rootfs.0": {"state": "booted",   "boot_status": "good", "bootname": "A"}},
    {"rootfs.1": {"state": "inactive", "boot_status": "bad",  "bootname": "B"}}
  ]
}`
	var info models.SteamOSInfo
	if !applyRAUCJSON(out, &info) {
		t.Fatal("expected JSON to parse")
	}
	if info.RAUCBootedSlot != "A" || info.RAUCBootedStatus != "good" {
		t.Errorf("booted: got %s/%s, want A/good", info.RAUCBootedSlot, info.RAUCBootedStatus)
	}
	if info.RAUCInactiveSlot != "B" || info.RAUCInactiveStatus != "bad" {
		t.Errorf("inactive: got %s/%s, want B/bad", info.RAUCInactiveSlot, info.RAUCInactiveStatus)
	}
}

func TestApplyRAUCJSONRejectsNonRAUC(t *testing.T) {
	var info models.SteamOSInfo
	if applyRAUCJSON(`{"unrelated": true}`, &info) {
		t.Error("should return false when no slots present (caller falls back to text)")
	}
}

func TestApplyRAUCText(t *testing.T) {
	out := `=== System Info ===
  Compatible:  Valve Steam Deck
=== Slot States ===
o [rootfs.0] (/dev/nvme0n1p4, ext4, booted)
        bootname: A
        boot status: good
x [rootfs.1] (/dev/nvme0n1p5, ext4, inactive)
        bootname: B
        boot status: bad`
	var info models.SteamOSInfo
	applyRAUCText(out, &info)
	if info.RAUCBootedSlot != "A" || info.RAUCBootedStatus != "good" {
		t.Errorf("booted: got %s/%s, want A/good", info.RAUCBootedSlot, info.RAUCBootedStatus)
	}
	if info.RAUCInactiveSlot != "B" || info.RAUCInactiveStatus != "bad" {
		t.Errorf("inactive: got %s/%s, want B/bad", info.RAUCInactiveSlot, info.RAUCInactiveStatus)
	}
}

func TestMapSteamOSDevice(t *testing.T) {
	cases := []struct {
		raw            string
		wantName       string
		wantRecognised bool
		wantDeck       bool
	}{
		{"Jupiter", "Steam Deck LCD", true, true},
		{"Galileo", "Steam Deck OLED", true, true},
		{"ROG Ally RC71L", "ASUS ROG Ally", true, false},
		{"ROG Ally X RC72LA", "ASUS ROG Ally X", true, false}, // X must win over plain Ally
		{"83E1", "Lenovo Legion Go S", true, false},
		{"OEMDEVICE", "Unknown AMD handheld", false, false},
		{"", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			name, rec, deck := mapSteamOSDevice(tc.raw)
			if name != tc.wantName || rec != tc.wantRecognised || deck != tc.wantDeck {
				t.Errorf("got (%q,%v,%v), want (%q,%v,%v)", name, rec, deck, tc.wantName, tc.wantRecognised, tc.wantDeck)
			}
		})
	}
}

func TestParseSecureBootVar(t *testing.T) {
	enabled, ok := parseSecureBootVar([]byte{0x06, 0x00, 0x00, 0x00, 0x01})
	if !ok || !enabled {
		t.Errorf("byte 4 = 0x01 should be enabled+ok, got enabled=%v ok=%v", enabled, ok)
	}
	disabled, ok := parseSecureBootVar([]byte{0x06, 0x00, 0x00, 0x00, 0x00})
	if !ok || disabled {
		t.Errorf("byte 4 = 0x00 should be disabled+ok, got enabled=%v ok=%v", disabled, ok)
	}
	if _, ok := parseSecureBootVar([]byte{0x06, 0x00}); ok {
		t.Error("too-short var should return ok=false")
	}
}

func TestFilterGamescopeErrors(t *testing.T) {
	out := `May 01 10:00:00 deck gamescope[1]: starting up
May 01 10:00:01 deck gamescope[1]: drm failed to set mode
May 01 10:00:02 deck gamescope[1]: frame presented
May 01 10:00:03 deck gamescope[1]: assert failed in xwm`
	hits := filterGamescopeErrors(out, 5)
	if len(hits) != 2 {
		t.Fatalf("expected 2 error lines, got %d: %v", len(hits), hits)
	}
}

func TestFilterGamescopeErrorsCaps(t *testing.T) {
	var sb string
	for i := 0; i < 10; i++ {
		sb += "line error here\n"
	}
	hits := filterGamescopeErrors(sb, 3)
	if len(hits) != 3 {
		t.Errorf("expected cap of 3, got %d", len(hits))
	}
}
