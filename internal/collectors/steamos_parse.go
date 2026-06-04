package collectors

import (
	"encoding/json"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Pure parsers for `dsd steamos`, kept free of build tags and live-system calls
// so they are unit-testable on any OS (the live probing lives in
// steamos_linux.go).

// osReleaseValue extracts a single key from /etc/os-release content.
func osReleaseValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && k == key {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// parseSteamOSChannel reads the steamos-atomupd client.conf and returns the raw
// channel/variant value and its human label. The config is INI-style; the
// channel lives in a "Variant" key. Values map: rel→stable, rc→rc, beta→beta,
// bc→beta-candidate, main→main.
func parseSteamOSChannel(content string) (raw, label string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key := strings.ToLower(strings.TrimSpace(k)); key == "variant" || key == "channel" {
			raw = strings.TrimSpace(v)
			return raw, mapSteamOSChannel(raw)
		}
	}
	return "", ""
}

func mapSteamOSChannel(raw string) string {
	switch strings.ToLower(raw) {
	case "rel", "stable":
		return "stable"
	case "rc":
		return "rc"
	case "beta":
		return "beta"
	case "bc":
		return "beta-candidate"
	case "main":
		return "main"
	default:
		return raw
	}
}

// mapSteamOSDevice maps a DMI product_name to a canonical SteamOS device name.
// Returns whether the model is recognised and whether it is a Steam Deck (whose
// firmware does not enforce Secure Boot, so that check is suppressed). Uses
// substring matching because DMI names sometimes carry revision suffixes.
func mapSteamOSDevice(raw string) (name string, recognised, isDeck bool) {
	r := strings.TrimSpace(raw)
	switch {
	case r == "Jupiter":
		return "Steam Deck LCD", true, true
	case r == "Galileo":
		return "Steam Deck OLED", true, true
	case strings.Contains(r, "ROG Ally X"):
		return "ASUS ROG Ally X", true, false
	case strings.Contains(r, "ROG Ally"):
		return "ASUS ROG Ally", true, false
	case strings.Contains(r, "Legion Go S") || strings.Contains(r, "83E1"):
		return "Lenovo Legion Go S", true, false
	case r == "":
		return "", false, false
	default:
		return "Unknown AMD handheld", false, false
	}
}

// parseSecureBootVar reads the Secure Boot state from the raw efivar bytes. The
// first 4 bytes are EFI variable attributes; byte 4 is the state (0x01 =
// enabled). ok is false when the variable is too short to be valid.
func parseSecureBootVar(data []byte) (enabled, ok bool) {
	if len(data) < 5 {
		return false, false
	}
	return data[4] == 0x01, true
}

// raucSlotJSON is a single slot's fields in `rauc status --output-format=json`.
type raucSlotJSON struct {
	State      string `json:"state"`       // booted / inactive / active
	BootStatus string `json:"boot_status"` // good / bad
	Bootname   string `json:"bootname"`    // A / B
}

// applyRAUCJSON parses RAUC JSON status into info. The "slots" array holds
// single-key objects ({"rootfs.0": {...}}). Returns false if the JSON is not the
// expected shape so the caller can fall back to text parsing.
func applyRAUCJSON(out string, info *models.SteamOSInfo) bool {
	var doc struct {
		Slots []map[string]raucSlotJSON `json:"slots"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Slots) == 0 {
		return false
	}
	found := false
	for _, slotMap := range doc.Slots {
		for _, slot := range slotMap {
			name := slot.Bootname
			if name == "" {
				continue
			}
			found = true
			if slot.State == "booted" {
				info.RAUCBootedSlot = name
				info.RAUCBootedStatus = slot.BootStatus
			} else {
				info.RAUCInactiveSlot = name
				info.RAUCInactiveStatus = slot.BootStatus
			}
		}
	}
	return found
}

// applyRAUCText parses the plain `rauc status` text. Each slot block looks like:
//
//	o [rootfs.0] (/dev/..., ext4, booted)
//	    bootname: A
//	    boot status: good
//
// "booted" / "active" in the slot header marks the running slot.
func applyRAUCText(out string, info *models.SteamOSInfo) {
	var curName, curStatus string
	booted := false
	flush := func() {
		if curName == "" {
			return
		}
		if booted {
			info.RAUCBootedSlot = curName
			info.RAUCBootedStatus = curStatus
		} else {
			info.RAUCInactiveSlot = curName
			info.RAUCInactiveStatus = curStatus
		}
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "o [") || strings.HasPrefix(trimmed, "x ["):
			flush()
			curName, curStatus, booted = "", "", strings.Contains(trimmed, "booted")
		case strings.HasPrefix(trimmed, "bootname:"):
			curName = strings.TrimSpace(strings.TrimPrefix(trimmed, "bootname:"))
		case strings.HasPrefix(trimmed, "boot status:"):
			curStatus = strings.TrimSpace(strings.TrimPrefix(trimmed, "boot status:"))
		}
	}
	flush()
}

// filterGamescopeErrors keeps up to maxLines journal lines that look like errors.
func filterGamescopeErrors(out string, maxLines int) []string {
	needles := []string{"error", "failed", "assert", "abort", "crash", "killed", "drm"}
	var hits []string
	for _, line := range strings.Split(out, "\n") {
		low := strings.ToLower(line)
		for _, n := range needles {
			if strings.Contains(low, n) {
				hits = append(hits, strings.TrimSpace(line))
				break
			}
		}
	}
	if len(hits) > maxLines {
		hits = hits[len(hits)-maxLines:] // most recent
	}
	return hits
}
