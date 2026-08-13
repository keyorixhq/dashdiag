package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const catSteamOS = "SteamOS"

// checkSteamOS turns SteamOS / Steam Deck state into insights. Only fires when
// Detected (gated on platform.IsSteamOS upstream). The single most important
// signal is a "bad" RAUC boot slot — a bad booted slot blocks updates outright
// (CRIT), a bad inactive slot removes the rollback safety net (WARN).
func checkSteamOS(s models.SteamOSInfo) []models.Insight {
	if !s.Detected {
		return nil
	}
	out := checkSteamOSDevice(s)
	out = append(out, checkSteamOSUpdate(s)...)
	out = append(out, checkSteamOSSession(s)...)
	out = append(out, checkSteamOSStorage(s)...)
	out = append(out, checkSteamOSNetwork(s)...)
	out = append(out, checkSteamOSRemotePlay(s)...)
	out = append(out, checkSteamOSDeep(s)...)
	return out
}

// checkSteamOSRemotePlay covers Steam Remote Play readiness (Spec 22 Part A):
// unbound primary ports, a blocking firewall rule, and suspected AP client
// isolation. VR ports (Optional) never warn. AP isolation is inferential → WARN.
func checkSteamOSRemotePlay(s models.SteamOSInfo) []models.Insight {
	rp := s.RemotePlay
	if rp == nil {
		return nil
	}
	var out []models.Insight

	var unbound []string
	for _, p := range rp.Ports {
		if !p.Optional && !p.Bound {
			unbound = append(unbound, fmt.Sprintf("%s/%d", p.Protocol, p.Port))
		}
	}
	if len(unbound) > 0 {
		out = append(out, insight("WARN", catSteamOS,
			fmt.Sprintf("Remote Play port(s) not bound: %s — Steam may not be running or Remote Play is disabled", strings.Join(unbound, ", ")),
			[]string{
				"to fix: launch Steam, then enable Steam → Settings → Remote Play",
				"to inspect: ss -tulpn | grep -E '27031|27036|27037'",
			},
		))
	}

	if rp.FirewallBlocking {
		out = append(out, insight("WARN", catSteamOS,
			"a firewall rule appears to block a Remote Play port",
			[]string{"to inspect: nft list ruleset   (or: iptables -L INPUT -n)"},
		))
	}

	if rp.ARPChecked && rp.APIsolationSuspected {
		out = append(out, insight("WARN", catSteamOS,
			"no LAN peers visible in the ARP cache — router AP client isolation may be blocking Remote Play discovery (inferential)",
			[]string{
				"to fix: disable 'AP isolation' / 'client isolation' in your router settings",
				"note: this is an inference, not a certainty — clients can't see each other under AP isolation even with internet access",
			},
		))
	}
	return out
}

// checkSteamOSDevice covers device identity (Spec 17a): an unrecognised model
// means the hardware thresholds may be wrong, and Secure Boot enabled on a
// non-Steam-Deck device blocks USB recovery until disabled in BIOS.
func checkSteamOSDevice(s models.SteamOSInfo) []models.Insight {
	var out []models.Insight
	if s.DeviceProductRaw != "" && !s.DeviceRecognised {
		out = append(out, insight("INFO", catSteamOS,
			fmt.Sprintf("unrecognised SteamOS device (DMI: %q) — hardware thresholds may not be accurate", s.DeviceProductRaw),
			nil,
		))
	}
	if s.SecureBootApplicable && s.SecureBootEnabled != nil && *s.SecureBootEnabled {
		out = append(out, insight("WARN", catSteamOS,
			"Secure Boot is enabled — USB recovery requires disabling it in BIOS first",
			[]string{
				"to fix: enter BIOS at boot (device-specific key) → Security → Secure Boot → Disabled",
				"note: Steam Deck firmware does not enforce Secure Boot; this applies to other handhelds",
			},
		))
	} else if s.SecureBootApplicable && s.SecureBootEnabled == nil {
		// efivarfs was unmounted, permission-denied, or the SecureBoot variable
		// was malformed/short — the state was never established, mirroring the
		// RAUCAvailable pattern below. Don't let this render identically to
		// "confirmed disabled".
		out = append(out, unverifiedInsight("INFO", catSteamOS,
			"Secure Boot state could not be verified — the efivarfs SecureBoot variable could not be read",
			[]string{"to inspect: cat /sys/firmware/efi/efivars/SecureBoot-*"},
		))
	}
	return out
}

// checkSteamOSUpdate covers the RAUC slots, read-only rootfs, and update channel.
func checkSteamOSUpdate(s models.SteamOSInfo) []models.Insight {
	var out []models.Insight

	// `rauc status` couldn't be read (D-Bus down, rauc.service dead, permission,
	// parse failure). The A/B slot health — the single most important
	// update-blocking signal on SteamOS — was NOT verified. The two checks below
	// are both gated on RAUCAvailable, so without this a failed query reads as a
	// silent OK. INFO doesn't raise the verdict.
	if !s.RAUCAvailable {
		out = append(out, unverifiedInsight("INFO", catSteamOS,
			"RAUC A/B slot health could not be verified — `rauc status` failed or returned no data",
			[]string{"to inspect: rauc status", "check: systemctl status rauc — is the service up?"},
		))
	}

	// RAUC booted slot bad — updates will fail to install.
	if s.RAUCAvailable && strings.EqualFold(s.RAUCBootedStatus, "bad") {
		out = append(out, insight("CRIT", catSteamOS,
			fmt.Sprintf("booted RAUC slot %s has boot status 'bad' — system updates will not install", s.RAUCBootedSlot),
			[]string{
				"to fix: sudo rauc status mark-active booted",
				"to inspect: rauc status",
			},
		))
	} else if s.RAUCAvailable && s.RAUCBootedStatus != "" && !strings.EqualFold(s.RAUCBootedStatus, "good") {
		// Neither "good" nor "bad" — a rauc version this parser doesn't know
		// about, or garbled/truncated output. The single most important
		// update-blocking signal this file covers must not silently read as
		// fine for a status it doesn't recognize.
		out = append(out, unverifiedInsight("INFO", catSteamOS,
			fmt.Sprintf("booted RAUC slot %s reports an unrecognized boot status %q — could not confirm it is healthy",
				s.RAUCBootedSlot, s.RAUCBootedStatus),
			[]string{"to inspect: rauc status"},
		))
	}
	// RAUC inactive slot bad — no rollback safety net.
	if s.RAUCAvailable && strings.EqualFold(s.RAUCInactiveStatus, "bad") {
		out = append(out, insight("WARN", catSteamOS,
			fmt.Sprintf("inactive RAUC slot %s has boot status 'bad' — no rollback available if the next update fails", s.RAUCInactiveSlot),
			[]string{
				fmt.Sprintf("to fix: sudo rauc status mark-good %s", s.RAUCInactiveSlot),
				"or: re-image to restore the slot",
			},
		))
	} else if s.RAUCAvailable && s.RAUCInactiveStatus != "" && !strings.EqualFold(s.RAUCInactiveStatus, "good") {
		out = append(out, unverifiedInsight("INFO", catSteamOS,
			fmt.Sprintf("inactive RAUC slot %s reports an unrecognized boot status %q — could not confirm rollback is available",
				s.RAUCInactiveSlot, s.RAUCInactiveStatus),
			[]string{"to inspect: rauc status"},
		))
	}

	// Read-only rootfs disabled — next update overwrites manual changes.
	if s.ReadonlyKnown && !s.ReadonlyEnabled {
		out = append(out, insight("CRIT", catSteamOS,
			"steamos-readonly is DISABLED — rootfs is writable; the next update will overwrite manual changes and may break the system",
			[]string{
				"to fix: sudo steamos-readonly enable",
				"note: a writable rootfs is the #1 cause of 'an update broke my packages'",
			},
		))
	} else if !s.ReadonlyKnown {
		// `steamos-readonly status` failed to run (binary missing, non-zero
		// exit, permission denied). Mirrors the RAUCAvailable INFO fallback
		// above — a check that couldn't run must not stay silent, matching
		// the project-wide "degrade to unmeasured, never silent OK" rule.
		out = append(out, unverifiedInsight("INFO", catSteamOS,
			"rootfs writability could not be verified — `steamos-readonly status` failed or is not available",
			[]string{"to inspect: steamos-readonly status"},
		))
	}

	// Update channel / config.
	if s.ChannelConfigMissing {
		out = append(out, insight("WARN", catSteamOS,
			"/etc/steamos-atomupd/client.conf is missing — the updater cannot determine its channel",
			[]string{"to fix: reinstall steamos-atomupd-client or restore the config"},
		))
	} else if s.Channel != "" && s.Channel != "stable" {
		out = append(out, insight("INFO", catSteamOS,
			fmt.Sprintf("update channel is '%s' (not stable) — expected on a dev/test device, unusual otherwise", s.Channel),
			[]string{"to switch: use Settings → System → Update Channel, or steamos-select-branch"},
		))
	}
	return out
}

// checkSteamOSSession covers a stuck Gamescope session.
func checkSteamOSSession(s models.SteamOSInfo) []models.Insight {
	if s.SessionMode == "gamemode" && !s.GamescopeActive {
		return []models.Insight{insight("CRIT", catSteamOS,
			"in Game Mode but gamescope-session is not active — the session has likely crashed (device stuck)",
			[]string{
				"to inspect: systemctl status gamescope-session",
				"to recover: sudo systemctl restart gamescope-session",
			},
		)}
	}
	return nil
}

// checkSteamOSStorage flags the tiny /var (256 MB) and /home.
func checkSteamOSStorage(s models.SteamOSInfo) []models.Insight {
	var out []models.Insight
	if l := levelPct(s.VarUsedPct, 70, 85); l != "" {
		out = append(out, insight(l, catSteamOS,
			fmt.Sprintf("/var at %.0f%% (%.0f / %.0f MB) — fills with journal, update temp files, logs", s.VarUsedPct, s.VarUsedMB, s.VarTotalMB),
			[]string{
				"to fix: sudo journalctl --vacuum-size=50M",
				"to inspect: sudo du -sh /var/* | sort -h | tail",
			},
		))
	}
	if l := levelPct(s.HomeUsedPct, 85, 95); l != "" {
		out = append(out, insight(l, catSteamOS,
			fmt.Sprintf("/home at %.0f%% (%.0f / %.0f GB) — Proton prefixes, shader cache, game saves, flatpaks", s.HomeUsedPct, s.HomeUsedGB, s.HomeTotalGB),
			[]string{"to inspect: du -sh ~/.steam/steam/steamapps/compatdata ~/.steam/steam/shadercache"},
		))
	}
	return out
}

// checkSteamOSNetwork covers Wi-Fi backend and update-server reachability.
func checkSteamOSNetwork(s models.SteamOSInfo) []models.Insight {
	var out []models.Insight
	// Wi-Fi backend (incl. the wpa_supplicant dev-mode note) is owned by dsd net
	// (checkSteamOSWifi) — kept out of here to avoid a duplicate insight in dsd health.
	if s.UpdateServerKnown && !s.UpdateServerReachable {
		out = append(out, insight("WARN", catSteamOS,
			"SteamOS update server (steamdeck-atomupd.steamos.cloud) is unreachable — updates cannot be fetched",
			[]string{
				"to inspect: ping steamdeck-atomupd.steamos.cloud",
				"to inspect: check Wi-Fi / DNS / VPN",
			},
		))
	}
	return out
}

// checkSteamOSDeep covers the deep-only growth checks (shader cache, flatpak).
func checkSteamOSDeep(s models.SteamOSInfo) []models.Insight {
	var out []models.Insight
	// Shader cache is owned by dsd disk (checkSteamOSDisk) — not duplicated here.
	if s.FlatpakDataGB > 20 {
		out = append(out, insight("WARN", catSteamOS,
			fmt.Sprintf("flatpak data is %.1f GB", s.FlatpakDataGB),
			[]string{"to reclaim: flatpak uninstall --unused"},
		))
	}
	return out
}

// checkSteamOSDisk covers the SteamOS-only disk section (Spec 19): btrfs root
// I/O errors (CRIT) vs other counters (WARN), shader-cache growth, broken
// offload bind mounts. Called from checkDiskExtras when disk.SteamOS is set.
func checkSteamOSDisk(d *models.SteamOSDisk) []models.Insight {
	var out []models.Insight

	// btrfs root error counters come from the generic btrfs collector/heuristic
	// (which already runs `btrfs device stats` on every mount) — not duplicated here.
	switch {
	case d.ShaderCacheGB > 30:
		out = append(out, insight("CRIT", catSteamOS,
			fmt.Sprintf("shader cache is %.1f GB — consuming /home aggressively", d.ShaderCacheGB),
			[]string{"to clear: Steam → Settings → Storage", "or per-game: rm -rf ~/.steam/steam/shadercache/<AppID>"},
		))
	case d.ShaderCacheGB > 10:
		out = append(out, insight("WARN", catSteamOS,
			fmt.Sprintf("shader cache is %.1f GB — consider cleanup", d.ShaderCacheGB),
			[]string{"to clear: Steam → Settings → Storage"},
		))
	}

	for _, bm := range d.BindMounts {
		if !bm.OK {
			out = append(out, insight("WARN", catSteamOS,
				fmt.Sprintf("offload bind mount for %s looks broken (expected → %s) — may indicate /home filesystem issues", bm.Path, bm.Target),
				[]string{fmt.Sprintf("to inspect: mount | grep %s", bm.Path), "to inspect: ls -la " + bm.Target},
			))
		}
	}
	return out
}

// checkSteamOSWifi covers the SteamOS Wi-Fi section (Spec 20 + 22B): backend
// anomalies, dual-band SSID conflict, slow Steam CDN DNS, and the connected-link
// quality profile that governs Remote Play streaming (band/width/signal/channel).
func checkSteamOSWifi(w *models.SteamOSWifi) []models.Insight {
	var out []models.Insight

	if w.BothBackends {
		out = append(out, insight("WARN", catSteamOS,
			"both iwd and wpa_supplicant are active — conflicting Wi-Fi backends",
			[]string{"to fix: disable one (SteamOS default is iwd): systemctl disable --now wpa_supplicant"},
		))
	} else if w.DevMode {
		out = append(out, insight("INFO", catSteamOS,
			"Wi-Fi managed by wpa_supplicant (dev-option workaround) — switch back to iwd once the 3.7.x regression is resolved",
			nil,
		))
	}

	if w.SSIDConflict {
		out = append(out, insight("WARN", catSteamOS,
			fmt.Sprintf("SSID %q appears on both 2.4GHz and 5GHz — a known Steam Deck OLED reliability issue", w.ConflictSSID),
			[]string{"to fix: give each band a unique name in your router (e.g. add a _5G suffix)"},
		))
	}

	if w.CDNDNSKnown && w.CDNDNSms > 500 {
		out = append(out, insight("WARN", catSteamOS,
			fmt.Sprintf("Steam CDN DNS is slow (%dms) — may cause slow downloads/updates", w.CDNDNSms),
			[]string{"to fix: Settings → Internet → set DNS to 1.1.1.1 or 8.8.8.8"},
		))
	}

	out = append(out, checkSteamOSWifiQuality(w)...)
	return out
}

// checkSteamOSWifiQuality covers the connected-link Remote Play profile (Spec 22B).
func checkSteamOSWifiQuality(w *models.SteamOSWifi) []models.Insight {
	if !w.Connected {
		return nil // disconnected — can't stream anyway, no WARN
	}
	var out []models.Insight

	if w.BandGHz == 2.4 {
		out = append(out, insight("WARN", catSteamOS,
			"Wi-Fi on 2.4GHz — switch to 5GHz for reliable Remote Play streaming",
			[]string{"to fix: connect to the 5GHz SSID on your router"},
		))
		if w.Channel != 0 && !steamChannel24OK(w.Channel) {
			out = append(out, insight("WARN", catSteamOS,
				fmt.Sprintf("2.4GHz channel %d is not one of the non-overlapping 1/6/11", w.Channel),
				[]string{"to fix: set the router to channel 1, 6, or 11"},
			))
		}
	}

	if w.WidthMHz == 20 {
		out = append(out, insight("WARN", catSteamOS,
			"Wi-Fi channel width is 20MHz — half the throughput of 40/80MHz",
			[]string{"to fix: enable 40/80MHz channel width in your router (5GHz)"},
		))
	}

	if w.SignalDBm != 0 {
		switch {
		case w.SignalDBm < -75:
			out = append(out, insight("CRIT", catSteamOS,
				fmt.Sprintf("Wi-Fi signal %d dBm — poor; move the device closer to the router", w.SignalDBm),
				nil,
			))
		case w.SignalDBm <= -65:
			out = append(out, insight("WARN", catSteamOS,
				fmt.Sprintf("Wi-Fi signal %d dBm — marginal; streaming quality may degrade", w.SignalDBm),
				nil,
			))
		}
	}
	return out
}

// steamChannel24OK reports whether a 2.4GHz channel is non-overlapping (1/6/11).
func steamChannel24OK(ch int) bool {
	return ch == 1 || ch == 6 || ch == 11
}
