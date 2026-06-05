package models

// SteamOSInfo is the output of `dsd steamos`. SteamOS (and the SteamFork /
// HoloISO / Bazzite family) is an immutable Arch derivative built on RAUC A/B
// slots + a read-only rootfs + a Gamescope session. The fields below mirror the
// pain sources that silently break a Steam Deck: a "bad" RAUC slot blocking
// updates, an accidentally-writable rootfs, a stuck Gamescope session, and the
// tiny 256 MB /var filling up.
//
// Detection is gated on platform.Profile.IsSteamOS (ID=steamos or
// VARIANT_ID=steamdeck). On non-SteamOS Linux every collector path is skipped
// and Detected stays false.
type SteamOSInfo struct {
	Detected bool `json:"detected"`

	// ── Device identity (Spec 17a) ──────────────────────────────────────
	// SteamOS 3.7+ runs on more than the Steam Deck (Legion Go S, ROG Ally,
	// …). Device model drives correct /var-size, thermal, and partition
	// assumptions. SecureBootEnabled is a tri-state: nil = not readable
	// (non-UEFI / efivars absent). SecureBootApplicable is false on Steam Deck
	// (its firmware does not enforce Secure Boot for SteamOS).
	DeviceProductRaw     string `json:"device_product_raw,omitempty"` // /sys/class/dmi/id/product_name
	DeviceName           string `json:"device_name,omitempty"`        // canonical, e.g. "Steam Deck OLED"
	DeviceRecognised     bool   `json:"device_recognised"`
	SecureBootApplicable bool   `json:"secure_boot_applicable"`
	SecureBootEnabled    *bool  `json:"secure_boot_enabled"`

	// ── System / update channel ─────────────────────────────────────────
	Version              string `json:"version,omitempty"`  // os-release VERSION_ID, e.g. "3.7.13"
	BuildID              string `json:"build_id,omitempty"` // os-release BUILD_ID
	Channel              string `json:"channel,omitempty"`  // stable / rc / beta / bc / main
	ChannelRaw           string `json:"channel_raw,omitempty"`
	ChannelConfigMissing bool   `json:"channel_config_missing,omitempty"` // /etc/steamos-atomupd/client.conf absent

	// steamos-readonly status. ReadonlyKnown is false when the command could
	// not run, so the heuristic can stay quiet rather than assert "writable".
	ReadonlyEnabled bool `json:"readonly_enabled"`
	ReadonlyKnown   bool `json:"readonly_known"`

	// ── RAUC A/B update slots ───────────────────────────────────────────
	RAUCAvailable      bool   `json:"rauc_available"`
	RAUCBootedSlot     string `json:"rauc_booted_slot,omitempty"`   // bootname, e.g. "A"
	RAUCBootedStatus   string `json:"rauc_booted_status,omitempty"` // good / bad
	RAUCInactiveSlot   string `json:"rauc_inactive_slot,omitempty"`
	RAUCInactiveStatus string `json:"rauc_inactive_status,omitempty"`

	// ── Session ─────────────────────────────────────────────────────────
	SessionMode         string `json:"session_mode,omitempty"` // gamemode / desktop / unknown
	GamescopeActive     bool   `json:"gamescope_session_active"`
	SteamLauncherActive bool   `json:"steam_launcher_active"`
	SDDMActive          bool   `json:"sddm_active"`

	// ── Storage (SteamOS-specific partition sizes) ──────────────────────
	VarUsedPct  float64 `json:"var_used_pct"`
	VarUsedMB   float64 `json:"var_used_mb"`
	VarTotalMB  float64 `json:"var_total_mb"`
	HomeUsedPct float64 `json:"home_used_pct"`
	HomeUsedGB  float64 `json:"home_used_gb"`
	HomeTotalGB float64 `json:"home_total_gb"`

	// ── Network ─────────────────────────────────────────────────────────
	// Wi-Fi backend/SSID/quality live in dsd net (models.SteamOSWifi) — the
	// single authoritative home. Only the atomic-update-server reachability
	// (distinct from net's download-CDN DNS check) is owned here.
	UpdateServerReachable bool `json:"update_server_reachable"`
	UpdateServerKnown     bool `json:"update_server_known"` // reachability test actually ran
	UpdateServerLatencyMs int  `json:"update_server_latency_ms,omitempty"`

	// ── Remote Play (Spec 22 Part A) ────────────────────────────────────
	RemotePlay *SteamOSRemotePlay `json:"remote_play,omitempty"`

	// ── Deep mode only ──────────────────────────────────────────────────
	Deep              bool     `json:"-"`
	GamescopeErrors   []string `json:"gamescope_errors,omitempty"`
	RAUCLastLog       string   `json:"rauc_last_log,omitempty"`
	ProtonPrefixCount int      `json:"proton_prefix_count,omitempty"`
	CompatDataGB      float64  `json:"compatdata_gb,omitempty"`
	// Shader cache lives in dsd disk (models.SteamOSDisk) — its fast path runs in
	// dsd health, so the size check surfaces there; not duplicated here.
	FlatpakAppCount int     `json:"flatpak_app_count,omitempty"`
	FlatpakDataGB   float64 `json:"flatpak_data_gb,omitempty"`
	BIOSVersion     string  `json:"bios_version,omitempty"`
}

// SteamOSWifi is the SteamOS-only Wi-Fi section of `dsd net` (Spec 20 + 22B):
// the Wi-Fi backend (iwd vs the wpa_supplicant dev workaround), dual-band SSID
// conflicts, Steam CDN DNS latency, and the connected-link quality profile
// (band / channel / width / signal) that determines Remote Play streaming quality.
type SteamOSWifi struct {
	Backend      string `json:"backend,omitempty"` // iwd / wpa_supplicant / unknown
	BothBackends bool   `json:"both_backends,omitempty"`
	DevMode      bool   `json:"dev_mode,omitempty"` // wpa_supplicant only (3.7.x workaround)
	SSIDConflict bool   `json:"ssid_conflict,omitempty"`
	ConflictSSID string `json:"conflict_ssid,omitempty"`
	CDNDNSKnown  bool   `json:"-"`
	CDNDNSms     int    `json:"cdn_dns_ms,omitempty"`

	// Connected-link quality profile (Spec 22B).
	Connected    bool    `json:"connected"`
	Interface    string  `json:"interface,omitempty"`
	BandGHz      float64 `json:"band_ghz,omitempty"` // 2.4 / 5 / 6
	Channel      int     `json:"channel,omitempty"`
	FrequencyMHz int     `json:"frequency_mhz,omitempty"`
	WidthMHz     int     `json:"width_mhz,omitempty"`
	SignalDBm    int     `json:"signal_dbm,omitempty"`
}

// SteamOSDisk is the SteamOS-only partition section of `dsd disk` (Spec 19):
// shader-cache growth and the offload bind mounts. These are the SteamOS-specific
// storage concerns NOT already covered by dsd disk's generic checks — btrfs root
// error counters come from the generic btrfs collector (which already runs
// `btrfs device stats` on every btrfs mount), and /var + /home sizes appear in
// the generic Filesystems list (with the 256MB-aware insight owned by dsd steamos).
type SteamOSDisk struct {
	ShaderCacheGB float64            `json:"shader_cache_gb,omitempty"`
	BindMounts    []SteamOSBindMount `json:"bind_mounts,omitempty"`
}

// SteamOSBindMount is a SteamOS offload bind mount (/opt, /root → /home/.steamos/offload/*).
type SteamOSBindMount struct {
	Path   string `json:"path"`
	Target string `json:"target"`
	OK     bool   `json:"ok"`
}

// RemotePlayPort is one Steam Remote Play port and its binding state.
type RemotePlayPort struct {
	Protocol string `json:"protocol"` // "udp" / "tcp"
	Port     int    `json:"port"`
	Bound    bool   `json:"bound"`
	Process  string `json:"process,omitempty"`
	PID      int    `json:"pid,omitempty"`
	Optional bool   `json:"optional,omitempty"` // VR ports — INFO when unbound, never WARN
}

// SteamOSRemotePlay holds Steam Remote Play readiness (Spec 22 Part A): whether
// the discovery/streaming ports are bound, whether the firewall blocks them, and
// an inference about router AP client isolation (which silently breaks LAN
// discovery). AP isolation is inferential — surfaced as WARN, never CRIT.
type SteamOSRemotePlay struct {
	Ports                []RemotePlayPort `json:"ports"`
	FirewallKnown        bool             `json:"-"` // false when nft/iptables couldn't be read
	FirewallBlocking     bool             `json:"firewall_blocking"`
	ARPChecked           bool             `json:"-"` // false when uptime < 120s or no gateway
	LANPeersVisible      int              `json:"lan_peers_visible"`
	APIsolationSuspected bool             `json:"ap_isolation_suspected"`
}
