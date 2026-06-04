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
	WifiBackend           string `json:"wifi_backend,omitempty"` // iwd / wpa_supplicant / unknown
	WifiDevMode           bool   `json:"wifi_dev_mode,omitempty"`
	UpdateServerReachable bool   `json:"update_server_reachable"`
	UpdateServerKnown     bool   `json:"update_server_known"` // reachability test actually ran
	UpdateServerLatencyMs int    `json:"update_server_latency_ms,omitempty"`

	// ── Remote Play (Spec 22 Part A) ────────────────────────────────────
	RemotePlay *SteamOSRemotePlay `json:"remote_play,omitempty"`

	// ── Deep mode only ──────────────────────────────────────────────────
	Deep              bool     `json:"-"`
	GamescopeErrors   []string `json:"gamescope_errors,omitempty"`
	RAUCLastLog       string   `json:"rauc_last_log,omitempty"`
	ProtonPrefixCount int      `json:"proton_prefix_count,omitempty"`
	CompatDataGB      float64  `json:"compatdata_gb,omitempty"`
	ShaderCacheGB     float64  `json:"shader_cache_gb,omitempty"`
	FlatpakAppCount   int      `json:"flatpak_app_count,omitempty"`
	FlatpakDataGB     float64  `json:"flatpak_data_gb,omitempty"`
	BIOSVersion       string   `json:"bios_version,omitempty"`
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
