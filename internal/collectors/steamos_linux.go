//go:build linux

package collectors

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// SteamOSCollector gathers Steam Deck / SteamOS diagnostics: RAUC A/B slot
// health, read-only rootfs state, the Gamescope session, the tiny /var and
// /home partitions, and Wi-Fi backend. All shell-outs are gated behind
// SteamOSAvailable() so this is zero-cost on non-SteamOS Linux.
type SteamOSCollector struct {
	Deep bool
}

func NewSteamOSCollector() *SteamOSCollector     { return &SteamOSCollector{} }
func NewSteamOSDeepCollector() *SteamOSCollector { return &SteamOSCollector{Deep: true} }

func (c *SteamOSCollector) Name() string { return "SteamOS" }

func (c *SteamOSCollector) Timeout() time.Duration {
	if c.Deep {
		return 20 * time.Second // du on compatdata/shadercache can be slow
	}
	return 6 * time.Second
}

// SteamOSAvailable reports whether the host is SteamOS (ID=steamos or
// VARIANT_ID=steamdeck). Used by `dsd health` to gate the collector — same
// pattern as KVMAvailable / K8sAvailable.
func SteamOSAvailable() bool {
	return platform.Detect().IsSteamOS
}

// steamdeckUpdateHost is the SteamOS atomic-update server. A failed resolve /
// connect means the device cannot fetch updates.
const steamdeckUpdateHost = "steamdeck-atomupd.steamos.cloud:443"

func (c *SteamOSCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.SteamOSInfo{Deep: c.Deep}

	prof := platform.Detect()
	if !prof.IsSteamOS {
		return info, nil // Detected stays false — cmd shows a graceful INFO
	}
	info.Detected = true
	info.Version = prof.DistroVersion

	c.collectDevice(info)
	c.collectSystem(ctx, info)
	c.collectRAUC(ctx, info)
	c.collectSession(ctx, info)
	c.collectStorage(info)
	c.collectNetwork(ctx, info)
	c.collectRemotePlay(ctx, info)

	if c.Deep {
		c.collectDeep(ctx, info)
	}
	return info, nil
}

// ── Remote Play (Spec 22 Part A) ───────────────────────────────────────────

func (c *SteamOSCollector) collectRemotePlay(ctx context.Context, info *models.SteamOSInfo) {
	rp := &models.SteamOSRemotePlay{}

	if out, err := runCmd(ctx, "ss", "-tulpn"); err == nil {
		rp.Ports = resolveRemotePlayPorts(remotePlayWantedPorts(), parseSSSockets(out))
	} else {
		rp.Ports = remotePlayWantedPorts() // ss unavailable — all unbound
	}

	// Firewall: SteamOS uses nftables; fall back to iptables. A missing binary /
	// empty ruleset is the normal stock state — treat as "not blocking".
	if rule, err := runCmd(ctx, "nft", "list", "ruleset"); err == nil {
		rp.FirewallKnown = true
		rp.FirewallBlocking = firewallBlocksPorts(rule, remotePlayPrimaryPorts)
	} else if rule, err := runCmd(ctx, "iptables", "-L", "INPUT", "-n"); err == nil {
		rp.FirewallKnown = true
		rp.FirewallBlocking = firewallBlocksPorts(rule, remotePlayPrimaryPorts)
	}

	// AP client isolation inference — guarded on uptime (ARP table may be empty
	// right after boot) and on having a gateway to compare against.
	if steamHostUptimeSeconds() >= 120 {
		gwOut, _ := runCmd(ctx, "ip", "route", "show", "default")
		if gw := parseDefaultGateway(gwOut); gw != "" {
			rp.ARPChecked = true
			neighOut, _ := runCmd(ctx, "ip", "neigh", "show")
			rp.LANPeersVisible = parseARPPeers(neighOut, gw)
			rp.APIsolationSuspected = rp.LANPeersVisible == 0
		}
	}

	info.RemotePlay = rp
}

// collectSteamOSDisk gathers the SteamOS-only disk section (Spec 19): btrfs root
// error counters, shader-cache size, offload bind-mount integrity, and /var +
// /home usage. Called by the disk collector's collectLinuxExtras (gated on
// SteamOSAvailable). It owns its timeout since collectLinuxExtras has no context.
// Individual checks degrade to zero/false when a tool or path is absent.
func collectSteamOSDisk() *models.SteamOSDisk {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	d := &models.SteamOSDisk{}

	// btrfs root error counters (live, mounted, zero perf impact).
	if out, err := runCmd(ctx, "btrfs", "device", "stats", "/"); err == nil {
		d.BtrfsRootChecked = true
		s := parseBtrfsDeviceStats(out)
		d.BtrfsReadErrs, d.BtrfsWriteErrs = s.Read, s.Write
		d.BtrfsFlushErrs, d.BtrfsCorruptionErrs, d.BtrfsGenerationErrs = s.Flush, s.Corruption, s.Generation
	}

	// Shader cache size (silently fills /home).
	home := steamUserHome()
	if shader := filepath.Join(home, ".steam/steam/shadercache"); dirExists(shader) {
		d.ShaderCacheGB = duGB(ctx, shader)
	}

	// Offload bind mounts: target dir must exist AND the path must be a mount.
	mounts := map[string]bool{}
	if data, err := os.ReadFile("/proc/mounts"); err == nil {
		mounts = parseMountPointSet(string(data))
	}
	for _, bm := range []models.SteamOSBindMount{
		{Path: "/opt", Target: "/home/.steamos/offload/opt"},
		{Path: "/root", Target: "/home/.steamos/offload/root"},
	} {
		bm.OK = dirExists(bm.Target) && mounts[bm.Path]
		d.BindMounts = append(d.BindMounts, bm)
	}

	if total, used, pct, ok := statfsUsage("/var"); ok {
		d.VarTotalMB, d.VarUsedMB, d.VarUsedPct = total/1e6, used/1e6, pct
	}
	if total, used, pct, ok := statfsUsage("/home"); ok {
		d.HomeTotalGB, d.HomeUsedGB, d.HomeUsedPct = total/1e9, used/1e9, pct
	}
	return d
}

func dirExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// steamHostUptimeSeconds returns system uptime from /proc/uptime (0 on error).
func steamHostUptimeSeconds() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return v
}

// secureBootEfivar holds the UEFI Secure Boot state (world-readable when
// efivarfs is mounted, which it is by default on SteamOS).
const secureBootEfivar = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

// ── Device identity (Spec 17a) ─────────────────────────────────────────────

func (c *SteamOSCollector) collectDevice(info *models.SteamOSInfo) {
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		info.DeviceProductRaw = strings.TrimSpace(string(data))
	}
	name, recognised, isDeck := mapSteamOSDevice(info.DeviceProductRaw)
	info.DeviceName = name
	info.DeviceRecognised = recognised

	// Steam Deck firmware does not enforce Secure Boot — skip the check there.
	if isDeck {
		info.SecureBootApplicable = false
		return
	}
	info.SecureBootApplicable = true
	if data, err := os.ReadFile(secureBootEfivar); err == nil { // #nosec G304 — fixed path
		if enabled, ok := parseSecureBootVar(data); ok {
			info.SecureBootEnabled = &enabled
		}
	}
	// SecureBootEnabled stays nil when efivars is absent (non-UEFI).
}

// ── System / channel / readonly ──────────────────────────────────────────

func (c *SteamOSCollector) collectSystem(ctx context.Context, info *models.SteamOSInfo) {
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		info.BuildID = osReleaseValue(string(data), "BUILD_ID")
	}

	const confPath = "/etc/steamos-atomupd/client.conf"
	if data, err := os.ReadFile(confPath); err == nil {
		info.ChannelRaw, info.Channel = parseSteamOSChannel(string(data))
	} else if os.IsNotExist(err) {
		info.ChannelConfigMissing = true
	}

	// steamos-readonly status → "enabled" / "disabled"
	if out, err := runCmd(ctx, "steamos-readonly", "status"); err == nil {
		info.ReadonlyKnown = true
		info.ReadonlyEnabled = strings.Contains(strings.TrimSpace(out), "enabled")
	}
}

// ── RAUC slots ─────────────────────────────────────────────────────────────

func (c *SteamOSCollector) collectRAUC(ctx context.Context, info *models.SteamOSInfo) {
	// Prefer JSON (modern RAUC); fall back to text on older versions.
	if out, err := runCmd(ctx, "rauc", "status", "--output-format=json"); err == nil && out != "" {
		if applyRAUCJSON(out, info) {
			info.RAUCAvailable = true
			return
		}
	}
	if out, err := runCmd(ctx, "rauc", "status"); err == nil && out != "" {
		applyRAUCText(out, info)
		info.RAUCAvailable = true
	}
}

// ── Session ──────────────────────────────────────────────────────────────

func (c *SteamOSCollector) collectSession(ctx context.Context, info *models.SteamOSInfo) {
	info.GamescopeActive = unitActive(ctx, "gamescope-session.service")
	info.SteamLauncherActive = unitActive(ctx, "steam-launcher.service")
	info.SDDMActive = unitActive(ctx, "sddm.service")
	info.SessionMode = detectSessionMode(info)
}

// detectSessionMode infers Game Mode vs Desktop Mode. XDG_SESSION_DESKTOP is the
// most direct signal; otherwise the active display manager / session unit decides.
func detectSessionMode(info *models.SteamOSInfo) string {
	switch strings.ToLower(os.Getenv("XDG_SESSION_DESKTOP")) {
	case "gamescope", "gamescope-wayland":
		return "gamemode"
	case "plasma", "kde", "plasmawayland":
		return "desktop"
	}
	switch {
	case info.GamescopeActive:
		return "gamemode"
	case info.SDDMActive:
		return "desktop"
	default:
		return "unknown"
	}
}

// ── Storage ────────────────────────────────────────────────────────────────

func (c *SteamOSCollector) collectStorage(info *models.SteamOSInfo) {
	if total, used, pct, ok := statfsUsage("/var"); ok {
		info.VarTotalMB = total / 1e6
		info.VarUsedMB = used / 1e6
		info.VarUsedPct = pct
	}
	if total, used, pct, ok := statfsUsage("/home"); ok {
		info.HomeTotalGB = total / 1e9
		info.HomeUsedGB = used / 1e9
		info.HomeUsedPct = pct
	}
}

// statfsUsage returns total bytes, used bytes, and used percent for a mount.
func statfsUsage(mount string) (total, used, pct float64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(mount, &st); err != nil || st.Blocks == 0 {
		return 0, 0, 0, false
	}
	bsize := float64(st.Bsize)
	total = float64(st.Blocks) * bsize
	free := float64(st.Bfree) * bsize
	used = total - free
	pct = (1 - float64(st.Bavail)/float64(st.Blocks)) * 100
	return total, used, pct, true
}

// ── Network ──────────────────────────────────────────────────────────────

func (c *SteamOSCollector) collectNetwork(ctx context.Context, info *models.SteamOSInfo) {
	// iwd is the SteamOS default; wpa_supplicant is the dev-option workaround
	// for the 3.7.x Wi-Fi regression.
	switch {
	case unitActive(ctx, "iwd.service"):
		info.WifiBackend = "iwd"
	case unitActive(ctx, "wpa_supplicant.service"):
		info.WifiBackend = "wpa_supplicant"
		info.WifiDevMode = true
	default:
		info.WifiBackend = "unknown"
	}

	info.UpdateServerKnown = true
	start := time.Now()
	conn, err := net.DialTimeout("tcp", steamdeckUpdateHost, 2*time.Second)
	if err != nil {
		info.UpdateServerReachable = false
		return
	}
	_ = conn.Close()
	info.UpdateServerReachable = true
	info.UpdateServerLatencyMs = int(time.Since(start).Milliseconds())
}

// ── Deep ───────────────────────────────────────────────────────────────────

func (c *SteamOSCollector) collectDeep(ctx context.Context, info *models.SteamOSInfo) {
	// Gamescope session errors from the journal.
	if out, err := runCmd(ctx, "journalctl", "-u", "gamescope-session", "-n", "50", "--no-pager"); err == nil {
		info.GamescopeErrors = filterGamescopeErrors(out, 5)
	}
	// Last RAUC log line (most recent update attempt result).
	if out, err := runCmd(ctx, "journalctl", "-u", "rauc", "-n", "30", "--no-pager"); err == nil {
		if last := lastNonEmptyLine(out); last != "" {
			info.RAUCLastLog = last
		}
	}

	home := steamUserHome()
	compat := filepath.Join(home, ".steam/steam/steamapps/compatdata")
	if entries, err := os.ReadDir(compat); err == nil {
		info.ProtonPrefixCount = len(entries)
		info.CompatDataGB = duGB(ctx, compat)
	}
	shader := filepath.Join(home, ".steam/steam/shadercache")
	if _, err := os.Stat(shader); err == nil {
		info.ShaderCacheGB = duGB(ctx, shader)
	}

	// Flatpak inventory.
	if out, err := runCmd(ctx, "flatpak", "list", "--app"); err == nil {
		info.FlatpakAppCount = countNonEmptyLines(out)
	}
	flatpakData := filepath.Join(home, ".local/share/flatpak")
	if _, err := os.Stat(flatpakData); err == nil {
		info.FlatpakDataGB = duGB(ctx, flatpakData)
	}

	// BIOS version (best-effort — needs root for dmidecode).
	if out, err := runCmd(ctx, "dmidecode", "-s", "bios-version"); err == nil {
		info.BIOSVersion = strings.TrimSpace(out)
	}
}

// steamUserHome returns the Steam Deck user's home. The default user is "deck";
// fall back to $HOME when that path is absent (HoloISO/Bazzite use other names).
func steamUserHome() string {
	if _, err := os.Stat("/home/deck"); err == nil {
		return "/home/deck"
	}
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return "/home/deck"
}

// duGB returns the size of a directory tree in GB via `du -sb` (bytes). Returns
// 0 on any error so a missing tool or permission issue stays quiet.
func duGB(ctx context.Context, path string) float64 {
	out, err := runCmd(ctx, "du", "-sb", path)
	if err != nil {
		return 0
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return 0
	}
	bytes, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return bytes / 1e9
}

// unitActive reports whether a systemd unit is active (is-active exits 0 and
// prints "active").
func unitActive(ctx context.Context, unit string) bool {
	out, err := runCmd(ctx, "systemctl", "is-active", unit)
	return err == nil && strings.TrimSpace(out) == "active"
}

func lastNonEmptyLine(out string) string {
	lines := strings.Split(out, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return t
		}
	}
	return ""
}

func countNonEmptyLines(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}
