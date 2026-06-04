package collectors

import (
	"encoding/json"
	"regexp"
	"strconv"
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

// ── Remote Play parsers (Spec 22 Part A) ───────────────────────────────────

// remotePlayWantedPorts is the Steam Remote Play port set (Valve docs): UDP
// 27031/27036 + TCP 27036/27037 are primary; UDP 10400/10401 are optional VR.
func remotePlayWantedPorts() []models.RemotePlayPort {
	return []models.RemotePlayPort{
		{Protocol: "udp", Port: 27031},
		{Protocol: "udp", Port: 27036},
		{Protocol: "tcp", Port: 27036},
		{Protocol: "tcp", Port: 27037},
		{Protocol: "udp", Port: 10400, Optional: true},
		{Protocol: "udp", Port: 10401, Optional: true},
	}
}

// remotePlayPrimaryPorts are the non-optional ports a blocking firewall rule
// would matter for.
var remotePlayPrimaryPorts = []int{27031, 27036, 27037}

// ssSocket is one listening socket parsed from `ss -tulpn`.
type ssSocket struct {
	Proto   string // udp / tcp
	Port    int
	Process string
	PID     int
}

var reSSUsers = regexp.MustCompile(`"([^"]+)",pid=(\d+)`)

// parseSSSockets parses `ss -tulpn` output into listening sockets. ss columns:
// Netid State Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process. The
// port is the segment after the last ':' of the local address (handles
// 0.0.0.0:N, *:N, and [::]:N). The process/pid come from the users:(("p",pid=N))
// field. Lines without a recognisable proto or port are skipped.
func parseSSSockets(out string) []ssSocket {
	var socks []ssSocket
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := fields[0]
		switch proto {
		case "udp", "udp6":
			proto = "udp"
		case "tcp", "tcp6":
			proto = "tcp"
		default:
			continue // header line ("Netid") or unrelated
		}
		local := fields[4]
		idx := strings.LastIndex(local, ":")
		if idx < 0 {
			continue
		}
		port, err := strconv.Atoi(local[idx+1:])
		if err != nil {
			continue
		}
		s := ssSocket{Proto: proto, Port: port}
		if m := reSSUsers.FindStringSubmatch(line); m != nil {
			s.Process = m[1]
			s.PID, _ = strconv.Atoi(m[2])
		}
		socks = append(socks, s)
	}
	return socks
}

// resolveRemotePlayPorts marks each wanted port bound/unbound against the parsed
// sockets, filling process/pid for bound ones. wanted preserves declared order
// (and the Optional flag for VR ports).
func resolveRemotePlayPorts(wanted []models.RemotePlayPort, socks []ssSocket) []models.RemotePlayPort {
	out := make([]models.RemotePlayPort, len(wanted))
	copy(out, wanted)
	for i := range out {
		for _, s := range socks {
			if s.Proto == out[i].Protocol && s.Port == out[i].Port {
				out[i].Bound = true
				out[i].Process = s.Process
				out[i].PID = s.PID
				break
			}
		}
	}
	return out
}

// parseDefaultGateway extracts the gateway IP from `ip route show default`
// ("default via 192.168.1.1 dev wlan0 ...").
func parseDefaultGateway(out string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "via" {
				return fields[i+1]
			}
		}
	}
	return ""
}

// parseARPPeers counts resolved neighbours (entries with an lladdr, not in a
// FAILED/INCOMPLETE state) excluding the gateway, from `ip neigh show`. A
// non-zero count means other LAN devices are visible → AP client isolation is
// not in effect.
func parseARPPeers(out, gateway string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == gateway || !strings.Contains(line, "lladdr") {
			continue
		}
		if strings.Contains(line, "FAILED") || strings.Contains(line, "INCOMPLETE") {
			continue
		}
		n++
	}
	return n
}

// firewallBlocksPorts reports whether a drop/reject rule in the ruleset/iptables
// text references any of the given ports. Inferential and conservative: only a
// line containing both a drop/reject action and a target port counts.
func firewallBlocksPorts(ruleset string, ports []int) bool {
	for _, line := range strings.Split(ruleset, "\n") {
		low := strings.ToLower(line)
		if !strings.Contains(low, "drop") && !strings.Contains(low, "reject") {
			continue
		}
		for _, p := range ports {
			if lineMentionsPort(line, p) {
				return true
			}
		}
	}
	return false
}

// lineMentionsPort reports whether line references port p as a whole number
// (avoids 27031 matching inside 270319).
func lineMentionsPort(line string, p int) bool {
	ps := strconv.Itoa(p)
	for _, tok := range strings.FieldsFunc(line, func(r rune) bool { return r < '0' || r > '9' }) {
		if tok == ps {
			return true
		}
	}
	return false
}

// ── Disk parsers (Spec 19) ─────────────────────────────────────────────────

// btrfsDeviceStats holds summed error counters from `btrfs device stats`.
type btrfsDeviceStats struct {
	Read, Write, Flush, Corruption, Generation int
}

// parseBtrfsDeviceStats sums each error counter across devices from `btrfs
// device stats <mount>` output. Each line is "[/dev/xxx].<counter>  <n>".
func parseBtrfsDeviceStats(out string) btrfsDeviceStats {
	var s btrfsDeviceStats
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil {
			continue
		}
		key := fields[0]
		switch {
		case strings.HasSuffix(key, ".read_io_errs"):
			s.Read += val
		case strings.HasSuffix(key, ".write_io_errs"):
			s.Write += val
		case strings.HasSuffix(key, ".flush_io_errs"):
			s.Flush += val
		case strings.HasSuffix(key, ".corruption_errs"):
			s.Corruption += val
		case strings.HasSuffix(key, ".generation_errs"):
			s.Generation += val
		}
	}
	return s
}

// parseMountPointSet returns the set of mount points from /proc/mounts content
// (mount point is the second whitespace-separated field of each line).
func parseMountPointSet(procMounts string) map[string]bool {
	set := map[string]bool{}
	for _, line := range strings.Split(procMounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			set[fields[1]] = true
		}
	}
	return set
}

// ── Wi-Fi parsers (Spec 20 + 22B) ──────────────────────────────────────────

// iwIface is one wireless interface parsed from `iw dev`.
type iwIface struct {
	Name     string
	SSID     string
	Channel  int
	FreqMHz  int
	WidthMHz int
}

// parseIwDev parses `iw dev` output into wireless interfaces. Channel/freq/width
// are only present when the interface is associated.
func parseIwDev(out string) []iwIface {
	var ifaces []iwIface
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "Interface "):
			ifaces = append(ifaces, iwIface{Name: strings.TrimSpace(strings.TrimPrefix(line, "Interface "))})
		case len(ifaces) == 0:
			continue
		case strings.HasPrefix(line, "ssid "):
			ifaces[len(ifaces)-1].SSID = strings.TrimSpace(strings.TrimPrefix(line, "ssid "))
		case strings.HasPrefix(line, "channel "):
			ch, freq, width := parseIwChannelLine(line)
			i := len(ifaces) - 1
			ifaces[i].Channel, ifaces[i].FreqMHz, ifaces[i].WidthMHz = ch, freq, width
		}
	}
	return ifaces
}

// parseIwChannelLine extracts channel, frequency, and width from a line like
// "channel 149 (5745 MHz), width: 80 MHz, center1: 5775 MHz".
func parseIwChannelLine(line string) (channel, freqMHz, widthMHz int) {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "channel" && i+1 < len(fields) {
			channel, _ = strconv.Atoi(fields[i+1])
		}
	}
	if o := strings.Index(line, "("); o >= 0 {
		if c := strings.Index(line[o:], " MHz)"); c >= 0 {
			freqMHz, _ = strconv.Atoi(strings.TrimSpace(line[o+1 : o+c]))
		}
	}
	if w := strings.Index(line, "width: "); w >= 0 {
		rest := line[w+len("width: "):]
		if sp := strings.IndexByte(rest, ' '); sp >= 0 {
			widthMHz, _ = strconv.Atoi(rest[:sp])
		}
	}
	return channel, freqMHz, widthMHz
}

// parseIwLinkSignal extracts connection state and RSSI from `iw dev <if> link`.
func parseIwLinkSignal(out string) (connected bool, signalDBm int) {
	if strings.Contains(out, "Not connected") {
		return false, 0
	}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "Connected to") {
			connected = true
		}
		if strings.HasPrefix(line, "signal:") {
			if f := strings.Fields(line); len(f) >= 2 { // "signal: -52 dBm"
				signalDBm, _ = strconv.Atoi(f[1])
				connected = true
			}
		}
	}
	return connected, signalDBm
}

// bandFromFreqMHz maps a frequency to its Wi-Fi band in GHz (0 = unknown).
func bandFromFreqMHz(mhz int) float64 {
	switch {
	case mhz >= 2400 && mhz < 2500:
		return 2.4
	case mhz >= 5925:
		return 6 // Wi-Fi 6E
	case mhz >= 4900 && mhz <= 5900:
		return 5
	default:
		return 0
	}
}

// detectSSIDConflict reports whether the same non-empty SSID appears on more
// than one interface (the dual-band Steam Deck OLED reliability issue).
func detectSSIDConflict(ifaces []iwIface) (conflict bool, ssid string) {
	counts := map[string]int{}
	for _, ifc := range ifaces {
		if ifc.SSID != "" {
			counts[ifc.SSID]++
		}
	}
	for name, n := range counts {
		if n >= 2 {
			return true, name
		}
	}
	return false, ""
}
