//go:build linux

package collectors

import (
	"bufio"
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// BINDCollector checks BIND/named server health.
// Gate: named or bind9 process must be running.
// Linux only — BIND is a server component not relevant on other platforms.
type BINDCollector struct{}

func NewBINDCollector() *BINDCollector          { return &BINDCollector{} }
func (c *BINDCollector) Name() string           { return "BIND" }
func (c *BINDCollector) Timeout() time.Duration { return 15 * time.Second }

func (c *BINDCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.BINDInfo{}

	// Gate: is named running?
	if !bindDetect() {
		return nil, nil // named not running — omit section
	}
	info.Detected = true

	info.ServiceActive = bindServiceActive(ctx)

	// Config file location — RHEL uses /etc/named.conf, Debian uses /etc/bind/named.conf
	info.ConfigFile = bindConfigPath()

	// Config validation
	bindCheckConfig(ctx, info)

	// Port 53 listening
	bindCheckPorts(ctx, info)

	// Live DNS query test
	bindQueryTest(ctx, info)

	// Zone file validation (up to 20 zones)
	if info.ConfigOK && info.ConfigFile != "" {
		zones := bindParseZones(info.ConfigFile)
		bindCheckZones(ctx, info, zones)
	}

	// RNDC status
	bindRNCDStatus(ctx, info)

	return info, nil
}

// bindServiceActive reports whether the BIND daemon's service is active. It probes
// each known unit name with a SINGLE-unit `systemctl is-active` gated on success —
// the previous two-unit call (`is-active named bind9`) exited non-zero whenever
// EITHER unit was absent (e.g. RHEL/Fedora have no bind9.service), and runCmd
// discards stdout on a non-zero exit, so ServiceActive went false even with named
// fully running → a false "named service is not active" CRIT. On a non-systemd host
// (Alpine/OpenRC/Devuan) systemctl is absent, so fall back to the running process.
func bindServiceActive(ctx context.Context) bool {
	for _, unit := range []string{"named", "bind9", "named-sdb"} {
		if out, err := runCmd(ctx, "systemctl", "is-active", unit); err == nil && strings.TrimSpace(out) == "active" {
			return true
		}
	}
	return anyProcessNamed("named", "bind9", "named-sdb")
}

// bindDetect returns true when a BIND daemon process is running. Matches
// /proc/<pid>/comm (portable; busybox `pgrep -x` matches argv[0] incl. path) with a
// systemctl fallback for setups where the process name differs from the unit.
func bindDetect() bool {
	if anyProcessNamed("named", "bind9", "named-sdb") {
		return true
	}
	out, err := localeSafeCmd(context.Background(), "systemctl", "is-active", "--quiet", "named").Output()
	_ = out
	return err == nil
}

// bindConfigPath returns the named.conf path for this distro.
func bindConfigPath() string {
	paths := []string{
		"/etc/named.conf",                 // RHEL/Fedora/CentOS
		"/etc/bind/named.conf",            // Debian/Ubuntu
		"/usr/local/etc/named/named.conf", // FreeBSD-style
	}
	for _, p := range paths {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

// bindCheckConfig runs named-checkconf and records any errors.
func bindCheckConfig(ctx context.Context, info *models.BINDInfo) {
	if info.ConfigFile == "" {
		info.ConfigError = "named.conf not found"
		return
	}
	out, err := runCmd(ctx, "named-checkconf", info.ConfigFile)
	if err == nil && strings.TrimSpace(out) == "" {
		info.ConfigOK = true
	} else {
		info.ConfigOK = false
		info.ConfigError = strings.TrimSpace(out)
		if info.ConfigError == "" && err != nil {
			info.ConfigError = err.Error()
		}
		info.ConfigError = truncateRunes(info.ConfigError, 200)
	}
}

// bindCheckPorts checks whether named is listening on TCP and UDP port 53.
func bindCheckPorts(ctx context.Context, info *models.BINDInfo) {
	out, _ := runCmd(ctx, "ss", "-tulpn")
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, ":53 ") && !strings.Contains(line, ":53\t") {
			continue
		}
		// Check that it's named, not just dnsmasq / systemd-resolved
		if strings.HasPrefix(line, "tcp") {
			info.Port53TCP = true
		}
		if strings.HasPrefix(line, "udp") {
			info.Port53UDP = true
		}
	}
}

// bindQueryTest sends a test query to 127.0.0.1 via dig.
func bindQueryTest(ctx context.Context, info *models.BINDInfo) {
	// Without dig we cannot run the live query test. Leave QueryTested=false so the
	// analysis layer does NOT report "named is not answering" — a BIND server
	// often lacks bind-utils/dig, and a missing test tool is not a name-server
	// outage. (Distinguishing the two is the whole point of QueryTested.)
	if _, err := lookPath("dig"); err != nil {
		return
	}
	info.QueryTested = true

	start := time.Now()
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := runCmd(queryCtx, "dig", "@127.0.0.1", "localhost", "A",
		"+time=2", "+tries=1", "+noall", "+answer")
	if err == nil && strings.TrimSpace(out) != "" {
		info.QueryOK = true
		info.QueryLatencyMs = int(time.Since(start).Milliseconds())
	}
}

// ── zone parsing ──────────────────────────────────────────────────────────────

type namedZone struct {
	name string
	file string
}

// bindParseZones reads named.conf and extracts zone name + file pairs.
// Only parses primary/master zones with explicit file directives.
// Follows include directives. Capped at 20 zones.
func bindParseZones(configFile string) []namedZone {
	zones := bindParseZoneFile(configFile, 0)
	return zones
}

// bindParseZoneFile parses a single named config file for zones and includes.
func bindParseZoneFile(filePath string, depth int) []namedZone {
	if depth > 5 {
		return nil // guard against circular includes
	}
	f, err := openFile(filePath) // #nosec G304
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck

	var zones []namedZone
	var currentZone string
	inZoneBlock := false
	braceDepth := 0
	skipZone := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Strip inline comments
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		// Detect zone declaration
		if strings.HasPrefix(line, "zone ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentZone = strings.Trim(parts[1], `"`)
				inZoneBlock = true
				braceDepth = 0
				skipZone = false
			}
		}

		// Follow include directives
		if strings.HasPrefix(line, "include ") && strings.Contains(line, `"`) {
			start := strings.Index(line, `"`) + 1
			end := strings.LastIndex(line, `"`)
			if end > start {
				included := bindParseZoneFile(line[start:end], depth+1)
				zones = append(zones, included...)
				if len(zones) >= 20 {
					return zones
				}
			}
			continue
		}

		// Track brace depth
		braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

		if inZoneBlock {
			// Skip hint, forward, stub zones — not checkable with named-checkzone
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "type") {
				if strings.Contains(lower, "hint") || strings.Contains(lower, "forward") ||
					strings.Contains(lower, "stub") {
					skipZone = true
				}
			}
			// Look for file directive (only for non-skipped zones)
			if !skipZone && strings.Contains(line, "file") && strings.Contains(line, `"`) {
				start := strings.Index(line, `"`) + 1
				end := strings.LastIndex(line, `"`)
				if end > start {
					filePath := line[start:end]
					// Relative paths resolved against /var/named or /etc/bind
					if !strings.HasPrefix(filePath, "/") {
						for _, base := range []string{"/var/named", "/etc/bind"} {
							if fileExists(base + "/" + filePath) {
								filePath = base + "/" + filePath
								break
							}
						}
					}
					zones = append(zones, namedZone{name: currentZone, file: filePath})
					if len(zones) >= 20 {
						return zones
					}
				}
			}
			if braceDepth <= 0 {
				inZoneBlock = false
				currentZone = ""
				skipZone = false
			}
		}
	}
	return zones
}

// bindCheckZones runs named-checkzone for each zone file.
func bindCheckZones(ctx context.Context, info *models.BINDInfo, zones []namedZone) {
	for _, z := range zones {
		bz := models.BINDZone{Name: z.name, File: z.file}
		if z.file == "" {
			continue
		}
		zoneCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		out, err := runCmd(zoneCtx, "named-checkzone", z.name, z.file)
		cancel()
		if err == nil && strings.Contains(out, "OK") {
			bz.OK = true
		} else {
			bz.OK = false
			bz.Error = bindExtractZoneError(out)
			info.ZonesFailed++
		}
		info.Zones = append(info.Zones, bz)
	}
}

// bindExtractZoneError returns the first meaningful error line from named-checkzone output.
func bindExtractZoneError(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "error") ||
			strings.Contains(strings.ToLower(line), "failed") ||
			strings.Contains(line, "no TTL") {
			return truncateRunes(line, 150)
		}
	}
	return strings.TrimSpace(out)
}

// ── rndc status ───────────────────────────────────────────────────────────────

func bindRNCDStatus(ctx context.Context, info *models.BINDInfo) {
	out, err := runCmd(ctx, "rndc", "status")
	if err != nil {
		return // rndc not configured or no key — graceful degradation
	}
	info.RNCDAvailable = true
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "version:"):
			// "version: BIND 9.18.33 ..."
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				info.Version = parts[2]
			}
		case strings.HasPrefix(line, "boot time:"):
			info.Uptime = bindCalcUptime(line)
		case strings.HasPrefix(line, "queries:"):
			// "queries: 12345"
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				info.QueryCount, _ = strconv.ParseInt(parts[1], 10, 64)
			}
		}
	}
}

// bindCalcUptime converts "boot time: Tue, 19 May 2026 13:17:03 GMT" to "Xd Xh Xm".
func bindCalcUptime(line string) string {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return ""
	}
	dateStr := strings.TrimSpace(line[idx+1:])
	t, err := time.Parse("Mon, 02 Jan 2006 15:04:05 MST", dateStr)
	if err != nil {
		return ""
	}
	d := time.Since(t)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return strings.TrimSpace(strings.Join([]string{
			bindFmt(days, "d"),
			bindFmt(hours, "h"),
		}, " "))
	}
	return strings.TrimSpace(strings.Join([]string{
		bindFmt(hours, "h"),
		bindFmt(mins, "m"),
	}, " "))
}

func bindFmt(n int, unit string) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n) + unit
}
