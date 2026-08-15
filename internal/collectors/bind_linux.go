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

const (
	bindProcNamed    = "named"
	bindProcNamedSDB = "named-sdb"
	bindProcBIND9    = "bind9"
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
	for _, unit := range []string{bindProcNamed, bindProcBIND9, bindProcNamedSDB} {
		if out, err := runCmd(ctx, "systemctl", "is-active", unit); err == nil && strings.TrimSpace(out) == "active" {
			return true
		}
	}
	return anyProcessNamed(bindProcNamed, bindProcBIND9, bindProcNamedSDB)
}

// bindDetect returns true when a BIND daemon process is running. Matches
// /proc/<pid>/comm (portable; busybox `pgrep -x` matches argv[0] incl. path) with a
// systemctl fallback for setups where the process name differs from the unit.
func bindDetect() bool {
	if anyProcessNamed(bindProcNamed, bindProcBIND9, bindProcNamedSDB) {
		return true
	}
	_, err := runCmd(context.Background(), "systemctl", "is-active", "--quiet", bindProcNamed)
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

// bindCheckConfig runs named-checkconf and records any errors. Uses
// runCmdCombined (not runCmd) because runCmd discards stdout entirely on a
// non-zero exit — named-checkconf's actual diagnostic ("unknown option 'foo'",
// a missing semicolon, ...) would otherwise never reach ConfigError, leaving
// only the generic "named-checkconf exited 1" with no actionable detail.
func bindCheckConfig(ctx context.Context, info *models.BINDInfo) {
	if info.ConfigFile == "" {
		info.ConfigError = "named.conf not found"
		return
	}
	out, err := runCmdCombined(ctx, "named-checkconf", info.ConfigFile)
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
	out, err := runCmd(ctx, "ss", "-tulpn")
	if err != nil {
		// `ss` (iproute2) absent or failed — we can't tell whether named is
		// listening. Leave PortsChecked false so consumers report "not verified"
		// instead of a false "not listening on port 53".
		return
	}
	info.PortsChecked = true
	privileged := geteuid() == 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, ":53 ") && !strings.Contains(line, ":53\t") {
			continue
		}
		// Check that it's actually named (not dnsmasq / systemd-resolved / unbound
		// also on :53) via ss -p's users:((bindProcNamed,pid=...)) column — matching on
		// the port alone credited whatever else happened to hold :53, silently
		// clearing the "named running but not listening" WARN for a real bind
		// failure (socket-open error, address-specific bind).
		if isBindProcess(line) {
			if strings.HasPrefix(line, "tcp") {
				info.Port53TCP = true
			}
			if strings.HasPrefix(line, "udp") {
				info.Port53UDP = true
			}
			continue
		}
		// Not attributed to named. As non-root, ss -p's owning-process column is
		// only populated for sockets owned by the invoking UID (no CAP_SYS_PTRACE-
		// equivalent) — for a :53 socket owned by another user (named/bind
		// typically runs under its own service account) ss still prints the line
		// but with an EMPTY users: field, not a wrong owner. That's a privilege
		// blind spot, not proof named isn't listening. A line that DOES carry a
		// populated users: field naming some other real process is a genuine
		// conflict and correctly stays a miss.
		if !privileged && !hasSSOwnerInfo(line) {
			info.PortsOwnershipUnverified = true
		}
	}
}

// isBindProcess reports whether an `ss -tulpn` line's process-owner column
// (users:(("name",pid=...))) names a BIND server binary.
func isBindProcess(line string) bool {
	for _, name := range []string{bindProcNamed, bindProcBIND9, bindProcNamedSDB} {
		if strings.Contains(line, "\""+name+"\"") {
			return true
		}
	}
	return false
}

// hasSSOwnerInfo reports whether an `ss -tulpn` line carries a populated
// users:(("name",pid=...)) owner column at all, regardless of which process it
// names. Distinguishes "we saw the owner and it wasn't named" (a genuine port
// conflict) from "we couldn't see who owns this socket" (the non-root
// ownership blind spot — ss can't resolve another UID's /proc/<pid>/fd
// without root).
func hasSSOwnerInfo(line string) bool {
	return strings.Contains(line, "users:((")
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

// bindMaxIncludeFiles bounds the total number of files bindParseZoneFile will
// open across an entire named.conf include tree — internal-collectors-03-04:
// the depth cap (5) only bounds how deep a single include chain can go, not
// how many sibling `include` directives a single file may list. A file with
// many include lines pointing at files that themselves have 0 zones (so the
// len(zones)>=20 early-exit never fires) could otherwise drive an unbounded
// number of file opens within the depth-5 ceiling.
const bindMaxIncludeFiles = 100

// bindParseZones reads named.conf and extracts zone name + file pairs.
// Only parses primary/master zones with explicit file directives.
// Follows include directives. Capped at 20 zones or bindMaxIncludeFiles
// opened files, whichever comes first.
func bindParseZones(configFile string) []namedZone {
	opened := 0
	zones := bindParseZoneFile(configFile, 0, &opened)
	return zones
}

// zoneBlockState tracks parser state while scanning inside a `zone "x" { ... }`
// block in a named.conf-style file — the brace depth (to know when the block
// closes), and whether the zone type (hint/forward/stub) makes it un-checkable.
type zoneBlockState struct {
	name       string
	active     bool
	braceDepth int
	skip       bool
}

func (z *zoneBlockState) enter(name string) {
	z.name = name
	z.active = true
	z.braceDepth = 0
	z.skip = false
}

func (z *zoneBlockState) exit() {
	z.name = ""
	z.active = false
	z.skip = false
}

// observeType flags the block as un-checkable when its `type` directive names
// a hint, forward, or stub zone — none have a local zone file named-checkzone
// can validate.
func (z *zoneBlockState) observeType(lowerLine string) {
	if strings.HasPrefix(lowerLine, "type") &&
		(strings.Contains(lowerLine, "hint") || strings.Contains(lowerLine, "forward") || strings.Contains(lowerLine, "stub")) {
		z.skip = true
	}
}

// extractQuoted returns the first double-quoted substring in line, if any.
func extractQuoted(line string) (string, bool) {
	start := strings.Index(line, `"`)
	if start < 0 {
		return "", false
	}
	end := strings.LastIndex(line, `"`)
	if end <= start {
		return "", false
	}
	return line[start+1 : end], true
}

// resolveZoneFilePath resolves a zone file directive's path against BIND's
// conventional config roots when named.conf gave a relative path.
func resolveZoneFilePath(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	for _, base := range []string{"/var/named", "/etc/bind"} {
		if fileExists(base + "/" + path) {
			return base + "/" + path
		}
	}
	return path
}

// bindParseZoneFile parses a single named config file for zones and includes.
// opened is a shared counter (across the whole recursion tree, via the same
// pointer) bounding total files opened at bindMaxIncludeFiles.
func bindParseZoneFile(filePath string, depth int, opened *int) []namedZone {
	if depth > 5 {
		return nil // guard against circular includes
	}
	if *opened >= bindMaxIncludeFiles {
		return nil
	}
	*opened++
	f, err := openFile(filePath) // #nosec G304
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck

	var zones []namedZone
	var zb zoneBlockState

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
			if parts := strings.Fields(line); len(parts) >= 2 {
				zb.enter(strings.Trim(parts[1], `"`))
			}
		}

		// Follow include directives
		if strings.HasPrefix(line, "include ") {
			if inc, ok := extractQuoted(line); ok {
				zones = append(zones, bindParseZoneFile(inc, depth+1, opened)...)
				if len(zones) >= 20 || *opened >= bindMaxIncludeFiles {
					return zones
				}
			}
			continue
		}

		if !zb.active {
			continue
		}

		zb.braceDepth += strings.Count(line, "{") - strings.Count(line, "}")
		zb.observeType(strings.ToLower(line))

		// Look for file directive (only for non-skipped zones)
		if !zb.skip && strings.Contains(line, "file") {
			if path, ok := extractQuoted(line); ok {
				zones = append(zones, namedZone{name: zb.name, file: resolveZoneFilePath(path)})
				if len(zones) >= 20 {
					return zones
				}
			}
		}

		if zb.braceDepth <= 0 {
			zb.exit()
		}
	}
	if err := scanner.Err(); err != nil {
		// Match the silent-skip convention used for the earlier openFile
		// failure in this function: a mid-read error means we can't trust
		// what was parsed, so don't return a partial zone list.
		return nil
	}
	return zones
}

// bindCheckZones runs named-checkzone for each zone file. Uses runCmdCombined
// (not runCmd) for the same reason as bindCheckConfig: runCmd discards stdout
// entirely on a non-zero exit, which would silently drop named-checkzone's
// actual diagnostic (bindExtractZoneError would always see "").
func bindCheckZones(ctx context.Context, info *models.BINDInfo, zones []namedZone) {
	for _, z := range zones {
		bz := models.BINDZone{Name: z.name, File: z.file}
		if z.file == "" {
			continue
		}
		zoneCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		out, err := runCmdCombined(zoneCtx, "named-checkzone", z.name, z.file)
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
