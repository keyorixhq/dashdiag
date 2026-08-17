package collectors

import (
	"context"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// IsZFSPresent returns true when ZFS is installed and usable on this host.
func IsZFSPresent() bool {
	_, err := lookPath("zpool")
	return err == nil
}

// ZFSCollector reads ZFS pool health via zpool status and zpool list.
// Works on Linux (OpenZFS) and macOS (OpenZFS via Homebrew).
// Gracefully returns empty when zpool is not installed.
type ZFSCollector struct{}

func NewZFSCollector() *ZFSCollector { return &ZFSCollector{} }

func (c *ZFSCollector) Name() string           { return "ZFS" }
func (c *ZFSCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *ZFSCollector) Collect(ctx context.Context) (any, error) {
	info := &models.ZFSInfo{}

	// zpool not installed — silent OK
	if _, err := lookPath("zpool"); err != nil {
		return info, nil
	}

	// zpool list -H -o name,size,free,frag,cap,health
	// -H: no header, tab-separated
	listOut, err := runCmd(ctx, "zpool", "list", "-H", "-o", "name,size,free,frag,cap,health")
	if err != nil {
		// zpool is installed but the list query failed (commonly permission denied).
		// Returning empty pools here would read as a silent "no ZFS problems"; flag it.
		info.ListReadFailed = true
		return info, nil
	}

	pools := parseZpoolList(listOut)

	// zpool status -v: detailed per-pool vdev error counts + scrub info. When it fails
	// (it can hang on a sick pool and hit the timeout), the per-vdev error counts and
	// scrub age are never read — mark each pool so the verdict reports them unverified
	// instead of treating the zero counters as clean.
	statusOut, err := runCmd(ctx, "zpool", "status", "-v")
	if err == nil {
		mergeZpoolStatus(statusOut, pools)
	} else {
		for name, p := range pools {
			p.StatusReadFailed = true
			pools[name] = p
		}
	}

	info.Pools = make([]models.ZFSPool, 0, len(pools))
	for _, p := range pools {
		info.Pools = append(info.Pools, p)
	}
	return info, nil
}

// parseZpoolList parses `zpool list -H -o name,size,free,frag,cap,health` output.
// Returns a map of pool name → ZFSPool for merging with status data.
func parseZpoolList(out string) map[string]models.ZFSPool {
	pools := map[string]models.ZFSPool{}
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		pool := models.ZFSPool{
			Name:  fields[0],
			State: strings.ToUpper(fields[5]),
		}
		pool.SizeGB = parseZFSSize(fields[1])
		pool.FreeGB = parseZFSSize(fields[2])
		if pool.SizeGB > 0 {
			pool.UsedPct = (pool.SizeGB - pool.FreeGB) / pool.SizeGB * 100
		}
		// frag%: "23%" or "-"
		pool.FragPct = parseZFSInt(strings.TrimSuffix(fields[3], "%"))
		// cap%: "45%" or "-"
		capStr := strings.TrimSuffix(fields[4], "%")
		if cap, ok := parseFiniteFloat(capStr); ok {
			pool.UsedPct = cap // cap is more accurate than computed
		}
		pool.ScrubAgeDays = -1 // default: never scrubbed
		pools[pool.Name] = pool
	}
	return pools
}

// mergeZpoolStatus parses `zpool status -v` and merges error counts and
// scrub age into the pools map populated by parseZpoolList.
func mergeZpoolStatus(out string, pools map[string]models.ZFSPool) {
	var currentPool string
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Pool header: "  pool: tank"
		if after, ok := strings.CutPrefix(trimmed, "pool:"); ok {
			currentPool = strings.TrimSpace(after)
			continue
		}

		if currentPool == "" {
			continue
		}
		pool, ok := pools[currentPool]
		if !ok {
			continue
		}

		// State line: "  state: DEGRADED"
		if after, ok0 := strings.CutPrefix(trimmed, "state:"); ok0 {
			state := strings.TrimSpace(after)
			pool.State = strings.ToUpper(state)
		}

		// Status message (human-readable problem description)
		if after, ok0 := strings.CutPrefix(trimmed, "status:"); ok0 {
			pool.StatusMsg = strings.TrimSpace(after)
			// Collect continuation lines
			for j := i + 1; j < len(lines) && j < i+3; j++ {
				cont := strings.TrimSpace(lines[j])
				if cont == "" || strings.Contains(cont, ":") {
					break
				}
				pool.StatusMsg += " " + cont
			}
		}

		// Scrub line: "  scan: scrub repaired 0B in 00:01:23 with 0 errors on Sun May 12 ..."
		//         or: "  scan: scrub in progress since ..."
		//         or: "  scan: none requested"
		if after, ok0 := strings.CutPrefix(trimmed, "scan:"); ok0 {
			scanLine := strings.TrimSpace(after)
			if strings.Contains(scanLine, "scrub repaired") {
				pool.ScrubAgeDays = parseScrubAge(scanLine)
				pool.ScrubErrors = parseScrubErrors(scanLine)
			} else if strings.Contains(scanLine, "scrub in progress") ||
				strings.Contains(scanLine, "scrub started") {
				// A scrub running right now is the healthiest possible state —
				// not "never scrubbed". Age 0 = scrubbed today.
				pool.ScrubAgeDays = 0
			} else if strings.Contains(scanLine, "none requested") ||
				strings.Contains(scanLine, "no scrubs") {
				pool.ScrubAgeDays = -1
			}
		}

		// Error counts from vdev table:
		// "  NAME        STATE     READ WRITE CKSUM"
		// "  sda         ONLINE       0     0     0"
		if r, w, c, ok := parseZFSVdevErrorLine(trimmed); ok {
			pool.ReadErrors += r
			pool.WriteErrors += w
			pool.CksumErrors += c
		}

		pools[currentPool] = pool
	}
}

// zfsStateTokens are the values zpool status prints in the vdev STATE column.
var zfsStateTokens = map[string]bool{
	"ONLINE": true, "DEGRADED": true, "FAULTED": true, "OFFLINE": true,
	"UNAVAIL": true, "REMOVED": true, "AVAIL": true, "INUSE": true,
}

// parseZFSVdevErrorLine parses a single (already-trimmed) zpool status vdev
// line. ok is false when the line isn't a vdev line (no recognized STATE token)
// or its counters didn't parse (garbled output).
func parseZFSVdevErrorLine(line string) (read, write, cksum int, ok bool) {
	fields := strings.Fields(line)
	stateIdx := -1
	for i, f := range fields {
		if zfsStateTokens[f] {
			stateIdx = i
			break
		}
	}
	if stateIdx < 0 || stateIdx+3 >= len(fields) {
		return 0, 0, 0, false
	}
	r, okR := parseZFSCount(fields[stateIdx+1])
	w, okW := parseZFSCount(fields[stateIdx+2])
	c, okC := parseZFSCount(fields[stateIdx+3])
	if !okR || !okW || !okC {
		return 0, 0, 0, false
	}
	return r, w, c, true
}

// parseZFSCount parses a zpool error counter, which is a plain integer or a
// ZFS-abbreviated value like "1.2K" / "15M" / "3.0G".
func parseZFSCount(s string) (int, bool) {
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 {
			return 0, false // a negative error count is garbled output, never a real zpool value
		}
		return n, true
	}
	if len(s) < 2 {
		return 0, false
	}
	var mult float64
	switch s[len(s)-1] {
	case 'K':
		mult = 1e3
	case 'M':
		mult = 1e6
	case 'G':
		mult = 1e9
	case 'T':
		mult = 1e12
	default:
		return 0, false
	}
	n, err := strconv.ParseFloat(s[:len(s)-1], 64)
	// Reject a negative value, and NaN/Inf — strconv.ParseFloat treats "NaN"/
	// "Inf" as successful parses, not errors, and `n < 0` is false for NaN
	// (all comparisons with NaN are false), so neither was actually caught
	// by the check this replaced. Found live by the continuous fuzzing rig:
	// "10000000000000000K" parsed as n=1e16, scaled by mult=1e3 to 1e19 —
	// past int64's ~9.2e18 max, so int(n*mult) silently wrapped to
	// math.MinInt64 (a negative vdev error count, the exact false-OK bug
	// class this project has fixed repeatedly: a negative count slips under
	// any ">0"/">=threshold" check).
	if err != nil || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, false
	}
	scaled := n * mult
	if scaled > float64(math.MaxInt) {
		return math.MaxInt, true // saturate — a huge garbled count reads as "very large", never wraps negative
	}
	return int(scaled), true
}

// parseScrubAge extracts the number of days since the last scrub completed.
// Input: "scrub repaired 0B in 00:01:23 with 0 errors on Sun May 12 03:25:01 2024"
func parseScrubAge(line string) int {
	// Find "on <weekday> <month> <day> <time> <year>"
	_, after, ok := strings.Cut(line, " on ")
	if !ok {
		return -1
	}
	datePart := strings.TrimSpace(after)
	// Parse: "Sun May 12 03:25:01 2024"
	t, err := time.Parse("Mon Jan 2 15:04:05 2006", datePart)
	if err != nil {
		// Try without weekday: "May 12 03:25:01 2024"
		t, err = time.Parse("Jan 2 15:04:05 2006", datePart)
		if err != nil {
			return 0
		}
	}
	days := int(time.Since(t).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

// parseScrubErrors extracts error count from scrub output line.
// Input: "scrub repaired 0B in 00:01:23 with 3 errors on ..."
func parseScrubErrors(line string) int {
	_, after, ok := strings.Cut(line, " with ")
	if !ok {
		return 0
	}
	rest := strings.TrimSpace(after)
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return 0
	}
	return parseZFSInt(fields[0])
}

// parseZFSInt parses an integer string, returning 0 on error.
// Used for error counts and percentages from zpool output.
func parseZFSInt(s string) int {
	s = strings.TrimSpace(s)
	n, _ := strconv.Atoi(s)
	return n
}

// parseZFSSize converts ZFS human-readable sizes to GB.
func parseZFSSize(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "-" || s == "" {
		return 0
	}
	upper := strings.ToUpper(s)
	var mult float64
	var numStr string
	switch {
	case strings.HasSuffix(upper, "T"):
		mult = 1024
		numStr = upper[:len(upper)-1]
	case strings.HasSuffix(upper, "G"):
		mult = 1
		numStr = upper[:len(upper)-1]
	case strings.HasSuffix(upper, "M"):
		mult = 1.0 / 1024
		numStr = upper[:len(upper)-1]
	case strings.HasSuffix(upper, "K"):
		mult = 1.0 / (1024 * 1024)
		numStr = upper[:len(upper)-1]
	case strings.HasSuffix(upper, "P"):
		mult = 1024 * 1024
		numStr = upper[:len(upper)-1]
	default:
		// Raw bytes
		if n, ok := parseFiniteFloat(upper); ok {
			return n / (1024 * 1024 * 1024)
		}
		return 0
	}
	n, ok := parseFiniteFloat(numStr)
	if !ok {
		return 0
	}
	v := n * mult
	if math.IsInf(v, 0) {
		// n was already finite/non-negative (parseFiniteFloat guarantees
		// that); a hostile/garbled huge value times mult (up to 1024*1024
		// for the P suffix) can still overflow float64 — the same class as
		// the fixed snapper_linux.go parseMiB bug (#862). Read as "not
		// measured" rather than an infinite pool size.
		return 0
	}
	return v
}
