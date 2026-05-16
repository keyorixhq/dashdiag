package collectors

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ZFSCollector reads ZFS pool health via zpool status and zpool list.
// Works on Linux (OpenZFS) and macOS (OpenZFS via Homebrew).
// Gracefully returns empty when zpool is not installed.
type ZFSCollector struct{}

func NewZFSCollector() *ZFSCollector { return &ZFSCollector{} }

func (c *ZFSCollector) Name() string           { return "ZFS" }
func (c *ZFSCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *ZFSCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.ZFSInfo{}

	// zpool not installed — silent OK
	if _, err := exec.LookPath("zpool"); err != nil {
		return info, nil
	}

	// zpool list -H -o name,size,free,frag,cap,health
	// -H: no header, tab-separated
	listOut, err := runCmd(ctx, "zpool", "list", "-H", "-o", "name,size,free,frag,cap,health")
	if err != nil {
		return info, nil
	}

	pools := parseZpoolList(listOut)

	// zpool status -v: detailed per-pool vdev error counts + scrub info
	statusOut, err := runCmd(ctx, "zpool", "status", "-v")
	if err == nil {
		mergeZpoolStatus(statusOut, pools)
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
	for _, line := range strings.Split(out, "\n") {
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
		if cap, err := strconv.ParseFloat(capStr, 64); err == nil {
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
		if strings.HasPrefix(trimmed, "pool:") {
			currentPool = strings.TrimSpace(strings.TrimPrefix(trimmed, "pool:"))
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
		if strings.HasPrefix(trimmed, "state:") {
			state := strings.TrimSpace(strings.TrimPrefix(trimmed, "state:"))
			pool.State = strings.ToUpper(state)
		}

		// Status message (human-readable problem description)
		if strings.HasPrefix(trimmed, "status:") {
			pool.StatusMsg = strings.TrimSpace(strings.TrimPrefix(trimmed, "status:"))
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
		if strings.HasPrefix(trimmed, "scan:") {
			scanLine := strings.TrimSpace(strings.TrimPrefix(trimmed, "scan:"))
			if strings.Contains(scanLine, "scrub repaired") {
				pool.ScrubAgeDays = parseScrubAge(scanLine)
				pool.ScrubErrors = parseScrubErrors(scanLine)
			} else if strings.Contains(scanLine, "none requested") ||
				strings.Contains(scanLine, "no scrubs") {
				pool.ScrubAgeDays = -1
			}
		}

		// Error counts from vdev table:
		// "  NAME        STATE     READ WRITE CKSUM"
		// "  sda         ONLINE       0     0     0"
		// Parse any line that has numeric error columns
		if strings.Contains(trimmed, "ONLINE") || strings.Contains(trimmed, "DEGRADED") ||
			strings.Contains(trimmed, "FAULTED") || strings.Contains(trimmed, "REMOVED") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 5 {
				r := parseZFSInt(fields[len(fields)-3])
				w := parseZFSInt(fields[len(fields)-2])
				c := parseZFSInt(fields[len(fields)-1])
				pool.ReadErrors += r
				pool.WriteErrors += w
				pool.CksumErrors += c
			}
		}

		pools[currentPool] = pool
	}
}

// parseScrubAge extracts the number of days since the last scrub completed.
// Input: "scrub repaired 0B in 00:01:23 with 0 errors on Sun May 12 03:25:01 2024"
func parseScrubAge(line string) int {
	// Find "on <weekday> <month> <day> <time> <year>"
	onIdx := strings.Index(line, " on ")
	if onIdx < 0 {
		return -1
	}
	datePart := strings.TrimSpace(line[onIdx+4:])
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
	withIdx := strings.Index(line, " with ")
	if withIdx < 0 {
		return 0
	}
	rest := strings.TrimSpace(line[withIdx+6:])
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
		if n, err := strconv.ParseFloat(upper, 64); err == nil {
			return n / (1024 * 1024 * 1024)
		}
		return 0
	}
	if n, err := strconv.ParseFloat(numStr, 64); err == nil {
		return n * mult
	}
	return 0
}
