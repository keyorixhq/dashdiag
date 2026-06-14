//go:build linux

package collectors

import (
	"bufio"
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// IsDRBDPresent returns true when the DRBD kernel module is loaded.
// /proc/drbd only exists when the drbd module is active.
func IsDRBDPresent() bool {
	_, err := os.Stat("/proc/drbd")
	return err == nil
}

// DRBDCollector reads /proc/drbd to detect DRBD resource health.
// Pure file read — no commands, no root required, zero overhead when absent.
type DRBDCollector struct{}

func NewDRBDCollector() *DRBDCollector { return &DRBDCollector{} }

func (c *DRBDCollector) Name() string           { return "DRBD" }
func (c *DRBDCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *DRBDCollector) Collect(_ context.Context) (interface{}, error) {
	info := &models.DRBDInfo{}

	f, err := openFile("/proc/drbd")
	if err != nil {
		return nil, nil // DRBD module not loaded — absent, gate off (no phantom row)
	}
	defer f.Close() //nolint:errcheck

	info = parseDRBDProc(f)

	if len(info.Resources) == 0 {
		// Module loaded (version header present) but no configured resources —
		// nothing to monitor. Absent, gate off (no phantom "DRBD ✅ OK" row).
		return nil, nil
	}
	return info, nil
}

// parseDRBDProc parses /proc/drbd content into DRBDInfo. Extracted from Collect so
// the resource/stats/sync line classification is unit-testable.
func parseDRBDProc(r io.Reader) *models.DRBDInfo {
	info := &models.DRBDInfo{}
	var current *models.DRBDResource
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())

		// Version line: "version: 8.4.11 (api:1/proto:86-101)"
		if strings.HasPrefix(trimmed, "version:") {
			info.Version = strings.TrimSpace(strings.TrimPrefix(trimmed, "version:"))
			continue
		}

		// Resource header: " 0: cs:Connected ro:Primary/Secondary ds:UpToDate/UpToDate C r-----"
		// The minor number (1-2 digits) precedes the first colon. The old check
		// (trimmed[1]==':' || trimmed[2]==':') also matched the per-resource STATS
		// line "ns:0 nr:0 dw:0 ..." (trimmed[2]==':'), so the stats line was parsed as
		// a NEW resource header — overwriting current and stealing the sync line. Anchor
		// on a numeric minor before the colon.
		if i := strings.IndexByte(trimmed, ':'); i >= 1 && i <= 2 && isAllDigits(trimmed[:i]) {
			if current != nil {
				info.Resources = append(info.Resources, *current)
			}
			current = parseDRBDResourceLine(trimmed)
			continue
		}

		// Sync progress line: "    [=>..................] sync'ed: 12.5% (98765/102400)K"
		if current != nil && strings.Contains(trimmed, "sync'ed:") {
			current.SyncPct, current.SyncKBLeft = parseDRBDSyncLine(trimmed)
		}
	}
	if current != nil {
		info.Resources = append(info.Resources, *current)
	}
	return info
}

// parseDRBDResourceLine parses a DRBD resource header line.
// Format: "0: cs:Connected ro:Primary/Secondary ds:UpToDate/UpToDate C r-----"
func parseDRBDResourceLine(line string) *models.DRBDResource {
	res := &models.DRBDResource{}

	// Extract minor number before the first ":"
	colonIdx := strings.IndexByte(line, ':')
	if colonIdx > 0 {
		res.Minor, _ = strconv.Atoi(strings.TrimSpace(line[:colonIdx]))
	}

	fields := strings.Fields(line)
	for _, field := range fields {
		switch {
		case strings.HasPrefix(field, "cs:"):
			res.ConnState = strings.TrimPrefix(field, "cs:")
		case strings.HasPrefix(field, "ro:"):
			roles := strings.Split(strings.TrimPrefix(field, "ro:"), "/")
			if len(roles) >= 1 {
				res.LocalRole = roles[0]
			}
		case strings.HasPrefix(field, "ds:"):
			disks := strings.Split(strings.TrimPrefix(field, "ds:"), "/")
			if len(disks) >= 1 {
				res.LocalDisk = disks[0]
			}
			if len(disks) >= 2 {
				res.RemoteDisk = disks[1]
			}
		}
	}
	return res
}

// parseDRBDSyncLine extracts sync percentage and KB remaining from:
// "[=>..................] sync'ed: 12.5% (98765/102400)K"
func parseDRBDSyncLine(line string) (pct float64, kbLeft int64) {
	// Find "sync'ed: N%"
	syncIdx := strings.Index(line, "sync'ed:")
	if syncIdx >= 0 {
		rest := strings.TrimSpace(line[syncIdx+8:])
		pctIdx := strings.Index(rest, "%")
		if pctIdx > 0 {
			pct, _ = strconv.ParseFloat(strings.TrimSpace(rest[:pctIdx]), 64)
		}
	}
	// Find KB remaining in "(.../....)K" — first number is remaining
	openParen := strings.Index(line, "(")
	closeParen := strings.Index(line, ")")
	if openParen >= 0 && closeParen > openParen {
		inner := line[openParen+1 : closeParen]
		// Remove trailing K if present
		inner = strings.TrimSuffix(inner, "K")
		parts := strings.Split(inner, "/")
		if len(parts) >= 1 {
			// Remove commas from numbers like "98,765"
			numStr := strings.ReplaceAll(parts[0], ",", "")
			kbLeft, _ = strconv.ParseInt(strings.TrimSpace(numStr), 10, 64)
		}
	}
	return pct, kbLeft
}
