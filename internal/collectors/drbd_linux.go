//go:build linux

package collectors

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// DRBDCollector reads /proc/drbd to check replication state of DRBD resources.
// Pure file read — no commands, no root required.
// Silent no-op when /proc/drbd does not exist (DRBD not loaded).
type DRBDCollector struct{}

func NewDRBDCollector() *DRBDCollector { return &DRBDCollector{} }

func (c *DRBDCollector) Name() string           { return "DRBD" }
func (c *DRBDCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *DRBDCollector) Collect(_ context.Context) (interface{}, error) {
	info := &models.DRBDInfo{}

	f, err := os.Open("/proc/drbd")
	if err != nil {
		// DRBD module not loaded — silent OK
		return info, nil
	}
	defer f.Close() //nolint:errcheck

	info.Resources = parseDRBDProc(f)
	return info, nil
}

// parseDRBDProc parses /proc/drbd output.
//
// /proc/drbd format (DRBD 8.x):
//
//	version: 8.4.11 (api:1/proto:86-101)
//	GIT-hash: ...
//
//	 0: cs:Connected ro:Primary/Secondary ds:UpToDate/UpToDate C r-----
//	    ns:0 nr:0 dw:0 dr:664 al:8 bm:0 lo:0 pe:0 ua:0 ap:0 ep:1 wo:f oos:0
//	 1: cs:SyncTarget ro:Secondary/Primary ds:Inconsistent/UpToDate C r-----
//	    [>..................] sync'ed:  1.4% (30652/31040)M
//	    ns:0 nr:49152 dw:49152 dr:0 al:0 bm:0 lo:0 pe:2 ua:0 ap:0 ep:1 wo:f oos:31809536
func parseDRBDProc(f *os.File) []models.DRBDResource {
	var resources []models.DRBDResource
	var current *models.DRBDResource

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "version:") || strings.HasPrefix(trimmed, "GIT-hash:") {
			continue
		}

		// Resource header line: " 0: cs:Connected ro:Primary/Secondary ds:UpToDate/UpToDate C r-----"
		// Starts with a minor number followed by ":"
		if len(line) > 0 && line[0] == ' ' && len(trimmed) > 2 && trimmed[1] == ':' {
			if current != nil {
				resources = append(resources, *current)
			}
			current = parseResourceHeader(trimmed)
			continue
		}

		if current == nil {
			continue
		}

		// Sync progress line: "    [>..................] sync'ed:  1.4% (30652/31040)M"
		if strings.Contains(trimmed, "sync'ed:") {
			current.Syncing = true
			current.SyncPct = parseSyncPct(trimmed)
		}

		// Stats line: "    ns:0 nr:0 dw:0 ... oos:0"
		// oos = out-of-sync kilobytes
		if strings.Contains(trimmed, "oos:") {
			current.OutOfSync = parseOOS(trimmed)
		}
	}

	if current != nil {
		resources = append(resources, *current)
	}
	return resources
}

// parseResourceHeader parses the main status line for a DRBD resource.
// Input: "0: cs:Connected ro:Primary/Secondary ds:UpToDate/UpToDate C r-----"
func parseResourceHeader(line string) *models.DRBDResource {
	res := &models.DRBDResource{}

	// Parse minor number: "0:"
	colonIdx := strings.IndexByte(line, ':')
	if colonIdx > 0 {
		res.Minor, _ = strconv.Atoi(strings.TrimSpace(line[:colonIdx]))
	}

	fields := strings.Fields(line)
	for _, field := range fields {
		kv := strings.SplitN(field, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key, val := kv[0], kv[1]
		switch key {
		case "cs":
			res.ConnState = val
		case "ro":
			// "Primary/Secondary"
			parts := strings.SplitN(val, "/", 2)
			res.LocalRole = parts[0]
			if len(parts) == 2 {
				res.RemoteRole = parts[1]
			}
		case "ds":
			// "UpToDate/UpToDate"
			parts := strings.SplitN(val, "/", 2)
			res.LocalDisk = parts[0]
			if len(parts) == 2 {
				res.RemoteDisk = parts[1]
			}
		}
	}
	return res
}

// parseSyncPct extracts the sync percentage from a sync progress line.
// Input: "[>..................] sync'ed:  1.4% (30652/31040)M"
func parseSyncPct(line string) float64 {
	idx := strings.Index(line, "sync'ed:")
	if idx < 0 {
		return 0
	}
	rest := strings.TrimSpace(line[idx+8:])
	pctIdx := strings.IndexByte(rest, '%')
	if pctIdx <= 0 {
		return 0
	}
	numStr := strings.TrimSpace(rest[:pctIdx])
	pct, _ := strconv.ParseFloat(numStr, 64)
	return pct
}

// parseOOS extracts out-of-sync kilobytes from the stats line.
// Input: "ns:0 nr:49152 dw:49152 dr:0 ... oos:31809536"
func parseOOS(line string) int64 {
	for _, field := range strings.Fields(line) {
		if strings.HasPrefix(field, "oos:") {
			val := strings.TrimPrefix(field, "oos:")
			n, _ := strconv.ParseInt(val, 10, 64)
			return n
		}
	}
	return 0
}
