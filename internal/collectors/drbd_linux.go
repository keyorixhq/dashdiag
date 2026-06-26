//go:build linux

package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// IsDRBDPresent returns true when the DRBD kernel module is loaded.
// /proc/drbd only exists when the drbd module is active.
func IsDRBDPresent() bool {
	return fileExists("/proc/drbd")
}

// DRBDCollector reads /proc/drbd to detect DRBD resource health.
// Pure file read — no commands, no root required, zero overhead when absent.
type DRBDCollector struct{}

func NewDRBDCollector() *DRBDCollector { return &DRBDCollector{} }

func (c *DRBDCollector) Name() string           { return "DRBD" }
func (c *DRBDCollector) Timeout() time.Duration { return 2 * time.Second }

func (c *DRBDCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.DRBDInfo{}

	f, err := openFile("/proc/drbd")
	if err != nil {
		return nil, nil // DRBD module not loaded — absent, gate off (no phantom row)
	}
	defer f.Close() //nolint:errcheck

	info = parseDRBDProc(f)

	if len(info.Resources) == 0 {
		// DRBD 9.x publishes only a version/transport header in /proc/drbd — all
		// per-resource state moved to netlink (`drbdsetup status`), so the 8.x-style
		// /proc/drbd parse finds nothing. Without this fallback a real DRBD 9 host
		// with a broken/diskless/disconnected resource reads as absent (silent
		// false-OK). Only attempt it when the module reports v9 — on 8.x an empty
		// parse genuinely means "no configured resources" and there's nothing to ask.
		if strings.HasPrefix(info.Version, "9") {
			if r9 := collectDRBD9(ctx, info.Version); r9 != nil && len(r9.Resources) > 0 {
				return r9, nil
			}
		}
		// Module loaded but no configured resources (or v9 status unreadable, e.g.
		// non-root: netlink needs CAP_NET_ADMIN). Absent, gate off — no phantom
		// "DRBD ✅ OK" row, so nothing falsely claims health.
		return nil, nil
	}
	return info, nil
}

// collectDRBD9 reads DRBD 9.x resource state from `drbdsetup status --json all`
// (netlink) and maps it onto the shared DRBDInfo/DRBDResource model so the same
// checkDRBDResource verdict logic applies. Returns nil if drbdsetup is absent or
// fails (e.g. unprivileged — netlink status needs root).
func collectDRBD9(ctx context.Context, version string) *models.DRBDInfo {
	out, err := runCmd(ctx, "drbdsetup", "status", "--json", "all")
	if err != nil || strings.TrimSpace(out) == "" {
		return nil
	}
	return parseDRBD9JSON([]byte(out), version)
}

// drbd9Resource mirrors the subset of `drbdsetup status --json` we consume.
type drbd9Resource struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	Devices []struct {
		Minor     int    `json:"minor"`
		DiskState string `json:"disk-state"`
	} `json:"devices"`
	Connections []struct {
		ConnectionState string `json:"connection-state"`
		PeerDevices     []struct {
			ReplicationState string  `json:"replication-state"`
			PeerDiskState    string  `json:"peer-disk-state"`
			PercentInSync    float64 `json:"percent-in-sync"`
			OutOfSync        int64   `json:"out-of-sync"`
		} `json:"peer_devices"`
	} `json:"connections"`
}

// parseDRBD9JSON converts drbdsetup's JSON into DRBDInfo. Extracted from the exec
// path so the field/state mapping is unit-testable against real tool output.
func parseDRBD9JSON(data []byte, version string) *models.DRBDInfo {
	var raw []drbd9Resource
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	info := &models.DRBDInfo{Version: version}
	for _, r := range raw {
		res := models.DRBDResource{LocalRole: r.Role}
		if len(r.Devices) > 0 {
			res.Minor = r.Devices[0].Minor
			res.LocalDisk = r.Devices[0].DiskState
		}
		applyDRBD9Connection(&res, r)
		info.Resources = append(info.Resources, res)
	}
	return info
}

// applyDRBD9Connection folds a resource's connections/peer-devices into the flat
// DRBDResource. DRBD 9 splits connection-state (link) from replication-state
// (sync), unlike 8.x's single cs: field. The 8.x heuristic keys sync handling on
// ConnState == SyncSource/SyncTarget, so an active resync (connection Connected,
// replication SyncTarget/SyncSource) is surfaced as that sync state; otherwise the
// worst non-Connected connection-state wins, so a down link still flags.
func applyDRBD9Connection(res *models.DRBDResource, r drbd9Resource) {
	for _, c := range r.Connections {
		// A failing/missing link is the strongest signal — take the first one and
		// keep it (don't let a later healthy peer overwrite it).
		if c.ConnectionState != "Connected" && res.ConnState == "" {
			res.ConnState = c.ConnectionState
		}
		for _, pd := range c.PeerDevices {
			if pd.PeerDiskState != "" {
				res.RemoteDisk = pd.PeerDiskState
			}
			switch pd.ReplicationState {
			case "SyncSource", "SyncTarget":
				res.ConnState = pd.ReplicationState
				res.SyncPct = pd.PercentInSync
				res.SyncKBLeft = pd.OutOfSync
			}
		}
	}
	if res.ConnState == "" {
		res.ConnState = "Connected"
	}
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
	// Clamp garbled values: a sync line is a progress report, so a NaN/Inf/negative
	// percentage or a negative KB-remaining is corrupt input, not a real state.
	if math.IsNaN(pct) || math.IsInf(pct, 0) || pct < 0 {
		pct = 0
	}
	if kbLeft < 0 {
		kbLeft = 0
	}
	return pct, kbLeft
}
