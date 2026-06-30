//go:build linux

package collectors

import (
	"bufio"
	"context"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// BondingCollector reads /proc/net/bonding/bond* — no commands, no root needed.
type BondingCollector struct{}

func NewBondingCollector() *BondingCollector       { return &BondingCollector{} }
func (c *BondingCollector) Name() string           { return "Bonding" }
func (c *BondingCollector) Timeout() time.Duration { return 3 * time.Second }

func (c *BondingCollector) Collect(_ context.Context) (interface{}, error) {
	info := &models.BondingInfo{}

	files, err := glob("/proc/net/bonding/bond*")
	if err != nil || len(files) == 0 {
		return info, nil
	}

	for _, path := range files {
		bond, err := parseBondFile(path)
		if err != nil {
			continue
		}
		info.Bonds = append(info.Bonds, bond)
	}
	return info, nil
}

// IsBondingPresent returns true if any bond interfaces exist.
func IsBondingPresent() bool {
	files, _ := glob("/proc/net/bonding/bond*")
	return len(files) > 0
}

// collectBonds returns bond health for all bond interfaces — used by NetworkCollector.
func collectBonds() []models.BondInterface {
	files, err := glob("/proc/net/bonding/bond*")
	if err != nil || len(files) == 0 {
		return nil
	}
	var bonds []models.BondInterface
	for _, path := range files {
		b, err := parseBondFile(path)
		if err != nil {
			continue
		}
		bonds = append(bonds, b) // Degraded/AllDown now set in parseBondFileContent
	}
	return bonds
}

func parseBondFile(path string) (models.BondInterface, error) {
	f, err := openFile(path)
	if err != nil {
		return models.BondInterface{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return models.BondInterface{}, err
	}
	return parseBondFileContent(filepath.Base(path), string(data))
}

func parseBondFileContent(name, content string) (models.BondInterface, error) {
	bond := models.BondInterface{Name: name}
	var currentSlave *models.BondSlave
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "Bonding Mode:") {
			mode := strings.TrimPrefix(line, "Bonding Mode:")
			bond.Mode = strings.TrimSpace(mode)
			bond.ModeShort = shortMode(bond.Mode)
			continue
		}
		if strings.HasPrefix(line, "Currently Active Slave:") {
			bond.ActiveSlave = strings.TrimSpace(strings.TrimPrefix(line, "Currently Active Slave:"))
			continue
		}
		// 802.3ad bond-level aggregator info (header section, before any slave). The
		// "Partner Mac Address" is the LACP partner's system MAC — all-zero means no
		// partner was ever heard. "Number of ports" is the active aggregator's member
		// count. Both are absent on non-LACP modes, so this is a no-op there.
		if currentSlave == nil && strings.HasPrefix(line, "Partner Mac Address:") {
			bond.PartnerMAC = strings.TrimSpace(strings.TrimPrefix(line, "Partner Mac Address:"))
			continue
		}
		if currentSlave == nil && strings.HasPrefix(line, "Number of ports:") {
			if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Number of ports:"))); err == nil {
				bond.AggregatorPorts = n
			}
			continue
		}
		if strings.HasPrefix(line, "Slave Interface:") {
			if currentSlave != nil {
				bond.Slaves = append(bond.Slaves, *currentSlave)
			}
			name := strings.TrimSpace(strings.TrimPrefix(line, "Slave Interface:"))
			currentSlave = &models.BondSlave{Name: name}
			continue
		}
		if currentSlave == nil {
			continue
		}
		if strings.HasPrefix(line, "MII Status:") {
			currentSlave.MIIStatus = strings.TrimSpace(strings.TrimPrefix(line, "MII Status:"))
			if currentSlave.MIIStatus == "down" {
				currentSlave.State = "down"
			} else {
				currentSlave.State = "up"
			}
			continue
		}
		if strings.HasPrefix(line, "Speed:") {
			speedStr := strings.TrimSpace(strings.TrimPrefix(line, "Speed:"))
			speedStr = strings.TrimSuffix(speedStr, " Mbps")
			if s, err := strconv.Atoi(speedStr); err == nil {
				currentSlave.SpeedMbps = s
			}
			continue
		}
		if strings.HasPrefix(line, "Link Failure Count:") {
			countStr := strings.TrimSpace(strings.TrimPrefix(line, "Link Failure Count:"))
			if n, err := strconv.Atoi(countStr); err == nil {
				currentSlave.LinkFails = n
			}
			continue
		}
		if strings.HasPrefix(line, "Aggregator ID:") {
			if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Aggregator ID:"))); err == nil {
				currentSlave.AggregatorID = n
			}
			continue
		}
	}
	if currentSlave != nil {
		bond.Slaves = append(bond.Slaves, *currentSlave)
	}

	for _, s := range bond.Slaves {
		if s.State == "down" {
			bond.DownSlaves++
		}
	}
	// Derive the verdict booleans here so EVERY caller gets them. The standalone
	// BondingCollector skipped this (only the NetworkCollector path set them), so
	// `dsd ... --json` raw bond payloads reported degraded=false/all_down=false even
	// for a fully-down bond — a false-OK in the machine-readable contract.
	bond.Degraded = bond.DownSlaves > 0
	bond.AllDown = bond.DownSlaves > 0 && bond.DownSlaves == len(bond.Slaves)
	bond.NotAggregating = lacpNotAggregating(bond)
	return bond, nil
}

// lacpNotAggregating reports whether an 802.3ad (LACP) bond has MII-up slaves that
// are NOT actually aggregating — the false-OK an MII-only check misses. A bond whose
// links are all "up" still carries no traffic if LACP never negotiated: the partner
// switch isn't speaking LACP (no partner MAC heard), or only some links joined the
// active aggregator (the rest sit in their own aggregator, unbundled). Signals, any of:
//   - Partner MAC is all-zero (00:00:00:00:00:00) — no LACP partner was ever heard.
//   - The active aggregator holds fewer ports than there are up slaves (partial bundle).
//   - Up slaves report more than one distinct aggregator ID (links failed to merge).
//
// All three degrade safely to "no signal" when the /proc data lacks LACP fields (older
// kernels, non-LACP modes), so this never fires outside 802.3ad.
func lacpNotAggregating(bond models.BondInterface) bool {
	if bond.ModeShort != "802.3ad" {
		return false
	}
	upSlaves := len(bond.Slaves) - bond.DownSlaves
	if upSlaves == 0 {
		return false // an all-down bond is already CRIT via AllDown; don't double-flag
	}

	if isZeroMAC(bond.PartnerMAC) {
		return true
	}
	if bond.AggregatorPorts > 0 && bond.AggregatorPorts < upSlaves {
		return true
	}

	aggIDs := make(map[int]struct{})
	for _, s := range bond.Slaves {
		if s.State != "down" && s.AggregatorID > 0 {
			aggIDs[s.AggregatorID] = struct{}{}
		}
	}
	return len(aggIDs) > 1
}

// isZeroMAC reports whether a MAC string is present but all zeros (e.g.
// "00:00:00:00:00:00") — the kernel's "no LACP partner heard" sentinel. An empty
// string (field absent) is NOT treated as zero, so absence is never a false signal.
func isZeroMAC(mac string) bool {
	mac = strings.TrimSpace(mac)
	if mac == "" {
		return false
	}
	return strings.Trim(mac, "0:") == ""
}

func shortMode(mode string) string {
	mode = strings.ToLower(mode)
	switch {
	case strings.Contains(mode, "802.3ad"):
		return "802.3ad"
	case strings.Contains(mode, "active-backup"):
		return "active-backup"
	case strings.Contains(mode, "round-robin"):
		return "balance-rr"
	case strings.Contains(mode, "xor"):
		return "balance-xor"
	case strings.Contains(mode, "broadcast"):
		return "broadcast"
	case strings.Contains(mode, "balance-tlb") || strings.Contains(mode, "transmit load balancing"):
		return "balance-tlb"
	case strings.Contains(mode, "balance-alb") || strings.Contains(mode, "adaptive load balancing"):
		return "balance-alb"
	default:
		return mode
	}
}
