//go:build linux

package collectors

import (
	"bufio"
	"context"
	"io"
	"os"
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

	files, err := filepath.Glob("/proc/net/bonding/bond*")
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
	files, _ := filepath.Glob("/proc/net/bonding/bond*")
	return len(files) > 0
}

func parseBondFile(path string) (models.BondInterface, error) {
	f, err := os.Open(path)
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
	}
	if currentSlave != nil {
		bond.Slaves = append(bond.Slaves, *currentSlave)
	}

	for _, s := range bond.Slaves {
		if s.State == "down" {
			bond.DownSlaves++
		}
	}
	return bond, nil
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
