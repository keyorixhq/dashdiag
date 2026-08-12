//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const ibSysClassDir = "/sys/class/infiniband"

type InfiniBandCollector struct{}

func NewInfiniBandCollector() *InfiniBandCollector    { return &InfiniBandCollector{} }
func (c *InfiniBandCollector) Name() string           { return "InfiniBand" }
func (c *InfiniBandCollector) Timeout() time.Duration { return 3 * time.Second }

func (c *InfiniBandCollector) Collect(_ context.Context) (interface{}, error) {
	info := &models.InfiniBandInfo{}

	// Stat the parent dir first (not just glob it): filepath.Glob silently
	// swallows read errors, so a restricted view (EACCES on a namespaced/
	// bind-mounted /sys) is indistinguishable from the directory genuinely
	// not existing (no IB kernel module loaded) via glob alone. Stat, unlike
	// ReadDir/Glob, is recorded on BOTH success and failure by the capture
	// layer (source.Recorder), so this distinction also replays faithfully —
	// see internal/source/bundle.go's statRec (notExist vs permission).
	if _, err := statFile(ibSysClassDir); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			info.ReadFailed = true
		}
		return info, nil
	}

	// /sys/class/infiniband/ — one dir per HCA device (mlx5_0, rxe0, etc.)
	devices, _ := glob(filepath.Join(ibSysClassDir, "*"))
	for _, dev := range devices {
		devName := filepath.Base(dev)
		// Each device has ports/ subdirectory
		ports, _ := glob(filepath.Join(dev, "ports", "*"))
		for _, portPath := range ports {
			port := readIBPort(devName, portPath)
			info.Ports = append(info.Ports, port)
		}
	}
	return info, nil
}

// IsInfiniBandPresent returns true when IB hardware is found, or when
// presence could not be confirmed one way or the other (a restricted /sys
// view) — in that case the collector still runs and discloses ReadFailed via
// InfiniBandInfo, rather than the health run silently skipping the section.
func IsInfiniBandPresent() bool {
	if _, err := statFile(ibSysClassDir); err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	devices, _ := glob(filepath.Join(ibSysClassDir, "*"))
	return len(devices) > 0
}

func readIBPort(device, portPath string) models.IBPort {
	portNum := filepath.Base(portPath)
	port := models.IBPort{Device: device}
	if n := 0; true {
		_ = n // suppress unused
		port.Port = parsePortNum(portNum)
	}
	port.State = strings.TrimSpace(readSysfsStr(filepath.Join(portPath, "state")))
	// "4: ACTIVE" → extract just "ACTIVE"
	if i := strings.Index(port.State, ": "); i >= 0 {
		port.State = port.State[i+2:]
	}
	port.Speed = strings.TrimSpace(readSysfsStr(filepath.Join(portPath, "rate")))
	// "100 Gb/sec (4X EDR)" → extract "EDR"
	if i := strings.Index(port.Speed, "("); i >= 0 {
		inner := port.Speed[i+1:]
		inner = strings.TrimSuffix(inner, ")")
		parts := strings.Fields(inner)
		if len(parts) >= 2 {
			port.Width = parts[0]
			port.Speed = parts[1]
		}
	}
	return port
}

func parsePortNum(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

func parseIBState(raw string) string {
	if i := strings.Index(raw, ": "); i >= 0 {
		return strings.TrimSpace(raw[i+2:])
	}
	return strings.TrimSpace(raw)
}
