//go:build linux

package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type InfiniBandCollector struct{}

func NewInfiniBandCollector() *InfiniBandCollector    { return &InfiniBandCollector{} }
func (c *InfiniBandCollector) Name() string           { return "InfiniBand" }
func (c *InfiniBandCollector) Timeout() time.Duration { return 3 * time.Second }

func (c *InfiniBandCollector) Collect(_ context.Context) (interface{}, error) {
	info := &models.InfiniBandInfo{}

	// /sys/class/infiniband/ — one dir per HCA device (mlx5_0, rxe0, etc.)
	devices, _ := filepath.Glob("/sys/class/infiniband/*")
	if len(devices) == 0 {
		return info, nil
	}

	for _, dev := range devices {
		devName := filepath.Base(dev)
		// Each device has ports/ subdirectory
		ports, _ := filepath.Glob(filepath.Join(dev, "ports", "*"))
		for _, portPath := range ports {
			port := readIBPort(devName, portPath)
			info.Ports = append(info.Ports, port)
		}
	}
	return info, nil
}

// IsInfiniBandPresent returns true when IB hardware is found.
func IsInfiniBandPresent() bool {
	devices, _ := filepath.Glob("/sys/class/infiniband/*")
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

// parseIBPortFromSysfs is exposed for unit tests
func parseIBPortFromSysfs(device, portNum, state, rate string) models.IBPort {
	port := models.IBPort{
		Device: device,
		Port:   parsePortNum(portNum),
		State:  parseIBState(state),
	}
	// Parse rate like "100 Gb/sec (4X EDR)"
	if i := strings.Index(rate, "("); i >= 0 {
		inner := strings.TrimSuffix(rate[i+1:], ")")
		parts := strings.Fields(inner)
		if len(parts) >= 2 {
			port.Width = parts[0]
			port.Speed = parts[1]
		}
	}

	// Optionally read device state from sysfs path
	if p, err := os.ReadFile(filepath.Join("/sys/class/infiniband", device, "ports", portNum, "state")); err == nil {
		port.State = parseIBState(strings.TrimSpace(string(p)))
	}

	return port
}
