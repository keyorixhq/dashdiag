//go:build linux

package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// HBACollector reads Fibre Channel HBA state from /sys/class/fc_host/.
// Pure sysfs — no commands, no root required.
type HBACollector struct{}

func NewHBACollector() *HBACollector           { return &HBACollector{} }
func (c *HBACollector) Name() string           { return "HBA" }
func (c *HBACollector) Timeout() time.Duration { return 4 * time.Second }

func (c *HBACollector) Collect(_ context.Context) (interface{}, error) {
	info := &models.HBAInfo{}

	hosts, err := filepath.Glob("/sys/class/fc_host/host*")
	if err != nil || len(hosts) == 0 {
		return info, nil
	}

	for _, host := range hosts {
		port := readHBAPort(host)
		info.Ports = append(info.Ports, port)
	}
	return info, nil
}

// IsHBAPresent returns true when any FC HBA is present.
func IsHBAPresent() bool {
	hosts, _ := filepath.Glob("/sys/class/fc_host/host*")
	return len(hosts) > 0
}

func readHBAPort(hostPath string) models.HBAPort {
	name := filepath.Base(hostPath)
	port := models.HBAPort{Name: name}

	port.PortState = strings.TrimSpace(readSysfsStr(hostPath + "/port_state"))
	port.NodeName = strings.TrimSpace(readSysfsStr(hostPath + "/node_name"))
	port.PortName = strings.TrimSpace(readSysfsStr(hostPath + "/port_name"))
	port.FabricName = strings.TrimSpace(readSysfsStr(hostPath + "/fabric_name"))

	speedStr := strings.TrimSpace(readSysfsStr(hostPath + "/speed"))
	// "16 Gbit" → 16
	fields := strings.Fields(speedStr)
	if len(fields) >= 1 {
		if s, err := strconv.Atoi(fields[0]); err == nil {
			port.SpeedGbps = s
		}
	}

	// Error counters
	port.LinkFailures = readSysfsInt(hostPath + "/statistics/link_failure_count")
	port.LossOfSync = readSysfsInt(hostPath + "/statistics/loss_of_sync_count")
	port.LossOfSignal = readSysfsInt(hostPath + "/statistics/loss_of_signal_count")

	// Detect driver from symlink target (e.g. ../../devices/.../lpfc)
	if target, err := os.Readlink(hostPath); err == nil {
		parts := strings.Split(target, "/")
		if len(parts) > 2 {
			port.Driver = parts[len(parts)-2]
		}
	}

	return port
}

func readSysfsInt(path string) int {
	s := strings.TrimSpace(readSysfsStr(path))
	n, _ := strconv.Atoi(s)
	return n
}
