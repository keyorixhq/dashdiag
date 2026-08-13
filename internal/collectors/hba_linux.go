//go:build linux

package collectors

import (
	"context"
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

	hosts, err := glob("/sys/class/fc_host/host*")
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
	hosts, _ := glob("/sys/class/fc_host/host*")
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

	// Error counters. The kernel SCSI FC transport class formats these ALWAYS as
	// hex with a "0x" prefix (fc_host_statistic, "0x%llx\n") — NOT decimal, so
	// readSysfsInt's plain Atoi would silently parse every one of these as 0.
	// A genuine read failure ALSO parses to 0 via readSysfsHexInt (empty string
	// → ParseInt error → ignored, returns 0) — indistinguishable from a real
	// zero count unless tracked separately, so use the ok-returning variant and
	// flag CountersUnreadable when any of the three fails.
	var lfOK, losOK, losigOK bool
	port.LinkFailures, lfOK = readSysfsHexIntOK(hostPath + "/statistics/link_failure_count")
	port.LossOfSync, losOK = readSysfsHexIntOK(hostPath + "/statistics/loss_of_sync_count")
	port.LossOfSignal, losigOK = readSysfsHexIntOK(hostPath + "/statistics/loss_of_signal_count")
	port.CountersUnreadable = !lfOK || !losOK || !losigOK

	// Detect driver from symlink target (e.g. ../../devices/.../lpfc)
	if target, err := readLink(hostPath); err == nil {
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

// readSysfsHexInt reads a sysfs counter formatted as hex with a "0x" prefix
// (e.g. "0x2f\n") — a plain decimal Atoi rejects the "x" and silently returns 0
// for every value, healthy or not.
func readSysfsHexInt(path string) int {
	n, _ := readSysfsHexIntOK(path)
	return n
}

// readSysfsHexIntOK is readSysfsHexInt with an ok result: false when the
// underlying read failed or the content didn't parse (empty string), true
// when a real hex value — including a genuine 0x0 — was read. Needed
// wherever the caller must distinguish "checked, zero" from "couldn't check".
func readSysfsHexIntOK(path string) (int, bool) {
	s := strings.TrimSpace(readSysfsStr(path))
	if s == "" {
		return 0, false
	}
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	// bitSize 0 means "must fit in int" — int is 32-bit on some platforms, and
	// this rejects a sysfs value too large for that outright instead of
	// silently wrapping it on truncation to int below.
	n, err := strconv.ParseInt(s, 16, 0)
	if err != nil {
		return 0, false
	}
	return int(n), true
}
