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

type SRIOVCollector struct{}

func NewSRIOVCollector() *SRIOVCollector         { return &SRIOVCollector{} }
func (c *SRIOVCollector) Name() string           { return "SRIOV" }
func (c *SRIOVCollector) Timeout() time.Duration { return 3 * time.Second }

func (c *SRIOVCollector) Collect(_ context.Context) (interface{}, error) {
	info := &models.SRIOVInfo{}

	// /sys/bus/pci/devices/*/sriov_numvfs — only PCI devices with SR-IOV capability
	numvfsFiles, _ := filepath.Glob("/sys/bus/pci/devices/*/sriov_numvfs")
	if len(numvfsFiles) == 0 {
		return info, nil
	}

	for _, nvf := range numvfsFiles {
		devPath := filepath.Dir(nvf)
		pci := filepath.Base(devPath)

		numVFs := readSysfsInt(nvf)
		totalVFs := readSysfsInt(filepath.Join(devPath, "sriov_totalvfs"))

		// Only surface devices that have VFs enabled or are SR-IOV capable
		if totalVFs == 0 {
			continue
		}

		driver := ""
		if target, err := filepath.EvalSymlinks(filepath.Join(devPath, "driver")); err == nil {
			driver = filepath.Base(target)
		}

		info.Devices = append(info.Devices, models.SRIOVDevice{
			PCI:      pci,
			Driver:   driver,
			NumVFs:   numVFs,
			TotalVFs: totalVFs,
		})
	}
	return info, nil
}

// IsSRIOVPresent returns true when any SR-IOV capable device exists.
func IsSRIOVPresent() bool {
	files, _ := filepath.Glob("/sys/bus/pci/devices/*/sriov_totalvfs")
	for _, f := range files {
		v := strings.TrimSpace(readSysfsStr(f))
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 {
			return true
		}
	}
	return false
}
