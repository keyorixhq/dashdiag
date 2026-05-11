//go:build linux

package collectors

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// GPUCollector reads GPU health via nvidia-smi.
// nvidia-smi is an acceptable wrapper — there is no stable kernel interface
// for GPU utilization, VRAM, or power draw on NVIDIA hardware.
// Xid error detection is handled by LogsCollector via /dev/kmsg.
type GPUCollector struct{}

func NewGPUCollector() *GPUCollector { return &GPUCollector{} }

func (c *GPUCollector) Name() string           { return "GPU" }
func (c *GPUCollector) Timeout() time.Duration { return 8 * time.Second }

func (c *GPUCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.GPUInfo{}

	// Hard 5s timeout on nvidia-smi
	smiCtx, smiCancel := context.WithTimeout(ctx, 5*time.Second)
	defer smiCancel()

	out, err := runCmd(smiCtx, "nvidia-smi",
		"--query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,driver_version",
		"--format=csv,noheader,nounits")
	if err != nil {
		return info, nil // nvidia-smi not available or timed out
	}

	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		dev, driverVer, err := parseNvidiaSMILine(line)
		if err != nil {
			continue
		}
		if driverVer != "" && info.DriverVersion == "" {
			info.DriverVersion = driverVer
		}
		// Collect GPU processes when utilization or temp is elevated
		if dev.UtilPct >= 50 || dev.TempC >= 70 {
			dev.Processes = collectGPUProcesses(smiCtx)
		}
		info.Devices = append(info.Devices, dev)
	}

	return info, nil
}

// collectGPUProcesses returns processes using the GPU via nvidia-smi.
func collectGPUProcesses(ctx context.Context) []models.GPUProcess {
	out, err := runCmd(ctx, "nvidia-smi",
		"--query-compute-apps=pid,used_memory,name",
		"--format=csv,noheader,nounits")
	if err != nil {
		return nil
	}

	var procs []models.GPUProcess
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, ",", 3)
		if len(fields) < 3 {
			continue
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(fields[0]))
		memStr := strings.TrimSpace(fields[1])
		// memory field may be "6823 MiB" or just "6823"
		memFields := strings.Fields(memStr)
		mem, _ := strconv.Atoi(memFields[0])
		name := strings.TrimSpace(fields[2])
		procs = append(procs, models.GPUProcess{
			PID:      pid,
			Name:     name,
			MemUseMB: mem,
		})
	}
	return procs
}

func parseNvidiaSMILine(line string) (models.GPUDevice, string, error) {
	fields := strings.Split(line, ",")
	if len(fields) < 8 {
		return models.GPUDevice{}, "", fmt.Errorf("unexpected fields: %d", len(fields))
	}
	trim := func(s string) string { return strings.TrimSpace(s) }

	idx, _ := strconv.Atoi(trim(fields[0]))
	name := trim(fields[1])
	temp, _ := strconv.Atoi(trim(fields[2]))
	util, _ := strconv.Atoi(trim(fields[3]))
	memUsed, _ := strconv.Atoi(trim(fields[4]))
	memTotal, _ := strconv.Atoi(trim(fields[5]))
	powerStr := trim(fields[6])
	var power float64
	if powerStr != "[N/A]" {
		power, _ = strconv.ParseFloat(powerStr, 64)
	}
	driverVer := trim(fields[7])

	memPct := 0.0
	if memTotal > 0 {
		memPct = float64(memUsed) / float64(memTotal) * 100
	}

	return models.GPUDevice{
		Index:      idx,
		Name:       name,
		TempC:      temp,
		UtilPct:    util,
		MemUsedMB:  memUsed,
		MemTotalMB: memTotal,
		MemUsedPct: memPct,
		PowerDrawW: power,
	}, driverVer, nil
}
