//go:build linux

package collectors

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// KVMCollector gathers KVM/libvirt diagnostics via virsh shell-outs.
// Gate: libvirtd must be running (checked via virsh version exit code).
// Linux only — libvirt is not available on other platforms.
type KVMCollector struct {
	Deep bool
}

func NewKVMCollector() *KVMCollector     { return &KVMCollector{} }
func NewKVMDeepCollector() *KVMCollector { return &KVMCollector{Deep: true} }

func (c *KVMCollector) Name() string           { return "KVM" }
func (c *KVMCollector) Timeout() time.Duration { return 15 * time.Second }

func (c *KVMCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.KVMInfo{}

	// Gate: virsh version proves libvirtd is reachable
	verOut, err := runCmd(ctx, "virsh", "version", "--daemon")
	if err != nil {
		// libvirt not installed or daemon not running — return empty (not an error)
		return info, nil
	}
	info.Detected = true
	parseVirshVersion(verOut, info)

	// Collect in parallel-ish order (sequential is fine — each call is fast)
	kvmCollectVMs(ctx, info)
	kvmCollectNetworks(ctx, info)
	kvmCollectPools(ctx, info)

	return info, nil
}

// parseVirshVersion extracts libvirt and QEMU versions from virsh version output.
func parseVirshVersion(out string, info *models.KVMInfo) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Using library:"):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				info.LibvirtVer = parts[len(parts)-1]
			}
		case strings.HasPrefix(line, "Running hypervisor:"):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				info.QEMUVer = parts[len(parts)-1]
			}
		}
	}
}

// ── VM collection ─────────────────────────────────────────────────────────────

func kvmCollectVMs(ctx context.Context, info *models.KVMInfo) {
	out, err := runCmd(ctx, "virsh", "list", "--all", "--name")
	if err != nil || strings.TrimSpace(out) == "" {
		return
	}

	for _, name := range strings.Split(strings.TrimSpace(out), "\n") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		vm := kvmDomInfo(ctx, name)
		kvmCheckDiskErrors(ctx, &vm)
		kvmReadLastLogError(&vm)
		updateKVMCounts(info, &vm)
		info.VMs = append(info.VMs, vm)
	}
}

// kvmDomInfo runs virsh dominfo for a single domain and parses it.
func kvmDomInfo(ctx context.Context, name string) models.KVMVM {
	vm := models.KVMVM{Name: name, ID: -1}
	out, err := runCmd(ctx, "virsh", "dominfo", name)
	if err != nil {
		return vm
	}
	for _, line := range strings.Split(out, "\n") {
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colonIdx])
		val := strings.TrimSpace(line[colonIdx+1:])
		switch key {
		case "Id":
			if val != "-" {
				vm.ID, _ = strconv.Atoi(val)
			}
		case "State":
			vm.State = models.KVMVMState(val)
		case "CPU(s)":
			vm.VCPU, _ = strconv.Atoi(val)
		case "Max memory":
			// "524288 KiB"
			fields := strings.Fields(val)
			if len(fields) >= 1 {
				kib, _ := strconv.Atoi(fields[0])
				vm.MaxMemMB = kib / 1024
			}
		case "Used memory":
			fields := strings.Fields(val)
			if len(fields) >= 1 {
				kib, _ := strconv.Atoi(fields[0])
				vm.UsedMemMB = kib / 1024
			}
		case "Autostart":
			vm.AutoStart = val == "enable"
		}
	}
	return vm
}

// kvmCheckDiskErrors runs virsh domblkerror — any line containing "error" = I/O error.
func kvmCheckDiskErrors(ctx context.Context, vm *models.KVMVM) {
	if vm.ID < 0 {
		return // not running — no live disk stats
	}
	out, err := runCmd(ctx, "virsh", "domblkerror", vm.Name)
	if err != nil {
		return
	}
	// "No errors found" = clean. Actual errors look like: "vda  I/O error"
	lower := strings.ToLower(strings.TrimSpace(out))
	if lower != "" && !strings.Contains(lower, "no errors") {
		vm.DiskIOError = true
	}
}

// kvmReadLastLogError reads the last error line from /var/log/libvirt/qemu/<name>.log.
func kvmReadLastLogError(vm *models.KVMVM) {
	logPath := filepath.Join("/var/log/libvirt/qemu", vm.Name+".log")
	f, err := os.Open(logPath) // #nosec G304
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck

	keywords := []string{"error", "failed", "killed", "abort", "permission denied", "no such file"}
	var lastError string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		lower := strings.ToLower(line)
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				lastError = strings.TrimSpace(line)
				break
			}
		}
	}
	if lastError != "" {
		if len(lastError) > 120 {
			lastError = lastError[:120] + "…"
		}
		vm.LastLogError = lastError
	}
}

// updateKVMCounts increments the relevant summary counters.
func updateKVMCounts(info *models.KVMInfo, vm *models.KVMVM) {
	switch vm.State {
	case models.KVMRunning:
		info.VMsRunning++
	case models.KVMPaused:
		info.VMsPaused++
	case models.KVMCrashed:
		info.VMsCrashed++
	case models.KVMShutOff, models.KVMShutDown:
		if vm.AutoStart {
			info.VMsDownAutostart++
		}
	}
	if vm.DiskIOError {
		info.DiskIOErrors++
	}
}

// ── Network collection ────────────────────────────────────────────────────────

func kvmCollectNetworks(ctx context.Context, info *models.KVMInfo) {
	out, err := runCmd(ctx, "virsh", "net-list", "--all")
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		// Format: " Name      State    Autostart   Persistent"
		// Data:   " default   active   yes         yes"
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] == "Name" || strings.HasPrefix(fields[0], "-") {
			continue
		}
		net := models.KVMNetwork{
			Name:      fields[0],
			State:     fields[1],
			Autostart: fields[2] == "yes",
		}
		if net.State != "active" {
			info.NetworksInactive++
		} else {
			// Check bridge link state
			bridgeOut, _ := runCmd(ctx, "virsh", "net-info", net.Name)
			net.Bridge = kvmParseBridge(bridgeOut)
			if net.Bridge != "" {
				linkOut, _ := runCmd(ctx, "ip", "link", "show", net.Bridge)
				net.BridgeUp = strings.Contains(linkOut, "state UP") ||
					(strings.Contains(linkOut, net.Bridge) && !strings.Contains(linkOut, "state DOWN"))
			}
		}
		info.Networks = append(info.Networks, net)
	}
}

// kvmParseBridge extracts the bridge name from virsh net-info output.
func kvmParseBridge(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Bridge:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

// ── Storage pool collection ───────────────────────────────────────────────────

func kvmCollectPools(ctx context.Context, info *models.KVMInfo) {
	out, err := runCmd(ctx, "virsh", "pool-list", "--all")
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] == "Name" || strings.HasPrefix(fields[0], "-") {
			continue
		}
		pool := models.KVMStoragePool{
			Name:  fields[0],
			State: fields[1],
		}
		if pool.State != "active" {
			info.PoolsInactive++
			info.StoragePools = append(info.StoragePools, pool)
			continue
		}
		// Get capacity details via pool-info
		infoOut, err := runCmd(ctx, "virsh", "pool-info", pool.Name)
		if err == nil {
			kvmParsePoolInfo(infoOut, &pool)
		}
		if pool.CapacityGB > 0 && pool.UsedPct >= 85 {
			info.PoolsNearFull++
		}
		info.StoragePools = append(info.StoragePools, pool)
	}
}

// kvmParsePoolInfo extracts capacity from virsh pool-info output.
func kvmParsePoolInfo(out string, pool *models.KVMStoragePool) {
	for _, line := range strings.Split(out, "\n") {
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colonIdx])
		val := strings.TrimSpace(line[colonIdx+1:])
		switch key {
		case "Capacity":
			pool.CapacityGB = kvmParseBytes(val)
		case "Available":
			pool.AvailableGB = kvmParseBytes(val)
		}
	}
	if pool.CapacityGB > 0 {
		used := pool.CapacityGB - pool.AvailableGB
		pool.UsedPct = used / pool.CapacityGB * 100
	}
}

// kvmParseBytes converts virsh capacity strings like "200.00 GiB" to GB.
func kvmParseBytes(s string) float64 {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return 0
	}
	val, _ := strconv.ParseFloat(fields[0], 64)
	unit := strings.ToUpper(fields[1])
	switch {
	case strings.HasPrefix(unit, "TIB") || strings.HasPrefix(unit, "TB"):
		return val * 1000
	case strings.HasPrefix(unit, "GIB") || strings.HasPrefix(unit, "GB"):
		return val
	case strings.HasPrefix(unit, "MIB") || strings.HasPrefix(unit, "MB"):
		return val / 1024
	case strings.HasPrefix(unit, "KIB") || strings.HasPrefix(unit, "KB"):
		return val / (1024 * 1024)
	}
	return 0
}

// KVMAvailable returns true when virsh is found, indicating libvirt is installed.
// The actual daemon check happens in Collect() — this is a cheap binary check.
func KVMAvailable() bool {
	_, err := runCmdTimeout(2*time.Second, "virsh", "version", "--daemon")
	return err == nil
}
