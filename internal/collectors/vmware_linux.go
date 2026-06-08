//go:build linux

package collectors

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// VMwareCollector reports VMware-guest configuration health for a Linux guest
// running under VMware (ESXi/Workstation/Fusion). All work is gated behind
// VMwareGuestAvailable() so it is zero-cost — and silent — on every host that is
// not a VMware guest. Scope is guest-side only (open-vm-tools, paravirtual
// drivers); ESXi internals and the vSwitch are not visible from inside the guest.
type VMwareCollector struct{}

func NewVMwareCollector() *VMwareCollector { return &VMwareCollector{} }

func (c *VMwareCollector) Name() string           { return "VMware" }
func (c *VMwareCollector) Timeout() time.Duration { return 3 * time.Second }

const dmiIDDir = "/sys/class/dmi/id"

// VMwareGuestAvailable reports whether this host is a Linux guest under VMware.
// Cheap gate (same shape as KVMAvailable/CloudInitAvailable): a world-readable
// DMI vendor/product string is enough — no root, no command execution.
func VMwareGuestAvailable() bool {
	return isVMwareGuest(
		readFileTrimmedLocal(filepath.Join(dmiIDDir, "sys_vendor")),
		readFileTrimmedLocal(filepath.Join(dmiIDDir, "product_name")),
	)
}

// isVMwareGuest matches VMware's DMI signatures. sys_vendor is "VMware, Inc."
// on ESXi guests; product_name is "VMware Virtual Platform" (older) or
// "VMware7,1" / "VMware20,1" (hardware-version-derived, newer).
func isVMwareGuest(sysVendor, productName string) bool {
	hay := strings.ToLower(sysVendor + " " + productName)
	return strings.Contains(hay, "vmware")
}

func (c *VMwareCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.VMwareInfo{
		IsGuest:     true,
		ProductName: readFileTrimmedLocal(filepath.Join(dmiIDDir, "product_name")),
	}

	info.ToolsInstalled = vmwareToolsInstalled()
	info.ToolsRunning = vmwareToolsRunning(ctx)

	info.NICDrivers, info.EmulatedNICs = collectNICDrivers("/sys/class/net")

	mods := readFileTrimmedLocal("/proc/modules")
	info.PVSCSILoaded = kernelModulePresent(mods, "vmw_pvscsi")
	info.BalloonLoaded = kernelModulePresent(mods, "vmw_balloon")

	// Host-imposed resource pressure/limits — only readable when tools run.
	if info.ToolsRunning {
		collectVMwareStat(ctx, info)
	}

	info.SCSITimeouts, info.LowSCSITimeouts = collectSCSITimeouts("/sys/block")

	return info, nil
}

// vmwareSCSITimeoutRecommended is VMware's recommended guest SCSI command
// timeout (seconds) — high enough to ride out a vMotion / storage-failover stun
// without the filesystem going read-only. The Linux kernel default is 30s.
const vmwareSCSITimeoutRecommended = 180

// collectVMwareStat fills the host-imposed resource fields from
// `vmware-toolbox-cmd stat`. balloon is read first as the probe: if it fails,
// the stat interface is unavailable (old tools / no permission) and everything
// is left zero with StatAvailable=false.
func collectVMwareStat(ctx context.Context, info *models.VMwareInfo) {
	toolbox := vmwareToolboxPath()
	if toolbox == "" {
		return
	}
	balloon, ok := vmwareStatMB(ctx, toolbox, "balloon")
	if !ok {
		return // stat unsupported / failed — leave StatAvailable false
	}
	info.StatAvailable = true
	info.BalloonMB = balloon
	if swap, ok := vmwareStatMB(ctx, toolbox, "swap"); ok {
		info.HostSwapMB = swap
	}
	if limit, limited := vmwareStatLimit(ctx, toolbox, "memlimit"); limited {
		info.MemLimitMB = limit
	}
	if limit, limited := vmwareStatLimit(ctx, toolbox, "cpulimit"); limited {
		info.CPULimitMHz = limit
	}
}

// vmwareToolboxPath locates vmware-toolbox-cmd, "" when absent.
func vmwareToolboxPath() string {
	if p, err := exec.LookPath("vmware-toolbox-cmd"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/bin/vmware-toolbox-cmd", "/usr/sbin/vmware-toolbox-cmd"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// vmwareStatMB runs `vmware-toolbox-cmd stat <key>` and parses a leading
// integer in MB (e.g. "128 MB" -> 128). ok is false on command failure or when
// no leading integer is present.
func vmwareStatMB(ctx context.Context, toolbox, key string) (int, bool) {
	out, err := runCmd(ctx, toolbox, "stat", key)
	if err != nil {
		return 0, false
	}
	return parseLeadingInt(out)
}

// vmwareStatLimit parses a `stat <key>` value that is either "Unlimited" (no
// host cap) or a number with a unit ("1500 MHz", "2048 MB"). limited is true
// only when a finite cap was parsed.
func vmwareStatLimit(ctx context.Context, toolbox, key string) (int, bool) {
	out, err := runCmd(ctx, toolbox, "stat", key)
	if err != nil {
		return 0, false
	}
	if strings.Contains(strings.ToLower(out), "unlimited") {
		return 0, false
	}
	v, ok := parseLeadingInt(out)
	if !ok {
		return 0, false
	}
	return v, true
}

// parseLeadingInt extracts a run of digits at the very start of s (after
// trimming whitespace), e.g. "128 MB" -> 128. ok is false when s does not begin
// with a digit.
func parseLeadingInt(s string) (int, bool) {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0, false
	}
	return n, true
}

// collectSCSITimeouts reads the command timeout (seconds) for each SCSI disk
// from /sys/block/sd*/device/timeout and returns those below the VMware
// recommendation. Scoped to sd* (SCSI) because the 180s guidance is about
// surviving a storage stun; virtio-blk (vd*) disks are not the target.
func collectSCSITimeouts(blockDir string) (map[string]int, []string) {
	entries, err := os.ReadDir(blockDir)
	if err != nil {
		return nil, nil
	}
	timeouts := map[string]int{}
	var low []string
	for _, e := range entries {
		dev := e.Name()
		if !strings.HasPrefix(dev, "sd") {
			continue
		}
		raw := readFileTrimmedLocal(filepath.Join(blockDir, dev, "device", "timeout"))
		t, ok := parseLeadingInt(raw)
		if !ok {
			continue
		}
		timeouts[dev] = t
		if t < vmwareSCSITimeoutRecommended {
			low = append(low, dev)
		}
	}
	if len(timeouts) == 0 {
		return nil, nil
	}
	sort.Strings(low)
	return timeouts, low
}

// vmwareToolsInstalled is true when the guest-tools daemon binary is present.
func vmwareToolsInstalled() bool {
	if _, err := exec.LookPath("vmtoolsd"); err == nil {
		return true
	}
	for _, p := range []string{"/usr/bin/vmtoolsd", "/usr/sbin/vmtoolsd", "/usr/bin/vmware-toolbox-cmd"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// vmwareToolsRunning is true when a vmtoolsd process is alive. Scans /proc/*/comm
// directly — distro-agnostic (the systemd unit is "vmtoolsd" on some distros,
// "open-vm-tools" on others) and needs no root.
func vmwareToolsRunning(ctx context.Context) bool {
	if running, ok := procCommRunning("vmtoolsd"); ok {
		return running
	}
	// Fallback: ask systemd if /proc was unreadable for some reason.
	for _, unit := range []string{"vmtoolsd", "open-vm-tools"} {
		if out, err := runCmd(ctx, "systemctl", "is-active", unit); err == nil &&
			strings.TrimSpace(out) == "active" {
			return true
		}
	}
	return false
}

// procCommRunning scans /proc/<pid>/comm for an exact process name. The second
// return is false when /proc could not be read at all (so the caller can fall
// back), distinguishing "not running" from "couldn't tell".
func procCommRunning(name string) (running, ok bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == name {
			return true, true
		}
	}
	return false, true
}

// collectNICDrivers maps each non-loopback interface to its kernel driver and
// returns the subset using emulated (non-paravirtual) drivers.
func collectNICDrivers(netDir string) (map[string]string, []string) {
	entries, err := os.ReadDir(netDir)
	if err != nil {
		return nil, nil
	}
	drivers := map[string]string{}
	var emulated []string
	for _, e := range entries {
		iface := e.Name()
		if iface == "lo" {
			continue
		}
		// /sys/class/net/<if>/device/driver is a symlink to the driver module.
		link, err := os.Readlink(filepath.Join(netDir, iface, "device", "driver"))
		if err != nil {
			continue
		}
		drv := filepath.Base(link)
		drivers[iface] = drv
		if nicDriverEmulated(drv) {
			emulated = append(emulated, iface)
		}
	}
	if len(drivers) == 0 {
		return nil, nil
	}
	sort.Strings(emulated)
	return drivers, emulated
}

// nicDriverEmulated reports whether a NIC driver is an emulated device (vs the
// paravirtual vmxnet3). Emulated NICs work but cost host CPU and cap throughput.
func nicDriverEmulated(driver string) bool {
	switch strings.ToLower(driver) {
	case "e1000", "e1000e", "vlance", "pcnet32":
		return true
	default: // vmxnet3 (paravirtual) and anything else (e.g. SR-IOV passthrough)
		return false
	}
}

// moduleLoaded reports whether a kernel module appears in /proc/modules content.
// Matches the module name in the first whitespace-delimited column of any line.
func moduleLoaded(procModules, name string) bool {
	for _, line := range strings.Split(procModules, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == name {
			return true
		}
	}
	return false
}

// kernelModulePresent reports whether a module is loaded (listed in
// /proc/modules) OR built into the kernel. A built-in module never appears in
// /proc/modules but does have a /sys/module/<name> directory, so checking both
// avoids a false "absent" for vmw_pvscsi/vmw_balloon on kernels that compile
// them in rather than ship them as loadable modules.
func kernelModulePresent(procModules, name string) bool {
	if moduleLoaded(procModules, name) {
		return true
	}
	_, err := os.Stat(filepath.Join("/sys/module", name))
	return err == nil
}

// readFileTrimmedLocal reads a file and trims whitespace, "" on any error.
func readFileTrimmedLocal(path string) string {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
