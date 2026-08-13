// Package inventory assembles a CMDB-ingestable hardware/software inventory
// from data DashDiag already collects (HardwareInfo + platform Profile) plus a
// few cheap identity reads. It probes nothing expensive and shells out only for
// the rpm package count. All filesystem reads are best-effort: on non-Linux
// hosts the Linux sysfs/proc paths simply don't exist and the fields stay empty.
package inventory

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// Build assembles the Inventory. hw, gpu, and cloud may be nil (e.g. on
// non-Linux or when a section is unavailable); identity fields are still
// populated where possible.
func Build(hw *models.HardwareInfo, gpu *models.GPUInfo, cloud *models.CloudInfo, profile platform.Profile, toolVersion, collectedAt string) models.Inventory {
	host, _ := os.Hostname()
	inv := models.Inventory{
		CollectedAt: collectedAt,
		Tool:        "dsd",
		ToolVersion: toolVersion,
		Host: models.InventoryHost{
			Hostname:      host,
			OS:            platform.OSPrettyName(),
			Distro:        profile.Distro,
			DistroVersion: profile.DistroVersion,
			Kernel:        readKernel(),
			Arch:          runtime.GOARCH,
			MachineID:     readMachineID(),
		},
		Software: models.InventorySoftware{
			PackageManager: profile.PackageManager,
			PackageCount:   countPackages(profile.PackageManager),
		},
	}

	if hw != nil {
		inv.System = models.InventorySystem{
			Vendor: hw.System.Vendor,
			Model:  hw.System.Model,
			Board:  hw.System.Board,
		}
		inv.CPU = models.InventoryCPU{
			Model:   hw.CPU.Model,
			Cores:   hw.CPU.Cores,
			Threads: hw.CPU.Threads,
		}
		inv.Memory.TotalGB = hw.Memory.TotalGB
		for _, s := range hw.Memory.Slots {
			// MemorySlot and InventorySlot have identical fields — direct convert.
			inv.Memory.Slots = append(inv.Memory.Slots, models.InventorySlot(s))
		}
		for _, n := range hw.NICs {
			// CMDB feed: keep only real interfaces with a valid EUI-48 MAC.
			// Drops loopback and tunnel pseudo-NICs (sit0, ip6tnl0, …) whose
			// MAC is empty or a non-standard length.
			if !isEUI48(n.MAC) {
				continue
			}
			inv.NICs = append(inv.NICs, models.InventoryNIC{
				Name: n.Name, MAC: n.MAC, SpeedMbps: n.SpeedMbps, Driver: n.Driver,
			})
		}
	}
	// DMI serial + physical drives come straight from sysfs (HardwareInfo
	// carries neither drive capacity nor serial).
	inv.System.Serial = readDMI("product_serial")
	inv.Drives = readBlockDevices("/sys/block")

	if gpu != nil {
		for i, d := range gpu.Devices {
			inv.GPUs = append(inv.GPUs, models.InventoryGPU{
				Index:       i,
				Name:        d.Name,
				Vendor:      d.Vendor,
				VRAMTotalGB: d.VRAMTotalGB,
				DRMDriver:   d.DRMDriver,
				MesaVersion: d.MesaVersion,
			})
		}
		// GPUs detected in sysfs but without a loaded driver are still hardware.
		baseIdx := len(gpu.Devices)
		for i, nd := range gpu.NoDriver {
			inv.GPUs = append(inv.GPUs, models.InventoryGPU{
				Index:    baseIdx + i,
				Name:     nd.Name,
				Vendor:   nd.Vendor,
				NoDriver: true,
			})
		}
	}

	if cloud != nil && cloud.Available {
		inv.Cloud = &models.InventoryCloud{
			Provider:     cloud.Provider,
			InstanceID:   cloud.InstanceID,
			InstanceType: cloud.InstanceType,
			Region:       cloud.Region,
		}
	}

	return inv
}

func readKernel() string {
	return readTrim("/proc/sys/kernel/osrelease")
}

func readMachineID() string {
	return readMachineIDFrom("/etc/machine-id", "/var/lib/dbus/machine-id")
}

// readMachineIDFrom reads the machine ID from primary, falling back to
// secondary when primary is missing or empty. Paths are injectable so tests
// never need to touch the real /etc or /var/lib.
func readMachineIDFrom(primary, secondary string) string {
	if id := readTrim(primary); id != "" {
		return id
	}
	return readTrim(secondary)
}

func readDMI(field string) string {
	return readTrim(filepath.Join("/sys/class/dmi/id", field))
}

// readBlockDevices enumerates real physical disks under blockDir, skipping
// virtual/removable noise (loop, ram, dm, sr, zram). Returns device path,
// model, serial, and decimal-GB capacity (sectors × 512).
func readBlockDevices(blockDir string) []models.InventoryDrive {
	entries, err := os.ReadDir(blockDir)
	if err != nil {
		return nil
	}
	var drives []models.InventoryDrive
	for _, e := range entries {
		name := e.Name()
		if isVirtualBlock(name) {
			continue
		}
		base := filepath.Join(blockDir, name)
		d := models.InventoryDrive{Device: "/dev/" + name}
		d.Model = readTrim(filepath.Join(base, "device", "model"))
		d.Serial = readTrim(filepath.Join(base, "device", "serial"))
		if sectors, err := strconv.ParseInt(readTrim(filepath.Join(base, "size")), 10, 64); err == nil && sectors > 0 {
			d.SizeGB = float64(sectors*512) / 1e9
		}
		drives = append(drives, d)
	}
	return drives
}

// isEUI48 reports whether mac is a standard 6-octet MAC (xx:xx:xx:xx:xx:xx).
func isEUI48(mac string) bool {
	if len(mac) != 17 {
		return false
	}
	// All-zero MACs (some bond/virtual devices report 00:00:00:00:00:00) are not
	// real hardware addresses — exclude them from the CMDB NIC list.
	if mac == "00:00:00:00:00:00" {
		return false
	}
	for i, c := range mac {
		if i%3 == 2 {
			if c != ':' {
				return false
			}
			continue
		}
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

func isVirtualBlock(name string) bool {
	for _, p := range []string{"loop", "ram", "dm-", "sr", "zram", "md", "fd", "nbd"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// countPackages returns the installed-package count for the detected manager.
// File-based where cheap (dpkg, pacman); a bounded shell-out for rpm. Returns 0
// when unknown — better an honest zero than a wrong number.
func countPackages(pm string) int {
	switch pm {
	case "apt":
		return countDpkg("/var/lib/dpkg/status")
	case "pacman":
		return countDir("/var/lib/pacman/local")
	case "dnf", "tdnf", "yum", "zypper":
		return countRPM()
	default:
		return 0
	}
}

func countDpkg(statusFile string) int {
	data, err := os.ReadFile(statusFile)
	if err != nil {
		return 0
	}
	return strings.Count(string(data), "\nStatus: install ok installed")
}

func countDir(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			n++
		}
	}
	return n
}

// resolveRPM resolves "rpm" to an absolute path via source.ResolveTrustedTool
// (trusted system dirs, never the invoking process's inherited $PATH) before
// countRPM execs it — this inventory build can run as root, so a directory
// earlier in $PATH than the real rpm binary could otherwise substitute a
// malicious one (same class internal/source/trustedexec.go's
// ResolveTrustedTool already hardens for the collectors package's exec
// path). A var so tests can point countRPM at a fake binary directly.
var resolveRPM = source.ResolveTrustedTool

func countRPM() int {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, resolveRPM("rpm"), "-qa").Output() // NOSONAR — hardcoded binary
	if err != nil {
		return 0
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, "\n") + 1
}

// readTrim reads path and trims surrounding whitespace, assuming — but not
// enforcing on its own — that kernel-exposed sysfs/DMI attribute values are
// printable text. A crafted DMI string or block-device model/serial can
// carry raw ANSI/OSC escape sequences, and every caller of readTrim ends up
// in models.Inventory string fields that reach `dsd inventory`'s JSON/CSV/
// stdout output with no other sanitization in the pipeline — strip control
// characters here so every caller gets an already-safe value.
func readTrim(path string) string {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return ""
	}
	return stripControl(strings.TrimSpace(string(data)))
}

// stripControl removes control characters (including ESC, which starts
// ANSI/OSC/DCS terminal escape sequences) from s, leaving printable text
// unchanged. inventory/ has no dependency on internal/output today, so this
// duplicates the small amount of logic in output.SanitizeControl rather than
// adding a new cross-package import for one helper.
func stripControl(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
