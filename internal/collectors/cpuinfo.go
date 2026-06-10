package collectors

import (
	"fmt"
	"strconv"
	"strings"
)

// procCPUInfo holds the fields parsed out of /proc/cpuinfo.
type procCPUInfo struct {
	model       string
	hardware    string // ARM bare-metal "Hardware" field
	implementer string // ARM "CPU implementer"
	part        string // ARM "CPU part" (core ID, e.g. 0xd0c = Neoverse-N1)
	threads     int
	cores       int
	freqMHz     float64
}

// parseProcCPUInfo parses the contents of /proc/cpuinfo.
//
// Logical-CPU count comes solely from the "processor" lines, which the kernel
// emits one-per-logical-CPU on both x86 and ARM. The "model name" line (x86
// only) is used to capture the model string but must NOT also bump the count —
// x86 has both a "processor" and a "model name" line per CPU, so counting both
// double-counts threads (and halves any load-per-thread figure derived from it).
func parseProcCPUInfo(data string) procCPUInfo {
	var info procCPUInfo
	coresSet := false

	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		switch key {
		case "processor": // one entry per logical CPU on both x86 and ARM
			info.threads++
		case "model name": // x86: capture model only — do NOT count (processor already does)
			if info.model == "" {
				info.model = val
			}
		case "cpu cores": // x86
			if !coresSet {
				if n, err := strconv.Atoi(val); err == nil {
					info.cores = n
					coresSet = true
				}
			}
		case "cpu MHz": // x86
			if info.freqMHz == 0 {
				if f, err := strconv.ParseFloat(val, 64); err == nil {
					info.freqMHz = f
				}
			}
		case "Hardware": // ARM bare-metal: "Raspberry Pi 4 Model B Rev 1.4"
			info.hardware = val
		case "CPU implementer": // ARM
			if info.implementer == "" {
				info.implementer = val
			}
		case "CPU part": // ARM core ID
			if info.part == "" {
				info.part = val
			}
		}
	}

	// ARM: prefer the Hardware field, else a vendor (+ core) description.
	if info.model == "" {
		info.model = info.hardware
	}
	if info.model == "" && info.implementer != "" {
		info.model = armModelString(info.implementer, info.part)
	}

	return info
}

// armModelString builds a human model string from the ARM implementer (vendor) and
// part (core) codes, e.g. "ARM Neoverse-N1 (aarch64)" or, when the core is unknown,
// "Ampere (aarch64)". ARM /proc/cpuinfo has no "model name" line, so this is the
// best identity available without DMI/SMBIOS (which needs real hardware).
func armModelString(implementer, part string) string {
	vendor := armImplementerName(implementer)
	if core := armPartName(implementer, part); core != "" {
		return fmt.Sprintf("%s %s (aarch64)", vendor, core)
	}
	return fmt.Sprintf("%s (aarch64)", vendor)
}

// armPartName maps an ARM implementer+part to a core name. Part IDs are scoped to
// the implementer, so they are matched per-vendor. Values are the canonical kernel
// IDs (arch/arm64/include/asm/cputype.h); unknown parts return "" (vendor-only).
func armPartName(implementer, part string) string {
	switch strings.ToLower(implementer) {
	case "0x41": // ARM Ltd — Cortex / Neoverse reference cores
		switch strings.ToLower(part) {
		case "0xd03":
			return "Cortex-A53"
		case "0xd05":
			return "Cortex-A55"
		case "0xd07":
			return "Cortex-A57"
		case "0xd08":
			return "Cortex-A72"
		case "0xd0b":
			return "Cortex-A76"
		case "0xd0c":
			return "Neoverse-N1" // Ampere Altra, AWS Graviton2
		case "0xd40":
			return "Neoverse-V1" // AWS Graviton3
		case "0xd49":
			return "Neoverse-N2"
		}
	case "0xc0": // Ampere
		if strings.ToLower(part) == "0xac3" {
			return "AmpereOne"
		}
	}
	return ""
}

// armImplementerName maps an ARM "CPU implementer" hex code to a vendor name.
func armImplementerName(code string) string {
	switch strings.ToLower(code) {
	case "0x41":
		return "ARM"
	case "0x42":
		return "Broadcom"
	case "0x43":
		return "Cavium"
	case "0x44":
		return "DEC"
	case "0x48":
		return "HiSilicon"
	case "0x49":
		return "Infineon"
	case "0x4d":
		return "Motorola/Freescale"
	case "0x4e":
		return "NVIDIA"
	case "0x50":
		return "APM"
	case "0x51":
		return "Qualcomm"
	case "0x53":
		return "Samsung"
	case "0x56":
		return "Marvell"
	case "0x61":
		return "Apple"
	case "0x66":
		return "Faraday"
	case "0x69":
		return "Intel"
	case "0x70":
		return "Phytium"
	case "0xc0":
		return "Ampere"
	default:
		return code
	}
}
