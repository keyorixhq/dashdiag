//go:build linux

package collectors

import (
	"path/filepath"
	"strconv"
	"strings"
)

// readMemHotplug reports memory hot-plug onlining state from sysfs: whether any
// memory blocks are offline (RAM the kernel sees but isn't using) and whether the
// kernel auto-onlines newly hot-added blocks. The classic bug it catches: a
// hypervisor hot-adds RAM to a running guest, auto-onlining is off, and the guest
// never uses the new memory. Cheap sysfs reads, so safe on the fast health path.
func readMemHotplug() (checked bool, offlineBlocks int, offlineMB int64, autoOnline bool) {
	return readMemHotplugFrom("/sys/devices/system/memory")
}

func readMemHotplugFrom(root string) (checked bool, offlineBlocks int, offlineMB int64, autoOnline bool) {
	entries, err := readDirNames(root)
	if err != nil {
		return false, 0, 0, false // memory-hotplug sysfs absent (non-hotplug kernel)
	}

	sawBlock := false
	for _, e := range entries {
		// Only memoryN block directories (memory0, memory1, …) — not the class dir's
		// own files (block_size_bytes, auto_online_blocks, …).
		rest := strings.TrimPrefix(e, "memory")
		if rest == e || !isAllDigits(rest) {
			continue
		}
		statePath := filepath.Join(root, e, "state")
		if !fileExists(statePath) {
			continue
		}
		sawBlock = true
		if readFileTrimmedLocal(statePath) == "offline" {
			offlineBlocks++
		}
	}
	if !sawBlock {
		return false, 0, 0, false
	}

	autoOnline = readFileTrimmedLocal(filepath.Join(root, "auto_online_blocks")) == "online"

	// block_size_bytes is reported in hex (e.g. "8000000" = 128 MiB). Best-effort:
	// if it doesn't parse we still report the block COUNT, just not the MB total.
	if bs, err := strconv.ParseInt(readFileTrimmedLocal(filepath.Join(root, "block_size_bytes")), 16, 64); err == nil && bs > 0 {
		offlineMB = int64(offlineBlocks) * bs / (1024 * 1024)
	}
	return true, offlineBlocks, offlineMB, autoOnline
}
