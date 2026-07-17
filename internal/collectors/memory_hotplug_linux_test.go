//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadMemHotplugFrom(t *testing.T) {
	// Build a fake /sys/devices/system/memory with 8 blocks, block size 128 MiB
	// (hex "8000000"), auto-online OFF, and 2 blocks offline — the hot-add bug.
	mk := func(t *testing.T) string {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "block_size_bytes"), []byte("8000000\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "auto_online_blocks"), []byte("offline\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 8; i++ {
			dir := filepath.Join(root, "memory"+itoa(i))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			state := "online\n"
			if i >= 6 { // memory6, memory7 offline
				state = "offline\n"
			}
			if err := os.WriteFile(filepath.Join(dir, "state"), []byte(state), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		// A non-block entry that must be ignored.
		if err := os.MkdirAll(filepath.Join(root, "power"), 0o755); err != nil {
			t.Fatal(err)
		}
		return root
	}

	root := mk(t)
	checked, offline, offlineMB, auto := readMemHotplugFrom(root)
	if !checked {
		t.Fatal("checked = false, want true (blocks present)")
	}
	if offline != 2 {
		t.Errorf("offlineBlocks = %d, want 2", offline)
	}
	if offlineMB != 256 { // 2 × 128 MiB
		t.Errorf("offlineMB = %d, want 256", offlineMB)
	}
	if auto {
		t.Error("autoOnline = true, want false (auto_online_blocks is offline)")
	}
}

func TestReadMemHotplugFromHealthy(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "block_size_bytes"), []byte("8000000\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "auto_online_blocks"), []byte("online\n"), 0o644)
	for i := 0; i < 4; i++ {
		dir := filepath.Join(root, "memory"+itoa(i))
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "state"), []byte("online\n"), 0o644)
	}
	checked, offline, offlineMB, auto := readMemHotplugFrom(root)
	if !checked || offline != 0 || offlineMB != 0 || !auto {
		t.Errorf("healthy: got checked=%v offline=%d mb=%d auto=%v, want true/0/0/true", checked, offline, offlineMB, auto)
	}
}

func TestReadMemHotplugFromAbsent(t *testing.T) {
	// No memory-hotplug sysfs (non-hotplug kernel) → checked=false, nothing flagged.
	checked, offline, offlineMB, auto := readMemHotplugFrom(filepath.Join(t.TempDir(), "nope"))
	if checked || offline != 0 || offlineMB != 0 || auto {
		t.Errorf("absent dir: got checked=%v offline=%d mb=%d auto=%v, want all zero/false", checked, offline, offlineMB, auto)
	}
}

// TestReadMemHotplugFrom_MissingStateFile covers the !fileExists(statePath)
// continue branch: a memoryN directory that exists in the root but has no "state"
// file is skipped without incrementing offlineBlocks — a different memory block
// with a state file still makes sawBlock=true so checked stays true.
func TestReadMemHotplugFrom_MissingStateFile(t *testing.T) {
	root := t.TempDir()
	// memory0: directory exists but has no state file → !fileExists → continue
	if err := os.MkdirAll(filepath.Join(root, "memory0"), 0o755); err != nil {
		t.Fatal(err)
	}
	// memory1: has a state file → sawBlock = true, state = online
	if err := os.MkdirAll(filepath.Join(root, "memory1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "memory1", "state"), []byte("online\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "block_size_bytes"), []byte("8000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "auto_online_blocks"), []byte("online\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	checked, offline, _, _ := readMemHotplugFrom(root)
	if !checked {
		t.Fatal("checked = false, want true (memory1 has a state file)")
	}
	if offline != 0 {
		t.Errorf("offlineBlocks = %d, want 0 (memory0 was skipped, memory1 is online)", offline)
	}
}

// TestReadMemHotplugFrom_NoMemoryBlocks covers the !sawBlock → return false
// path: the root directory exists and is readable, but contains no memoryN
// block directories — only non-matching entries like "power". sawBlock stays
// false so the function returns checked=false.
func TestReadMemHotplugFrom_NoMemoryBlocks(t *testing.T) {
	root := t.TempDir()
	// Only a non-block entry — must be skipped by the memoryN filter.
	if err := os.MkdirAll(filepath.Join(root, "power"), 0o755); err != nil {
		t.Fatal(err)
	}
	checked, offline, offlineMB, auto := readMemHotplugFrom(root)
	if checked || offline != 0 || offlineMB != 0 || auto {
		t.Errorf("no blocks: got checked=%v offline=%d mb=%d auto=%v, want all zero/false",
			checked, offline, offlineMB, auto)
	}
}

// itoa avoids importing strconv just for the test loop.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [4]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
