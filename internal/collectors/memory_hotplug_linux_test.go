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
