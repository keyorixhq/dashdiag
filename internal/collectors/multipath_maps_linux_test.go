//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

// multipathMapsPresent must detect a dm-multipath map by its sysfs dm/uuid prefix,
// and ignore non-multipath dm devices (LVM, crypt) — so IsMultipathPresent registers
// the collector for a real (even daemon-stopped) multipath host but NOT for a
// SAN-less host that merely has the multipath-tools package.
func TestMultipathMapsPresent(t *testing.T) {
	dir := t.TempDir()
	mk := func(name, uuid string) {
		d := filepath.Join(dir, name, "dm")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "uuid"), []byte(uuid+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Only LVM + crypt maps → not multipath.
	mk("dm-0", "LVM-abcdef")
	mk("dm-1", "CRYPT-LUKS2-xyz")
	if multipathMapsPresent(dir) {
		t.Error("LVM/crypt dm devices must not count as multipath maps")
	}

	// Add a real multipath map.
	mk("dm-2", "mpath-3600140512345")
	if !multipathMapsPresent(dir) {
		t.Error("an mpath- dm/uuid must be detected as a multipath map")
	}

	// Empty / no dm devices → false.
	if multipathMapsPresent(t.TempDir()) {
		t.Error("no dm devices must report no multipath maps")
	}
}
