package collectors

import (
	"os"
	"strings"
	"testing"
)

func TestReadMounts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		input       string
		wantCount   int // entries returned by readMounts (no filtering)
		wantDevices []string
		wantSkipped []string // fs types that should NOT appear when filtered
	}{
		{
			name: "linux fixture",
			input: `sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/sda1 / ext4 rw,relatime 0 0
/dev/sda2 /data ext4 rw,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime 0 0
`,
			wantCount:   5,
			wantDevices: []string{"/dev/sda1", "/dev/sda2"},
			wantSkipped: []string{"tmpfs", "sysfs", "proc"},
		},
		{
			name:      "empty input",
			input:     "",
			wantCount: 0,
		},
		{
			name:      "lines with fewer than 3 fields are skipped",
			input:     "/dev/sda1\n/dev/sda2 /data\n/dev/sdb1 /mnt ext4 rw 0 0\n",
			wantCount: 1,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			entries, err := readMounts(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(entries) != tc.wantCount {
				t.Errorf("entry count: got %d, want %d", len(entries), tc.wantCount)
			}
			// Verify non-skip devices are present
			deviceSet := make(map[string]bool)
			for _, e := range entries {
				deviceSet[e.device] = true
			}
			for _, dev := range tc.wantDevices {
				if !deviceSet[dev] {
					t.Errorf("expected device %q in results", dev)
				}
			}
			// Verify skipped FS types would be filtered by skipFSTypes
			for _, e := range entries {
				if skipFSTypes[e.fsType] {
					found := false
					for _, s := range tc.wantSkipped {
						if e.fsType == s {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("unexpected skippable fsType %q in test case", e.fsType)
					}
				}
			}
		})
	}
}

func TestReadMounts_ReadOnly(t *testing.T) {
	t.Parallel()
	input := "/dev/sda1 / ext4 ro,relatime 0 0\n/dev/sda2 /data ext4 rw,relatime 0 0\n"
	entries, err := readMounts(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	if !entries[0].readOnly {
		t.Errorf("entry 0 (ro): expected readOnly=true")
	}
	if entries[1].readOnly {
		t.Errorf("entry 1 (rw): expected readOnly=false")
	}
}

func TestReadMounts_FixtureFile(t *testing.T) {
	t.Parallel()
	f, err := os.Open("../../testdata/fixtures/disk/mounts_linux.txt")
	if err != nil {
		t.Fatalf("opening fixture: %v", err)
	}
	defer f.Close()

	entries, err := readMounts(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Fixture has 5 lines: sysfs, proc, /dev/sda1, /dev/sda2, tmpfs
	if len(entries) != 5 {
		t.Errorf("want 5 entries, got %d", len(entries))
	}

	// Count non-skipped entries
	var real int
	for _, e := range entries {
		if !skipFSTypes[e.fsType] {
			real++
		}
	}
	if real != 2 {
		t.Errorf("want 2 real (non-skipped) entries, got %d", real)
	}
}
