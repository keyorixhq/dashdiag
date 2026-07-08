package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckDiskGrowth(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		fs       models.FilesystemInfo
		wantWarn bool
		wantHint string // substring expected in a hint when wantWarn
	}{
		{
			name:     "ext4 device grown 20GB, fs still 9.8GB → WARN",
			fs:       models.FilesystemInfo{Mount: "/", Device: "/dev/sda1", FSType: "ext4", TotalGB: 9.8, DeviceSizeGB: 20},
			wantWarn: true, wantHint: "resize2fs /dev/sda1",
		},
		{
			name:     "xfs grown → WARN with xfs_growfs on the mount",
			fs:       models.FilesystemInfo{Mount: "/data", Device: "/dev/mapper/vg-data", FSType: "xfs", TotalGB: 50, DeviceSizeGB: 100},
			wantWarn: true, wantHint: "xfs_growfs /data",
		},
		{
			name:     "btrfs grown → WARN with btrfs resize",
			fs:       models.FilesystemInfo{Mount: "/mnt/b", Device: "/dev/sdb1", FSType: "btrfs", TotalGB: 10, DeviceSizeGB: 30},
			wantWarn: true, wantHint: "btrfs filesystem resize max /mnt/b",
		},
		{
			// Normal filesystem metadata overhead (~2%) must NEVER flag.
			name: "fully-resized ext4 (2% overhead) → no WARN",
			fs:   models.FilesystemInfo{Mount: "/", Device: "/dev/sda1", FSType: "ext4", TotalGB: 98, DeviceSizeGB: 100},
		},
		{
			// 25% gap but only 0.5GB absolute — the 1GB floor protects small disks.
			name: "small disk under the 1GB floor → no WARN",
			fs:   models.FilesystemInfo{Mount: "/boot", Device: "/dev/sda2", FSType: "ext4", TotalGB: 1.5, DeviceSizeGB: 2.0},
		},
		{
			name: "device size unknown (0) → no WARN",
			fs:   models.FilesystemInfo{Mount: "/", Device: "/dev/sda1", FSType: "ext4", TotalGB: 10, DeviceSizeGB: 0},
		},
		{
			name: "non-resizable fstype (tmpfs) → no WARN",
			fs:   models.FilesystemInfo{Mount: "/run", Device: "tmpfs", FSType: "tmpfs", TotalGB: 1, DeviceSizeGB: 50},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := checkDiskGrowth(tc.fs)
			if tc.wantWarn {
				if len(got) != 1 || got[0].Level != "WARN" {
					t.Fatalf("want one WARN, got %+v", got)
				}
				found := false
				for _, h := range got[0].Hints {
					if strings.Contains(h, tc.wantHint) {
						found = true
					}
				}
				if !found {
					t.Errorf("want a hint containing %q, got %v", tc.wantHint, got[0].Hints)
				}
			} else if len(got) != 0 {
				t.Errorf("want no insight, got %+v", got)
			}
		})
	}
}
