//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestIsVirtualDisk(t *testing.T) {
	tests := []struct {
		name  string
		dev   string
		model string
		want  bool
	}{
		// Virtual — by device name
		{"virtio-blk vda", "vda", "", true},
		{"virtio-blk vdb", "vdb", "", true},
		{"xen xvda", "xvda", "", true},
		// Virtual — by emulated-controller model (QEMU/VMware/Hyper-V/VBox)
		{"qemu scsi", "sda", "QEMU HARDDISK", true},
		{"vmware", "sda", "VMware Virtual S", true},
		{"hyper-v", "sda", "Msft Virtual Disk", true},
		{"virtualbox", "sda", "VBOX HARDDISK", true},
		{"virtio scsi model", "sda", "VIRTIO disk", true},
		// Real — bare metal on this host and common models, must NOT be virtual
		{"real liteonit ssd (this host sda)", "sda", "LITEONIT LCS-128", false},
		{"real wdc hdd (this host sdb)", "sdb", "WDC WD2003FYYS-0", false},
		{"real samsung nvme", "nvme0n1", "Samsung SSD 980", false},
		{"real intel ssd", "sda", "INTEL SSDSC2KB019T8", false},
		{"real seagate", "sdc", "ST4000NM0035-1V4", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := models.PhysicalDrive{Name: tt.dev, Model: tt.model}
			if got := isVirtualDisk(d); got != tt.want {
				t.Errorf("isVirtualDisk(name=%q model=%q) = %v, want %v", tt.dev, tt.model, got, tt.want)
			}
		})
	}
}
