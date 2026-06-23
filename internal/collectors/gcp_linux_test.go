//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsGCPGuest(t *testing.T) {
	cases := []struct {
		name             string
		product, sysVend string
		want             bool
	}{
		{"gce product name", "Google Compute Engine", "Google", true},
		{"google sys_vendor only", "", "Google", true},
		{"aws not gcp", "t3.micro", "Amazon EC2", false},
		{"vmware not gcp", "VMware7,1", "VMware, Inc.", false},
		{"empty", "", "", false},
	}
	for _, c := range cases {
		if got := isGCPGuest(c.product, c.sysVend); got != c.want {
			t.Errorf("%s: isGCPGuest=%v want %v", c.name, got, c.want)
		}
	}
}

func TestGCPNICDriver(t *testing.T) {
	// gVNIC present → usesGVNIC true, primary (alphabetically-first) driver reported.
	netDir := filepath.Join(t.TempDir(), "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeNIC(t, netDir, "eth0", "gve", "up")
	drv, gvnic := gcpNICDriver(netDir)
	if drv != "gve" || !gvnic {
		t.Errorf("gve NIC: driver=%q usesGVNIC=%v, want gve/true", drv, gvnic)
	}

	// virtio_net only → not gVNIC (valid, not a fault).
	netDir2 := filepath.Join(t.TempDir(), "net")
	if err := os.MkdirAll(netDir2, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeNIC(t, netDir2, "ens4", "virtio_net", "up")
	drv2, gvnic2 := gcpNICDriver(netDir2)
	if drv2 != "virtio_net" || gvnic2 {
		t.Errorf("virtio NIC: driver=%q usesGVNIC=%v, want virtio_net/false", drv2, gvnic2)
	}

	// No NICs → empty, not a crash.
	if drv3, gvnic3 := gcpNICDriver(filepath.Join(t.TempDir(), "empty")); drv3 != "" || gvnic3 {
		t.Errorf("no NICs: driver=%q usesGVNIC=%v, want empty/false", drv3, gvnic3)
	}
}
