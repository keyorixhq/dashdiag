//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsAzureGuest(t *testing.T) {
	cases := []struct {
		name                         string
		sysVendor, product, assetTag string
		want                         bool
	}{
		{"azure asset tag", "Microsoft Corporation", "Virtual Machine", azureChassisAssetTag, true},
		{"azure asset tag whitespace", "", "", "  " + azureChassisAssetTag + " ", true},
		{"microsoft azure literal", "Microsoft Azure", "Virtual Machine", "", true},
		{"on-prem hyper-v NOT azure", "Microsoft Corporation", "Virtual Machine", "", false},
		{"vmware not azure", "VMware, Inc.", "VMware7,1", "", false},
		{"empty", "", "", "", false},
	}
	for _, c := range cases {
		if got := isAzureGuest(c.sysVendor, c.product, c.assetTag); got != c.want {
			t.Errorf("%s: isAzureGuest=%v want %v", c.name, got, c.want)
		}
	}
}

func TestAcceleratedVFDriver(t *testing.T) {
	for _, d := range []string{"mlx5_core", "mlx4_en", "mana", "MLX5_CORE"} {
		if !acceleratedVFDriver(d) {
			t.Errorf("%q should be an accelerated VF driver", d)
		}
	}
	for _, d := range []string{"hv_netvsc", "e1000", "virtio_net", ""} {
		if acceleratedVFDriver(d) {
			t.Errorf("%q should NOT be an accelerated VF driver", d)
		}
	}
}

// fakeNIC builds <netDir>/<iface> with a device/driver symlink (base = driver) and an
// operstate file, mimicking the sysfs layout collectNICDrivers/nicOperstateUp read.
func fakeNIC(t *testing.T, netDir, iface, driver, operstate string) {
	t.Helper()
	ifDir := filepath.Join(netDir, iface)
	if err := os.MkdirAll(filepath.Join(ifDir, "device"), 0o755); err != nil {
		t.Fatal(err)
	}
	drvTarget := filepath.Join(netDir, "..", "drivers", driver)
	if err := os.MkdirAll(drvTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(drvTarget, filepath.Join(ifDir, "device", "driver")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ifDir, "operstate"), []byte(operstate+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCollectAcceleratedNetworking_BondedVF(t *testing.T) {
	netDir := filepath.Join(t.TempDir(), "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeNIC(t, netDir, "eth0", "hv_netvsc", "up")
	fakeNIC(t, netDir, "enP1s2", "mlx5_core", "up")
	// transparent bonding: eth0 has a lower_enP1s2 link
	if err := os.WriteFile(filepath.Join(netDir, "eth0", "lower_enP1s2"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	syn, ifaces, hasVF := collectAcceleratedNetworking(netDir)
	if len(syn) != 1 || syn[0] != "eth0" {
		t.Fatalf("synthetics = %v, want [eth0]", syn)
	}
	if !hasVF || len(ifaces) != 1 {
		t.Fatalf("ifaces = %+v hasVF=%v, want one VF", ifaces, hasVF)
	}
	vf := ifaces[0]
	if vf.VF != "enP1s2" || vf.Driver != "mlx5_core" || vf.Synthetic != "eth0" || !vf.Bonded || !vf.Up {
		t.Errorf("VF = %+v, want bonded+up enP1s2/mlx5_core under eth0", vf)
	}
}

func TestCollectAcceleratedNetworking_UnbondedVF(t *testing.T) {
	netDir := filepath.Join(t.TempDir(), "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeNIC(t, netDir, "eth0", "hv_netvsc", "up")
	fakeNIC(t, netDir, "enP1s2", "mlx5_core", "down") // VF present, NOT linked under eth0

	_, ifaces, hasVF := collectAcceleratedNetworking(netDir)
	if !hasVF || len(ifaces) != 1 {
		t.Fatalf("ifaces = %+v, want one unbonded VF", ifaces)
	}
	if ifaces[0].Bonded || ifaces[0].Up {
		t.Errorf("VF = %+v, want bonded=false up=false", ifaces[0])
	}
}

func TestCollectAcceleratedNetworking_SyntheticOnly(t *testing.T) {
	netDir := filepath.Join(t.TempDir(), "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeNIC(t, netDir, "eth0", "hv_netvsc", "up")

	syn, ifaces, hasVF := collectAcceleratedNetworking(netDir)
	if len(syn) != 1 || hasVF || len(ifaces) != 0 {
		t.Errorf("synthetic-only: syn=%v ifaces=%+v hasVF=%v, want [eth0]/none/false", syn, ifaces, hasVF)
	}
}
