//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestKVMCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewKVMCollector()
	if c.Name() != "KVM" {
		t.Errorf("Name() = %q, want KVM", c.Name())
	}
	if c.Timeout() != 15*time.Second {
		t.Errorf("Timeout() = %v, want 15s", c.Timeout())
	}
	if c.Deep {
		t.Error("NewKVMCollector: expected Deep=false")
	}
	if !NewKVMDeepCollector().Deep {
		t.Error("NewKVMDeepCollector: expected Deep=true")
	}
}

func TestKVMDomInfo(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("virsh", []string{"dominfo", "vm1"},
			"Id:             3\n"+
				"Name:           vm1\n"+
				"State:          running\n"+
				"CPU(s):         4\n"+
				"Max memory:     4194304 KiB\n"+
				"Used memory:    2097152 KiB\n"+
				"Autostart:      enable\n", 0)
	})
	vm := kvmDomInfo(context.Background(), "vm1")
	if vm.ID != 3 || vm.State != models.KVMRunning || vm.VCPU != 4 {
		t.Errorf("vm = %+v", vm)
	}
	if vm.MaxMemMB != 4096 || vm.UsedMemMB != 2048 {
		t.Errorf("mem = %d/%d MB, want 4096/2048", vm.MaxMemMB, vm.UsedMemMB)
	}
	if !vm.AutoStart {
		t.Error("expected AutoStart=true")
	}
}

func TestKVMDomInfo_ShutOffNoID(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("virsh", []string{"dominfo", "vm2"},
			"Id:             -\n"+
				"Name:           vm2\n"+
				"State:          shut off\n"+
				"Autostart:      disable\n", 0)
	})
	vm := kvmDomInfo(context.Background(), "vm2")
	if vm.ID != -1 {
		t.Errorf("ID = %d, want -1 for a shut-off VM", vm.ID)
	}
	if vm.State != models.KVMShutOff {
		t.Errorf("State = %q", vm.State)
	}
	if vm.AutoStart {
		t.Error("expected AutoStart=false")
	}
}

func TestKVMDomInfo_CmdFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("virsh", []string{"dominfo", "gone"})
	})
	vm := kvmDomInfo(context.Background(), "gone")
	if vm.Name != "gone" || vm.ID != -1 || vm.State != "" {
		t.Errorf("vm = %+v, want zero-value with Name/ID set", vm)
	}
}

func TestKVMCheckDiskErrors_NotRunning(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	vm := models.KVMVM{Name: "vm1", ID: -1}
	kvmCheckDiskErrors(context.Background(), &vm)
	if vm.DiskIOError {
		t.Error("expected DiskIOError=false: not running, no live stats possible")
	}
}

func TestKVMCheckDiskErrors_Clean(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("virsh", []string{"domblkerror", "vm1"}, "No errors found\n", 0)
	})
	vm := models.KVMVM{Name: "vm1", ID: 3}
	kvmCheckDiskErrors(context.Background(), &vm)
	if vm.DiskIOError {
		t.Error("expected DiskIOError=false")
	}
}

func TestKVMCheckDiskErrors_Found(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("virsh", []string{"domblkerror", "vm1"}, "vda  I/O error\n", 0)
	})
	vm := models.KVMVM{Name: "vm1", ID: 3}
	kvmCheckDiskErrors(context.Background(), &vm)
	if !vm.DiskIOError {
		t.Error("expected DiskIOError=true")
	}
}

func TestKVMCheckDiskErrors_CmdFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("virsh", []string{"domblkerror", "vm1"})
	})
	vm := models.KVMVM{Name: "vm1", ID: 3}
	kvmCheckDiskErrors(context.Background(), &vm)
	if vm.DiskIOError {
		t.Error("expected DiskIOError=false on command failure")
	}
}

func TestKVMReadLastLogError_Found(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/libvirt/qemu/vm1.log", []byte(
			"2026-01-01 startup ok\n"+
				"2026-01-02 qemu-system-x86_64: error: failed to connect to disk\n"+
				"2026-01-03 running normally\n"))
	})
	vm := &models.KVMVM{Name: "vm1"}
	kvmReadLastLogError(vm)
	if vm.LastLogError == "" {
		t.Fatal("expected a LastLogError to be found")
	}
	if !strings.Contains(vm.LastLogError, "failed to connect to disk") {
		t.Errorf("LastLogError = %q", vm.LastLogError)
	}
}

func TestKVMReadLastLogError_KeepsLast(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/libvirt/qemu/vm1.log", []byte(
			"2026-01-01 error: first failure\n"+
				"2026-01-02 running normally\n"+
				"2026-01-03 killed by signal\n"))
	})
	vm := &models.KVMVM{Name: "vm1"}
	kvmReadLastLogError(vm)
	if !strings.Contains(vm.LastLogError, "killed by signal") {
		t.Errorf("LastLogError = %q, want the LAST matching line, not the first", vm.LastLogError)
	}
}

func TestKVMReadLastLogError_NoErrors(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/libvirt/qemu/vm1.log", []byte("all good\nstill fine\n"))
	})
	vm := &models.KVMVM{Name: "vm1"}
	kvmReadLastLogError(vm)
	if vm.LastLogError != "" {
		t.Errorf("LastLogError = %q, want empty", vm.LastLogError)
	}
}

func TestKVMReadLastLogError_FileMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	vm := &models.KVMVM{Name: "nope"}
	kvmReadLastLogError(vm)
	if vm.LastLogError != "" {
		t.Errorf("LastLogError = %q, want empty when log file is absent", vm.LastLogError)
	}
}

// TestKVMReadLastLogError_NameTraversalRejected guards internal-collectors-18-06:
// vm.Name comes from `virsh list --all --name` output with no character-class
// validation. Without a containment check, a domain named with "../" segments
// (a name a user in the libvirt group, or a compromised management tool, could
// define) would let filepath.Join resolve outside /var/log/libvirt/qemu/ and
// read an arbitrary .log-suffixed file the dsd process can access — surfacing
// its content (e.g. auth.log lines) as this VM's LastLogError.
func TestKVMReadLastLogError_NameTraversalRejected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// A file OUTSIDE the libvirt qemu log dir that the traversal name reaches.
		b.PutFile("/etc/secret.log", []byte("error: leaked secret line\n"))
	})
	vm := &models.KVMVM{Name: "../../../../etc/secret"}
	kvmReadLastLogError(vm)
	if vm.LastLogError != "" {
		t.Errorf("LastLogError = %q, want empty — traversal name must not escape /var/log/libvirt/qemu/", vm.LastLogError)
	}
}

func TestKVMCollectVMs_Happy(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("virsh", []string{"list", "--all", "--name"}, "vm1\nvm2\n", 0)
		b.PutCmd("virsh", []string{"dominfo", "vm1"},
			"Id:             3\nState:          running\nAutostart:      disable\n", 0)
		b.PutCmd("virsh", []string{"domblkerror", "vm1"}, "No errors found\n", 0)
		b.PutFile("/var/log/libvirt/qemu/vm1.log", []byte("ok\n"))
		b.PutCmd("virsh", []string{"dominfo", "vm2"},
			"Id:             -\nState:          shut off\nAutostart:      enable\n", 0)
		b.PutFile("/var/log/libvirt/qemu/vm2.log", []byte("ok\n"))
	})
	info := &models.KVMInfo{}
	kvmCollectVMs(context.Background(), info, false)
	if len(info.VMs) != 2 {
		t.Fatalf("got %d VMs, want 2", len(info.VMs))
	}
	if info.VMsRunning != 1 || info.VMsDownAutostart != 1 {
		t.Errorf("VMsRunning=%d VMsDownAutostart=%d, want 1/1", info.VMsRunning, info.VMsDownAutostart)
	}
	if info.Status != "" {
		t.Errorf("Status = %q, want empty on success", info.Status)
	}
}

// TestKVMCollectVMs_SkipsDashPrefixedName is the regression guard for
// internal-collectors-18-09: a domain name beginning with "-" (from `virsh
// list --all --name`) would otherwise be passed as a positional argv element
// to `virsh dominfo`/`dumpxml`/`domblkerror`, which virsh could parse as an
// option instead of the domain name. The fixture registers a suspicious
// "--evil"-named domain's dominfo call returning a fabricated "running"
// VM (Id 999) — if the fix's guard didn't skip it, that fabricated entry
// would show up in info.VMs, proving the call was made.
func TestKVMCollectVMs_SkipsDashPrefixedName(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("virsh", []string{"list", "--all", "--name"}, "vm1\n--evil\n", 0)
		b.PutCmd("virsh", []string{"dominfo", "vm1"},
			"Id:             3\nState:          running\nAutostart:      disable\n", 0)
		b.PutCmd("virsh", []string{"domblkerror", "vm1"}, "No errors found\n", 0)
		b.PutFile("/var/log/libvirt/qemu/vm1.log", []byte("ok\n"))
		// Fabricated: if this ever gets called, the guard failed.
		b.PutCmd("virsh", []string{"dominfo", "--evil"},
			"Id:             999\nState:          running\nAutostart:      disable\n", 0)
	})
	info := &models.KVMInfo{}
	kvmCollectVMs(context.Background(), info, false)
	if len(info.VMs) != 1 || info.VMs[0].Name != "vm1" {
		t.Fatalf("VMs = %+v, want exactly [vm1] — the \"--evil\" domain must be skipped", info.VMs)
	}
	for _, vm := range info.VMs {
		if vm.ID == 999 {
			t.Fatal("the fabricated ID-999 VM appeared — virsh dominfo was called with the dash-prefixed name")
		}
	}
}

func TestKVMCollectVMs_EnumFailed(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("virsh", []string{"list", "--all", "--name"})
	})
	info := &models.KVMInfo{}
	kvmCollectVMs(context.Background(), info, false)
	if info.Status != "enum-failed" {
		t.Errorf("Status = %q, want enum-failed", info.Status)
	}
	if len(info.VMs) != 0 {
		t.Errorf("VMs = %+v, want empty", info.VMs)
	}
}

func TestKVMCollectVMs_NoDomains(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("virsh", []string{"list", "--all", "--name"}, "\n", 0)
	})
	info := &models.KVMInfo{}
	kvmCollectVMs(context.Background(), info, false)
	if len(info.VMs) != 0 || info.Status != "" {
		t.Errorf("info = %+v, want a clean empty result", info)
	}
}

func TestKVMCollectVMs_DeepCallsXML(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("virsh", []string{"list", "--all", "--name"}, "vm1\n", 0)
		b.PutCmd("virsh", []string{"dominfo", "vm1"},
			"Id:             -\nState:          shut off\nAutostart:      disable\n", 0)
		b.PutFile("/var/log/libvirt/qemu/vm1.log", []byte("ok\n"))
		b.PutCmd("virsh", []string{"dumpxml", "vm1"},
			`<domain><devices><interface><mac address='52:54:00:11:22:33'/><model type='e1000'/></interface></devices></domain>`, 0)
	})
	info := &models.KVMInfo{}
	kvmCollectVMs(context.Background(), info, true)
	if len(info.VMs) != 1 || len(info.VMs[0].EmulatedNICs) != 1 {
		t.Errorf("expected deep=true to populate EmulatedNICs via dumpxml, got %+v", info.VMs)
	}
}

// TestKVMCollectVMs_BlankLineInOutput covers kvm_linux.go:98 — the blank-name
// continue inside the virsh-list name loop (embedded empty line in output).
func TestKVMCollectVMs_BlankLineInOutput(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("virsh", []string{"list", "--all", "--name"}, "vm1\n\nvm2\n", 0)
		b.PutCmd("virsh", []string{"dominfo", "vm1"},
			"Id:             1\nState:          running\nAutostart:      disable\n", 0)
		b.PutCmd("virsh", []string{"domblkerror", "vm1"}, "No errors found\n", 0)
		b.PutFile("/var/log/libvirt/qemu/vm1.log", []byte("ok\n"))
		b.PutCmd("virsh", []string{"dominfo", "vm2"},
			"Id:             2\nState:          running\nAutostart:      disable\n", 0)
		b.PutCmd("virsh", []string{"domblkerror", "vm2"}, "No errors found\n", 0)
		b.PutFile("/var/log/libvirt/qemu/vm2.log", []byte("ok\n"))
	})
	info := &models.KVMInfo{}
	kvmCollectVMs(context.Background(), info, false)
	if len(info.VMs) != 2 {
		t.Errorf("blank line in virsh output must be skipped; expected 2 VMs, got %d", len(info.VMs))
	}
}

// TestKVMCollectVMs_EmptyMACFallback covers kvm_linux.go:168 — the fallback that
// uses the model type as the NIC identifier when the MAC address is empty.
func TestKVMCollectVMs_EmptyMACFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("virsh", []string{"list", "--all", "--name"}, "vm1\n", 0)
		b.PutCmd("virsh", []string{"dominfo", "vm1"},
			"Id:             -\nState:          shut off\nAutostart:      disable\n", 0)
		b.PutFile("/var/log/libvirt/qemu/vm1.log", []byte("ok\n"))
		// mac address='' → id = "" → fallback to model type "e1000"
		b.PutCmd("virsh", []string{"dumpxml", "vm1"},
			`<domain><devices><interface><mac address=''/><model type='e1000'/></interface></devices></domain>`, 0)
	})
	info := &models.KVMInfo{}
	kvmCollectVMs(context.Background(), info, true)
	if len(info.VMs) != 1 {
		t.Fatalf("expected 1 VM, got %d", len(info.VMs))
	}
	if len(info.VMs[0].EmulatedNICs) != 1 {
		t.Fatalf("expected 1 EmulatedNIC (model-type fallback), got %d: %v", len(info.VMs[0].EmulatedNICs), info.VMs[0].EmulatedNICs)
	}
	if !strings.Contains(info.VMs[0].EmulatedNICs[0], "e1000") {
		t.Errorf("NIC identifier should use model type when MAC is empty, got %q", info.VMs[0].EmulatedNICs[0])
	}
}

func TestKVMCollectNetworks(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("virsh", []string{"net-list", "--all"},
			" Name      State    Autostart   Persistent\n"+
				"----------------------------------------------\n"+
				" default   active   yes         yes\n"+
				" isolated  inactive no          yes\n", 0)
		b.PutCmd("virsh", []string{"net-info", "default"}, "Bridge:         virbr0\n", 0)
		b.PutCmd("ip", []string{"link", "show", "virbr0"},
			"3: virbr0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n", 0)
	})
	info := &models.KVMInfo{}
	kvmCollectNetworks(context.Background(), info)
	if len(info.Networks) != 2 {
		t.Fatalf("got %d networks, want 2", len(info.Networks))
	}
	if info.NetworksInactive != 1 {
		t.Errorf("NetworksInactive = %d, want 1", info.NetworksInactive)
	}
	var def models.KVMNetwork
	for _, n := range info.Networks {
		if n.Name == "default" {
			def = n
		}
	}
	if def.Bridge != "virbr0" || !def.BridgeUp {
		t.Errorf("default network = %+v, want bridge virbr0 up", def)
	}
}

// TestKVMCollectNetworks_CmdFails is the regression guard for
// internal-collectors-18-04: `virsh net-list` failing must set the same
// enum-failed Status/StatusReason kvmCollectVMs already uses on its own
// enumeration failure — a silent empty Networks/zero NetworksInactive is
// indistinguishable from a host with no libvirt networks defined at all.
func TestKVMCollectNetworks_CmdFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("virsh", []string{"net-list", "--all"})
	})
	info := &models.KVMInfo{}
	kvmCollectNetworks(context.Background(), info)
	if len(info.Networks) != 0 {
		t.Errorf("Networks = %+v, want empty", info.Networks)
	}
	if info.Status != "enum-failed" {
		t.Errorf("Status = %q, want enum-failed", info.Status)
	}
	if info.StatusReason == "" {
		t.Error("StatusReason is empty, want an explanation of the virsh net-list failure")
	}
}

// TestKVMCollectNetworks_CmdFails_VMEnumAlreadyFailedKeepsReason guards the
// precedence rule: when kvmCollectVMs already recorded its own enum-failed
// reason (checked first, and the more severe of the two), a subsequent
// network enumeration failure must NOT overwrite it.
func TestKVMCollectNetworks_CmdFails_VMEnumAlreadyFailedKeepsReason(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("virsh", []string{"net-list", "--all"})
	})
	info := &models.KVMInfo{Status: "enum-failed", StatusReason: "libvirt is up but `virsh list` failed — VM states could not be read"}
	kvmCollectNetworks(context.Background(), info)
	if info.StatusReason != "libvirt is up but `virsh list` failed — VM states could not be read" {
		t.Errorf("StatusReason = %q, want the original VM-enum failure reason preserved", info.StatusReason)
	}
}

func TestKVMParseBridge(t *testing.T) {
	t.Parallel()
	out := "Name:           default\nUUID:           abc\nActive:         yes\nBridge:         virbr0\n"
	if br := kvmParseBridge(out); br != "virbr0" {
		t.Errorf("got %q, want virbr0", br)
	}
}

func TestKVMParseBridge_Absent(t *testing.T) {
	t.Parallel()
	if br := kvmParseBridge("Name: isolated\n"); br != "" {
		t.Errorf("got %q, want empty", br)
	}
}

func TestKVMCollectPools(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("virsh", []string{"pool-list", "--all"},
			" Name      State      Autostart\n"+
				"---------------------------------\n"+
				" default   active     yes\n"+
				" backup    inactive   no\n", 0)
		b.PutCmd("virsh", []string{"pool-info", "default"},
			"Name:           default\n"+
				"State:          running\n"+
				"Capacity:       100.00 GiB\n"+
				"Allocation:     95.00 GiB\n"+
				"Available:      5.00 GiB\n", 0)
	})
	info := &models.KVMInfo{}
	kvmCollectPools(context.Background(), info)
	if len(info.StoragePools) != 2 {
		t.Fatalf("got %d pools, want 2", len(info.StoragePools))
	}
	if info.PoolsInactive != 1 {
		t.Errorf("PoolsInactive = %d, want 1", info.PoolsInactive)
	}
	if info.PoolsNearFull != 1 {
		t.Errorf("PoolsNearFull = %d, want 1 (95%% used >= 85%%)", info.PoolsNearFull)
	}
}

func TestKVMCollectPools_CmdFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("virsh", []string{"pool-list", "--all"})
	})
	info := &models.KVMInfo{}
	kvmCollectPools(context.Background(), info)
	if len(info.StoragePools) != 0 {
		t.Errorf("StoragePools = %+v, want empty", info.StoragePools)
	}
}

func TestKVMParsePoolInfo(t *testing.T) {
	t.Parallel()
	out := "Capacity:       200.00 GiB\nAllocation:     50.00 GiB\nAvailable:      150.00 GiB\n"
	pool := &models.KVMStoragePool{}
	kvmParsePoolInfo(out, pool)
	if pool.CapacityGB != 200 || pool.AvailableGB != 150 {
		t.Errorf("pool = %+v", pool)
	}
	if pool.UsedPct != 25 {
		t.Errorf("UsedPct = %v, want 25", pool.UsedPct)
	}
}

func TestKVMParseBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want float64
	}{
		{"200.00 GiB", 200},
		{"1.00 TiB", 1000},
		{"512.00 MiB", 0.5},
		{"1024.00 KiB", 1024.0 / (1024 * 1024)},
		{"garbage", 0},
		{"5", 0},
		{"5.0 UNKNOWN", 0},
	}
	for _, tt := range tests {
		if got := kvmParseBytes(tt.in); got != tt.want {
			t.Errorf("kvmParseBytes(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestKVMAvailable_True(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("virsh", []string{"version", "--daemon"}, "Compiled: libvirt 10.0.0\n", 0)
	})
	if !KVMAvailable() {
		t.Error("expected true")
	}
}

func TestKVMAvailable_FalseNoLibvirtNoPVE(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("virsh", []string{"version", "--daemon"})
		b.PutGlob("/var/run/qemu-server/*.pid", nil)
	})
	if KVMAvailable() {
		t.Error("expected false")
	}
}

func TestKVMAvailable_PVEFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("virsh", []string{"version", "--daemon"})
		b.PutGlob("/var/run/qemu-server/*.pid", []string{"/var/run/qemu-server/100.pid"})
	})
	if !KVMAvailable() {
		t.Error("expected true via PVE qemu-server pid fallback")
	}
}

func TestPveHasRunningQEMU(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/var/run/qemu-server/*.pid", []string{"/var/run/qemu-server/100.pid"})
	})
	if !pveHasRunningQEMU() {
		t.Error("expected true")
	}
}

func TestPveHasRunningQEMU_None(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/var/run/qemu-server/*.pid", nil)
	})
	if pveHasRunningQEMU() {
		t.Error("expected false")
	}
}

// TestKVMCollector_Collect_LibvirtHappyPath drives the full Collect() success
// path: virsh reachable, one VM, one active network, one storage pool.
func TestKVMCollector_Collect_LibvirtHappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("virsh", []string{"version", "--daemon"},
			"Using library: libvirt 10.0.0\nRunning hypervisor: QEMU 8.2.0\n", 0)
		b.PutCmd("virsh", []string{"list", "--all", "--name"}, "vm1\n", 0)
		b.PutCmd("virsh", []string{"dominfo", "vm1"},
			"Id:             3\nState:          running\nAutostart:      disable\n", 0)
		b.PutCmd("virsh", []string{"domblkerror", "vm1"}, "No errors found\n", 0)
		b.PutFile("/var/log/libvirt/qemu/vm1.log", []byte("ok\n"))
		b.PutCmd("virsh", []string{"net-list", "--all"}, " default   active   yes   yes\n", 0)
		b.PutCmd("virsh", []string{"net-info", "default"}, "Bridge:         virbr0\n", 0)
		b.PutCmd("ip", []string{"link", "show", "virbr0"}, "state UP\n", 0)
		b.PutCmd("virsh", []string{"pool-list", "--all"}, " default   active\n", 0)
		b.PutCmd("virsh", []string{"pool-info", "default"},
			"Capacity:       100.00 GiB\nAvailable:      50.00 GiB\n", 0)
	})
	got, err := NewKVMCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.KVMInfo)
	if !info.Detected {
		t.Error("expected Detected=true")
	}
	if info.LibvirtVer != "10.0.0" || info.QEMUVer != "8.2.0" {
		t.Errorf("versions = %q/%q", info.LibvirtVer, info.QEMUVer)
	}
	if len(info.VMs) != 1 || len(info.Networks) != 1 || len(info.StoragePools) != 1 {
		t.Errorf("info = %+v", info)
	}
}

// TestKVMCollector_Collect_NoLibvirtPVEFallback drives Collect()'s
// virsh-unavailable branch on a Proxmox host with a running QEMU guest.
func TestKVMCollector_Collect_NoLibvirtPVEFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("virsh", []string{"version", "--daemon"})
		b.PutStat("/usr/bin/pvedaemon", source.FileMeta{})
		b.PutGlob("/var/run/qemu-server/*.pid", []string{"/var/run/qemu-server/100.pid"})
		b.PutFile("/var/run/qemu-server/100.pid", []byte("999999999\n"))
	})
	got, err := NewKVMCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.KVMInfo)
	if !info.Detected {
		t.Error("expected Detected=true via PVE fallback")
	}
	if len(info.VMs) != 1 || info.VMs[0].Name != "VM 100" {
		t.Errorf("VMs = %+v", info.VMs)
	}
}

// TestKVMCollector_Collect_NoLibvirtNoPVE drives Collect()'s fully-empty gate:
// no libvirt, not a PVE host.
func TestKVMCollector_Collect_NoLibvirtNoPVE(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("virsh", []string{"version", "--daemon"})
	})
	got, err := NewKVMCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := got.(*models.KVMInfo)
	if info.Detected {
		t.Error("expected Detected=false")
	}
	if len(info.VMs) != 0 {
		t.Errorf("VMs = %+v, want empty", info.VMs)
	}
}
