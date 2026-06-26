//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// BUG-015: Proxmox VE manages QEMU directly (no libvirt). Running VMs leave a
// <vmid>.pid file in /var/run/qemu-server/. kvmCollectPVEFromDir must enumerate
// those guests and mark the collector as detected.
func TestKVMCollectPVEFromDir(t *testing.T) {
	dir := t.TempDir()
	// Two "running" VMs (pid files). 2147483647 is a pid that will not exist,
	// so the guest is enumerated but classified as not-running (shut off).
	writePidFile(t, dir, "100.pid", "2147483647")
	writePidFile(t, dir, "101.pid", "2147483646")

	info := &models.KVMInfo{}
	kvmCollectPVEFromDir(dir, info)

	if !info.Detected {
		t.Fatal("Detected should be true when qemu-server pid files exist (BUG-015)")
	}
	if len(info.VMs) != 2 {
		t.Fatalf("expected 2 VMs enumerated, got %d: %+v", len(info.VMs), info.VMs)
	}
	names := map[string]bool{}
	for _, vm := range info.VMs {
		names[vm.Name] = true
	}
	if !names["VM 100"] || !names["VM 101"] {
		t.Errorf("expected guests named from vmid, got %+v", info.VMs)
	}
}

// Empty / non-PVE directory must leave the collector undetected (zero noise).
func TestKVMCollectPVEFromDirEmpty(t *testing.T) {
	info := &models.KVMInfo{}
	kvmCollectPVEFromDir(t.TempDir(), info)
	if info.Detected {
		t.Error("Detected should stay false with no pid files")
	}
	if len(info.VMs) != 0 {
		t.Errorf("expected no VMs, got %+v", info.VMs)
	}
}

// A live pid whose process name is not "kvm" must not be reported as running —
// guards against stale pid files and pid reuse.
func TestKVMCollectPVERunningState(t *testing.T) {
	dir := t.TempDir()
	// Point at this very test process: alive, but its name is not "kvm".
	writePidFile(t, dir, "200.pid", strconv.Itoa(os.Getpid()))

	info := &models.KVMInfo{}
	kvmCollectPVEFromDir(dir, info)

	if len(info.VMs) != 1 {
		t.Fatalf("expected 1 VM, got %+v", info.VMs)
	}
	if info.VMs[0].State == models.KVMRunning {
		t.Errorf("non-kvm live process must not be marked running, got %+v", info.VMs[0])
	}
	if info.VMsRunning != 0 {
		t.Errorf("expected 0 running, got %d", info.VMsRunning)
	}
}

func writePidFile(t *testing.T, dir, name, pid string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(pid+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestUpdateKVMCounts pins the state→counter mapping, including the false-OK
// fixes: abnormal states (pmsuspended/in shutdown/idle/blocked) and an empty
// state (virsh dominfo failed) must be counted, not silently treated as healthy.
func TestUpdateKVMCounts(t *testing.T) {
	cases := []struct {
		state                     models.KVMVMState
		autostart                 bool
		wantAbnormal, wantUnread  int
		wantRunning, wantDownAuto int
	}{
		{models.KVMRunning, false, 0, 0, 1, 0},
		{models.KVMPMSuspended, false, 1, 0, 0, 0},
		{models.KVMInShutdown, false, 1, 0, 0, 0},
		{models.KVMIdle, false, 1, 0, 0, 0},
		{models.KVMBlocked, false, 1, 0, 0, 0},
		{"", false, 0, 1, 0, 0}, // dominfo failed → unreadable, not healthy
		{models.KVMShutOff, true, 0, 0, 0, 1},
		{models.KVMShutOff, false, 0, 0, 0, 0}, // deliberately stopped, no autostart → silent
	}
	for _, tc := range cases {
		t.Run(string(tc.state), func(t *testing.T) {
			info := &models.KVMInfo{}
			vm := &models.KVMVM{Name: "vm", State: tc.state, AutoStart: tc.autostart}
			updateKVMCounts(info, vm)
			if info.VMsAbnormal != tc.wantAbnormal {
				t.Errorf("VMsAbnormal = %d, want %d", info.VMsAbnormal, tc.wantAbnormal)
			}
			if info.VMsUnreadable != tc.wantUnread {
				t.Errorf("VMsUnreadable = %d, want %d", info.VMsUnreadable, tc.wantUnread)
			}
			if info.VMsRunning != tc.wantRunning {
				t.Errorf("VMsRunning = %d, want %d", info.VMsRunning, tc.wantRunning)
			}
			if info.VMsDownAutostart != tc.wantDownAuto {
				t.Errorf("VMsDownAutostart = %d, want %d", info.VMsDownAutostart, tc.wantDownAuto)
			}
		})
	}
}
