//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
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

// TestKVMCollectPVEFromDir_TrulyRunning guards the one branch the real-tempdir
// tests above can never reach: pveKVMProcessAlive actually returning true
// (Name: kvm). Fully fixture-driven (glob + pid file + /proc/<pid>/status all
// seeded into one Bundle) since a real process can never legitimately be named
// "kvm" from a test's perspective.
func TestKVMCollectPVEFromDir_TrulyRunning(t *testing.T) {
	dir := "/var/run/qemu-server"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob(filepath.Join(dir, "*.pid"), []string{filepath.Join(dir, "100.pid")})
		b.PutFile(filepath.Join(dir, "100.pid"), []byte("777\n"))
		b.PutFile(filepath.Join("/proc", "777", "status"), []byte("Name:\tkvm\nState:\tR (running)\n"))
	})

	info := &models.KVMInfo{}
	kvmCollectPVEFromDir(dir, info)

	if !info.Detected {
		t.Fatal("Detected should be true")
	}
	if len(info.VMs) != 1 || info.VMs[0].State != models.KVMRunning || info.VMs[0].ID != 777 {
		t.Fatalf("expected 1 running VM with ID=777, got %+v", info.VMs)
	}
	if info.VMsRunning != 1 {
		t.Errorf("VMsRunning = %d, want 1", info.VMsRunning)
	}
}

// A pid file with unparsable/invalid content must be treated as unreadable
// (not-running), never crash the enumeration.
func TestKVMCollectPVEFromDir_BadPidContent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writePidFile(t, dir, "300.pid", "not-a-number")

	info := &models.KVMInfo{}
	kvmCollectPVEFromDir(dir, info)

	if len(info.VMs) != 1 {
		t.Fatalf("expected 1 VM, got %+v", info.VMs)
	}
	if info.VMs[0].State == models.KVMRunning {
		t.Errorf("unreadable pid content must not be marked running, got %+v", info.VMs[0])
	}
}

func TestReadPVEVMPid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "valid.pid")
		if err := os.WriteFile(path, []byte("1234\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		pid, ok := readPVEVMPid(path)
		if !ok || pid != 1234 {
			t.Errorf("readPVEVMPid() = %d, %v, want 1234, true", pid, ok)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		pid, ok := readPVEVMPid(filepath.Join(dir, "nope.pid"))
		if ok || pid != 0 {
			t.Errorf("readPVEVMPid() = %d, %v, want 0, false", pid, ok)
		}
	})

	t.Run("non-numeric content", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "junk.pid")
		if err := os.WriteFile(path, []byte("abc\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		pid, ok := readPVEVMPid(path)
		if ok || pid != 0 {
			t.Errorf("readPVEVMPid() = %d, %v, want 0, false", pid, ok)
		}
	})

	t.Run("zero pid rejected", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(dir, "zero.pid")
		if err := os.WriteFile(path, []byte("0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		pid, ok := readPVEVMPid(path)
		if ok || pid != 0 {
			t.Errorf("readPVEVMPid() = %d, %v, want 0, false for pid<=0", pid, ok)
		}
	})
}

func TestPveKVMProcessAlive(t *testing.T) {
	// No top-level t.Parallel(): two subtests below swap the package-global source
	// via withFixtureSource, which must not run during the global parallel phase
	// where a sibling test could read the source concurrently.

	t.Run("nonexistent pid", func(t *testing.T) {
		t.Parallel()
		if pveKVMProcessAlive(999999999) {
			t.Error("expected false for a pid with no /proc/<pid>/status")
		}
	})

	t.Run("live process wrong name", func(t *testing.T) {
		t.Parallel()
		// The running test binary is alive but its Name is not "kvm".
		if pveKVMProcessAlive(os.Getpid()) {
			t.Error("expected false: live process name is not kvm")
		}
	})

	t.Run("process named kvm", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile(filepath.Join("/proc", "4242", "status"),
				[]byte("Name:\tkvm\nState:\tR (running)\nPid:\t4242\n"))
		})
		if !pveKVMProcessAlive(4242) {
			t.Error("expected true when /proc/<pid>/status Name is kvm")
		}
	})

	t.Run("status file has no Name line", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile(filepath.Join("/proc", "5050", "status"), []byte("State:\tR (running)\nPid:\t5050\n"))
		})
		if pveKVMProcessAlive(5050) {
			t.Error("expected false when the status file has no Name: line at all")
		}
	})
}

// TestUpdateKVMCounts_DiskIOErrorCombined pins the second independent
// increment in updateKVMCounts: DiskIOErrors accumulates alongside whatever
// state-based counter fires, rather than being mutually exclusive with it.
func TestUpdateKVMCounts_DiskIOErrorCombined(t *testing.T) {
	t.Parallel()
	info := &models.KVMInfo{}
	vm := &models.KVMVM{Name: "vm", State: models.KVMRunning, DiskIOError: true}
	updateKVMCounts(info, vm)
	if info.VMsRunning != 1 {
		t.Errorf("VMsRunning = %d, want 1", info.VMsRunning)
	}
	if info.DiskIOErrors != 1 {
		t.Errorf("DiskIOErrors = %d, want 1", info.DiskIOErrors)
	}
}

// TestUpdateKVMCounts pins the state→counter mapping, including the false-OK
// fixes: abnormal states (pmsuspended/in shutdown/idle/blocked) and an empty
// state (virsh dominfo failed) must be counted, not silently treated as healthy.
func TestUpdateKVMCounts(t *testing.T) {
	cases := []struct {
		state                                              models.KVMVMState
		autostart                                          bool
		wantAbnormal, wantUnread                           int
		wantRunning, wantDownAuto, wantPaused, wantCrashed int
	}{
		{models.KVMRunning, false, 0, 0, 1, 0, 0, 0},
		{models.KVMPaused, false, 0, 0, 0, 0, 1, 0},
		{models.KVMCrashed, false, 0, 0, 0, 0, 0, 1},
		{models.KVMPMSuspended, false, 1, 0, 0, 0, 0, 0},
		{models.KVMInShutdown, false, 1, 0, 0, 0, 0, 0},
		{models.KVMIdle, false, 1, 0, 0, 0, 0, 0},
		{models.KVMBlocked, false, 1, 0, 0, 0, 0, 0},
		{"", false, 0, 1, 0, 0, 0, 0},                  // dominfo failed → unreadable, not healthy
		{"in crash-recovery", false, 0, 1, 0, 0, 0, 0}, // internal-collectors-18-07: unrecognized non-empty
		// state (future libvirt release, modified virsh) must not silently vanish
		// from every counter — counted the same as the unreadable (empty) case.
		{models.KVMShutOff, true, 0, 0, 0, 1, 0, 0},
		{models.KVMShutOff, false, 0, 0, 0, 0, 0, 0}, // deliberately stopped, no autostart → silent
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
			if info.VMsPaused != tc.wantPaused {
				t.Errorf("VMsPaused = %d, want %d", info.VMsPaused, tc.wantPaused)
			}
			if info.VMsCrashed != tc.wantCrashed {
				t.Errorf("VMsCrashed = %d, want %d", info.VMsCrashed, tc.wantCrashed)
			}
		})
	}
}
