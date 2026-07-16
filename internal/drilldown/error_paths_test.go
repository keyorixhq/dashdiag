package drilldown

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestDispatchLive_PanicRecoversToNil covers drilldown.go:90-92 (the
// defer/recover block in dispatchLive) by swapping runCmd to panic.
// dispatchLive must catch the panic and return nil rather than propagating it.
// No t.Parallel() — uses swapRunCmd and swapLookPath.
func TestDispatchLive_PanicRecoversToNil(t *testing.T) {
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		panic("simulated crash inside a drill-down sub-collector")
	})
	swapLookPath(t, func(string) (string, error) { return "/usr/bin/journalctl", nil })

	ins := models.Insight{Level: "WARN", Check: "Systemd", Message: "unit crash.service has failed"}
	got := dispatchLive(context.Background(), ins, nil)
	if got != nil {
		t.Errorf("expected dispatchLive to recover a panic and return nil, got %+v", got)
	}
}

// TestLargestDirs_ReadDirError covers disk.go:23-25 (the os.ReadDir error
// branch that falls back to largestDirsFallback) by passing a nonexistent path.
// largestDirsFallback also fails on the same nonexistent path, returning
// (nil, non-nil error).
func TestLargestDirs_ReadDirError(t *testing.T) {
	t.Parallel()
	nonexistent := filepath.Join(t.TempDir(), "no-such-mount-point")
	got, err := LargestDirs(context.Background(), nonexistent)
	if got != nil || err == nil {
		t.Errorf("expected (nil, error) for a nonexistent mount path, got (%+v, %v)", got, err)
	}
}

// TestTopProcessesByFDLinux_PermissionDeniedSetsPartialAndNote covers
// fdlimits.go:45-50 (the partial=true branch when /proc/<pid>/fd is
// permission-denied) and fdlimits.go:92-94 (the Note assignment when partial).
// A mode-0000 fd directory triggers EACCES for non-root callers only.
func TestTopProcessesByFDLinux_PermissionDeniedSetsPartialAndNote(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits don't block the read")
	}
	procRoot := t.TempDir()
	const pid = 33341
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	fdDir := filepath.Join(dir, "fd")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll dir: %v", err)
	}
	if err := os.Mkdir(fdDir, 0000); err != nil {
		t.Fatalf("Mkdir fd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(fdDir, 0755) })

	got, err := topProcessesByFDLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByFDLinuxAt: %v", err)
	}
	if got.Note == "" {
		t.Error("expected a partial-visibility note when /proc/<pid>/fd is permission-denied")
	}
}

// TestTopProcessesByIOLinux_PermissionDeniedSetsPartial covers io.go:69-73
// (the partial=true branch when /proc/<pid>/io is permission-denied in
// sampleAllProcIO).  Skipped under root (chmod doesn't restrict reads).
func TestTopProcessesByIOLinux_PermissionDeniedSetsPartial(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits don't block the read")
	}
	procRoot := t.TempDir()
	const pid = 33342
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	ioPath := filepath.Join(dir, "io")
	if err := os.WriteFile(ioPath, []byte("read_bytes: 100\nwrite_bytes: 50\n"), 0000); err != nil {
		t.Fatalf("WriteFile io: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(ioPath, 0644) })

	_, partial := sampleAllProcIO(context.Background(), procRoot)
	if !partial {
		t.Error("expected partial=true when /proc/<pid>/io is permission-denied")
	}
}

// TestTopProcessesByIOLinuxAt_PermissionWithRowsNote covers io.go:155-156
// (the Note branch when partial && len(rows) > 0).  Requires both a
// permission-denied process and a visible I/O-active process.
// Skipped under root.
func TestTopProcessesByIOLinuxAt_PermissionWithRowsNote(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits don't block the read")
	}
	procRoot := t.TempDir()

	const hiddenPID = 33343
	hiddenDir := filepath.Join(procRoot, strconv.Itoa(hiddenPID))
	if err := os.MkdirAll(hiddenDir, 0755); err != nil {
		t.Fatalf("MkdirAll hidden: %v", err)
	}
	hiddenIO := filepath.Join(hiddenDir, "io")
	if err := os.WriteFile(hiddenIO, []byte("read_bytes: 0\nwrite_bytes: 0\n"), 0000); err != nil {
		t.Fatalf("WriteFile hidden io: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(hiddenIO, 0644) })

	const visiblePID = 33344
	writeProcIOFixture(t, procRoot, visiblePID, 1000, 0)
	if err := os.WriteFile(filepath.Join(procRoot, strconv.Itoa(visiblePID), "comm"), []byte("visible\n"), 0644); err != nil {
		t.Fatalf("WriteFile comm: %v", err)
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		writeProcIOFixture(t, procRoot, visiblePID, 8000, 0)
	}()

	got, err := topProcessesByIOLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesByIOLinuxAt: %v", err)
	}
	if got.Note == "" {
		t.Error("expected a partial-visibility note when some processes are permission-denied")
	}
}

// TestTopProcessesBySwapLinux_PermissionSetsPartialAndNote covers swap.go:45-50
// (partial=true on EACCES) and swap.go:102-104 (the Note assignment when partial).
// Skipped under root (chmod doesn't restrict reads).
func TestTopProcessesBySwapLinux_PermissionSetsPartialAndNote(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits don't block the read")
	}
	procRoot := t.TempDir()
	const pid = 33345
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0000); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0755) })

	got, err := topProcessesBySwapLinuxAt(context.Background(), 5, procRoot)
	if err != nil {
		t.Fatalf("topProcessesBySwapLinuxAt: %v", err)
	}
	if got.Note == "" {
		t.Error("expected a partial-visibility note when /proc/<pid>/status is permission-denied")
	}
}

// TestClockTrackingMac_DirectCall covers clock.go:13-14 (the darwin dispatch
// in ClockTracking) by calling clockTrackingMac directly.  The internal
// function is callable on any platform; calling it proves the code path the
// darwin branch delegates to works correctly.
// No t.Parallel() — uses swapRunCmd.
func TestClockTrackingMac_DirectCallFromErrorPaths(t *testing.T) {
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		return "", errNotFound
	})
	got, err := clockTrackingMac(context.Background())
	if err != nil {
		t.Fatalf("clockTrackingMac: %v", err)
	}
	if got == nil || got.Type != tableKV {
		t.Errorf("expected a kv_table Details, got %+v", got)
	}
}

// TestTopProcessesByCPUMac_DirectCallFromErrorPaths covers cpu.go:21-22 (the
// darwin dispatch in TopProcessesByCPU) by calling topProcessesByCPUMac
// directly.  No t.Parallel() — uses swapRunCmd.
func TestTopProcessesByCPUMac_DirectCallFromErrorPaths(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "  PID  %CPU COMM\n  100  50.0 busy\n", nil
	})
	got, err := topProcessesByCPUMac(context.Background(), 5)
	if err != nil {
		t.Fatalf("topProcessesByCPUMac: %v", err)
	}
	if got == nil || got.Type != tableProcesses {
		t.Errorf("unexpected shape: %+v", got)
	}
}

// TestTopProcessesByFDMac_DirectCallFromErrorPaths covers fdlimits.go:19-21
// (the darwin dispatch in TopProcessesByFDPercent) by calling
// topProcessesByFDMac directly.  No t.Parallel() — uses swapRunCmd.
func TestTopProcessesByFDMac_DirectCallFromErrorPaths(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		switch name {
		case "lsof":
			return "p42\nn/dev/null\n", nil
		case "ps":
			return "testproc\n", nil
		default:
			t.Fatalf("unexpected command: %s %v", name, args)
			return "", nil
		}
	})
	got, err := topProcessesByFDMac(context.Background(), 5)
	if err != nil {
		t.Fatalf("topProcessesByFDMac: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil Details")
	}
}

// TestTopProcessesByRSSMac_DirectCallFromErrorPaths covers memory.go:20-22
// (the darwin dispatch in TopProcessesByRSS) by calling topProcessesByRSSMac
// directly.  No t.Parallel() — uses swapRunCmd.
func TestTopProcessesByRSSMac_DirectCallFromErrorPaths(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "  PID %MEM    RSS COMM\n  42  5.0  1024 myproc\n", nil
	})
	got, err := topProcessesByRSSMac(context.Background(), 5)
	if err != nil {
		t.Fatalf("topProcessesByRSSMac: %v", err)
	}
	if got == nil || got.Type != tableProcesses {
		t.Errorf("unexpected shape: %+v", got)
	}
}

// TestTCPStatesMac_DirectCallFromErrorPaths covers network.go:31-33 (the
// darwin dispatch in TCPStateAttribution) by calling tcpStatesMac directly.
// No t.Parallel() — uses swapRunCmd.
func TestTCPStatesMac_DirectCallFromErrorPaths(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "netstat" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "tcp4  0  0  *.80  *.*  LISTEN\ntcp4  0  0  *.443  *.*  ESTABLISHED\n", nil
	})
	got, err := tcpStatesMac(context.Background())
	if err != nil {
		t.Fatalf("tcpStatesMac: %v", err)
	}
	if got == nil || got.Type != ddNetKeyTCPStates {
		t.Errorf("unexpected shape: %+v", got)
	}
}

// TestZombiesWithParentMac_DirectCallFromErrorPaths covers processes.go:102-104
// (the darwin dispatch in ZombiesWithParent) by calling zombiesWithParentMac
// directly.  No t.Parallel() — uses swapRunCmd.
func TestZombiesWithParentMac_DirectCallFromErrorPaths(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "  PID STAT PPID COMM\n    1    Ss    0 init\n", nil
	})
	got, err := zombiesWithParentMac(context.Background())
	if err != nil {
		t.Fatalf("zombiesWithParentMac: %v", err)
	}
	if got == nil || got.Type != tableProcesses {
		t.Errorf("unexpected shape: %+v", got)
	}
}
