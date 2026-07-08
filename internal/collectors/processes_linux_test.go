//go:build linux

package collectors

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── constructor / interface methods ──────────────────────────────────────────

func TestNewProcessesCollector_NameAndTimeout(t *testing.T) {
	c := NewProcessesCollector()
	if c.Name() != "Processes" {
		t.Errorf("Name() = %q, want Processes", c.Name())
	}
	if c.Timeout() != 2*time.Second {
		t.Errorf("Timeout() = %v, want 2s", c.Timeout())
	}
}

// ── pidFromDir / readWchan / readComm ────────────────────────────────────────

func TestPidFromDir(t *testing.T) {
	tests := []struct {
		dir  string
		want int
	}{
		{"/proc/1234", 1234},
		{"/proc/1", 1},
		{"/proc/notanumber", 0},
	}
	for _, tt := range tests {
		if got := pidFromDir(tt.dir); got != tt.want {
			t.Errorf("pidFromDir(%q) = %d, want %d", tt.dir, got, tt.want)
		}
	}
}

func TestReadWchan(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/300/wchan", []byte("pipe_wait\n"))
	})
	if got := readWchan(300); got != "pipe_wait" {
		t.Errorf("readWchan(300) = %q, want pipe_wait", got)
	}
}

func TestReadWchan_Missing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := readWchan(999); got != "" {
		t.Errorf("readWchan(999) = %q, want empty on unreadable file", got)
	}
}

func TestReadComm(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/1/comm", []byte("systemd\n"))
	})
	if got := readComm(1); got != "systemd" {
		t.Errorf("readComm(1) = %q, want systemd", got)
	}
}

func TestReadComm_Missing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := readComm(999); got != "" {
		t.Errorf("readComm(999) = %q, want empty on unreadable file", got)
	}
}

// ── collectLinux (via Collect, since GOOS==linux in this test binary) ───────

func TestProcessesCollector_Collect_Linux(t *testing.T) {
	selfPID := os.Getpid()
	// A normal-parent PID for the counted zombie/hung cases below. Must not
	// collide with selfPID (the ppid==selfPID skip is tested separately with
	// PID 600) or with the ppid==2 kernel-parent sentinel — offset selfPID by
	// a large constant so it can never coincide even if the test binary itself
	// happens to run as PID 1 or 2 in a minimal container.
	normalParent := selfPID + 100000
	dirs := []string{
		"/proc/100", // running -> skipped
		"/proc/200", // zombie, normal parent -> counted
		"/proc/300", // D-state, normal parent -> counted
		"/proc/400", // zombie, ppid=2 (kernel parent) -> skipped
		"/proc/500", // zombie, kernel-thread name -> skipped
		"/proc/600", // zombie, ppid==self -> skipped
		"/proc/700", // zombie, shell parent -> skipped
	}
	normalParentStr := strconv.Itoa(normalParent)
	shellParent := normalParent + 1
	shellParentStr := strconv.Itoa(shellParent)
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", dirs)
		b.PutFile("/proc/100/stat", []byte("100 (nginx) S "+normalParentStr+" 100 100 0 -1 0"))
		b.PutFile("/proc/200/stat", []byte("200 (myapp) Z "+normalParentStr+" 200 200 0 -1 0"))
		b.PutFile("/proc/300/stat", []byte("300 (somejob) D "+normalParentStr+" 300 300 0 -1 0"))
		b.PutFile("/proc/300/wchan", []byte("pipe_wait"))
		b.PutFile("/proc/400/stat", []byte("400 (orphan) Z 2 400 400 0 -1 0"))
		b.PutFile("/proc/500/stat", []byte("500 (kworker/0:1) Z "+normalParentStr+" 500 500 0 -1 0"))
		b.PutFile("/proc/600/stat", []byte("600 (child) Z "+strconv.Itoa(selfPID)+" 600 600 0 -1 0"))
		b.PutFile("/proc/700/stat", []byte("700 (grandchild) Z "+shellParentStr+" 700 700 0 -1 0"))
		b.PutFile("/proc/"+normalParentStr+"/comm", []byte("systemd\n"))
		b.PutFile("/proc/"+shellParentStr+"/comm", []byte("bash\n"))
	})

	c := NewProcessesCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := result.(*models.ProcessInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.ProcessInfo", result)
	}
	if info.Total != len(dirs) {
		t.Errorf("Total = %d, want %d", info.Total, len(dirs))
	}
	if info.ZombieCount != 1 {
		t.Fatalf("ZombieCount = %d, want 1, procs=%+v", info.ZombieCount, info.ZombieProcs)
	}
	if info.ZombieProcs[0].PID != 200 || info.ZombieProcs[0].ParentName != "systemd" {
		t.Errorf("ZombieProcs[0] = %+v, want PID=200 ParentName=systemd", info.ZombieProcs[0])
	}
	if info.HungCount != 1 {
		t.Fatalf("HungCount = %d, want 1, procs=%+v", info.HungCount, info.HungProcs)
	}
	if info.HungProcs[0].PID != 300 || info.HungProcs[0].WChan != "pipe_wait" {
		t.Errorf("HungProcs[0] = %+v, want PID=300 WChan=pipe_wait", info.HungProcs[0])
	}
}

func TestProcessesCollector_Collect_Linux_GlobError(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	c := NewProcessesCollector()
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("expected an error when /proc globbing fails")
	}
}

func TestProcessesCollector_Collect_Linux_UnreadableOrMalformedStat(t *testing.T) {
	dirs := []string{"/proc/100", "/proc/200"}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", dirs)
		// /proc/100/stat is left unseeded -> readFile fails -> skipped.
		b.PutFile("/proc/200/stat", []byte("garbage, no parens"))
	})
	c := NewProcessesCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := result.(*models.ProcessInfo)
	if info.ZombieCount != 0 || info.HungCount != 0 {
		t.Errorf("expected zero zombies/hung with unreadable+malformed stats, got %+v", info)
	}
	if info.Total != 2 {
		t.Errorf("Total = %d, want 2 (glob count unaffected by parse failures)", info.Total)
	}
}

// ── collectDarwin (called directly — the test binary's GOOS is linux, but the
// function itself has no runtime.GOOS check; only Collect()'s dispatch does) ─

func TestProcessesCollector_CollectDarwin(t *testing.T) {
	selfPID := os.Getpid()
	// Offset sentinel PIDs so they can never collide with selfPID, even if the
	// test binary happens to run as PID 1 in a minimal container (see the
	// analogous comment in TestProcessesCollector_Collect_Linux).
	launchd := selfPID + 100000
	shellPID := launchd + 1
	launchdStr := strconv.Itoa(launchd)
	shellPIDStr := strconv.Itoa(shellPID)
	out := "  PID  PPID STAT COMM\n" +
		" " + launchdStr + " 0 Ss launchd\n" +
		" 100 " + launchdStr + " Z zombiechild\n" +
		" 200 " + launchdStr + " D somejob\n" +
		" 300 " + strconv.Itoa(selfPID) + " Z selfchild\n" +
		" 400 " + shellPIDStr + " Z shellchild\n" +
		" " + shellPIDStr + " " + launchdStr + " Ss bash\n"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ps", []string{"axo", "pid,ppid,stat,comm"}, out, 0)
	})

	c := NewProcessesCollector()
	info, err := c.collectDarwin(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ZombieCount != 1 {
		t.Fatalf("ZombieCount = %d, want 1 (selfchild/shellchild skipped), procs=%+v", info.ZombieCount, info.ZombieProcs)
	}
	if info.ZombieProcs[0].PID != 100 || info.ZombieProcs[0].ParentName != "launchd" {
		t.Errorf("ZombieProcs[0] = %+v, want PID=100 ParentName=launchd", info.ZombieProcs[0])
	}
	if info.HungCount != 1 || info.HungProcs[0].PID != 200 {
		t.Errorf("HungProcs = %+v, want one entry PID=200", info.HungProcs)
	}
}

func TestProcessesCollector_CollectDarwin_CommandUnavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	c := NewProcessesCollector()
	info, err := c.collectDarwin(context.Background())
	if err != nil {
		t.Fatalf("collectDarwin must not return an error when ps is unavailable, got %v", err)
	}
	if info.Total != 0 || info.ZombieCount != 0 || info.HungCount != 0 {
		t.Errorf("expected empty ProcessInfo when ps is unavailable, got %+v", info)
	}
}
