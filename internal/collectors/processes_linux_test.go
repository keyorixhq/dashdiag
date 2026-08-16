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
		"/proc/500", // zombie, real kernel thread (PF_KTHREAD flag set) -> skipped
		"/proc/600", // zombie, ppid==self -> skipped
		"/proc/700", // zombie, shell parent -> skipped
		"/proc/800", // zombie, SPOOFED kernel-thread name but PF_KTHREAD unset -> counted
	}
	normalParentStr := strconv.Itoa(normalParent)
	shellParent := normalParent + 1
	shellParentStr := strconv.Itoa(shellParent)
	withCombinedFixture(t, nil, map[string]string{
		// internal-collectors-27-02: the shell-parent skip is now verified via
		// /proc/<ppid>/exe (kernel-set at exec(), not the spoofable comm name)
		// — see isVerifiedShellParent. This fixture's shellParent is a GENUINE
		// bash parent, so its /exe link resolves to a real shell binary.
		"/proc/" + shellParentStr + "/exe": "/bin/bash",
	}, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", dirs)
		b.PutFile("/proc/100/stat", []byte("100 (nginx) S "+normalParentStr+" 100 100 0 -1 0"))
		b.PutFile("/proc/200/stat", []byte("200 (myapp) Z "+normalParentStr+" 200 200 0 -1 0"))
		b.PutFile("/proc/300/stat", []byte("300 (somejob) D "+normalParentStr+" 300 300 0 -1 0"))
		b.PutFile("/proc/300/wchan", []byte("pipe_wait"))
		b.PutFile("/proc/400/stat", []byte("400 (orphan) Z 2 400 400 0 -1 0"))
		// flags field (7th field after the name) carries PF_KTHREAD (2097152) —
		// the kernel-controlled signal a genuine kernel thread is detected by,
		// not the spoofable comm name.
		b.PutFile("/proc/500/stat", []byte("500 (kworker/0:1) Z "+normalParentStr+" 500 500 0 -1 2097152"))
		b.PutFile("/proc/600/stat", []byte("600 (child) Z "+strconv.Itoa(selfPID)+" 600 600 0 -1 0"))
		b.PutFile("/proc/700/stat", []byte("700 (grandchild) Z "+shellParentStr+" 700 700 0 -1 0"))
		// A userspace process that renamed itself via prctl(PR_SET_NAME) to look
		// like a kernel thread, but has no PF_KTHREAD bit set (flags=0) and a
		// normal (non-kthreadd) parent — must NOT be exempted by name alone.
		b.PutFile("/proc/800/stat", []byte("800 (kworker/0:1) Z "+normalParentStr+" 800 800 0 -1 0"))
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
	if info.ZombieCount != 2 {
		t.Fatalf("ZombieCount = %d, want 2, procs=%+v", info.ZombieCount, info.ZombieProcs)
	}
	if info.ZombieProcs[0].PID != 200 || info.ZombieProcs[0].ParentName != "systemd" {
		t.Errorf("ZombieProcs[0] = %+v, want PID=200 ParentName=systemd", info.ZombieProcs[0])
	}
	var spoofed *models.ProcessState
	for i := range info.ZombieProcs {
		if info.ZombieProcs[i].PID == 800 {
			spoofed = &info.ZombieProcs[i]
		}
	}
	if spoofed == nil {
		t.Fatalf("expected PID 800 (spoofed kernel-thread name, PF_KTHREAD unset) to be counted, procs=%+v", info.ZombieProcs)
	}
	if info.HungCount != 1 {
		t.Fatalf("HungCount = %d, want 1, procs=%+v", info.HungCount, info.HungProcs)
	}
	if info.HungProcs[0].PID != 300 || info.HungProcs[0].WChan != "pipe_wait" {
		t.Errorf("HungProcs[0] = %+v, want PID=300 WChan=pipe_wait", info.HungProcs[0])
	}
}

// TestProcessesCollector_Collect_Linux_SpoofedShellParentNotExempted is the
// regression test for internal-collectors-27-02: a process whose comm name
// self-reports as "bash" (spoofable via prctl(PR_SET_NAME)) but whose actual
// /proc/<pid>/exe does NOT resolve to a real shell binary must NOT exempt its
// zombie child — otherwise any process can hide a real zombie leak by simply
// renaming itself.
func TestProcessesCollector_Collect_Linux_SpoofedShellParentNotExempted(t *testing.T) {
	selfPID := os.Getpid()
	fakeParent := selfPID + 200000
	fakeParentStr := strconv.Itoa(fakeParent)
	dirs := []string{"/proc/900"}
	withCombinedFixture(t, nil, map[string]string{
		// The parent's real executable is NOT a shell — comm alone claims
		// "bash", but /exe (kernel-verified) says otherwise.
		"/proc/" + fakeParentStr + "/exe": "/usr/bin/evil-payload",
	}, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", dirs)
		b.PutFile("/proc/900/stat", []byte("900 (zombiechild) Z "+fakeParentStr+" 900 900 0 -1 0"))
		b.PutFile("/proc/"+fakeParentStr+"/comm", []byte("bash\n")) // spoofed
	})

	c := NewProcessesCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := result.(*models.ProcessInfo)
	if info.ZombieCount != 1 {
		t.Errorf("ZombieCount = %d, want 1 — a spoofed comm name must not exempt the zombie, got %+v", info.ZombieCount, info.ZombieProcs)
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

// TestProcessesCollector_Collect_Linux_CtxCancelledStopsLoop is the
// regression test for internal-collectors-27-03: collectLinux's per-PID scan
// must check ctx and stop, not run every /proc entry to completion regardless
// of the caller's cancellation or the collector's own advertised Timeout().
func TestProcessesCollector_Collect_Linux_CtxCancelledStopsLoop(t *testing.T) {
	dirs := []string{"/proc/100", "/proc/200"}
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", dirs)
		b.PutFile("/proc/100/stat", []byte("100 (myapp) Z 1 100 100 0 -1 0"))
		b.PutFile("/proc/200/stat", []byte("200 (myapp) Z 1 200 200 0 -1 0"))
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewProcessesCollector()
	result, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := result.(*models.ProcessInfo)
	if info.ZombieCount != 0 || info.HungCount != 0 {
		t.Errorf("expected the per-PID scan to stop immediately on a cancelled ctx, got %+v", info)
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
		// internal-collectors-27-02: the shell-parent skip now requires
		// lsof-verified corroboration (macOS has no /proc/<pid>/exe). This
		// shellPID is a GENUINE bash parent, so its txt segment resolves to
		// a real shell binary.
		b.PutCmd("lsof", []string{"-p", shellPIDStr, "-a", "-d", "txt", "-Fn"},
			"p"+shellPIDStr+"\nftxt\nn/bin/bash\nftxt\nn/usr/lib/dyld\n", 0)
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

// TestProcessesCollector_CollectDarwin_SpoofedShellParentNotExempted is the
// darwin regression test for internal-collectors-27-02: a parent process
// whose ps comm self-reports as "bash" but whose actual mapped executable
// (verified via lsof's txt file descriptors, since macOS has no
// /proc/<pid>/exe) is NOT a shell must not exempt its zombie child —
// otherwise any process can hide a real zombie leak by simply renaming
// itself.
func TestProcessesCollector_CollectDarwin_SpoofedShellParentNotExempted(t *testing.T) {
	selfPID := os.Getpid()
	fakeParent := selfPID + 300000
	fakeParentStr := strconv.Itoa(fakeParent)
	out := " " + fakeParentStr + " 1 Ss bash\n" + // comm claims "bash"
		" 500 " + fakeParentStr + " Z zombiechild\n"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ps", []string{"axo", "pid,ppid,stat,comm"}, out, 0)
		// The parent's real mapped executable is NOT a shell.
		b.PutCmd("lsof", []string{"-p", fakeParentStr, "-a", "-d", "txt", "-Fn"},
			"p"+fakeParentStr+"\nftxt\nn/usr/bin/evil-payload\n", 0)
	})
	c := NewProcessesCollector()
	info, err := c.collectDarwin(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ZombieCount != 1 {
		t.Errorf("ZombieCount = %d, want 1 — a spoofed comm name must not exempt the zombie, got %+v", info.ZombieCount, info.ZombieProcs)
	}
}

// TestProcessesCollector_CollectDarwin_LsofUnavailableNotExempted guards the
// fail-closed posture when lsof itself can't be run (unavailable, or ppid
// already exited): a comm-only "bash" claim must not be trusted without
// corroboration.
func TestProcessesCollector_CollectDarwin_LsofUnavailableNotExempted(t *testing.T) {
	selfPID := os.Getpid()
	fakeParent := selfPID + 400000
	fakeParentStr := strconv.Itoa(fakeParent)
	out := " " + fakeParentStr + " 1 Ss bash\n" +
		" 600 " + fakeParentStr + " Z zombiechild\n"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ps", []string{"axo", "pid,ppid,stat,comm"}, out, 0)
		// lsof deliberately NOT seeded — Replay.Run returns ErrNotRecorded.
	})
	c := NewProcessesCollector()
	info, err := c.collectDarwin(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ZombieCount != 1 {
		t.Errorf("ZombieCount = %d, want 1 — an unverifiable shell-parent claim must not exempt the zombie, got %+v", info.ZombieCount, info.ZombieProcs)
	}
}

// TestProcessesCollector_CollectDarwin_NonNumericPIDSkipped guards the
// pid→name map build: a line whose PID field fails to parse must be skipped
// while resolving other processes' parent names still works.
func TestProcessesCollector_CollectDarwin_NonNumericPIDSkipped(t *testing.T) {
	out := "  PID  PPID STAT COMM\n" +
		"notapid 1 Ss weird\n" +
		"100 1 Z zombiechild\n"
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ps", []string{"axo", "pid,ppid,stat,comm"}, out, 0)
	})
	c := NewProcessesCollector()
	info, err := c.collectDarwin(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ZombieCount != 1 {
		t.Fatalf("ZombieCount = %d, want 1 (non-numeric-PID line skipped, not fatal)", info.ZombieCount)
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
