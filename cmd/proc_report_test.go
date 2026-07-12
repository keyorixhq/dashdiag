package cmd

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// Golden-output tests for proc.go's report renderers — plain data structs, no
// live I/O. No t.Parallel() (corrupts captureStdout's shared os.Stdout swap).

func TestTruncateProcStr(t *testing.T) {
	if got := truncateProcStr("short", 10); got != "short" {
		t.Errorf("a short string should pass through unchanged, got %q", got)
	}
	if got := truncateProcStr("a very long process name here", 10); got != "a very lon…" {
		t.Errorf("truncateProcStr(30, 10) = %q, want 'a very lon…'", got)
	}
}

func TestFmtDuration(t *testing.T) {
	cases := []struct {
		sec  int
		want string
	}{
		{30, "30s"},
		{90, "1m 30s"},
		{7200, "2h 0m"},
		{90000, "1d 1h"},
	}
	for _, c := range cases {
		if got := fmtDuration(c.sec); got != c.want {
			t.Errorf("fmtDuration(%d) = %q, want %q", c.sec, got, c.want)
		}
	}
}

func TestPrintProcTopList(t *testing.T) {
	out := captureStdout(t, func() {
		printProcTopList(&models.ProcInfo{TopProcs: []models.ProcessMemStat{
			{PID: 100, Name: "chrome", RSSMB: 512.3, MemPct: 12.5},
		}}, output.ModeHuman)
	})
	if !strings.Contains(out, "chrome") || !strings.Contains(out, "512.3MB") {
		t.Errorf("the top process should be listed with its RSS, got:\n%s", out)
	}
	if !strings.Contains(out, "dsd proc <PID>") {
		t.Errorf("human mode should hint at the detail command, got:\n%s", out)
	}

	plain := captureStdout(t, func() {
		printProcTopList(&models.ProcInfo{TopProcs: []models.ProcessMemStat{{PID: 100, Name: "chrome"}}}, output.ModePlain)
	})
	if strings.Contains(plain, "dsd proc <PID>") {
		t.Errorf("plain mode must not include the human-only hint, got:\n%s", plain)
	}
}

func TestPrintProcState(t *testing.T) {
	running := captureStdout(t, func() { printProcState(&models.ProcInfo{State: "S"}, output.ModeHuman) })
	if !strings.Contains(running, "S") || strings.Contains(running, "UNINTERRUPTIBLE") {
		t.Errorf("a non-D state should render as-is, got:\n%s", running)
	}

	dstate := captureStdout(t, func() {
		printProcState(&models.ProcInfo{State: "D", DState: true, WChan: "nfs_wait"}, output.ModeHuman)
	})
	if !strings.Contains(dstate, "UNINTERRUPTIBLE") {
		t.Errorf("a D-state process should be explained, got:\n%s", dstate)
	}
	if !strings.Contains(dstate, "nfs_wait") || !strings.Contains(dstate, "blocking this process") {
		t.Errorf("a D-state process's wchan should be annotated as the blocking function, got:\n%s", dstate)
	}
}

func TestPrintProcResourcesFD(t *testing.T) {
	unreadable := captureStdout(t, func() {
		printProcResources(&models.ProcInfo{FDReadable: false}, output.ModeHuman)
	})
	if !strings.Contains(unreadable, "unreadable") {
		t.Errorf("an unreadable FD count must say so, not render a false 0, got:\n%s", unreadable)
	}

	pressure := captureStdout(t, func() {
		printProcResources(&models.ProcInfo{FDReadable: true, FDCount: 900, FDLimit: 1024, FDPressure: true}, output.ModeHuman)
	})
	if !strings.Contains(pressure, "900 / 1024") || !strings.Contains(pressure, "80% of limit") {
		t.Errorf("FD pressure should show the count/limit and the warning, got:\n%s", pressure)
	}

	memMap := captureStdout(t, func() {
		printProcResources(&models.ProcInfo{FDReadable: true, MemMap: &models.ProcMemMap{RSSKb: 2048, PrivateDirtyKb: 1024}}, output.ModeHuman)
	})
	if !strings.Contains(memMap, "Memory map") || !strings.Contains(memMap, "1024 kB") {
		t.Errorf("a present MemMap should render the smaps_rollup section, got:\n%s", memMap)
	}
}

func TestPrintProcFilesDeletedLibs(t *testing.T) {
	if out := captureStdout(t, func() { printProcFiles(&models.ProcInfo{}, output.ModeHuman, true) }); strings.Contains(out, "Deleted") {
		t.Errorf("no deleted libs should not mention them, got:\n%s", out)
	}

	deleted := captureStdout(t, func() {
		printProcFiles(&models.ProcInfo{DeletedLibs: []string{"/usr/lib/libssl.so.3 (deleted)"}}, output.ModeHuman, true)
	})
	if !strings.Contains(deleted, "libssl.so.3") || !strings.Contains(deleted, "restart process after package update") {
		t.Errorf("a deleted shared library should be named with the restart hint, got:\n%s", deleted)
	}
}

func TestPrintProcConnections(t *testing.T) {
	if out := captureStdout(t, func() { printProcConnections(&models.ProcInfo{}, output.ModeHuman, true) }); out != "" {
		t.Errorf("no connections should print nothing, got:\n%s", out)
	}

	// More than 20 connections must truncate with a "… and N more" summary,
	// not dump an unbounded list.
	conns := make([]models.ProcNetConn, 25)
	for i := range conns {
		conns[i] = models.ProcNetConn{Protocol: "tcp", LocalAddr: "127.0.0.1:8080", RemoteAddr: "10.0.0.1:443", State: "ESTABLISHED"}
	}
	out := captureStdout(t, func() { printProcConnections(&models.ProcInfo{Connections: conns}, output.ModeHuman, true) })
	if !strings.Contains(out, "and 5 more") {
		t.Errorf("25 connections shown 20 at a time should say 5 more, got:\n%s", out)
	}
}

func TestPrintDStateGuide(t *testing.T) {
	out := captureStdout(t, func() { printDStateGuide("nfs_wait", 1234) })
	if !strings.Contains(out, "nfs_wait") || !strings.Contains(out, "1234") {
		t.Errorf("the D-state guide should reference the wchan and PID, got:\n%s", out)
	}
}

func TestPrintProcDetailDispatch(t *testing.T) {
	out := captureStdout(t, func() {
		printProcDetail(&models.ProcInfo{PID: 42, Name: "sshd", State: "D", DState: true, WChan: "nfs_wait", FDReadable: true}, output.ModeHuman)
	})
	if !strings.Contains(out, "Process 42") || !strings.Contains(out, "sshd") {
		t.Errorf("the process identity header should be shown, got:\n%s", out)
	}
	if !strings.Contains(out, "D-state diagnosis") {
		t.Errorf("a D-state process in human mode should append the diagnosis guide, got:\n%s", out)
	}
}

// TestPrintProcIdentity covers the optional identity fields (Parent, User,
// Cgroup) and the plain-mode branch of printProcLine (human mode is already
// exercised by the other tests in this file).
func TestPrintProcIdentity(t *testing.T) {
	minimal := captureStdout(t, func() {
		printProcIdentity(&models.ProcInfo{PID: 100, Cmdline: "sleep 10"}, output.ModeHuman)
	})
	if strings.Contains(minimal, "Parent") || strings.Contains(minimal, "User") || strings.Contains(minimal, "Cgroup") {
		t.Errorf("no PPID/User/Cgroup should suppress those lines, got:\n%s", minimal)
	}

	full := captureStdout(t, func() {
		printProcIdentity(&models.ProcInfo{
			PID: 100, PPID: 1, ParentName: "systemd", User: "root",
			CgroupName: "system:docker", Cmdline: "sleep 10", UptimeSec: 90,
		}, output.ModePlain)
	})
	if !strings.Contains(full, "1 (systemd)") {
		t.Errorf("a named parent should be shown as PPID (name), got:\n%s", full)
	}
	if !strings.Contains(full, "root") || !strings.Contains(full, "system:docker") {
		t.Errorf("User and Cgroup should be shown, got:\n%s", full)
	}
}

// TestRunProc exercises runProc's real (read-only) /proc collector wiring in
// three modes: the default top-list (no PID), an invalid PID argument, and a
// concrete PID (the test process's own PID, which is always readable). Same
// real-I/O precedent as cpu_report_test.go / hardware_test.go. Skipped on
// non-Linux because /proc does not exist on macOS.
func TestRunProc(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc is Linux-only")
	}
	topCmd := newBareCloudCmd()
	topCmd.SetContext(context.Background())
	_ = topCmd.Flags().Set("plain", "true")
	topOut := captureStdout(t, func() {
		if err := runProc(topCmd, nil); err != nil {
			t.Fatalf("runProc (top list): %v", err)
		}
	})
	if topOut == "" {
		t.Error("runProc (top list) produced no output")
	}

	badPIDCmd := newBareCloudCmd()
	badPIDCmd.SetContext(context.Background())
	if err := runProc(badPIDCmd, []string{"not-a-pid"}); err == nil {
		t.Error("runProc with a non-numeric PID arg should return an error")
	}

	selfCmd := newBareCloudCmd()
	selfCmd.SetContext(context.Background())
	_ = selfCmd.Flags().Set("json", "true")
	pid := os.Getpid()
	selfOut := captureStdout(t, func() {
		if err := runProc(selfCmd, []string{strconv.Itoa(pid)}); err != nil {
			t.Fatalf("runProc (self PID, json): %v", err)
		}
	})
	if !strings.Contains(selfOut, "{") {
		t.Errorf("json mode should emit JSON, got: %q", selfOut)
	}
}
