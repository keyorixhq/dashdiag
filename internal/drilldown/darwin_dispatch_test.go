//go:build darwin

package drilldown

import (
	"context"
	"testing"
)

// The tests in this file cover the darwin-branch dispatch guards in exported
// functions (runtime.GOOS == "darwin" checks).  They are build-tag-constrained
// to darwin because those branches are structurally dead code on Linux — the
// Go runtime.GOOS constant cannot be faked, and a Linux binary will never
// execute a "darwin" branch at runtime.
//
// Each test calls the exported function directly (not the internal *Mac
// variant), so the dispatch guard line itself is executed and marked covered.
// runCmd is swapped for all tests that shell out.

// TestClockTracking_DarwinDispatch covers clock.go:13-14 (the darwin branch
// guard in ClockTracking).  No t.Parallel() — uses swapRunCmd.
func TestClockTracking_DarwinDispatch(t *testing.T) {
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		return "", errNotFound
	})
	got, err := ClockTracking(context.Background())
	if err != nil {
		t.Fatalf("ClockTracking on darwin: %v", err)
	}
	if got == nil || got.Type != tableKV {
		t.Errorf("expected a kv_table from clockTrackingMac, got %+v", got)
	}
}

// TestTopProcessesByCPU_DarwinDispatch covers cpu.go:21-22 (the darwin branch
// guard in TopProcessesByCPU).  No t.Parallel() — uses swapRunCmd.
func TestTopProcessesByCPU_DarwinDispatch(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "  PID  %CPU COMM\n  1  0.1 launchd\n", nil
	})
	got, err := TopProcessesByCPU(context.Background(), 5)
	if err != nil {
		t.Fatalf("TopProcessesByCPU on darwin: %v", err)
	}
	if got == nil || got.Type != tableProcesses {
		t.Errorf("unexpected shape: %+v", got)
	}
}

// TestTopProcessesByFDPercent_DarwinDispatch covers fdlimits.go:19-21 (the
// darwin branch guard in TopProcessesByFDPercent).  No t.Parallel() — uses
// swapRunCmd.
func TestTopProcessesByFDPercent_DarwinDispatch(t *testing.T) {
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		return "", errNotFound
	})
	_, err := TopProcessesByFDPercent(context.Background(), 5)
	if err == nil {
		t.Error("expected an error when lsof fails on darwin")
	}
}

// TestTopProcessesByIO_DarwinDispatch covers io.go:21-27 (the darwin branch
// guard in TopProcessesByIO — the whole block is a literal return).
func TestTopProcessesByIO_DarwinDispatch(t *testing.T) {
	t.Parallel()
	got, err := TopProcessesByIO(context.Background(), 5)
	if err != nil {
		t.Fatalf("TopProcessesByIO on darwin: %v", err)
	}
	if got == nil || got.Type != "kv_table" {
		t.Errorf("expected a kv_table with the macOS note, got %+v", got)
	}
	if got.Note == "" {
		t.Error("expected a Note explaining macOS limitation")
	}
}

// TestPoliciesNotEnforcing_DarwinDispatch covers kernelsec.go:24-26 (the
// darwin branch guard in PoliciesNotEnforcing).
func TestPoliciesNotEnforcing_DarwinDispatch(t *testing.T) {
	t.Parallel()
	got, err := PoliciesNotEnforcing(context.Background())
	if err != nil || got != nil {
		t.Errorf("PoliciesNotEnforcing on darwin: want (nil, nil), got (%+v, %v)", got, err)
	}
}

// TestTopProcessesByRSS_DarwinDispatch covers memory.go:20-22 (the darwin
// branch guard in TopProcessesByRSS).  No t.Parallel() — uses swapRunCmd.
func TestTopProcessesByRSS_DarwinDispatch(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "  PID %MEM    RSS COMM\n  1  0.1  1024 launchd\n", nil
	})
	got, err := TopProcessesByRSS(context.Background(), 5)
	if err != nil {
		t.Fatalf("TopProcessesByRSS on darwin: %v", err)
	}
	if got == nil || got.Type != tableProcesses {
		t.Errorf("unexpected shape: %+v", got)
	}
}

// TestTCPStateAttribution_DarwinDispatch covers network.go:31-33 (the darwin
// branch guard in TCPStateAttribution).  No t.Parallel() — uses swapRunCmd.
func TestTCPStateAttribution_DarwinDispatch(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "netstat" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "tcp4  0  0  *.80  *.*  LISTEN\n", nil
	})
	got, err := TCPStateAttribution(context.Background(), nil)
	if err != nil {
		t.Fatalf("TCPStateAttribution on darwin: %v", err)
	}
	if got == nil || got.Type != ddNetKeyTCPStates {
		t.Errorf("unexpected shape: %+v", got)
	}
}

// TestHungProcesses_DarwinDispatch covers processes.go:23-29 (the darwin
// branch guard in HungProcesses — the whole block is a literal return).
func TestHungProcesses_DarwinDispatch(t *testing.T) {
	t.Parallel()
	got, err := HungProcesses(context.Background())
	if err != nil {
		t.Fatalf("HungProcesses on darwin: %v", err)
	}
	if got == nil || got.Type != "kv_table" {
		t.Errorf("expected a kv_table with the macOS note, got %+v", got)
	}
	if got.Note == "" {
		t.Error("expected a Note explaining macOS limitation")
	}
}

// TestZombiesWithParent_DarwinDispatch covers processes.go:102-104 (the darwin
// branch guard in ZombiesWithParent).  No t.Parallel() — uses swapRunCmd.
func TestZombiesWithParent_DarwinDispatch(t *testing.T) {
	swapRunCmd(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "ps" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "  PID STAT PPID COMM\n    1    Ss    0 launchd\n", nil
	})
	got, err := ZombiesWithParent(context.Background())
	if err != nil {
		t.Fatalf("ZombiesWithParent on darwin: %v", err)
	}
	if got == nil || got.Type != tableProcesses {
		t.Errorf("unexpected shape: %+v", got)
	}
}

// TestTopProcessesBySwap_DarwinDispatch covers swap.go:21-23 (the darwin
// branch guard in TopProcessesBySwap — returns nil, nil).
func TestTopProcessesBySwap_DarwinDispatch(t *testing.T) {
	t.Parallel()
	got, err := TopProcessesBySwap(context.Background(), 5)
	if got != nil || err != nil {
		t.Errorf("TopProcessesBySwap on darwin: want (nil, nil), got (%+v, %v)", got, err)
	}
}

// TestActualVsRecommended_DarwinDispatch covers sysctl.go:31-33 (the darwin
// branch guard in ActualVsRecommended — returns nil, nil).
func TestActualVsRecommended_DarwinDispatch(t *testing.T) {
	t.Parallel()
	got, err := ActualVsRecommended(context.Background(), "vm.swappiness warning")
	if got != nil || err != nil {
		t.Errorf("ActualVsRecommended on darwin: want (nil, nil), got (%+v, %v)", got, err)
	}
}
