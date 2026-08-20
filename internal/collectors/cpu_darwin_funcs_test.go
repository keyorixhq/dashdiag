package collectors

// cpu_darwin_funcs_test.go — loadAvgDarwin/cpuUsageDarwin themselves carry no
// runtime.GOOS check (the OS gating lives one level up, in the caller); they
// just wrap runCmd, which is fixture-injectable via source.Replay the same as
// every other collector — so these run and are covered on any host, not just
// real macOS. Parsing correctness (parseLoadAvg/parseDarwinCPUUsage) already
// has its own table-driven tests; these only cover the runCmd integration
// (happy path + the error/empty-output paths).

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestLoadAvgDarwin_HappyPath(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("sysctl", []string{"-n", "vm.loadavg"}, "{ 0.52 0.43 0.32 }\n", 0)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	l1, l5, l15, err := loadAvgDarwin(context.Background())
	if err != nil {
		t.Fatalf("loadAvgDarwin: %v", err)
	}
	if l1 != 0.52 || l5 != 0.43 || l15 != 0.32 {
		t.Errorf("loadAvgDarwin = (%v, %v, %v), want (0.52, 0.43, 0.32)", l1, l5, l15)
	}
}

func TestLoadAvgDarwin_LocaleCommaDecimal(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("sysctl", []string{"-n", "vm.loadavg"}, "{ 2,12 0,43 0,32 }\n", 0)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	l1, _, _, err := loadAvgDarwin(context.Background())
	if err != nil {
		t.Fatalf("loadAvgDarwin: %v", err)
	}
	if l1 != 2.12 {
		t.Errorf("loadAvgDarwin l1 = %v, want 2.12 (comma decimal normalized)", l1)
	}
}

func TestLoadAvgDarwin_SysctlFails(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("sysctl", []string{"-n", "vm.loadavg"}, "", 1)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	if _, _, _, err := loadAvgDarwin(context.Background()); err == nil {
		t.Error("loadAvgDarwin() = nil error, want an error when sysctl fails")
	}
}

func TestCPUUsageDarwin_HappyPath(t *testing.T) {
	b := source.NewBundle()
	top := "Processes: 400 total\n" +
		"CPU usage: 4.00% user, 2.00% sys, 94.00% idle\n" +
		"CPU usage: 8.97% user, 4.77% sys, 86.25% idle\n"
	b.PutCmd("top", []string{"-l", "2", "-s", "1", "-n", "0"}, top, 0)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	got := cpuUsageDarwin(context.Background())
	want := 8.97 + 4.77
	if got != want {
		t.Errorf("cpuUsageDarwin() = %v, want %v (last sample's user+sys)", got, want)
	}
}

func TestCPUUsageDarwin_TopFailsReturnsZero(t *testing.T) {
	b := source.NewBundle()
	b.PutCmd("top", []string{"-l", "2", "-s", "1", "-n", "0"}, "", 1)
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	if got := cpuUsageDarwin(context.Background()); got != 0 {
		t.Errorf("cpuUsageDarwin() = %v, want 0 when top fails", got)
	}
}
