package drilldown

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSysctlFixture(t *testing.T, procSysRoot, key, value string) {
	t.Helper()
	relPath := strings.ReplaceAll(key, ".", "/")
	path := filepath.Join(procSysRoot, relPath)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestReadSysctl(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeSysctlFixture(t, root, "net.core.somaxconn", "128")

	if got := readSysctl(root, "net.core.somaxconn"); got != "128" {
		t.Errorf("readSysctl() = %q, want %q", got, "128")
	}
}

func TestReadSysctl_MissingFile(t *testing.T) {
	t.Parallel()
	if got := readSysctl(t.TempDir(), "net.core.somaxconn"); got != "n/a" {
		t.Errorf("readSysctl() for missing file = %q, want %q", got, "n/a")
	}
}

func TestActualVsRecommendedAt_MessageMatch(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeSysctlFixture(t, root, "vm.swappiness", "60")

	got, err := actualVsRecommendedAt(context.Background(), "vm.swappiness is set too high", root)
	if err != nil {
		t.Fatalf("actualVsRecommendedAt: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	want := []string{"vm.swappiness", "60", "10"}
	for i, w := range want {
		if got.Rows[0][i] != w {
			t.Errorf("row[%d] = %q, want %q (full row: %+v)", i, got.Rows[0][i], w, got.Rows[0])
		}
	}
}

func TestActualVsRecommendedAt_MatchingValueExcluded(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeSysctlFixture(t, root, "vm.swappiness", "10") // already at recommended value

	got, err := actualVsRecommendedAt(context.Background(), "vm.swappiness warning", root)
	if err != nil {
		t.Fatalf("actualVsRecommendedAt: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil Details when current already matches recommended, got %+v", got)
	}
}

func TestActualVsRecommendedAt_NoKeyMatchUsesDefaults(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeSysctlFixture(t, root, "net.core.somaxconn", "128")
	writeSysctlFixture(t, root, "kernel.pid_max", "32768")

	got, err := actualVsRecommendedAt(context.Background(), "some unrelated message", root)
	if err != nil {
		t.Fatalf("actualVsRecommendedAt: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("expected 2 default rows (somaxconn, pid_max), got %d: %+v", len(got.Rows), got.Rows)
	}
}
