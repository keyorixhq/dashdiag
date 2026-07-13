package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNetReadTCPStatesFrom(t *testing.T) {
	t.Parallel()

	// Minimal /proc/net/tcp-shaped fixture: header line + space-separated hex
	// fields, state is field index 3 (0-based).
	tcp4 := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0100007F:1F91 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0\n" +
		"   2: 0100007F:1F92 00000000:0000 06 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0\n"

	tcp6 := "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 22345 1 0000000000000000 100 0 0 10 0\n"

	dir := t.TempDir()
	tcp4Path := filepath.Join(dir, "tcp")
	tcp6Path := filepath.Join(dir, "tcp6")
	if err := os.WriteFile(tcp4Path, []byte(tcp4), 0o644); err != nil {
		t.Fatalf("writing tcp4 fixture: %v", err)
	}
	if err := os.WriteFile(tcp6Path, []byte(tcp6), 0o644); err != nil {
		t.Fatalf("writing tcp6 fixture: %v", err)
	}

	got := netReadTCPStatesFrom(tcp4Path, tcp6Path)

	want := map[string]int{
		"LISTEN":    0, // 0A is not in the tcpStateNames map, so it must be absent
		"ESTAB":     2, // one from tcp4 (01), one from tcp6 (01)
		"TIME-WAIT": 1,
	}
	if got["ESTAB"] != want["ESTAB"] {
		t.Errorf("ESTAB count = %d, want %d (got %+v)", got["ESTAB"], want["ESTAB"], got)
	}
	if got["TIME-WAIT"] != want["TIME-WAIT"] {
		t.Errorf("TIME-WAIT count = %d, want %d (got %+v)", got["TIME-WAIT"], want["TIME-WAIT"], got)
	}
	if _, ok := got["LISTEN"]; ok {
		t.Errorf("state 0A is unmapped and must not appear, got %+v", got)
	}
}

func TestNetReadTCPStatesFrom_EmptyFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tcp4Path := filepath.Join(dir, "tcp")
	tcp6Path := filepath.Join(dir, "tcp6")
	if err := os.WriteFile(tcp4Path, []byte(""), 0o644); err != nil {
		t.Fatalf("writing empty tcp4 fixture: %v", err)
	}
	if err := os.WriteFile(tcp6Path, []byte("header only, no entries\n"), 0o644); err != nil {
		t.Fatalf("writing tcp6 fixture: %v", err)
	}

	got := netReadTCPStatesFrom(tcp4Path, tcp6Path)
	if len(got) != 0 {
		t.Errorf("empty/header-only files should yield no states, got %+v", got)
	}
}

func TestNetReadTCPStatesFrom_MissingFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	got := netReadTCPStatesFrom(filepath.Join(dir, "nope-tcp"), filepath.Join(dir, "nope-tcp6"))
	if len(got) != 0 {
		t.Errorf("missing files should yield no states (not an error), got %+v", got)
	}
}

func TestNetReadTCPStatesFrom_ShortLineSkipped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tcp4Path := filepath.Join(dir, "tcp")
	tcp6Path := filepath.Join(dir, "tcp6")
	// Header + a line with fewer than 4 fields — must be skipped, not panic.
	content := "header\n0: too short\n"
	if err := os.WriteFile(tcp4Path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing tcp4 fixture: %v", err)
	}
	if err := os.WriteFile(tcp6Path, []byte("header\n"), 0o644); err != nil {
		t.Fatalf("writing tcp6 fixture: %v", err)
	}

	got := netReadTCPStatesFrom(tcp4Path, tcp6Path)
	if len(got) != 0 {
		t.Errorf("a short line should be skipped, got %+v", got)
	}
}

func TestNetReadTCPStates_UsesRealProcPaths(t *testing.T) {
	t.Parallel()
	// Smoke test for the production wrapper — just confirm it runs without
	// panicking and returns a (possibly empty) map on whatever host this runs on.
	got := netReadTCPStates()
	if got == nil {
		t.Error("netReadTCPStates should never return a nil map")
	}
}
