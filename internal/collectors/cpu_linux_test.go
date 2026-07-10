//go:build linux

package collectors

import (
	"io"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestNewCPUCollector_ReadersWireCorrectPaths proves the three closures
// NewCPUCollector wires actually call openFile on the expected /proc paths —
// the constructor's closure bodies (lines never invoked by a mere non-nil
// check) route through the active source, so seeding a fixture source proves
// both the wiring AND the "no direct filesystem access" contract.
func TestNewCPUCollector_ReadersWireCorrectPaths(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/loadavg", []byte("0.10 0.20 0.30 1/100 999\n"))
		b.PutFile("/proc/stat", []byte("cpu  1 2 3 4 5 6 7 8 9 10\n"))
		b.PutFile("/proc/self/stat", []byte("1 (dsd) R 0 1 1 0 -1 0 0 0 0 0 1 1 1 1 0 0 0 20 1\n"))
	})

	c := NewCPUCollector(platform.ContainerContext{})

	r, err := c.readers.loadAvgOpen()
	if err != nil {
		t.Fatalf("loadAvgOpen: %v", err)
	}
	data, _ := io.ReadAll(r)
	_ = r.Close()
	if !strings.Contains(string(data), "0.10 0.20 0.30") {
		t.Errorf("loadAvgOpen did not read the fixture /proc/loadavg, got %q", data)
	}

	r, err = c.readers.statOpen()
	if err != nil {
		t.Fatalf("statOpen: %v", err)
	}
	data, _ = io.ReadAll(r)
	_ = r.Close()
	if !strings.Contains(string(data), "cpu  1 2 3") {
		t.Errorf("statOpen did not read the fixture /proc/stat, got %q", data)
	}

	r, err = c.readers.selfStatOpen()
	if err != nil {
		t.Fatalf("selfStatOpen: %v", err)
	}
	data, _ = io.ReadAll(r)
	_ = r.Close()
	if !strings.Contains(string(data), "(dsd)") {
		t.Errorf("selfStatOpen did not read the fixture /proc/self/stat, got %q", data)
	}
}
