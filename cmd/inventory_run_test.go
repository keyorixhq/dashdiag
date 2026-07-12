package cmd

// inventory_run_test.go covers runInventory's real (read-only) HardwareCollector
// wiring in its three output paths: default JSON to stdout, --csv, and --out
// (write to file) — same real-I/O precedent as cpu_report_test.go.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newBareInventoryCmd builds a bare cobra.Command with the flags runInventory reads.
func newBareInventoryCmd() *cobra.Command {
	c := &cobra.Command{}
	f := c.Flags()
	f.Bool("csv", false, "")
	f.String("out", "", "")
	c.SetContext(context.Background())
	return c
}

func TestRunInventoryJSONToStdout(t *testing.T) {
	c := newBareInventoryCmd()
	out := captureStdout(t, func() {
		if err := runInventory(c, nil); err != nil {
			t.Fatalf("runInventory: %v", err)
		}
	})
	if !strings.Contains(out, "{") {
		t.Errorf("default output should be JSON, got: %q", out)
	}
}

func TestRunInventoryCSV(t *testing.T) {
	c := newBareInventoryCmd()
	_ = c.Flags().Set("csv", "true")
	out := captureStdout(t, func() {
		if err := runInventory(c, nil); err != nil {
			t.Fatalf("runInventory --csv: %v", err)
		}
	})
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("--csv output should not be JSON, got: %q", out)
	}
	if out == "" {
		t.Error("--csv output should not be empty")
	}
}

func TestRunInventoryOutFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")

	c := newBareInventoryCmd()
	_ = c.Flags().Set("out", path)
	stderr := captureStderr(t, func() {
		if err := runInventory(c, nil); err != nil {
			t.Fatalf("runInventory --out: %v", err)
		}
	})
	if !strings.Contains(stderr, path) {
		t.Errorf("--out should confirm the write path on stderr, got: %q", stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading --out file: %v", err)
	}
	if !strings.Contains(string(data), "{") {
		t.Errorf("--out file should contain JSON, got: %q", string(data))
	}
}
