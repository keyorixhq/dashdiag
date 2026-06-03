package cmd

// mock_raw_test.go — verifies dsd capture preserves disk raw data into the
// fixture and dsd mock replays it through the real model type (the "raw path"),
// while fixtures without raw data still replay unchanged (backward compat).

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// lvmWarnJSON is the raw struct dsd health --json emits for an LVM thin pool
// that has crossed the 85% data-usage WARN threshold.
const lvmWarnJSON = `{"thin_pools":[{"name":"data","vg":"pve","data_pct":92.4,"meta_pct":40.1,"size_gb":500}]}`

func TestMockRawData_LVMWarnRoundTrips(t *testing.T) {
	got := mockRawData("LVM", lvmWarnJSON)
	if got == nil {
		t.Fatal("mockRawData returned nil for valid LVM raw JSON — raw path did not fire")
	}
	lvm, ok := got.(*models.LVMInfo)
	if !ok {
		t.Fatalf("mockRawData returned %T, want *models.LVMInfo", got)
	}
	if len(lvm.ThinPools) != 1 {
		t.Fatalf("decoded %d thin pools, want 1", len(lvm.ThinPools))
	}
	if lvm.ThinPools[0].DataPct <= 85 {
		t.Errorf("thin pool data_pct = %.1f, want >85 (the WARN condition)", lvm.ThinPools[0].DataPct)
	}
}

func TestMockRawData_BackwardCompat(t *testing.T) {
	// Fixtures without raw data must fall back to the text-only stub (nil here).
	if got := mockRawData("LVM", ""); got != nil {
		t.Errorf("empty raw should yield nil (text-only fallback), got %T", got)
	}
	// Malformed raw must not crash — it falls back, no regression.
	if got := mockRawData("LVM", "{not valid json"); got != nil {
		t.Errorf("malformed raw should yield nil (fallback), got %T", got)
	}
	// "Drives" is covered by Disk — no separate mapping, falls back.
	if got := mockRawData("Drives", lvmWarnJSON); got != nil {
		t.Errorf("Drives has no model mapping, want nil, got %T", got)
	}
}

func TestBuildFixtureRow_PreservesDiskRaw(t *testing.T) {
	c := captureCheck{
		Name:   "LVM",
		Status: "WARN",
		Raw:    json.RawMessage(lvmWarnJSON),
	}
	insights := map[string]captureInsight{
		"LVM": {Check: "LVM", Level: "WARN", Message: "thin pool pve/data 92% full"},
	}
	row := buildFixtureRow(c, insights)
	if row.RawJSON == "" {
		t.Fatal("buildFixtureRow dropped raw JSON for LVM check")
	}
	if !strings.Contains(row.RawJSON, `"data_pct":92.4`) {
		t.Errorf("preserved raw JSON missing thin pool data: %q", row.RawJSON)
	}
	if row.Level != "WARN" {
		t.Errorf("row level = %q, want WARN", row.Level)
	}
}

func TestBuildFixtureRow_IgnoresRawForNonDiskCheck(t *testing.T) {
	c := captureCheck{
		Name:   "CPU Load",
		Status: "OK",
		Raw:    json.RawMessage(`{"foo":1}`),
	}
	row := buildFixtureRow(c, map[string]captureInsight{})
	if row.RawJSON != "" {
		t.Errorf("non-disk check should not carry raw JSON, got %q", row.RawJSON)
	}
}

// TestMockReplayLVMWarn is an end-to-end check: a fixture carrying raw LVM data
// and a WARN row replays the WARN correctly through `dsd mock`.
func TestMockReplayLVMWarn(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess replay test in short mode")
	}
	fixture := "host: test-host\n" +
		"os: AlmaLinux 9.4\n" +
		"version: v0.6.1\n" +
		"rows:\n" +
		"  - name: LVM\n" +
		"    level: WARN\n" +
		"    message: \"thin pool pve/data 92% full — VMs freeze when full\"\n" +
		"    hints:\n" +
		"      - \"to fix: lvextend --size +50G pve/data\"\n" +
		"    raw: '" + lvmWarnJSON + "'\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "lvm-warn.yaml")
	if err := os.WriteFile(path, []byte(fixture), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	cmd := exec.Command("go", "run", "github.com/keyorixhq/dashdiag/cmd/dsd", "mock", path)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("dsd mock failed: %v\nstderr: %s", err, stderr.String())
	}

	out := stdout.String() + stderr.String()
	if !strings.Contains(out, "LVM") {
		t.Errorf("mock output missing LVM row:\n%s", out)
	}
	if !strings.Contains(out, "thin pool pve/data 92% full") {
		t.Errorf("mock output missing WARN message:\n%s", out)
	}
}
