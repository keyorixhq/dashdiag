package render

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// quietStdout runs f with os.Stdout redirected to /dev/null so renderer output
// (which writes directly to stdout) doesn't pollute test logs.
func quietStdout(t *testing.T, f func()) {
	t.Helper()
	old := os.Stdout
	dn, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = dn
	defer func() { os.Stdout = old; dn.Close() }()
	f()
}

func sampleResults() []runner.Result {
	return []runner.Result{
		{Name: "CPU Load", Data: models.CPUInfo{UsagePct: 95, LoadAvg1: 8, NumCPU: 4}},
		{Name: "Memory", Data: models.MemoryInfo{TotalGB: 16, UsedPct: 50}},
		{Name: "Disk", Data: models.DiskInfo{Filesystems: []models.FilesystemInfo{{Mount: "/", Device: "/dev/sda1", UsedPct: 92}}}},
		{Name: "Systemd", Data: models.SystemdInfo{Available: true}},
		// A collector that signals unavailable + no insight + no inline data → hidden row.
		{Name: "Ceph", Data: models.CephInfo{Available: false}},
	}
}

func sampleInsights() []models.Insight {
	return []models.Insight{
		{
			Level: "CRIT", Check: "CPU Load", Message: "95% CPU",
			Hints: []string{"to inspect: uptime", "to fix: kill the runaway process", "note: check top consumers"},
			Details: &models.Details{
				Type: "table", Title: "Top processes",
				Columns: []string{"PID", "CPU%", "CMD"},
				Rows:    [][]string{{"123", "80", "stress"}, {"456", "10", "node"}},
				KV:      map[string]string{"load": "8.0"},
				Note:    "sampled over 1s",
			},
		},
		{Level: "WARN", Check: "Disk", Message: "disk 92% on /", Hints: []string{"to inspect: df -h"}},
	}
}

func TestPrintAll_Modes(t *testing.T) {
	results, insights := sampleResults(), sampleInsights()
	for _, mode := range []output.OutputMode{output.ModeHuman, output.ModePlain} {
		r := NewRenderer(mode)
		quietStdout(t, func() {
			r.PrintAll(results, insights)
			r.PrintCorrelations(nil)
			r.PrintContainerBanner(platform.ContainerContext{InContainer: true})
		})
	}
}

func TestRenderJSONYAML(t *testing.T) {
	results, insights := sampleResults(), sampleInsights()
	j, err := RenderJSON(results, insights)
	if err != nil || len(j) == 0 {
		t.Fatalf("RenderJSON: err=%v len=%d", err, len(j))
	}
	y, err := RenderYAML(results, insights)
	if err != nil || len(y) == 0 {
		t.Fatalf("RenderYAML: err=%v len=%d", err, len(y))
	}
}

func snap(host string) *baseline.Snapshot {
	return &baseline.Snapshot{
		Hostname:  host,
		Version:   "v0.6.1",
		Timestamp: time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC),
		Checks: []baseline.CheckResult{
			{Name: "CPU Load", Status: "CRIT", Value: "95% CPU"},
			{Name: "Disk", Status: "WARN", Value: "disk 92%"},
		},
	}
}

func TestGenerateReport(t *testing.T) {
	out, err := GenerateReport(snap("host1"), sampleInsights(), 5*time.Second, nil)
	if err != nil || out == "" {
		t.Fatalf("GenerateReport: err=%v empty=%v", err, out == "")
	}
}

func TestRenderStoryAndPostMortem(t *testing.T) {
	s := snap("host1")
	if got := RenderStory(sampleInsights(), s); got == "" {
		t.Error("RenderStory returned empty")
	}
	// Single-point history and multi-point history take different code paths.
	if got := RenderStoryFromHistory([]*baseline.Snapshot{s}); got == "" {
		t.Error("RenderStoryFromHistory (single) returned empty")
	}
	if got := RenderStoryFromHistory([]*baseline.Snapshot{snap("h1"), snap("h2")}); got == "" {
		t.Error("RenderStoryFromHistory (multi) returned empty")
	}
	if got := RenderPostMortem("incident", s, sampleInsights(), output.ModeHuman); got == "" {
		t.Error("RenderPostMortem returned empty")
	}
}

func TestPrintDiff(t *testing.T) {
	before, after := snap("host1"), snap("host1")
	after.Checks[0].Status = "OK" // a change to render

	var human bytes.Buffer
	if err := PrintDiff(&human, before, after, output.ModeHuman); err != nil {
		t.Errorf("PrintDiff human: %v", err)
	}
	if human.Len() == 0 {
		t.Error("PrintDiff human wrote nothing")
	}

	// JSON mode must write exactly one valid JSON document to the given writer
	// (the caller routes this to stderr so stdout stays a single document).
	var jsonBuf bytes.Buffer
	if err := PrintDiff(&jsonBuf, before, after, output.ModeJSON); err != nil {
		t.Errorf("PrintDiff json: %v", err)
	}
	var entries []baseline.DiffEntry
	if err := json.Unmarshal(jsonBuf.Bytes(), &entries); err != nil {
		t.Errorf("PrintDiff json output is not a single valid JSON document: %v", err)
	}
}
