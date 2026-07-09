package drilldown

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestDispatchReplaysCachedDetails guards drill-down replay hermeticity: the
// drill-downs read live /proc (often a two-sample timing delta, e.g. top-CPU%),
// so under `dsd replay` they must NOT re-read the replaying machine — the derived
// *Details is routed through Source.Cached and replayed verbatim. We seed a known
// table under the exact dispatch key during capture, then replay with a CANCELLED
// ctx and nil results — a live recompute would read /proc / bail to nil, so a
// returned table proves the value came from the cache, not a re-run.
func TestDispatchReplaysCachedDetails(t *testing.T) {
	ins := models.Insight{Level: "WARN", Check: "CPU Load", Message: "load high"}
	key := "drilldown\x00" + ins.Check + "\x00" + ins.Message
	want := &models.Details{
		Type:    "process_table",
		Title:   "Top processes by CPU%",
		Columns: []string{"PID", "CPU%", "COMMAND"},
		Rows:    [][]string{{"4242", "99.9%", "busy"}},
	}
	blob, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	rec := source.NewRecorder(source.Live{})
	prev := collectors.SetSource(rec)
	if _, err := rec.Cached(key, func() ([]byte, error) { return blob, nil }); err != nil {
		collectors.SetSource(prev)
		t.Fatalf("seeding cached drilldown: %v", err)
	}
	collectors.SetSource(prev)

	rp := source.NewReplay(rec.Bundle())
	restore := collectors.SetSource(rp)
	defer collectors.SetSource(restore)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := dispatch(ctx, ins, nil)
	if got == nil || len(got.Rows) != 1 || got.Rows[0][0] != "4242" {
		t.Fatalf("dispatch did not replay the cached drill-down details (live re-read leaked?): %+v", got)
	}
}

func TestPopulateAll_OKInsightsUnchanged(t *testing.T) {
	ins := []models.Insight{
		{Level: "OK", Check: "CPU Load", Message: "all good"},
		{Level: "OK", Check: "Memory", Message: "all good"},
	}
	ctx := context.Background()
	got := PopulateAll(ctx, ins, nil)
	for _, i := range got {
		if i.Details != nil {
			t.Errorf("OK insight %q got unexpected Details", i.Check)
		}
	}
}

func TestPopulateAll_UnknownCheckPassesThrough(t *testing.T) {
	ins := []models.Insight{
		{Level: "WARN", Check: "UnknownCheck", Message: "something weird"},
	}
	ctx := context.Background()
	got := PopulateAll(ctx, ins, nil)
	if got[0].Details != nil {
		t.Errorf("unknown check should have nil Details, got %+v", got[0].Details)
	}
}

func TestPopulateAll_CancelledContextNocrash(t *testing.T) {
	ins := []models.Insight{
		{Level: "CRIT", Check: "Memory", Message: "RAM at 96%"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled
	// Should not panic or hang
	_ = PopulateAll(ctx, ins, nil)
}

func TestPopulateAll_MultipleWARNCRIT(t *testing.T) {
	ins := []models.Insight{
		{Level: "OK", Check: "CPU Load", Message: "fine"},
		{Level: "WARN", Check: "UnknownA", Message: "warn"},
		{Level: "CRIT", Check: "UnknownB", Message: "crit"},
	}
	ctx := context.Background()
	got := PopulateAll(ctx, ins, nil)
	if got[0].Level != "OK" {
		t.Error("first insight should still be OK")
	}
	// UnknownA and UnknownB should have nil Details (no dispatcher entry)
	if got[1].Details != nil || got[2].Details != nil {
		t.Error("unknown checks should produce nil Details")
	}
}

func TestPopulateAll_ResultsPassedThrough(t *testing.T) {
	results := []runner.Result{
		{Name: "Network", Data: nil},
	}
	ins := []models.Insight{
		{Level: "WARN", Check: "Network", Message: "gateway ping is 250 ms"},
	}
	ctx := context.Background()
	// Should not panic even if the Network drilldown finds no ss/netstat
	_ = PopulateAll(ctx, ins, results)
}

func TestParseMountFromMessage(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"disk usage at 85% on / (/dev/sda1)", "/"},
		{"disk usage at 85% on /var (/dev/sdb1)", "/var"},
		{"disk usage at 90% on /data/logs (/dev/sdc)", "/data/logs"},
		{"inode usage at 90% on /home", "/home"},
		{"something unrelated", "/"},
	}
	for _, c := range cases {
		got := parseMountFromMessage(c.msg)
		if got != c.want {
			t.Errorf("parseMountFromMessage(%q) = %q, want %q", c.msg, got, c.want)
		}
	}
}

func TestParseUnitFromMessage(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"unit foo.service has failed", "foo.service"},
		{"unit nginx.service has failed", "nginx.service"},
		{"unrelated message", ""},
	}
	for _, c := range cases {
		got := parseUnitFromMessage(c.msg)
		if got != c.want {
			t.Errorf("parseUnitFromMessage(%q) = %q, want %q", c.msg, got, c.want)
		}
	}
}

func TestZombiesFromResults_HappyPath(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "Processes", Data: &models.ProcessInfo{
			ZombieProcs: []models.ProcessState{
				{PID: 300, PPID: 50, Name: "deadproc", ParentName: "systemd"},
			},
		}},
	}
	got := zombiesFromResults(results)
	if got == nil {
		t.Fatal("expected non-nil Details")
	}
	if got.Type != "process_table" {
		t.Errorf("unexpected Type: %q", got.Type)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	want := []string{"300", "50", "systemd"}
	for i, w := range want {
		if got.Rows[0][i] != w {
			t.Errorf("row[%d] = %q, want %q (full row: %+v)", i, got.Rows[0][i], w, got.Rows[0])
		}
	}
}

// TestZombiesFromResults_ParentNameFallsBackToProc guards the ParentName=="" ->
// procComm("/proc", PPID) fallback branch (real /proc read for PID 1, which
// always exists in the test container).
func TestZombiesFromResults_ParentNameFallsBackToProc(t *testing.T) {
	results := []runner.Result{
		{Name: "Processes", Data: &models.ProcessInfo{
			ZombieProcs: []models.ProcessState{
				{PID: 301, PPID: 1, Name: "deadproc"}, // ParentName empty
			},
		}},
	}
	got := zombiesFromResults(results)
	if got == nil || len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %+v", got)
	}
	if got.Rows[0][2] == "" {
		t.Errorf("expected parent name fallback to /proc/1/comm to produce a non-empty name, got %+v", got.Rows[0])
	}
}

func TestZombiesFromResults_NoProcessesResult(t *testing.T) {
	t.Parallel()
	if got := zombiesFromResults(nil); got != nil {
		t.Errorf("expected nil with no Processes result, got %+v", got)
	}
	if got := zombiesFromResults([]runner.Result{{Name: "Memory", Data: nil}}); got != nil {
		t.Errorf("expected nil when Processes result is absent, got %+v", got)
	}
}

func TestZombiesFromResults_EmptyZombiesReturnsNil(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "Processes", Data: &models.ProcessInfo{ZombieProcs: nil}},
	}
	if got := zombiesFromResults(results); got != nil {
		t.Errorf("expected nil when ZombieProcs is empty, got %+v", got)
	}
}

func TestZombiesFromResults_WrongDataType(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "Processes", Data: "not a ProcessInfo"},
	}
	if got := zombiesFromResults(results); got != nil {
		t.Errorf("expected nil for a type-assertion mismatch, got %+v", got)
	}
}

func TestHungProcessesFromResults_HappyPath(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "Processes", Data: &models.ProcessInfo{
			HungProcs: []models.ProcessState{
				{PID: 400, Name: "stuckproc", PPID: 1, WChan: "wait_on_page_bit"},
			},
		}},
	}
	got := hungProcessesFromResults(results)
	if got == nil {
		t.Fatal("expected non-nil Details")
	}
	if got.Type != "process_table" {
		t.Errorf("unexpected Type: %q", got.Type)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(got.Rows), got.Rows)
	}
	want := []string{"400", "stuckproc", "1", "wait_on_page_bit"}
	for i, w := range want {
		if got.Rows[0][i] != w {
			t.Errorf("row[%d] = %q, want %q (full row: %+v)", i, got.Rows[0][i], w, got.Rows[0])
		}
	}
}

func TestHungProcessesFromResults_NoProcessesResult(t *testing.T) {
	t.Parallel()
	if got := hungProcessesFromResults(nil); got != nil {
		t.Errorf("expected nil with no Processes result, got %+v", got)
	}
}

func TestHungProcessesFromResults_EmptyHungReturnsNil(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "Processes", Data: &models.ProcessInfo{HungProcs: nil}},
	}
	if got := hungProcessesFromResults(results); got != nil {
		t.Errorf("expected nil when HungProcs is empty, got %+v", got)
	}
}

func TestHungProcessesFromResults_WrongDataType(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "Processes", Data: 42},
	}
	if got := hungProcessesFromResults(results); got != nil {
		t.Errorf("expected nil for a type-assertion mismatch, got %+v", got)
	}
}

func TestHardeningFromResults_UnexpectedPorts(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "Hardening", Data: &models.SecurityInfo{
			ListeningPorts: []models.PortEntry{
				{Port: 22, Protocol: "tcp", Process: "sshd", Expected: true},
				{Port: 31337, Protocol: "tcp", Process: "backdoor", Expected: false},
			},
		}},
	}
	got := hardeningFromResults(results, "unexpected port 31337 listening")
	if got == nil {
		t.Fatal("expected non-nil Details for an unexpected-port message")
	}
	if len(got.Rows) != 1 || got.Rows[0][0] != "31337" {
		t.Errorf("expected only the unexpected port row, got %+v", got.Rows)
	}
}

func TestHardeningFromResults_UnexpectedPortsNeedRootNote(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "Hardening", Data: &models.SecurityInfo{
			PortsNeedRoot: true,
			ListeningPorts: []models.PortEntry{
				{Port: 9999, Protocol: "tcp", Process: "", Expected: false},
			},
		}},
	}
	got := hardeningFromResults(results, "unexpected port 9999 listening")
	if got == nil {
		t.Fatal("expected non-nil Details")
	}
	if got.Note == "" {
		t.Error("expected a run-as-root note when PortsNeedRoot is true")
	}
}

func TestHardeningFromResults_FailedLogins(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "Hardening", Data: &models.SecurityInfo{
			FailedLoginIPs: []string{"1.2.3.4 (10)", "5.6.7.8 (3)"},
		}},
	}
	got := hardeningFromResults(results, "5 failed login attempts detected")
	if got == nil {
		t.Fatal("expected non-nil Details for a failed-login message")
	}
	if len(got.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %d: %+v", len(got.Rows), got.Rows)
	}
}

func TestHardeningFromResults_NoMatchingMessageReturnsNil(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "Hardening", Data: &models.SecurityInfo{
			ListeningPorts: []models.PortEntry{{Port: 22, Expected: true}},
		}},
	}
	got := hardeningFromResults(results, "some unrelated hardening message")
	if got != nil {
		t.Errorf("expected nil when the message matches neither known branch, got %+v", got)
	}
}

func TestHardeningFromResults_NoHardeningResult(t *testing.T) {
	t.Parallel()
	if got := hardeningFromResults(nil, "unexpected port 22 listening"); got != nil {
		t.Errorf("expected nil with no Hardening result, got %+v", got)
	}
}

func TestHardeningFromResults_NilData(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "Hardening", Data: (*models.SecurityInfo)(nil)},
	}
	if got := hardeningFromResults(results, "unexpected port 22 listening"); got != nil {
		t.Errorf("expected nil for nil SecurityInfo data, got %+v", got)
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{512, "512B"},
		{1500, "1.5KB"},
		{2 * 1024 * 1024, "2.0MB"},
		{3 * 1024 * 1024 * 1024, "3.0GB"},
	}
	for _, c := range cases {
		got := formatBytes(c.in)
		if got != c.want {
			t.Errorf("formatBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
