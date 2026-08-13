package drilldown

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
		Type:    tableProcesses,
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

// TestDispatch_MalformedCachedJSONReturnsNil guards the json.Unmarshal error
// branch in dispatch: a cached blob that isn't valid Details JSON (a corrupt
// bundle, or a schema mismatch from an older dsd version) must degrade to nil
// rather than propagating a decode error or panicking.
func TestDispatch_MalformedCachedJSONReturnsNil(t *testing.T) {
	ins := models.Insight{Level: "WARN", Check: "CPU Load", Message: "load high malformed"}
	key := "drilldown\x00" + ins.Check + "\x00" + ins.Message

	rec := source.NewRecorder(source.Live{})
	prev := collectors.SetSource(rec)
	if _, err := rec.Cached(key, func() ([]byte, error) { return []byte("{not valid json"), nil }); err != nil {
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
	if got != nil {
		t.Errorf("expected nil for malformed cached JSON, got %+v", got)
	}
}

// TestDispatchSanitizesReplayedControlChars guards Finding internal-drilldown-01-02:
// a capture bundle is untrusted input (docs/THREAT_MODEL.md §1) and its
// drilldown\x00... cache entries are json.Unmarshal'd straight into
// *models.Details with no shape/content validation elsewhere in the replay
// path. A hand-crafted bundle whose cached Details carries raw ANSI/OSC
// escape bytes in Title/Note/Rows/KV must NOT reach dispatch()'s caller
// verbatim — dispatch is the single funnel every drill-down source (live or
// replayed) returns through.
func TestDispatchSanitizesReplayedControlChars(t *testing.T) {
	ins := models.Insight{Level: "WARN", Check: "CPU Load", Message: "load high evil"}
	key := "drilldown\x00" + ins.Check + "\x00" + ins.Message
	evil := "\x1b[2J\x1b]0;pwned\x07evilname"
	want := &models.Details{
		Type:    tableProcesses,
		Title:   "Top processes by CPU% " + evil,
		Columns: []string{"PID", "CPU%", "COMMAND"},
		Rows:    [][]string{{"4242", "99.9%", evil}},
		KV:      map[string]string{"log_tail": evil},
		Note:    "note " + evil,
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
	if got == nil {
		t.Fatal("expected non-nil replayed Details")
	}
	if strings.ContainsAny(got.Title, "\x1b\x07") {
		t.Errorf("Title still contains raw control bytes: %q", got.Title)
	}
	if strings.ContainsAny(got.Note, "\x1b\x07") {
		t.Errorf("Note still contains raw control bytes: %q", got.Note)
	}
	if strings.ContainsAny(got.Rows[0][2], "\x1b\x07") {
		t.Errorf("Rows still contain raw control bytes: %q", got.Rows[0][2])
	}
	if strings.ContainsAny(got.KV["log_tail"], "\x1b\x07") {
		t.Errorf("KV still contains raw control bytes: %q", got.KV["log_tail"])
	}
	// The printable payload itself must survive — sanitizing strips control
	// bytes, it must not mangle or drop the rest of the string.
	if !strings.Contains(got.Rows[0][2], "evilname") {
		t.Errorf("expected printable text to survive sanitization, got %q", got.Rows[0][2])
	}
}

// TestSanitizeDetails_StripsAllFields is a direct unit test of the shared
// helper every drill-down entry point wraps its return value in: control
// characters (including ESC, the start of ANSI/OSC/DCS sequences) must be
// stripped from Title, Note, every Row cell, and KV keys/values, while
// leaving nil untouched and ordinary printable text unchanged.
func TestSanitizeDetails_StripsAllFields(t *testing.T) {
	t.Parallel()
	if got := sanitizeDetails(nil); got != nil {
		t.Errorf("sanitizeDetails(nil) = %+v, want nil", got)
	}

	d := &models.Details{
		Title: "Title\x1b[31m",
		Note:  "Note\x07bell",
		Rows:  [][]string{{"1", "proc\x1bname"}},
		KV:    map[string]string{"k\x1b": "v\x1b"},
	}
	got := sanitizeDetails(d)
	if strings.ContainsAny(got.Title, "\x1b\x07") {
		t.Errorf("Title not sanitized: %q", got.Title)
	}
	if strings.ContainsAny(got.Note, "\x1b\x07") {
		t.Errorf("Note not sanitized: %q", got.Note)
	}
	if strings.ContainsAny(got.Rows[0][1], "\x1b\x07") {
		t.Errorf("Row cell not sanitized: %q", got.Rows[0][1])
	}
	for k, v := range got.KV {
		if strings.ContainsAny(k, "\x1b\x07") || strings.ContainsAny(v, "\x1b\x07") {
			t.Errorf("KV entry not sanitized: %q=%q", k, v)
		}
	}
	if !strings.Contains(got.Title, "Title") || !strings.Contains(got.Rows[0][1], "procname") {
		t.Errorf("printable text was mangled, got Title=%q Row=%q", got.Title, got.Rows[0][1])
	}
}

// TestProcComm_StripsControlChars guards Finding internal-drilldown-01-03:
// /proc/<pid>/comm is fully attacker-controlled (prctl(PR_SET_NAME) or a
// truncated argv[0]) and procComm's only prior defense was TrimSpace, which
// does not remove embedded ESC/control bytes.
func TestProcComm_StripsControlChars(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	const pid = 4242
	dir := filepath.Join(procRoot, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// ESC (0x1b) is the control byte that starts the CSI sequence; "[2J" itself
	// is ordinary printable text and SanitizeControl leaves it as-is — only
	// the ESC byte is a control rune and gets stripped.
	evil := "evil\x1b[2Jname\n"
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(evil), 0644); err != nil {
		t.Fatalf("WriteFile comm: %v", err)
	}

	got := procComm(procRoot, pid)
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("procComm() = %q, still contains ESC", got)
	}
	if got != "evil[2Jname" {
		t.Errorf("procComm() = %q, want %q", got, "evil[2Jname")
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
	if got.Type != tableProcesses {
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

// TestZombiesFromResults_ParentNameWithSlashIsBasenamed guards the
// LastIndexByte(parentName, '/') branch: a ParentName carrying a full path
// (as some collectors/platforms may report) must be reduced to its base name
// so it doesn't break the table's column formatting.
func TestZombiesFromResults_ParentNameWithSlashIsBasenamed(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "Processes", Data: &models.ProcessInfo{
			ZombieProcs: []models.ProcessState{
				{PID: 302, PPID: 2, ParentName: "/usr/lib/systemd/systemd"},
			},
		}},
	}
	got := zombiesFromResults(results)
	if got == nil || len(got.Rows) != 1 {
		t.Fatalf("expected 1 row, got %+v", got)
	}
	if got.Rows[0][2] != "systemd" {
		t.Errorf("expected ParentName reduced to base name %q, got %q", "systemd", got.Rows[0][2])
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
	if got.Type != tableProcesses {
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

// TestHungProcessesFromResults_SkipsNonMatchingResultFirst guards the
// `r.Name != "Processes" { continue }` loop branch: a non-matching result
// entry preceding the real Processes entry must be skipped, not cause an
// early wrong return.
func TestHungProcessesFromResults_SkipsNonMatchingResultFirst(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "Memory", Data: nil},
		{Name: "Processes", Data: &models.ProcessInfo{
			HungProcs: []models.ProcessState{
				{PID: 401, Name: "stuckproc2", PPID: 1, WChan: "io_wait"},
			},
		}},
	}
	got := hungProcessesFromResults(results)
	if got == nil || len(got.Rows) != 1 || got.Rows[0][0] != "401" {
		t.Errorf("expected the Processes entry to be found after skipping Memory, got %+v", got)
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

// TestHardeningFromResults_SkipsNonMatchingResultFirst guards the
// `r.Name != "Hardening" { continue }` loop branch: a non-matching result
// entry preceding the real Hardening entry must be skipped, not cause an
// early wrong return.
func TestHardeningFromResults_SkipsNonMatchingResultFirst(t *testing.T) {
	t.Parallel()
	results := []runner.Result{
		{Name: "Memory", Data: nil},
		{Name: "Hardening", Data: &models.SecurityInfo{
			ListeningPorts: []models.PortEntry{{Port: 31337, Protocol: "tcp", Process: "evil", Expected: false}},
		}},
	}
	got := hardeningFromResults(results, "unexpected port 31337 listening")
	if got == nil || len(got.Rows) != 1 || got.Rows[0][0] != "31337" {
		t.Errorf("expected the Hardening entry to be found after skipping Memory, got %+v", got)
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

// TestDispatchLive_AllChecks exercises every switch arm in dispatchLive so
// each Check name is proven to route to its drill-down function (not just
// exercised transitively via the individual _test.go files for each
// sub-collector). runCmd/lookPath are swapped to "nothing installed" so every
// branch degrades quickly and deterministically instead of depending on the
// container's actual tooling — this test only cares that dispatch happens,
// not what a real host would return. No t.Parallel(): swapRunCmd/swapLookPath
// mutate shared package state (see runcmd_helper_test.go's doc comment).
func TestDispatchLive_AllChecks(t *testing.T) {
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		return "", errNotFound
	})
	swapLookPath(t, func(string) (string, error) {
		return "", errNotFound
	})

	cases := []struct {
		name string
		ins  models.Insight
	}{
		{"Memory", models.Insight{Check: "Memory", Message: "RAM at 96%"}},
		{"Memory/Slab", models.Insight{Check: "Memory/Slab", Message: "slab high"}},
		{"CPU Load", models.Insight{Check: "CPU Load", Message: "load high"}},
		{"Swap", models.Insight{Check: "Swap", Message: "swap high"}},
		{"Disk", models.Insight{Check: "Disk", Message: "disk usage at 91% on /var (/dev/sda1)"}},
		{"IO", models.Insight{Check: "IO", Message: "await high"}},
		{"Network plain", models.Insight{Check: "Network", Message: "gateway ping is 250 ms"}},
		{"Network USB excluded", models.Insight{Check: "Network", Message: "USB NIC not responding"}},
		{"Network Wi-Fi excluded", models.Insight{Check: "Network", Message: "Wi-Fi link flapping"}},
		{"Network wireless excluded", models.Insight{Check: "Network", Message: "wireless signal weak"}},
		{"Network not-responding excluded", models.Insight{Check: "Network", Message: "gateway not responding"}},
		{"Processes hung", models.Insight{Check: "Processes", Message: "3 hung processes in uninterruptible sleep"}},
		{"Processes zombies", models.Insight{Check: "Processes", Message: "5 zombie processes"}},
		{"Systemd", models.Insight{Check: "Systemd", Message: "unit foo.service has failed"}},
		{"FDLimits", models.Insight{Check: "FDLimits", Message: "fd usage high"}},
		{"Clock", models.Insight{Check: "Clock", Message: "clock drift"}},
		{"Sysctl", models.Insight{Check: "Sysctl", Message: "vm.swappiness not recommended"}},
		{"SELinux", models.Insight{Check: "SELinux", Message: "policy not enforcing"}},
		{"KernelSec", models.Insight{Check: "KernelSec", Message: "policy not enforcing"}},
		{"Hardening", models.Insight{Check: "Hardening", Message: "unexpected port 31337 listening"}},
		{"unknown check", models.Insight{Check: "TotallyUnknown", Message: "n/a"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Should never panic regardless of what the fake tooling returns.
			_ = dispatchLive(context.Background(), tc.ins, nil)
		})
	}
}

// TestDispatchLive_ProcessesResultsShortCircuit guards the Processes branches
// that prefer already-captured results (hungProcessesFromResults /
// zombiesFromResults) over a fresh /proc scan: when results carry a non-empty
// table, dispatchLive must return it directly rather than falling through to
// HungProcesses/ZombiesWithParent.
func TestDispatchLive_ProcessesResultsShortCircuit(t *testing.T) {
	swapRunCmd(t, func(context.Context, string, ...string) (string, error) {
		t.Fatal("no subprocess should run when results already supply the table")
		return "", nil
	})

	hungResults := []runner.Result{
		{Name: "Processes", Data: &models.ProcessInfo{
			HungProcs: []models.ProcessState{{PID: 1, Name: "stuck", PPID: 1, WChan: "io_wait"}},
		}},
	}
	got := dispatchLive(context.Background(), models.Insight{Check: "Processes", Message: "hung process detected"}, hungResults)
	if got == nil || got.Title != "Hung (uninterruptible) processes" {
		t.Errorf("expected the from-results hung table, got %+v", got)
	}

	zombieResults := []runner.Result{
		{Name: "Processes", Data: &models.ProcessInfo{
			ZombieProcs: []models.ProcessState{{PID: 2, PPID: 1, ParentName: "init"}},
		}},
	}
	got = dispatchLive(context.Background(), models.Insight{Check: "Processes", Message: "zombie process detected"}, zombieResults)
	if got == nil || got.Title != "Zombie processes (parent is the reaping offender)" {
		t.Errorf("expected the from-results zombie table, got %+v", got)
	}
}

// TestDispatchLive_HardeningNilData exercises the Hardening branch through
// dispatchLive end-to-end (not just hardeningFromResults directly, which
// TestHardeningFromResults_NilData already covers): a nil-interface
// SecurityInfo must yield a nil Details rather than a crash.
func TestDispatchLive_HardeningNilData(t *testing.T) {
	results := []runner.Result{
		{Name: "Hardening", Data: (*models.SecurityInfo)(nil)},
	}
	got := dispatchLive(context.Background(), models.Insight{Check: "Hardening", Message: "unexpected port 22 listening"}, results)
	if got != nil {
		t.Errorf("expected nil Details, got %+v", got)
	}
}

// TestWalkProcs_NonPermissionFnErrorSkipped guards the `err != nil &&
// !os.IsPermission(err) { return nil }` branch: every real caller's fn always
// returns nil internally (they encode failures as "skip, don't propagate"),
// so this asserts walkProcs's OWN defensive handling directly — a fn that
// returns a genuine, non-permission error for one PID must not fail the
// whole walk or propagate that error through g.Wait(), matching the "/proc
// entries vanish" comment on that line.
func TestWalkProcs_NonPermissionFnErrorSkipped(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(procRoot, "111"), 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	err := walkProcs(context.Background(), procRoot, func(pid int) error {
		return fmt.Errorf("synthetic non-permission failure for pid %d", pid)
	})
	if err != nil {
		t.Errorf("expected walkProcs to swallow a non-permission fn error, got %v", err)
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
