package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/render"
)

func TestResolvePairs_Args(t *testing.T) {
	t.Parallel()
	pairs, err := resolvePairs([]string{"src1.tar.gz:dst1.tar.gz", "src2.tar.gz:dst2.tar.gz"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}
	if pairs[0].Src != "src1.tar.gz" || pairs[0].Dst != "dst1.tar.gz" {
		t.Errorf("pair 0 mismatch: %+v", pairs[0])
	}
	if pairs[1].Src != "src2.tar.gz" || pairs[1].Dst != "dst2.tar.gz" {
		t.Errorf("pair 1 mismatch: %+v", pairs[1])
	}
}

func TestResolvePairs_File(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := filepath.Join(dir, "pairs.txt")
	content := "# comment\n/path/to/src1.tar.gz /path/to/dst1.tar.gz\n\n/path/src2.tar.gz /path/dst2.tar.gz\n"
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	pairs, err := resolvePairs(nil, f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}
	if pairs[0].Src != "/path/to/src1.tar.gz" {
		t.Errorf("unexpected src: %q", pairs[0].Src)
	}
}

func TestResolvePairs_BadArg(t *testing.T) {
	t.Parallel()
	_, err := resolvePairs([]string{"no-colon-here"}, "")
	if err == nil {
		t.Fatal("expected error for arg without colon separator")
	}
}

func TestResolvePairs_BadFileLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := filepath.Join(dir, "pairs.txt")
	if err := os.WriteFile(f, []byte("only-one-field\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := resolvePairs(nil, f)
	if err == nil {
		t.Fatal("expected error for line with only one field")
	}
}

func TestWaveWorstVerdict(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		results []waveResult
		want    string
	}{
		{"all pass", []waveResult{{Verdict: certPass}, {Verdict: certPass}}, certPass},
		{"any warn", []waveResult{{Verdict: certPass}, {Verdict: certWarn}}, certWarn},
		{"any fail", []waveResult{{Verdict: certWarn}, {Verdict: certFail}}, certFail},
		{"fail beats warn", []waveResult{{Verdict: certFail}, {Verdict: certWarn}}, certFail},
		{"empty", []waveResult{}, certPass},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := waveWorstVerdict(tc.results); got != tc.want {
				t.Errorf("waveWorstVerdict = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildWaveReport(t *testing.T) {
	t.Parallel()
	results := []waveResult{
		{
			Verdict:     certPass,
			Regressions: nil,
		},
		{
			Verdict:     certWarn,
			Regressions: []baseline.DiffEntry{{Name: "Memory", Before: "OK value", After: "WARN value"}},
		},
		{
			Verdict: certFail,
			Err:     nil,
			Regressions: []baseline.DiffEntry{
				{Name: "Disk", Before: "OK value", After: "CRIT value"},
				{Name: "Net", Before: "OK value", After: "WARN value"},
			},
		},
	}
	report := buildWaveReport(results, "Test Wave")
	if report.Name != "Test Wave" {
		t.Errorf("expected name 'Test Wave', got %q", report.Name)
	}
	if report.Verdict != certFail {
		t.Errorf("expected FAIL verdict, got %q", report.Verdict)
	}
	if report.VerdictClass != "crit" {
		t.Errorf("expected crit class, got %q", report.VerdictClass)
	}
	if report.Total != 3 {
		t.Errorf("expected total=3, got %d", report.Total)
	}
	if report.CountPass != 1 || report.CountWarn != 1 || report.CountFail != 1 {
		t.Errorf("count mismatch: pass=%d warn=%d fail=%d", report.CountPass, report.CountWarn, report.CountFail)
	}
	if len(report.Pairs) != 3 {
		t.Fatalf("expected 3 pair rows, got %d", len(report.Pairs))
	}
	// PASS row: no regressions, ok class
	if report.Pairs[0].VerdictClass != "ok" || report.Pairs[0].RegressionCount != 0 {
		t.Errorf("pair 0 mismatch: class=%q regressions=%d", report.Pairs[0].VerdictClass, report.Pairs[0].RegressionCount)
	}
	// WARN row: 1 regression, top = Memory
	if report.Pairs[1].RegressionCount != 1 || report.Pairs[1].TopRegression != "Memory" {
		t.Errorf("pair 1 mismatch: regressions=%d top=%q", report.Pairs[1].RegressionCount, report.Pairs[1].TopRegression)
	}
	// FAIL row: 2 regressions, top = Disk
	if report.Pairs[2].RegressionCount != 2 || report.Pairs[2].TopRegression != "Disk" {
		t.Errorf("pair 2 mismatch: regressions=%d top=%q", report.Pairs[2].RegressionCount, report.Pairs[2].TopRegression)
	}
}

func TestWaveVerdictClass(t *testing.T) {
	t.Parallel()
	tests := []struct{ verdict, want string }{
		{certPass, "ok"},
		{certWarn, "warn"},
		{certFail, "crit"},
		{"", "ok"},
	}
	for _, tc := range tests {
		if got := waveVerdictClass(tc.verdict); got != tc.want {
			t.Errorf("waveVerdictClass(%q) = %q, want %q", tc.verdict, got, tc.want)
		}
	}
}

func TestBuildWaveReport_WithError(t *testing.T) {
	t.Parallel()
	results := []waveResult{
		{Verdict: certFail, Err: fmt.Errorf("bundle not found")},
	}
	report := buildWaveReport(results, "")
	if len(report.Pairs) != 1 {
		t.Fatalf("expected 1 pair row, got %d", len(report.Pairs))
	}
	row := report.Pairs[0]
	if row.VerdictClass != "error" {
		t.Errorf("expected error class for errored pair, got %q", row.VerdictClass)
	}
	if row.Error == "" {
		t.Errorf("expected non-empty error on pair row")
	}
}

func TestPrintWaveTable_NoName(t *testing.T) {
	t.Parallel()
	results := []waveResult{
		{Verdict: certPass},
		{Verdict: certWarn},
		{Verdict: certFail},
	}
	// Just verify it doesn't panic — output goes to stdout.
	printWaveTable(results, "")
}

func TestPrintWaveTable_WithName(t *testing.T) {
	t.Parallel()
	printWaveTable([]waveResult{{Verdict: certPass}}, "Acme Corp Wave")
}

func TestEmitWaveJSON(t *testing.T) {
	t.Parallel()
	results := []waveResult{
		{Verdict: certPass, Regressions: nil},
		{
			Verdict:     certWarn,
			Regressions: []baseline.DiffEntry{{Name: "Memory", Before: "OK", After: "WARN"}},
		},
		{Verdict: certFail, Err: fmt.Errorf("bundle load failed")},
	}
	if err := emitWaveJSON(results, "Test Wave"); err != nil {
		t.Fatalf("emitWaveJSON returned error: %v", err)
	}
}

func TestEmitWaveJSON_AllPass(t *testing.T) {
	t.Parallel()
	results := []waveResult{{Verdict: certPass}, {Verdict: certPass}}
	if err := emitWaveJSON(results, ""); err != nil {
		t.Fatalf("emitWaveJSON returned error: %v", err)
	}
}

func TestCertifyPair_SrcNotFound(t *testing.T) {
	t.Parallel()
	p := wavePair{Src: "/nonexistent/src.tar.gz", Dst: "/nonexistent/dst.tar.gz"}
	r := certifyPair(p, false, false, false)
	if r.Verdict != certFail {
		t.Errorf("expected FAIL for missing src bundle, got %q", r.Verdict)
	}
	if r.Err == nil {
		t.Error("expected non-nil error for missing src bundle")
	}
}

func TestCertifyWave_SrcNotFound_Verbose(t *testing.T) {
	t.Parallel()
	pairs := []wavePair{
		{Src: "/nonexistent/src.tar.gz", Dst: "/nonexistent/dst.tar.gz"},
	}
	// quiet=false: exercises the stderr printing branch
	results := certifyWave(pairs, false, false, false, false)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verdict != certFail {
		t.Errorf("expected FAIL, got %q", results[0].Verdict)
	}
}

func TestCertifyWave_SrcNotFound_Quiet(t *testing.T) {
	t.Parallel()
	pairs := []wavePair{
		{Src: "/nonexistent/src.tar.gz", Dst: "/nonexistent/dst.tar.gz"},
	}
	// quiet=true: skips the stderr printing branch
	results := certifyWave(pairs, false, false, false, true)
	if len(results) != 1 || results[0].Verdict != certFail {
		t.Errorf("expected 1 FAIL result, got %v", results)
	}
}

// Verify WavePairRow and WaveReport are exported from the render package
// (compile-time check — no runtime assertions needed).
var _ render.WaveReport
var _ render.WavePairRow
