package render

import (
	"html/template"
	"os"
	"strings"
	"testing"
)

func TestBuildWaveHTML_Structure(t *testing.T) {
	t.Parallel()
	report := WaveReport{
		Date:         "2026-07-16 12:00:00 UTC",
		Version:      "v1.19.1",
		Verdict:      "FAIL",
		VerdictClass: "crit",
		VerdictText:  "1 pair(s) failed certification — regressions detected.",
		Total:        3,
		CountPass:    1,
		CountWarn:    1,
		CountFail:    1,
		Year:         2026,
		Pairs: []WavePairRow{
			{Source: "vm01-src", SourceOS: "Ubuntu 24.04", Destination: "vm01-dst", DestOS: "Ubuntu 24.04", Verdict: "PASS", VerdictClass: "ok"},
			{Source: "vm02-src", SourceOS: "Ubuntu 22.04", Destination: "vm02-dst", DestOS: "Ubuntu 22.04", Verdict: "PASS-WITH-WARNINGS", VerdictClass: "warn", RegressionCount: 1, TopRegression: "Memory"},
			{Source: "vm03-src", Destination: "vm03-dst", Verdict: "FAIL", VerdictClass: "crit", RegressionCount: 2, TopRegression: "Disk"},
		},
	}

	html, err := buildWaveHTML(report)
	if err != nil {
		t.Fatalf("buildWaveHTML error: %v", err)
	}

	for _, want := range []string{
		"Migration Wave Certification",
		"vm01-src",
		"vm02-dst",
		"PASS",
		"PASS-WITH-WARNINGS",
		"FAIL",
		"Ubuntu 24.04",
		"Disk",
		"DashDiag",
		"v1.19.1",
		"Certification Results",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("expected %q in wave HTML output", want)
		}
	}
}

func TestBuildWaveHTML_AllPass(t *testing.T) {
	t.Parallel()
	report := WaveReport{
		Date:         "2026-07-16 12:00:00 UTC",
		Version:      "v1.19.1",
		Verdict:      "PASS",
		VerdictClass: "ok",
		VerdictText:  "All pairs passed certification — the migration wave is clean.",
		Total:        2,
		CountPass:    2,
		Year:         2026,
		Pairs: []WavePairRow{
			{Source: "vm01-src", Destination: "vm01-dst", Verdict: "PASS", VerdictClass: "ok"},
			{Source: "vm02-src", Destination: "vm02-dst", Verdict: "PASS", VerdictClass: "ok"},
		},
	}

	html, err := buildWaveHTML(report)
	if err != nil {
		t.Fatalf("buildWaveHTML error: %v", err)
	}
	if !strings.Contains(html, "All pairs passed certification") {
		t.Errorf("expected clean verdict text in wave HTML")
	}
}

func TestBuildWaveHTML_WithError(t *testing.T) {
	t.Parallel()
	report := WaveReport{
		Date:         "2026-07-16 12:00:00 UTC",
		Version:      "v1.19.1",
		Verdict:      "FAIL",
		VerdictClass: "crit",
		VerdictText:  "1 pair(s) failed certification — regressions detected.",
		Total:        1,
		CountFail:    1,
		Year:         2026,
		Pairs: []WavePairRow{
			{Source: "vm01-src", Destination: "", Verdict: "FAIL", VerdictClass: "error", Error: "loading destination: not found"},
		},
	}

	html, err := buildWaveHTML(report)
	if err != nil {
		t.Fatalf("buildWaveHTML error: %v", err)
	}
	if !strings.Contains(html, "loading destination: not found") {
		t.Errorf("expected error message in wave HTML output")
	}
}

func TestBuildWaveHTML_NamedWave(t *testing.T) {
	t.Parallel()
	report := WaveReport{
		Name:         "Acme Corp July Wave",
		Date:         "2026-07-16 12:00:00 UTC",
		Version:      "v1.19.1",
		Verdict:      "PASS",
		VerdictClass: "ok",
		VerdictText:  "All pairs passed certification — the migration wave is clean.",
		Total:        1,
		CountPass:    1,
		Year:         2026,
		Pairs:        []WavePairRow{{Source: "vm01-src", Destination: "vm01-dst", Verdict: "PASS", VerdictClass: "ok"}},
	}

	html, err := buildWaveHTML(report)
	if err != nil {
		t.Fatalf("buildWaveHTML error: %v", err)
	}
	if !strings.Contains(html, "Acme Corp July Wave") {
		t.Errorf("expected wave name in HTML output")
	}
}

func TestBuildWaveHTML_YearZero(t *testing.T) {
	t.Parallel()
	// Year intentionally zero — buildWaveHTML should fill it from time.Now().
	report := WaveReport{
		Date: "2026-07-16 12:00:00 UTC", Version: "v1.19.1",
		Verdict: "PASS", VerdictClass: "ok",
		VerdictText: "All pairs passed certification — the migration wave is clean.",
		Total:       1, CountPass: 1,
		Pairs: []WavePairRow{{Source: "vm01-src", Destination: "vm01-dst", Verdict: "PASS", VerdictClass: "ok"}},
	}
	html, err := buildWaveHTML(report)
	if err != nil {
		t.Fatalf("buildWaveHTML error: %v", err)
	}
	if !strings.Contains(html, "All pairs passed certification") {
		t.Errorf("expected verdict text in wave HTML output")
	}
}

func TestGenerateWaveHTMLReport(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	report := WaveReport{
		Date: "2026-07-16 12:00:00 UTC", Version: "v1.19.1",
		Verdict: "PASS", VerdictClass: "ok",
		VerdictText: "All pairs passed certification — the migration wave is clean.",
		Total:       1, CountPass: 1, Year: 2026,
		Pairs: []WavePairRow{{Source: "vm01-src", Destination: "vm01-dst", Verdict: "PASS", VerdictClass: "ok"}},
	}
	path, err := GenerateWaveHTMLReport(report)
	if err != nil {
		t.Fatalf("GenerateWaveHTMLReport error: %v", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("report file not created at %q: %v", path, statErr)
	}
}

// TestBuildWaveHTML_TemplateExecuteError covers the template.Execute error branch
// in buildWaveHTML. Not parallel — swaps the package-level waveHTMLTmpl.
func TestBuildWaveHTML_TemplateExecuteError(t *testing.T) {
	orig := waveHTMLTmpl
	waveHTMLTmpl = template.Must(template.New("bad").Parse(`{{template "missing" .}}`))
	defer func() { waveHTMLTmpl = orig }()

	report := WaveReport{Year: 2026, Pairs: []WavePairRow{{Source: "s", Destination: "d", Verdict: "PASS", VerdictClass: "ok"}}}
	if _, err := buildWaveHTML(report); err == nil {
		t.Error("expected error from broken template, got nil")
	}
}

// TestGenerateWaveHTMLReport_BuildError covers the buildWaveHTML error
// propagation path inside GenerateWaveHTMLReport. Not parallel — swaps waveHTMLTmpl.
func TestGenerateWaveHTMLReport_BuildError(t *testing.T) {
	orig := waveHTMLTmpl
	waveHTMLTmpl = template.Must(template.New("bad").Parse(`{{template "missing" .}}`))
	defer func() { waveHTMLTmpl = orig }()

	report := WaveReport{Year: 2026, Pairs: []WavePairRow{{Source: "s", Destination: "d", Verdict: "PASS", VerdictClass: "ok"}}}
	if _, err := GenerateWaveHTMLReport(report); err == nil {
		t.Error("expected error when template execution fails, got nil")
	}
}

// TestGenerateWaveHTMLReport_WriteFails covers the os.WriteFile error branch by
// making the CWD read-only. Skips as root (root ignores permission bits).
func TestGenerateWaveHTMLReport_WriteFails(t *testing.T) {
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	if f, createErr := os.CreateTemp(dir, "rootcheck-*"); createErr == nil {
		f.Close()
		_ = os.Remove(f.Name())
		t.Skip("running as root; directory-permission restriction cannot be triggered")
	}

	report := WaveReport{
		Date: "2026-07-17 12:00:00 UTC", Version: "v1.19.1",
		Verdict: "PASS", VerdictClass: "ok",
		VerdictText: "All pairs passed certification — the migration wave is clean.",
		Total:       1, CountPass: 1, Year: 2026,
		Pairs: []WavePairRow{{Source: "vm01-src", Destination: "vm01-dst", Verdict: "PASS", VerdictClass: "ok"}},
	}
	if _, err := GenerateWaveHTMLReport(report); err == nil {
		t.Error("expected error writing to read-only directory")
	}
}

func TestBuildWaveHTML_Branded(t *testing.T) {
	prev := brandOverride
	SetBrand(Brand{Company: "Acme MSP"})
	defer SetBrand(prev)

	report := WaveReport{
		Date:         "2026-07-16 12:00:00 UTC",
		Version:      "v1.19.1",
		Verdict:      "PASS",
		VerdictClass: "ok",
		VerdictText:  "All pairs passed certification — the migration wave is clean.",
		Total:        1,
		CountPass:    1,
		Year:         2026,
		Pairs:        []WavePairRow{{Source: "vm01-src", Destination: "vm01-dst", Verdict: "PASS", VerdictClass: "ok"}},
	}

	html, err := buildWaveHTML(report)
	if err != nil {
		t.Fatalf("buildWaveHTML error: %v", err)
	}
	if !strings.Contains(html, "Acme MSP") {
		t.Errorf("branded wave report should contain company name")
	}
	if !strings.Contains(html, "powered by") {
		t.Errorf("branded wave report should retain DashDiag attribution")
	}
}
