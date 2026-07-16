package render

import (
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
