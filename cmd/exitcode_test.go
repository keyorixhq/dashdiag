package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestRecordExitCodeRaisesMonotonically(t *testing.T) {
	defer func() { pendingExitCode = 0 }()
	pendingExitCode = 0

	recordExitCode(1)
	if pendingExitCode != 1 {
		t.Fatalf("after WARN: got %d, want 1", pendingExitCode)
	}
	recordExitCode(2)
	if pendingExitCode != 2 {
		t.Fatalf("after CRIT: got %d, want 2", pendingExitCode)
	}
	// A lower code must not lower the recorded worst severity.
	recordExitCode(1)
	if pendingExitCode != 2 {
		t.Fatalf("WARN must not override CRIT: got %d, want 2", pendingExitCode)
	}
}

func TestRecordWorstInsight(t *testing.T) {
	cases := []struct {
		name     string
		insights []models.Insight
		want     int
	}{
		{"empty", nil, 0},
		{"info only", []models.Insight{{Level: "INFO"}}, 0},
		{"warn", []models.Insight{{Level: "INFO"}, {Level: "WARN"}}, 1},
		{"crit wins", []models.Insight{{Level: "WARN"}, {Level: "CRIT"}, {Level: "WARN"}}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pendingExitCode = 0
			defer func() { pendingExitCode = 0 }()
			recordWorstInsight(tc.insights)
			if pendingExitCode != tc.want {
				t.Errorf("got %d, want %d", pendingExitCode, tc.want)
			}
		})
	}
}

func TestRecordCVEResultSeverity(t *testing.T) {
	cases := []struct {
		name string
		r    *models.CVEResult
		want int
	}{
		{"nil", nil, 0},
		{"patched", &models.CVEResult{Status: models.CVEPatched}, 0},
		{"not affected", &models.CVEResult{Status: models.CVENotAffected}, 0},
		{"unknown stays quiet", &models.CVEResult{Status: models.CVEUnknown}, 0},
		{"vulnerable low → WARN", &models.CVEResult{Status: models.CVEVulnerable, CVSS3Score: "5.5"}, 1},
		{"vulnerable high CVSS → CRIT", &models.CVEResult{Status: models.CVEVulnerable, CVSS3Score: "9.8"}, 2},
		{"vulnerable + KEV → CRIT", &models.CVEResult{Status: models.CVEVulnerable, CVSS3Score: "5.0", KnownExploited: true}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pendingExitCode = 0
			defer func() { pendingExitCode = 0 }()
			recordCVEResultSeverity(tc.r)
			if pendingExitCode != tc.want {
				t.Errorf("got %d, want %d", pendingExitCode, tc.want)
			}
		})
	}
}
