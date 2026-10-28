package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/render"
)

func TestHealthRegistry_GateRecordsWhatTheProbeLeftOut(t *testing.T) {
	var reg healthRegistry
	var cols []collectors.Collector
	cols = reg.gate(cols, true, collectors.NewInfiniBandCollector())
	cols = reg.gate(cols, false, collectors.NewHBACollector())
	cols = reg.gatePlatform(cols, false, collectors.NewPressureCollector())
	if len(cols) != 1 || cols[0].Name() != "InfiniBand" {
		t.Fatalf("cols = %v, want only InfiniBand", cols)
	}
	want := []absentCollector{
		{Name: collectors.NewHBACollector().Name(), Reason: models.ReasonNotPresent},
		{Name: collectors.NewPressureCollector().Name(), Reason: models.ReasonNotSupportedPlatform},
	}
	if len(reg.absent) != 2 || reg.absent[0] != want[0] || reg.absent[1] != want[1] {
		t.Fatalf("absent = %+v, want %+v", reg.absent, want)
	}
}

// TestHealthRegistry_AbsentAreNotApplicableNotChecks: on this host, whatever the
// probes found, the collectors they left out are reported not_applicable with a
// valid reason, never run, never an OK check, and never also in the run list.
func TestHealthRegistry_AbsentAreNotApplicableNotChecks(t *testing.T) {
	cols, absent := buildHealthRegistry(platform.ContainerContext{}, platform.Profile{}, healthRunOpts{})
	ran := map[string]bool{}
	for _, c := range cols {
		ran[c.Name()] = true
	}
	results := absentResults(nil, absent)
	if len(results) == 0 {
		t.Skip("every probe passed on this host")
	}
	for _, a := range absent {
		if ran[a.Name] {
			t.Errorf("%s is both run and reported absent", a.Name)
		}
		if a.Reason != models.ReasonNotPresent && a.Reason != models.ReasonNotSupportedPlatform {
			t.Errorf("%s: reason %q is not a not_applicable reason", a.Name, a.Reason)
		}
	}
	cov := render.Coverage(results, nil)
	if cov.NotApplicable != len(results) || cov.Checked != 0 || cov.NotChecked != 0 {
		t.Errorf("coverage = %+v, want %d not applicable and nothing else", cov, len(results))
	}
	if got := absentResults(results, absent); len(got) != 0 {
		t.Errorf("absentResults duplicated names that already have a result: %+v", got)
	}
}
