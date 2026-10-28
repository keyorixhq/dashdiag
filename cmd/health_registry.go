package cmd

import (
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// absentCollector is a probe-gated collector the probe left out of the run: its
// Name as it would have appeared in the results, and the coverage reason it is
// not applicable for (models.ReasonNotPresent / ReasonNotSupportedPlatform).
type absentCollector struct {
	Name, Reason string
}

// healthRegistry records what buildHealthRegistry's probes left out. It is the one
// helper every `if probe { cols = append(cols, ...) }` site goes through, so the
// skipped names cannot be forgotten at a new call site.
type healthRegistry struct {
	absent []absentCollector
}

// gate appends c when its probe found the subsystem, else records it as not
// present on this host. The constructor runs either way (they are cheap and only
// build a struct); the probe, not the constructor, decides whether it collects.
func (r *healthRegistry) gate(cols []collectors.Collector, present bool, c collectors.Collector) []collectors.Collector {
	return r.add(cols, present, c, models.ReasonNotPresent)
}

// gatePlatform is gate for a probe that asks whether the kernel or CPU supports
// the feature at all (PSI, MTE, cpufreq), not whether the host uses it.
func (r *healthRegistry) gatePlatform(cols []collectors.Collector, supported bool, c collectors.Collector) []collectors.Collector {
	return r.add(cols, supported, c, models.ReasonNotSupportedPlatform)
}

func (r *healthRegistry) add(cols []collectors.Collector, ok bool, c collectors.Collector, reason string) []collectors.Collector {
	if ok {
		return append(cols, c)
	}
	r.absent = append(r.absent, absentCollector{Name: c.Name(), Reason: reason})
	return cols
}

// absentResults turns the left-out collectors into results for the run. They carry
// no data and no error and say why (runner.Result.Absent), so render.Coverage
// reports them not_applicable in every output while checks[] omits them, exactly
// like a collector that ran and found nothing. A name that also ran (a deep and a
// plain variant never both register) is not duplicated.
func absentResults(ran []runner.Result, absent []absentCollector) []runner.Result {
	have := make(map[string]bool, len(ran))
	for _, r := range ran {
		have[r.Name] = true
	}
	var out []runner.Result
	for _, a := range absent {
		if have[a.Name] {
			continue
		}
		have[a.Name] = true
		out = append(out, runner.Result{Name: a.Name, Absent: a.Reason})
	}
	return out
}
