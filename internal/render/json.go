package render

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/version"
)

// JSONOutput is the stable public JSON contract for dsd health --json.
type JSONOutput struct {
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
	// Verdict is the worst insight level ("CRIT" | "WARN" | "OK"), EXCEPT: if at
	// least one checks[] entry errored (Counts.Errored > 0) and the insight-only
	// verdict would otherwise read "OK", Verdict is forced to "WARN" instead —
	// see buildOutput. A collector that failed outright typically produces only
	// an INFO "couldn't measure" insight (which never raises verdict on its
	// own), so without this a run where every collector errored still reported
	// "OK" to a consumer branching on `jq -r .verdict` alone
	// (internal-render-03-04). A genuine CRIT/WARN insight already explains
	// itself and is left untouched.
	Verdict  string        `json:"verdict"`
	Counts   JSONCounts    `json:"counts"` // insight tallies by level
	Checks   []JSONCheck   `json:"checks"`
	Insights []JSONInsight `json:"insights"`
}

// JSONCounts tallies insights by level so a consumer can branch without
// iterating .insights (e.g. `jq -r .verdict`, `jq '.counts.crit'`). Mirrors the
// process exit code (CRIT->2, WARN->1, OK->0).
type JSONCounts struct {
	Crit int `json:"crit"`
	Warn int `json:"warn"`
	Info int `json:"info"`
	// Errored is the number of checks[] entries with status "ERROR" (the
	// collector itself failed to run — r.Err != nil). internal-render-03-04:
	// Verdict/Crit/Warn/Info are derived purely from insight levels, and a
	// failed collector typically produces only an INFO-level "couldn't
	// measure" insight (never raising Verdict), so a machine consumer
	// branching on Verdict/Counts alone had no way to see that some checks
	// didn't run at all — the per-check "ERROR" status was only visible by
	// iterating checks[]. Additive, omitempty: existing consumers validating
	// against the frozen schema are unaffected when it's zero.
	Errored int `json:"errored,omitempty"`
	// Unverified is the number of insights with Unverified=true — a check
	// that RAN without error but could not determine the thing it checks
	// (permission denied, an unreadable file, a read that failed mid-parse).
	// This is distinct from Errored: the collector succeeded, one specific
	// measurement inside it didn't. Its Level is usually a downgraded INFO,
	// which (like Errored) never raises Verdict/Crit/Warn on its own — see
	// buildOutput's verdict-floor logic, which forces Verdict to at least
	// WARN when this is nonzero and would otherwise read OK. Additive,
	// omitempty.
	Unverified int `json:"unverified,omitempty"`
}

type JSONCheck struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Inline   string `json:"inline,omitempty"`
	Duration string `json:"duration,omitempty"`
	Error    string `json:"error,omitempty"`
	Raw      any    `json:"raw,omitempty"`
}

type JSONInsight struct {
	Check   string          `json:"check"`
	Level   string          `json:"level"`
	Message string          `json:"message"`
	Hints   []string        `json:"hints,omitempty"`
	Details *models.Details `json:"details,omitempty"`
	// Unverified marks an insight whose Level reflects a downgrade because
	// the underlying data could NOT be read/measured this run — not a
	// genuine "nothing wrong here" finding. See models.Insight.Unverified.
	// Additive, omitempty: existing consumers validating against the frozen
	// schema are unaffected when it's false/absent.
	Unverified bool `json:"unverified,omitempty"`
}

func RenderJSON(results []runner.Result, insights []models.Insight) ([]byte, error) {
	return json.MarshalIndent(buildOutput(results, insights), "", "  ")
}

func RenderYAML(results []runner.Result, insights []models.Insight) ([]byte, error) {
	out := buildOutput(results, insights)
	return yaml.Marshal(out)
}

func buildOutput(results []runner.Result, insights []models.Insight) JSONOutput {
	hostname := platform.Hostname() // honors the replay identity override

	insightMap := make(map[string]models.Insight, len(insights))
	for _, ins := range insights {
		prev, ok := insightMap[ins.Check]
		if !ok || severityOrder(ins.Level) > severityOrder(prev.Level) {
			insightMap[ins.Check] = ins
		}
	}

	checks := make([]JSONCheck, 0, len(results))
	for _, r := range results {
		// Keep the JSON/YAML contract consistent with live health and --report
		// (baseline.BuildSnapshot): a collector that gated itself off (nil data,
		// no error) or reports itself not-applicable (Available=false) with no
		// insight is absent. Emitting it as a phantom "OK" check — e.g.
		// {"name":"Launchd","status":"OK","raw":null} on Linux — is the same noise
		// #129/#131 removed from the other surfaces. Errors are always kept.
		if r.Err == nil {
			if r.Data == nil {
				continue
			}
			if _, hasInsight := insightMap[r.Name]; !hasInsight && !runner.IsAvailable(r.Data) {
				continue
			}
		}
		c := JSONCheck{
			Name:     r.Name,
			Status:   "OK",
			Duration: r.Duration.String(),
			Raw:      r.Data,
			Inline:   inlineData(r), // pre-rendered for dsd capture
		}
		if r.Err != nil {
			c.Status = "ERROR"
			c.Error = r.Err.Error()
		} else if ins, ok := insightMap[r.Name]; ok && ins.Level != "OK" {
			c.Status = ins.Level
		} else {
			prefix := r.Name + " "
			slash := r.Name + "/"
			for chk, ins := range insightMap {
				if (strings.HasPrefix(chk, prefix) || strings.HasPrefix(chk, slash)) && severityOrder(ins.Level) > severityOrder(c.Status) {
					c.Status = ins.Level
				}
			}
		}
		checks = append(checks, c)
	}

	jsonInsights := make([]JSONInsight, 0)
	for _, ins := range insights {
		if ins.Level == "OK" {
			continue
		}
		jsonInsights = append(jsonInsights, JSONInsight{
			Check:      ins.Check,
			Level:      ins.Level,
			Message:    ins.Message,
			Hints:      ins.Hints, // all hints, not just first
			Details:    ins.Details,
			Unverified: ins.Unverified,
		})
	}

	// Stable ordering so `dsd health --json`, `dsd capture`, and `dsd replay`
	// produce byte-stable, diffable artifacts — collectors complete in
	// nondeterministic order, which otherwise shuffles these arrays run to run
	// (TRIAGE §I). Checks by name; insights worst-first then alphabetical, matching
	// the human renderer (report.go). The human path does its own sort, so this
	// only affects the machine-consumed JSON/YAML surface.
	sort.SliceStable(checks, func(i, j int) bool { return checks[i].Name < checks[j].Name })
	sort.SliceStable(jsonInsights, func(i, j int) bool {
		a, b := jsonInsights[i], jsonInsights[j]
		if oa, ob := severityOrder(a.Level), severityOrder(b.Level); oa != ob {
			return oa > ob // CRIT before WARN before INFO
		}
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.Message < b.Message
	})

	verdict, counts := summarizeInsights(insights)
	for _, c := range checks {
		if c.Status == "ERROR" {
			counts.Errored++
		}
	}
	// internal-render-03-04, extended for C1: at least one collector errored
	// outright, OR at least one insight is Unverified (ran fine, but could
	// not determine the specific thing it checks — see C2, /dev/kmsg) — and
	// there's no WARN/CRIT insight to already explain it — don't let the
	// verdict read "OK". WARN is the closed enum's (schema/dsd-output.json)
	// best fit for "not confirmed healthy" without overstating severity; a
	// real CRIT/WARN insight is left as-is (it already outranks this).
	if (counts.Errored > 0 || counts.Unverified > 0) && verdict == "OK" {
		verdict = "WARN"
	}

	return JSONOutput{
		Hostname:  hostname,
		OS:        platform.OSPrettyName(),
		Timestamp: time.Now().UTC(),
		Version:   version.Version,
		Verdict:   verdict,
		Counts:    counts,
		Checks:    checks,
		Insights:  jsonInsights,
	}
}

// summarizeInsights returns the overall verdict (worst level) and per-level
// counts. CRIT outranks WARN outranks OK; INFO/OK never raise the verdict.
func summarizeInsights(insights []models.Insight) (string, JSONCounts) {
	var c JSONCounts
	for _, ins := range insights {
		switch ins.Level {
		case "CRIT":
			c.Crit++
		case "WARN":
			c.Warn++
		case "INFO":
			c.Info++
		}
		if ins.Unverified {
			c.Unverified++
		}
	}
	verdict := "OK"
	switch {
	case c.Crit > 0:
		verdict = "CRIT"
	case c.Warn > 0:
		verdict = "WARN"
	}
	return verdict, c
}
