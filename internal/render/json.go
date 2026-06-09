package render

import (
	"encoding/json"
	"os"
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
	Hostname  string        `json:"hostname"`
	OS        string        `json:"os"`
	Timestamp time.Time     `json:"timestamp"`
	Version   string        `json:"version"`
	Verdict   string        `json:"verdict"` // worst insight level: "CRIT" | "WARN" | "OK"
	Counts    JSONCounts    `json:"counts"`  // insight tallies by level
	Checks    []JSONCheck   `json:"checks"`
	Insights  []JSONInsight `json:"insights"`
}

// JSONCounts tallies insights by level so a consumer can branch without
// iterating .insights (e.g. `jq -r .verdict`, `jq '.counts.crit'`). Mirrors the
// process exit code (CRIT->2, WARN->1, OK->0).
type JSONCounts struct {
	Crit int `json:"crit"`
	Warn int `json:"warn"`
	Info int `json:"info"`
}

type JSONCheck struct {
	Name     string      `json:"name"`
	Status   string      `json:"status"`
	Inline   string      `json:"inline,omitempty"`
	Duration string      `json:"duration,omitempty"`
	Error    string      `json:"error,omitempty"`
	Raw      interface{} `json:"raw,omitempty"`
}

type JSONInsight struct {
	Check   string          `json:"check"`
	Level   string          `json:"level"`
	Message string          `json:"message"`
	Hints   []string        `json:"hints,omitempty"`
	Details *models.Details `json:"details,omitempty"`
}

func RenderJSON(results []runner.Result, insights []models.Insight) ([]byte, error) {
	return json.MarshalIndent(buildOutput(results, insights), "", "  ")
}

func RenderYAML(results []runner.Result, insights []models.Insight) ([]byte, error) {
	out := buildOutput(results, insights)
	return yaml.Marshal(out)
}

func buildOutput(results []runner.Result, insights []models.Insight) JSONOutput {
	hostname, _ := os.Hostname()

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
			Check:   ins.Check,
			Level:   ins.Level,
			Message: ins.Message,
			Hints:   ins.Hints, // all hints, not just first
			Details: ins.Details,
		})
	}

	verdict, counts := summarizeInsights(insights)

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
