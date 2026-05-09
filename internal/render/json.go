package render

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/version"
)

// JSONOutput is the stable public JSON contract for dsd health --json.
type JSONOutput struct {
	Hostname  string        `json:"hostname"`
	Timestamp time.Time     `json:"timestamp"`
	Version   string        `json:"version"`
	Checks    []JSONCheck   `json:"checks"`
	Insights  []JSONInsight `json:"insights"`
}

type JSONCheck struct {
	Name     string      `json:"name"`
	Status   string      `json:"status"`
	Duration string      `json:"duration,omitempty"`
	Error    string      `json:"error,omitempty"`
	Raw      interface{} `json:"raw,omitempty"`
}

type JSONInsight struct {
	Check   string          `json:"check"`
	Level   string          `json:"level"`
	Message string          `json:"message"`
	Hint    string          `json:"hint,omitempty"`
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
		c := JSONCheck{Name: r.Name, Status: "OK", Duration: r.Duration.String(), Raw: r.Data}
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
		ji := JSONInsight{Check: ins.Check, Level: ins.Level, Message: ins.Message, Details: ins.Details}
		if len(ins.Hints) > 0 {
			ji.Hint = ins.Hints[0]
		}
		jsonInsights = append(jsonInsights, ji)
	}

	return JSONOutput{
		Hostname:  hostname,
		Timestamp: time.Now().UTC(),
		Version:   version.Version,
		Checks:    checks,
		Insights:  jsonInsights,
	}
}
