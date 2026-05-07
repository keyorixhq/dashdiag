package render

import (
	"encoding/json"
	"os"
	"time"

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
	Name     string `json:"name"`
	Status   string `json:"status"`
	Duration string `json:"duration,omitempty"`
	Error    string `json:"error,omitempty"`
}

type JSONInsight struct {
	Level   string   `json:"level"`
	Check   string   `json:"check"`
	Message string   `json:"message"`
	Hints   []string `json:"hints,omitempty"`
}

func RenderJSON(results []runner.Result, insights []models.Insight) ([]byte, error) {
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
		c := JSONCheck{
			Name:     r.Name,
			Status:   "OK",
			Duration: r.Duration.String(),
		}
		if r.Err != nil {
			c.Status = "ERROR"
			c.Error = r.Err.Error()
		} else if ins, ok := insightMap[r.Name]; ok && ins.Level != "OK" {
			c.Status = ins.Level
		}
		checks = append(checks, c)
	}

	jsonInsights := make([]JSONInsight, 0)
	for _, ins := range insights {
		if ins.Level == "OK" {
			continue
		}
		jsonInsights = append(jsonInsights, JSONInsight{
			Level:   ins.Level,
			Check:   ins.Check,
			Message: ins.Message,
			Hints:   ins.Hints,
		})
	}

	out := JSONOutput{
		Hostname:  hostname,
		Timestamp: time.Now().UTC(),
		Version:   version.Version,
		Checks:    checks,
		Insights:  jsonInsights,
	}

	return json.MarshalIndent(out, "", "  ")
}
