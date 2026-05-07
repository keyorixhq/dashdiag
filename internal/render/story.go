package render

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
)

func RenderStory(insights []models.Insight, snap *baseline.Snapshot) string {
	active := make(map[string]models.Insight)
	for _, ins := range insights {
		if ins.Level != "WARN" && ins.Level != "CRIT" {
			continue
		}
		// Keep worst per check
		if prev, ok := active[ins.Check]; !ok || severityOrder(ins.Level) > severityOrder(prev.Level) {
			active[ins.Check] = ins
		}
	}

	if len(active) == 0 {
		return fmt.Sprintf("All %d health checks passed on %s. System is operating normally.",
			len(snap.Checks), snap.Hostname)
	}

	var paragraphs []string

	if ins, ok := active["Memory"]; ok {
		paragraphs = append(paragraphs,
			fmt.Sprintf("Memory pressure detected on %s. %s "+
				"Risk of OOM kill if trend continues. "+
				"Top consumers: run `ps aux --sort=-%%mem | head -10`",
				snap.Hostname, ins.Message))
	}
	if ins, ok := active["Swap"]; ok {
		paragraphs = append(paragraphs,
			fmt.Sprintf("Swap activity detected on %s. %s",
				snap.Hostname, ins.Message))
	}
	if ins, ok := active["DiskIO"]; ok {
		paragraphs = append(paragraphs,
			fmt.Sprintf("Disk IO saturation on %s. %s",
				snap.Hostname, ins.Message))
	}
	if ins, ok := active["CPU"]; ok {
		paragraphs = append(paragraphs,
			fmt.Sprintf("CPU load elevated on %s. %s "+
				"System has been under sustained load.",
				snap.Hostname, ins.Message))
	}
	if ins, ok := active["Network"]; ok {
		paragraphs = append(paragraphs,
			fmt.Sprintf("Network connectivity issue detected on %s. %s",
				snap.Hostname, ins.Message))
	}

	// Remaining checks not covered by specific templates
	covered := map[string]bool{"Memory": true, "Swap": true, "DiskIO": true, "CPU": true, "Network": true}
	for check, ins := range active {
		if !covered[check] {
			paragraphs = append(paragraphs,
				fmt.Sprintf("%s issue on %s: %s", check, snap.Hostname, ins.Message))
		}
	}

	return strings.Join(paragraphs, "\n\n")
}

func severityOrder(level string) int {
	switch level {
	case "CRIT":
		return 2
	case "WARN":
		return 1
	default:
		return 0
	}
}
