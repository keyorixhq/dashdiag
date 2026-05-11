package drilldown

import (
	"context"
	"os"
	"runtime"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// recommended sysctl values for common failing keys.
var sysctlRecommended = map[string]struct {
	recommended string
	note        string
}{
	"net.core.somaxconn":            {"4096", "increase for high-concurrency servers"},
	"vm.swappiness":                 {"10", "lower for k8s/database; 60 for general workloads"},
	"fs.file-max":                   {"1048576", "increase if file descriptor limit is hit"},
	"kernel.pid_max":                {"4194304", "increase for systems running many processes"},
	"net.ipv4.tcp_tw_reuse":         {"1", "allow TIME_WAIT socket reuse for outbound connections"},
	"vm.max_map_count":              {"262144", "required for k8s/Elasticsearch"},
	"fs.inotify.max_user_watches":   {"524288", "required for k8s file watchers"},
	"fs.inotify.max_user_instances": {"512", "required for k8s"},
}

// ActualVsRecommended returns current vs recommended values for sysctl keys
// mentioned in the insight message.
func ActualVsRecommended(ctx context.Context, message string) (*models.Details, error) {
	if runtime.GOOS == "darwin" {
		return nil, nil
	}

	// Determine which sysctl key is failing from the message.
	var keys []string
	for key := range sysctlRecommended {
		if strings.Contains(message, key) || strings.Contains(message, strings.ReplaceAll(key, ".", "_")) {
			keys = append(keys, key)
		}
	}
	// Always include somaxconn and pid_max if nothing matched (common suspects).
	if len(keys) == 0 {
		keys = []string{"net.core.somaxconn", "kernel.pid_max"}
	}

	rows := make([][]string, 0, len(keys))
	for _, key := range keys {
		current := readSysctl(key)
		rec := sysctlRecommended[key]
		// Only show rows where current differs from recommended
		if current == rec.recommended {
			continue
		}
		rows = append(rows, []string{key, current, rec.recommended, rec.note})
	}

	if len(rows) == 0 {
		return nil, nil
	}

	return &models.Details{
		Type:    "sysctl_table",
		Title:   "Sysctl: current vs recommended",
		Columns: []string{"SYSCTL", "CURRENT", "RECOMMENDED", "NOTE"},
		Rows:    rows,
	}, nil
}

func readSysctl(key string) string {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	data, err := os.ReadFile(path)
	if err != nil {
		return "n/a"
	}
	return strings.TrimSpace(string(data))
}
