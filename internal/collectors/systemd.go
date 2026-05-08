package collectors

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

type SystemdCollector struct{}

func NewSystemdCollector() *SystemdCollector { return &SystemdCollector{} }

func (c *SystemdCollector) Name() string           { return "Systemd" }
func (c *SystemdCollector) Timeout() time.Duration { return 3 * time.Second }

// parseUnitList parses `systemctl list-units --no-legend --no-pager --plain` output.
// Each line's first field that contains "." is the unit name.
func parseUnitList(r io.Reader) []string {
	var units []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		// Skip non-unit lines (header/summary) and bullet indicators
		if !strings.Contains(name, ".") {
			if len(fields) > 1 && strings.Contains(fields[1], ".") {
				name = fields[1]
			} else {
				continue
			}
		}
		units = append(units, name)
	}
	return units
}

var cloudInitUnits = map[string]bool{
	"cloud-final.service":      true,
	"cloud-config.service":     true,
	"cloud-init.service":       true,
	"cloud-init-local.service": true,
}

func filterUnits(units []string, ignore map[string]bool) []string {
	out := units[:0]
	for _, u := range units {
		if !ignore[u] {
			out = append(out, u)
		}
	}
	return out
}

func listUnits(ctx context.Context, state string) []string {
	out, err := exec.CommandContext(ctx, "systemctl", "list-units", // #nosec G204 -- command is hardcoded "systemctl"; state is from internal enum values, not user input
		"--state="+state, "--no-legend", "--no-pager", "--plain").Output()
	if err != nil {
		return nil
	}
	return parseUnitList(strings.NewReader(string(out)))
}

func (c *SystemdCollector) Collect(ctx context.Context) (interface{}, error) {
	if runtime.GOOS == "darwin" || !platform.SystemdAvailable() {
		return &models.SystemdInfo{Available: false}, nil
	}

	failed := filterUnits(listUnits(ctx, "failed"), cloudInitUnits)
	return &models.SystemdInfo{
		Available:   true,
		FailedUnits: failed,
		// activating state alone does not indicate stuck; socket-activated on-demand
		// services (e.g. systemd-timedated.service) appear here during normal operation.
		// We cannot determine duration without reading ActiveEnterTimestamp, so we skip.
		StuckUnits: nil,
	}, nil
}
