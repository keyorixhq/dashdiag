//go:build linux

package collectors

import (
	"bufio"
	"context"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type NspawnCollector struct{}

func NewNspawnCollector() *NspawnCollector        { return &NspawnCollector{} }
func (c *NspawnCollector) Name() string           { return "Nspawn" }
func (c *NspawnCollector) Timeout() time.Duration { return 4 * time.Second }

func (c *NspawnCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.NspawnInfo{}

	if _, err := lookPath("machinectl"); err != nil {
		return info, nil
	}

	out, err := runCmd(ctx, "machinectl", "list", "--no-legend", "--no-pager")
	if err != nil || strings.TrimSpace(out) == "" {
		return info, nil
	}

	info.Available = true
	info.Containers = parseMachinectlList(out)
	info.FailedCount = countFailedNspawnUnits(ctx)
	return info, nil
}

// countFailedNspawnUnits counts systemd-nspawn@<name> service units in the failed
// state — the actual source of nspawn-container failure. `machinectl list` only shows
// RUNNING machines (a crashed container is simply absent from it), so the old check —
// comparing the OS column (fields[3], e.g. "debian") to "failed"/"degraded" — could
// never match and FailedCount was always 0.
func countFailedNspawnUnits(ctx context.Context) int {
	out, err := runCmd(ctx, "systemctl", "list-units", "systemd-nspawn@*.service",
		"--state=failed", "--no-legend", "--no-pager", "--plain")
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "systemd-nspawn@") {
			count++
		}
	}
	return count
}

// IsNspawnPresent returns true when machinectl is available.
func IsNspawnPresent() bool {
	_, err := lookPath("machinectl")
	return err == nil
}

// parseMachinectlList parses "machinectl list --no-legend" output.
// Format: "machine-name container nspawn running"
func parseMachinectlList(out string) []models.NspawnContainer {
	var containers []models.NspawnContainer
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		// `machinectl list` columns are MACHINE CLASS SERVICE OS VERSION ADDRESSES —
		// there is no state column, so every listed machine is running. (The old code
		// read fields[3], the OS, as a "state" — it never equalled "failed".)
		containers = append(containers, models.NspawnContainer{
			Name:  fields[0],
			State: "running",
		})
	}
	return containers
}
