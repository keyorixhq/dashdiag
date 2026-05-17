//go:build linux

package collectors

import (
	"bufio"
	"context"
	"os/exec"
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

	if _, err := exec.LookPath("machinectl"); err != nil {
		return info, nil
	}

	out, err := runCmd(ctx, "machinectl", "list", "--no-legend", "--no-pager")
	if err != nil || strings.TrimSpace(out) == "" {
		return info, nil
	}

	info.Available = true
	info.Containers = parseMachinectlList(out)
	for _, c := range info.Containers {
		if c.State == "degraded" || c.State == "failed" {
			info.FailedCount++
		}
	}
	return info, nil
}

// IsNspawnPresent returns true when machinectl is available.
func IsNspawnPresent() bool {
	_, err := exec.LookPath("machinectl")
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
		state := "running"
		if len(fields) >= 4 {
			state = strings.ToLower(fields[3])
		}
		containers = append(containers, models.NspawnContainer{
			Name:  fields[0],
			State: state,
		})
	}
	return containers
}
