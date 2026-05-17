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

type ISCSICollector struct{}

func NewISCSICollector() *ISCSICollector         { return &ISCSICollector{} }
func (c *ISCSICollector) Name() string           { return "iSCSI" }
func (c *ISCSICollector) Timeout() time.Duration { return 5 * time.Second }

func (c *ISCSICollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.ISCSIInfo{}

	if _, err := exec.LookPath("iscsiadm"); err != nil {
		return info, nil
	}
	info.Available = true

	// iscsiadm -m session prints one line per active session
	out, err := runCmd(ctx, "iscsiadm", "-m", "session")
	if err != nil {
		// No sessions or daemon not running — not an error
		return info, nil
	}

	info.Sessions = parseISCSISessions(out)
	for _, s := range info.Sessions {
		if strings.ToUpper(s.State) != "LOGGED_IN" {
			info.FailedCount++
		}
	}
	return info, nil
}

// IsISCSIPresent returns true when iscsiadm is installed.
func IsISCSIPresent() bool {
	_, err := exec.LookPath("iscsiadm")
	return err == nil
}

// parseISCSISessions parses `iscsiadm -m session` output.
// Format: "tcp: [1] 10.0.0.1:3260,1 iqn.2019-01.com.example:storage (non-flash)"
func parseISCSISessions(out string) []models.ISCSISession {
	var sessions []models.ISCSISession
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		// Minimum: "tcp: [1] portal,tid target"
		if len(parts) < 4 {
			continue
		}
		portal := parts[2]
		portal = strings.TrimSuffix(portal, ",1")
		target := parts[3]
		session := models.ISCSISession{
			Target: target,
			Portal: portal,
			State:  "LOGGED_IN",
		}
		sessions = append(sessions, session)
	}
	return sessions
}
