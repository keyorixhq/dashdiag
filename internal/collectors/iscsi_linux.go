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
		return nil, nil // no initiator tooling — absent, gate off (no phantom row)
	}
	info.Available = true

	// iscsiadm -m session prints one line per active session
	out, err := runCmd(ctx, "iscsiadm", "-m", "session")
	if err != nil {
		// No sessions or daemon not running — initiator installed but not in use.
		// open-iscsi ships by default on Ubuntu/Debian with zero targets logged in,
		// so an empty initiator is "absent" (matches the VLAN gate), not a phantom OK.
		return nil, nil
	}

	info.Sessions = parseISCSISessions(out)
	if len(info.Sessions) == 0 {
		return nil, nil // initiator present but no active sessions — absent
	}
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
		// portal is "host:port,<tid>" — strip the portal-group tag regardless of
		// its value. The tid is always after the final comma (IPv6 portals like
		// "[fe80::1]:3260,1" keep their colons), so trim from the last comma; the
		// previous code only handled the ",1" default and left ",2"/",3"/… on.
		portal := parts[2]
		if i := strings.LastIndex(portal, ","); i != -1 {
			portal = portal[:i]
		}
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
