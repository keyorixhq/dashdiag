//go:build linux

package collectors

import (
	"bufio"
	"context"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

type ISCSICollector struct{}

func NewISCSICollector() *ISCSICollector         { return &ISCSICollector{} }
func (c *ISCSICollector) Name() string           { return "iSCSI" }
func (c *ISCSICollector) Timeout() time.Duration { return 5 * time.Second }

func (c *ISCSICollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.ISCSIInfo{}

	if _, err := lookPath("iscsiadm"); err != nil {
		return nil, nil // no initiator tooling — absent, gate off (no phantom row)
	}
	info.Available = true

	// `-P 1` includes the per-session "iSCSI Session State" — the bare `-m session`
	// listing does NOT, so the previous parser hardcoded every session LOGGED_IN and
	// FailedCount could never increment (a failed/reconnecting session read as fine).
	out, err := runCmd(ctx, "iscsiadm", "-m", "session", "-P", "1")
	if err != nil {
		// iscsiadm failed. Tell "no sessions" (benign, silent) apart from "sessions
		// exist but their state needs root": `-P 1` reads per-session sysfs fields that
		// are mode 0400 (e.g. session*/username), so unprivileged it fails with the
		// SAME exit 21 as no-sessions. /sys/class/iscsi_session/ itself is world-
		// readable, so its session* dir count is the honest discriminator.
		if iscsiSessionDirCount() > 0 {
			return &models.ISCSIInfo{Available: true, NeedsRoot: true}, nil
		}
		// open-iscsi ships by default on Ubuntu/Debian with zero targets logged in,
		// so an empty initiator is "absent" (matches the VLAN gate), not a phantom OK.
		return nil, nil
	}

	info.Sessions = parseISCSISessions(out)
	if len(info.Sessions) == 0 {
		// internal-collectors-17-02: iscsiadm exited 0 but no recognizable
		// "Current Portal:"/"iSCSI Session State:" line was found — the same
		// world-readable sysfs cross-check the error path above already uses
		// distinguishes "genuinely no sessions" from "sessions exist but this
		// iscsiadm's output didn't match the expected format" (a locale
		// change inherited from the invoking environment, or a differently
		// formatted iscsiadm build).
		if iscsiSessionDirCount() > 0 {
			return &models.ISCSIInfo{Available: true, SessionsParseFailed: true}, nil
		}
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
	_, err := lookPath("iscsiadm")
	return err == nil
}

// iscsiSessionDirCount counts active iSCSI sessions via sysfs
// (/sys/class/iscsi_session/session*), which is world-readable — so it works
// unprivileged even when `iscsiadm -P 1` can't read the per-session 0400 fields.
// Used to tell "no sessions" from "sessions present but unreadable as non-root".
func iscsiSessionDirCount() int {
	m, _ := glob("/sys/class/iscsi_session/session*")
	return len(m)
}

// parseISCSISessions parses `iscsiadm -m session -P 1` output, which groups state
// under each portal:
//
//	Target: iqn.2026-06.example:tgt0 (non-flash)
//	    Current Portal: 10.0.0.1:3260,1
//	        iSCSI Session State: LOGGED_IN
//	    Current Portal: 10.0.0.2:3260,1
//	        iSCSI Session State: FAILED
//
// Each "Current Portal" begins a session; its "iSCSI Session State" sets the real
// state (the old parser read the stateless `-m session` form and hardcoded
// LOGGED_IN, so a failed/reconnecting session was never counted).
func parseISCSISessions(out string) []models.ISCSISession {
	var sessions []models.ISCSISession
	var target, portal string
	pending := false
	// flush records the current portal's session; state "UNKNOWN" when a portal had
	// no "iSCSI Session State" line (counted as not-logged-in by the caller).
	// internal-collectors-17-06: target/portal come straight from iscsiadm's
	// output — sanitize before they land in the model so a crafted/adversarial
	// target IQN or portal string can't smuggle control/ANSI bytes downstream.
	flush := func(state string) {
		if pending {
			sessions = append(sessions, models.ISCSISession{
				Target: source.SanitizeControl(target),
				Portal: source.SanitizeControl(portal),
				State:  state,
			})
			pending = false
		}
	}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "Target:"):
			if f := strings.Fields(strings.TrimPrefix(line, "Target:")); len(f) > 0 {
				target = f[0] // the IQN; drop the trailing "(non-flash)"
			}
		case strings.HasPrefix(line, "Current Portal:"):
			flush("UNKNOWN") // previous portal had no state line
			p := strings.TrimSpace(strings.TrimPrefix(line, "Current Portal:"))
			if i := strings.LastIndex(p, ","); i != -1 {
				p = p[:i] // strip the ",<tid>" group tag (IPv6 portals keep their colons)
			}
			portal = p
			pending = true
		case strings.HasPrefix(line, "iSCSI Session State:"):
			flush(strings.TrimSpace(strings.TrimPrefix(line, "iSCSI Session State:")))
		}
	}
	flush("UNKNOWN")
	return sessions
}
