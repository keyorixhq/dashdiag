//go:build linux

package collectors

import (
	"bufio"
	"context"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type AuthCollector struct{}

func NewAuthCollector() *AuthCollector          { return &AuthCollector{} }
func (c *AuthCollector) Name() string           { return "Auth" }
func (c *AuthCollector) Timeout() time.Duration { return 6 * time.Second }

func (c *AuthCollector) Collect(ctx context.Context) (interface{}, error) {
	// Hide the row when sshd is not installed — nothing to monitor.
	if _, err := runCmd(ctx, "pgrep", "-x", "sshd"); err != nil {
		// Also check if the binary exists even if not running right now
		if _, err2 := runCmd(ctx, "which", "sshd"); err2 != nil {
			return &models.AuthInfo{}, nil // Available=false → row hidden
		}
	}

	info := &models.AuthInfo{Available: true, Checked: true}

	// journalctl is the most portable source — works on all systemd distros.
	// grep for "Failed password" and "Invalid user" from sshd. As a non-root user
	// without journal access this returns nothing (the sshd entries live in the
	// system journal), so an empty result is NOT proof of "no failures" — fall
	// through to the text logs to decide.
	out, err := runCmd(ctx, "journalctl", "_COMM=sshd", "--since", "24 hours ago",
		"--no-pager", "-o", "cat")
	if err != nil || strings.TrimSpace(out) == "" {
		fileOut, readable, denied := readAuthLog(ctx)
		switch {
		case readable:
			// A text log was readable; empty content here genuinely means no
			// failed logins.
			out = fileOut
		case denied:
			// An auth log exists but we could not read it (typically non-root on
			// Debian/Ubuntu/RHEL, where /var/log/{auth.log,secure} is mode 640),
			// and the journal gave us nothing either — we have NO auth data.
			// Report "not checked" rather than a clean bill of health (a false-OK:
			// "0 failed logins" read off a log we never opened).
			info.Checked = false
			info.StatusReason = "auth log unreadable — run as root to verify SSH auth failures"
			return info, nil
		default:
			// No journal data and no auth log file present at all (e.g. a
			// journald-only host with genuinely no sshd failures). Trust the empty
			// result — avoids false-alarming healthy quiet hosts.
		}
	}

	counts := map[string]int{}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "failed password") &&
			!strings.Contains(lower, "invalid user") &&
			!strings.Contains(lower, "connection closed by authenticating") {
			continue
		}
		info.FailedLast24h++
		if strings.Contains(lower, "root") {
			info.RootAttempts++
		}
		// Extract source IP: "from 1.2.3.4 port"
		if i := strings.Index(line, " from "); i >= 0 {
			rest := line[i+6:]
			if j := strings.Index(rest, " port"); j >= 0 {
				ip := rest[:j]
				ip = strings.TrimSpace(ip)
				if ip != "" {
					counts[ip]++
				}
			}
		}
	}

	// Top 5 sources
	type kv struct {
		k string
		v int
	}
	var sorted []kv
	for k, v := range counts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
	max := 5
	if len(sorted) < max {
		max = len(sorted)
	}
	for _, s := range sorted[:max] {
		info.TopSources = append(info.TopSources, models.FailedLoginSource{
			Source: s.k,
			Count:  s.v,
		})
	}
	return info, nil
}

// readAuthLog scans the system auth logs for failed-login lines. It returns the
// matching lines, whether any candidate file was actually readable, and whether a
// candidate existed but was permission-denied. The readable/denied distinction is
// what lets the caller tell "no failed logins" (readable, empty) apart from "could
// not read the log" (denied) — the latter must not be reported as a clean host.
//
// We probe readability with os.Open (which distinguishes permission-denied from
// absent via os.IsPermission) and only then grep, so a grep exit of 1 (no matches)
// on a file we know is readable correctly means "zero failures", not "unreadable".
func readAuthLog(ctx context.Context) (content string, readable, denied bool) {
	// Try auth.log (Debian/Ubuntu) then secure (RHEL/CentOS).
	return readAuthLogFrom(ctx, []string{"/var/log/auth.log", "/var/log/secure"})
}

// readAuthLogFrom is the testable core of readAuthLog over an explicit candidate
// list. (The permission-denied branch can't be exercised in CI, which runs as
// root and bypasses file modes — it is covered by a live non-root check.)
func readAuthLogFrom(ctx context.Context, candidates []string) (content string, readable, denied bool) {
	for _, path := range candidates {
		f, err := os.Open(path) // #nosec G304 -- fixed candidate list
		if err != nil {
			if os.IsPermission(err) {
				denied = true // exists but we can't read it
			}
			continue // absent or unreadable — try the next candidate
		}
		_ = f.Close()
		// Readable. grep exit 1 (no matches) is fine — the file opened, so an
		// empty result genuinely means no failed logins.
		out, _ := runCmd(ctx, "grep", "-E", "Failed password|Invalid user", path)
		return out, true, denied
	}
	return "", false, denied
}

// parseAuthLogLine is kept for unit tests
func parseAuthLogLine(line string) (ip string, isRoot bool) {
	lower := strings.ToLower(line)
	isRoot = strings.Contains(lower, "root")
	if i := strings.Index(line, " from "); i >= 0 {
		rest := line[i+6:]
		if j := strings.Index(rest, " port"); j >= 0 {
			ip = strings.TrimSpace(rest[:j])
		}
	}
	return ip, isRoot
}
