//go:build linux

package collectors

import (
	"bufio"
	"context"
	"os"
	"regexp"
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
		ip, isRoot := parseAuthLogLine(line)
		if isRoot {
			info.RootAttempts++
		}
		if ip != "" {
			counts[ip]++
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
	// count desc, then source asc — the key tiebreaker keeps the top-N deterministic
	// (counts is a map; without it ties keep random iteration order). TRIAGE §I.
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].v != sorted[j].v {
			return sorted[i].v > sorted[j].v
		}
		return sorted[i].k < sorted[j].k
	})
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

	// Read the effective sshd auth policy so the brute-force verdict can be
	// config-aware. Reuse the security collector's SSH parser (same package) and
	// trust it ONLY when it came from `sshd -T` (the fully merged, authoritative
	// config) — the file-parse fallback leaves PasswordAuthentication at its zero
	// value when the directive is absent, which is indistinguishable from an
	// explicit "no", and acting on that would risk a false "you're safe" downgrade.
	var sec models.SecurityInfo
	parseSSHConfig(ctx, &sec)
	if sec.SSHAuditSource == "sshd -T" {
		info.SSHConfigChecked = true
		info.PasswordAuthEnabled = sec.SSHPasswordAuth
		info.RootPasswordLoginAllowed = sec.SSHRootLogin // PermitRootLogin yes
	}
	return info, nil
}

// readAuthLog scans the system auth logs for failed-login lines. It returns the
// matching lines, whether any candidate file was actually readable, and whether a
// candidate existed but was permission-denied. The readable/denied distinction is
// what lets the caller tell "no failed logins" (readable, empty) apart from "could
// not read the log" (denied) — the latter must not be reported as a clean host.
//
// We probe readability with openFile (which distinguishes permission-denied from
// absent via os.IsPermission) and only then grep, so a grep exit of 1 (no matches)
// on a file we know is readable correctly means "zero failures", not "unreadable".
func readAuthLog(ctx context.Context) (content string, readable, denied bool) {
	// Try auth.log (Debian/Ubuntu), then secure (RHEL/CentOS), then messages. The
	// last covers busybox/Alpine (and other minimal syslog setups), which have no
	// separate auth log — sshd's "Failed password"/"Invalid user" lines land in the
	// general /var/log/messages. Without it, dsd missed SSH brute-force attempts on
	// those hosts and reported "no failed logins" (a security false-OK). The
	// first-readable-file order means messages is only consulted when auth.log and
	// secure are both absent, so it never double-counts on Debian/RHEL.
	return readAuthLogFrom(ctx, []string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages"})
}

// readAuthLogFrom is the testable core of readAuthLog over an explicit candidate
// list. (The permission-denied branch can't be exercised in CI, which runs as
// root and bypasses file modes — it is covered by a live non-root check.)
func readAuthLogFrom(ctx context.Context, candidates []string) (content string, readable, denied bool) {
	for _, path := range candidates {
		f, err := openFile(path) // #nosec G304 -- fixed candidate list
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

// sshLoginMarkerRe matches the fixed, sshd-authored text that always precedes
// the attacker-controlled username field in a failed-login log line. Because
// these markers are written by sshd itself and the username always comes
// after them, the FIRST occurrence in the line is always the genuine one —
// anything a crafted username echoes back to mimic a marker can only appear
// later, inside the username's own text.
var sshLoginMarkerRe = regexp.MustCompile(`Failed password for (?:invalid user )?|Invalid user |Connection closed by authenticating user `)

// sshFromPortRe matches the "from <ip> port <port>" suffix sshd appends
// after the username in "Failed password"/"Invalid user" lines.
var sshFromPortRe = regexp.MustCompile(`from (\S+) port \d+`)

// parseAuthLogLine extracts the source IP and whether a failed-login attempt
// targeted the root account from a single sshd auth-log line. Handles both
// journalctl -o cat output (bare message) and syslog-formatted auth.log/
// secure/messages lines (with a "Jul 8 10:00:00 host sshd[123]: " prefix).
//
// sshd logs the attacker-supplied username verbatim, and that username is
// arbitrary attacker-chosen text — it can itself contain a fake
// " from <ip> port <port>" sequence, or the substring "root". A naive
// first-match-anywhere-in-the-line search picks up the attacker's fake
// fields instead of the real ones sshd appended. This parser is anchored
// against that: the username is bracketed between the FIRST marker match
// (always genuine, sshd-authored) and the LAST "from <ip> port <port>"
// match (always genuine — sshd appends the real one after the username, so
// it is necessarily the rightmost occurrence). Only the exact bracketed
// username is compared against "root", not the whole line.
func parseAuthLogLine(line string) (ip string, isRoot bool) {
	loc := sshLoginMarkerRe.FindStringIndex(line)
	if loc == nil {
		return "", false
	}
	marker := line[loc[0]:loc[1]]
	rest := line[loc[1]:]

	if strings.HasPrefix(marker, "Connection closed") {
		// This message shape has no "from" keyword — the IP follows the
		// username directly with no unambiguous delimiter, so (matching
		// prior behavior) no IP is extracted here. Only the first
		// whitespace-delimited token — the username — is checked for root.
		user, _, _ := strings.Cut(rest, " ")
		return "", user == "root"
	}

	matches := sshFromPortRe.FindAllStringIndex(rest, -1)
	if len(matches) == 0 {
		return "", false
	}
	last := matches[len(matches)-1]
	user := strings.TrimSpace(rest[:last[0]])
	if fields := strings.Fields(rest[last[0]:last[1]]); len(fields) >= 2 {
		ip = fields[1]
	}
	return ip, user == "root"
}
