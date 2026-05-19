package collectors

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// SessionsCollector reads active login sessions via `w -h`.
// Works on Linux and macOS (w is available on both).
// Used by dsd health to surface the [Active sessions] sub-check (Spec H1).
type SessionsCollector struct{}

func NewSessionsCollector() *SessionsCollector { return &SessionsCollector{} }

func (c *SessionsCollector) Name() string           { return "Sessions" }
func (c *SessionsCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *SessionsCollector) Collect(ctx context.Context) (interface{}, error) {
	out, err := runCmd(ctx, "w", "-h")
	if err != nil {
		// `w` not available — return empty, not an error
		return &models.SessionsInfo{}, nil
	}
	return parseSessions(out), nil
}

// parseSessions parses `w -h` output into a SessionsInfo.
//
// `w -h` column layout (Linux and macOS):
//
//	USER   TTY      FROM             LOGIN@   IDLE  JCPU   PCPU  WHAT
//	andrei pts/0    192.168.1.1      10:00    0.00s 0.01s  0.00s w -h
//	root   tty1                      09:00   55:12  0.02s  0.00s -bash
//
// FROM is absent when the login is local (physical terminal).
// IDLE format: seconds "0.00s", minutes+seconds "3:12", days "2days".
func parseSessions(out string) *models.SessionsInfo {
	info := &models.SessionsInfo{}
	uniqueIPs := map[string]bool{}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		// Minimum meaningful line: USER TTY LOGIN IDLE (4 fields)
		if len(fields) < 4 {
			continue
		}

		sess := models.Session{
			User: fields[0],
			TTY:  fields[1],
		}

		// Detect whether FROM column is present.
		// FROM is present when field[2] looks like an IP or hostname (not a time).
		// A time looks like "10:00" or "09:00am" — contains ":" or "am"/"pm".
		// An IP or hostname contains "." or ":" (IPv6) but not "am/pm".
		fromCandidate := fields[2]
		hasFrom := looksLikeHost(fromCandidate)

		if hasFrom {
			sess.From = fromCandidate
			// LOGIN@=fields[3], IDLE=fields[4]
			if len(fields) > 3 {
				sess.LoginAt = fields[3]
			}
			if len(fields) > 4 {
				sess.Idle = fields[4]
				sess.IdleSec = parseIdleSec(fields[4])
			}
			if len(fields) > 7 {
				sess.Command = strings.Join(fields[7:], " ")
			}
		} else {
			// No FROM column — local terminal
			sess.LoginAt = fields[2]
			sess.Idle = fields[3]
			sess.IdleSec = parseIdleSec(fields[3])
			if len(fields) > 6 {
				sess.Command = strings.Join(fields[6:], " ")
			}
		}

		info.Sessions = append(info.Sessions, sess)
		info.TotalCount++

		// Remote session detection
		if sess.From != "" && sess.From != "-" && sess.From != "0.0.0.0" {
			info.RemoteCount++
			ip := sess.From
			if host, _, err := net.SplitHostPort(sess.From); err == nil {
				ip = host
			}
			uniqueIPs[ip] = true
		}

		// Root logged in over SSH
		if sess.User == "root" && sess.From != "" && sess.From != "-" {
			info.RootSSH = true
		}

		// Long idle (> 8 hours = 28800 seconds)
		if sess.IdleSec > 28800 {
			info.LongIdle = append(info.LongIdle, sess.User)
		}
	}

	for ip := range uniqueIPs {
		info.UniqueIPs = append(info.UniqueIPs, ip)
	}
	return info
}

// looksLikeHost returns true when a string looks like a hostname or IP address
// rather than a login time. Login times look like "10:00", "9:00am", "Mon".
func looksLikeHost(s string) bool {
	if s == "-" {
		return false // explicit "no from" marker on some systems
	}
	// Times: contain ":" but followed by digits only (HH:MM), or contain am/pm
	lower := strings.ToLower(s)
	if strings.HasSuffix(lower, "am") || strings.HasSuffix(lower, "pm") {
		return false
	}
	// "Mon", "Tue" etc. — day-of-week login timestamps
	days := []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
	for _, d := range days {
		if strings.HasPrefix(lower, d) {
			return false
		}
	}
	// Contains "." (IPv4 or hostname) or is an IPv6 address
	if strings.Contains(s, ".") {
		return true
	}
	// IPv6 in brackets or raw
	if strings.Contains(s, ":") && strings.ContainsAny(s, "abcdefABCDEF[]") {
		return true
	}
	return false
}

// parseIdleSec converts w idle strings to seconds for threshold comparisons.
//
//	"0.00s" → 0
//	"3:12"  → 192  (3 min 12 sec)
//	"2days" → 172800
//	"1:00m" → 3600 (1 hour)
func parseIdleSec(s string) int {
	s = strings.TrimSpace(s)
	if s == "" || s == "?" {
		return 0
	}
	lower := strings.ToLower(s)

	// Days: "2days"
	if strings.HasSuffix(lower, "days") {
		var days int
		_, _ = strings.NewReader(lower), strings.TrimSuffix(lower, "days")
		// Parse leading digits
		numStr := strings.TrimSuffix(lower, "days")
		days = atoi(numStr)
		return days * 86400
	}
	// Seconds: "0.00s", "45s"
	if strings.HasSuffix(lower, "s") {
		n := parseFloatSimple(strings.TrimSuffix(lower, "s"))
		return int(n)
	}
	// Minutes via "m" suffix or "MM:SSm" format: "1:00m" = 1 hour? No.
	// w uses "MM:SS" for < 1h, "HH:MMm" for >= 1h.
	if strings.HasSuffix(lower, "m") {
		// "HH:MMm" — hours and minutes
		core := strings.TrimSuffix(lower, "m")
		if idx := strings.Index(core, ":"); idx > 0 {
			h := atoi(core[:idx])
			m := atoi(core[idx+1:])
			return h*3600 + m*60
		}
		return atoi(core) * 60
	}
	// "MM:SS" — minutes:seconds (no suffix)
	if idx := strings.Index(s, ":"); idx > 0 {
		m := atoi(s[:idx])
		sec := atoi(s[idx+1:])
		return m*60 + sec
	}
	return 0
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

func parseFloatSimple(s string) float64 {
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	}
	parts := strings.SplitN(s, ".", 2)
	whole := float64(atoi(parts[0]))
	frac := 0.0
	if len(parts) == 2 {
		f := float64(atoi(parts[1]))
		denom := 1.0
		for range parts[1] {
			denom *= 10
		}
		frac = f / denom
	}
	result := whole + frac
	if neg {
		return -result
	}
	return result
}
