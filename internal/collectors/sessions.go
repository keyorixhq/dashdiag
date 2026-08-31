package collectors

import (
	"context"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// w LOGIN@ shapes that must never be mistaken for a FROM host:
//   - a day-of-week, optionally with a time/hour suffix: "Mon", "Tue08", "Wed14"
//   - a "DDmonYY" date stamp: "23Jun24"
//
// Both patterns are deliberately narrow, not (?i)/any-3-letters, per
// internal-collectors-30-02: dsd forces LC_ALL=C/LANG=C on every subprocess
// it runs (platform.HardenedEnv), so `w`'s weekday/month abbreviations always
// come out in the fixed C-locale title case ("Mon", "Jun", never "mon" or
// "MON") — anchoring to that exact, guaranteed shape is real corroboration,
// not a guess, and it stops a real (if unusual) short hostname like "sun" or
// "mon" — or a hostname that happens to be shaped like "23xyz24" under the
// old any-3-letters date pattern — from being misclassified as a LOGIN@
// artifact and silently losing its RemoteCount/RootSSH attribution.
var (
	wDayLogin  = regexp.MustCompile(`^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\d*$`)
	wDateLogin = regexp.MustCompile(`^\d{1,2}(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\d{2}$`)
	// wAmPmLogin matches a 12-hour LOGIN@ time stamp ("9am", "9:00am",
	// "12:30PM") — never a host, since it requires the WHOLE string to start
	// with digits and end in exactly "am"/"pm". Deliberately narrower than a
	// bare HasSuffix(s, "am"/"pm") check (see looksLikeHost).
	wAmPmLogin = regexp.MustCompile(`(?i)^\d{1,2}(:\d{2})?\s*(am|pm)$`)
)

// SessionsCollector reads active login sessions via `w -h`.
// Works on Linux and macOS (w is available on both).
// Used by dsd health to surface the [Active sessions] sub-check (Spec H1).
type SessionsCollector struct{}

func NewSessionsCollector() *SessionsCollector { return &SessionsCollector{} }

func (c *SessionsCollector) Name() string           { return "Sessions" }
func (c *SessionsCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *SessionsCollector) Collect(ctx context.Context) (any, error) {
	out, err := runCmd(ctx, "w", "-h")
	if err != nil {
		// `w` not available — return empty, not an error
		return &models.SessionsInfo{}, nil
	}
	info := parseSessions(out)
	// PVE requires root SSH for cluster management; record it so the root-SSH
	// finding can be exempted (matching checkSecurity's PermitRootLogin handling).
	info.IsPVE = IsPVEHost()
	info.Checked = true
	return info, nil
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

	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		// Minimum meaningful line: USER TTY LOGIN IDLE (4 fields)
		if len(fields) < 4 {
			continue
		}

		sess := models.Session{User: fields[0]}

		// Resolve the variable columns after USER. The canonical layout is
		// TTY [FROM] LOGIN@ IDLE JCPU PCPU WHAT, but two columns can be blank and
		// strings.Fields collapses them:
		//   - FROM is blank for a local console login (the original case).
		//   - TTY is blank for a PTY-LESS session — a non-interactive `ssh host cmd`
		//     or an sshd priv-sep entry shows up as `<blank> 1.2.3.4 ...`. Reading
		//     fields[1] as the TTY then stored the FROM IP as the TTY and lost the
		//     remote attribution entirely (RemoteCount stayed 0 — a false-OK).
		// rest is the slice starting at LOGIN@ once TTY/FROM are consumed.
		var rest []string
		switch {
		case isTTYName(fields[1]):
			sess.TTY = fields[1]
			if looksLikeHost(fields[2]) { // FROM present (host/IP, or "-")
				sess.From = fields[2]
				rest = fields[3:]
			} else { // FROM column blank — local console
				rest = fields[2:]
			}
		case looksLikeHost(fields[1]):
			// TTY column blank — fields[1] is the FROM (pty-less session).
			sess.From = fields[1]
			rest = fields[2:]
		default:
			// Unrecognised fields[1] — treat it as the TTY (prior behaviour).
			sess.TTY = fields[1]
			rest = fields[2:]
		}

		// rest = LOGIN@ IDLE JCPU PCPU WHAT...
		if len(rest) > 0 {
			sess.LoginAt = rest[0]
		}
		if len(rest) > 1 {
			sess.Idle = rest[1]
			sess.IdleSec = parseIdleSec(rest[1])
		}
		if len(rest) > 4 {
			sess.Command = strings.Join(rest[4:], " ")
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

// isTTYName reports whether a `w` column value is a terminal name rather than a
// FROM host or a LOGIN@ stamp. Used to tell whether the TTY column is present:
// it is blank for a pty-less session, where the next field is the FROM host.
// Covers Linux (tty1, ttyS0, pts/0, console) and macOS (ttys000), plus an X
// display seat (":0", ":0.0" — colon followed by a digit, distinct from an IPv6
// FROM like "::1").
func isTTYName(s string) bool {
	switch {
	case strings.HasPrefix(s, "tty"), strings.HasPrefix(s, "pts"):
		return true
	case s == "console":
		return true
	case len(s) >= 2 && s[0] == ':' && s[1] >= '0' && s[1] <= '9':
		return true
	default:
		return false
	}
}

// looksLikeHost returns true when the `w` FROM-column candidate is a hostname or
// IP rather than a LOGIN@ timestamp. It must recognise bare LAN hostnames with no
// dot (e.g. "workstation") — missing those previously misclassified a remote root
// SSH session as a local console, defeating the RootSSH security signal.
func looksLikeHost(s string) bool {
	if s == "" {
		return false
	}
	if s == "-" {
		// "-" IS the FROM column — the local-login marker `w` prints for a console
		// session. Treating it as "no FROM column" took the column-shifted branch and
		// mis-read LOGIN@/IDLE/command. It's a present (empty) FROM; the remote/RootSSH
		// checks already exclude From=="-".
		return true
	}
	// IPv4/FQDN always contain a dot, and none of the LOGIN@ timestamp shapes
	// this function guards against (12-hour time, day-of-week, date stamp)
	// ever do — so a dot is checked FIRST, before any timestamp-shape
	// heuristic below, making it an unambiguous, unspoofable "this is a
	// host" signal. This used to run last (as the "IPv4/FQDN have a dot"
	// check below), which let a dotted hostname ending in "am"/"pm" (e.g. a
	// real host under the .pm ccTLD, or a domain an attacker controls) be
	// misclassified as a LOGIN@ time stamp by the suffix check that ran
	// first — and with `UseDNS` sshd logs the resolved PTR hostname as the
	// FROM value, so an attacker who controls their own reverse-DNS record
	// could pick one ending in "am"/"pm" to suppress the RemoteCount/RootSSH
	// signal for their own login (Finding: internal-collectors-30-02).
	if strings.Contains(s, ".") {
		return true
	}
	// "9am" / "9:00pm" — a 12-hour login time, never a host. Anchored to the
	// WHOLE string (wAmPmLogin), not a bare suffix check, so it can't fire
	// on an ordinary word that merely ends in "am"/"pm".
	if wAmPmLogin.MatchString(s) {
		return false
	}
	// A colon means either a time ("10:00" — digits before the colon) or an IPv6
	// host ("fe80::1" — non-digits before the colon).
	if before, _, ok := strings.Cut(s, ":"); ok {
		return !isAllDigits(before)
	}
	// Day-of-week / date login stamps ("Mon", "Tue08", "23Jun24").
	if wDayLogin.MatchString(s) || wDateLogin.MatchString(s) {
		return false
	}
	// A bare (dotless) hostname contains a letter.
	return strings.IndexFunc(s, func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
	}) >= 0
}

// isAllDigits reports whether s is non-empty and contains only ASCII digits.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
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
	if before, ok := strings.CutSuffix(lower, "s"); ok {
		n := parseFloatSimple(before)
		return int(n)
	}
	// Minutes via "m" suffix or "MM:SSm" format: "1:00m" = 1 hour? No.
	// w uses "MM:SS" for < 1h, "HH:MMm" for >= 1h.
	if before, ok := strings.CutSuffix(lower, "m"); ok {
		// "HH:MMm" — hours and minutes
		core := before
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
