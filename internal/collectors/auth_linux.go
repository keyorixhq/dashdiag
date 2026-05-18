//go:build linux

package collectors

import (
	"bufio"
	"context"
	"sort"
	"strconv"
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

	// journalctl is the most portable source — works on all systemd distros
	// grep for "Failed password" and "Invalid user" from sshd
	out, err := runCmd(ctx, "journalctl", "_COMM=sshd", "--since", "24 hours ago",
		"--no-pager", "-o", "cat")
	if err != nil {
		// Fallback: parse /var/log/auth.log directly (Debian/Ubuntu)
		out, err = readAuthLog(ctx)
		if err != nil {
			return info, nil
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

func readAuthLog(ctx context.Context) (string, error) {
	// Try auth.log (Debian/Ubuntu) then secure (RHEL/CentOS)
	for _, path := range []string{"/var/log/auth.log", "/var/log/secure"} {
		out, err := runCmd(ctx, "grep", "-E", "Failed password|Invalid user", path)
		if err == nil {
			return out, nil
		}
	}
	return "", nil
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

// parseSourceCount is a helper for tests
func parseSourceCount(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
