//go:build linux

package collectors

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type AuditCollector struct{}

func NewAuditCollector() *AuditCollector         { return &AuditCollector{} }
func (c *AuditCollector) Name() string           { return "Auditd" }
func (c *AuditCollector) Timeout() time.Duration { return 4 * time.Second }

func (c *AuditCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.AuditInfo{}

	if _, err := lookPath("auditctl"); err != nil {
		return info, nil
	}
	info.Available = true

	// Check if the daemon is running. systemctl is-active fails on a non-systemd
	// host (OpenRC/SysV) even when auditd is running, which would false-alarm
	// "auditd installed but not running — compliance logging inactive" in the
	// verdict. Confirm via the running process too (matching /proc/<pid>/comm —
	// portable where `pgrep -x` is not; same fallback as cron detection).
	// internal-collectors-01-04: unlike cron's presence check (accuracy, not a
	// security control), a false "auditd is running" here suppresses a real
	// compliance WARN — a prctl(PR_SET_NAME)-renamed process could otherwise
	// spoof anyProcessNamed("auditd") by comm alone. verifiedAuditdRunning
	// additionally requires the matched PID's real /proc/<pid>/exe (kernel-set,
	// unspoofable) to resolve under a genuine system-binary directory.
	if _, err := runCmd(ctx, "systemctl", "is-active", "auditd"); err == nil {
		info.Running = true
	} else if verifiedAuditdRunning("/proc") {
		info.Running = true
	}

	// Rule count. auditctl -l typically requires root; on EACCES/failure the
	// zero value must not read as "genuinely zero rules loaded" — a non-root
	// run against a host with hundreds of loaded rules would otherwise report
	// rules_loaded=0, indistinguishable from an unconfigured auditd, to any
	// consumer (raw --json, a downstream compliance tool) reading the count
	// directly (internal-collectors-01-03).
	out, err := runCmd(ctx, "auditctl", "-l")
	if err == nil {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		for _, l := range lines {
			if strings.HasPrefix(l, "-") {
				info.RulesLoaded++
			}
		}
	} else {
		info.RulesUnreadable = true
	}

	// Audit log size. The 0700 root:root audit dir denies non-root — set an
	// explicit sentinel so that case isn't confused with a genuinely small log.
	if fi, err := statFile("/var/log/audit/audit.log"); err == nil {
		info.AuditLogSizeGB = float64(fi.Size) / (1024 * 1024 * 1024)
	} else {
		info.AuditLogSizeUnreadable = true
	}

	// Recent event count from audit log. Same false-OK risk as RulesLoaded
	// above — ausearch also typically requires root.
	out, err = runCmd(ctx, "ausearch", "-ts", "1hour ago", "--raw")
	if err == nil {
		info.EventsLast1h = strings.Count(out, "type=")
	} else {
		info.EventsUnreadable = true
	}

	return info, nil
}

func IsAuditdPresent() bool {
	_, err := lookPath("auditctl")
	return err == nil
}

func parseAuditctlRules(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "-") {
			n++
		}
	}
	return n
}

func parseAuditEventCount(out string) int {
	return strings.Count(out, "type=")
}

// auditdBinDirPrefixes lists root-owned system directories under which
// auditd's real executable must live for verifiedAuditdRunning to trust a
// comm=="auditd" match. Mirrors internal/analysis/heuristics_security.go's
// exePathUnderSystemDir/systemBinDirPrefixes (internal-analysis-08-02) —
// collectors cannot import analysis (layering: collectors -> models,
// platform, source ONLY), so this is a small, independently-owned duplicate
// of the same ~10-line check rather than a cross-layer import. The security
// property that matters is shared: an unprivileged local user cannot write
// into any of these paths without already having root, so a renamed
// backdoor copied to $HOME/tmp/etc. can never satisfy this prefix check no
// matter what it calls itself.
var auditdBinDirPrefixes = []string{
	"/usr/", "/bin/", "/sbin/", "/opt/", "/snap/",
}

// exePathUnderSystemDir reports whether path is a real, non-empty path
// falling under one of auditdBinDirPrefixes.
func exePathUnderSystemDir(path string) bool {
	if path == "" {
		return false
	}
	cleaned := filepath.Clean(path)
	for _, prefix := range auditdBinDirPrefixes {
		if strings.HasPrefix(cleaned, prefix) {
			return true
		}
	}
	return false
}

// verifiedAuditdRunning reports whether a process named "auditd" is running,
// corroborated where possible by its kernel-set /proc/<pid>/exe path
// resolving under a real system-binary directory — not just its
// self-reported /proc/<pid>/comm, which is spoofable via
// prctl(PR_SET_NAME) (internal-collectors-01-04: the same threat shape
// closed for network-listener attribution by internal-analysis-08-02's
// exePathUnderSystemDir). A comm match whose /exe resolves OUTSIDE a system
// dir is the spoofing case this closes and is never trusted. A comm match
// whose /exe can't be resolved at all (permission denied, or the process
// exited mid-scan) falls back to the collector's pre-fix posture — still
// counted as running — so this hardening only ever makes a false "running"
// harder to fake, never a genuine non-root read failure worse than it
// already was.
func verifiedAuditdRunning(procDir string) bool {
	entries, err := readDirEntries(procDir)
	if err != nil {
		return false
	}
	unverifiable := false
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue // not a PID directory
		}
		data, err := readFile(filepath.Join(procDir, e.Name(), "comm")) // #nosec G304 -- /proc/<pid>/comm
		if err != nil {
			continue // process exited or comm unreadable — skip
		}
		if strings.TrimSpace(string(data)) != "auditd" {
			continue
		}
		target, err := readLink(filepath.Join(procDir, e.Name(), "exe")) // #nosec G304 -- /proc/<pid>/exe
		if err != nil {
			// Can't corroborate or refute this match — remember it as a
			// fallback; a later PID in the scan may still verify cleanly.
			unverifiable = true
			continue
		}
		if exePathUnderSystemDir(target) {
			return true
		}
		// exe resolved but points outside any real system-binary directory —
		// the spoofing case. Do not count it; keep scanning in case a genuine
		// auditd is also present under a different PID.
	}
	return unverifiable
}
