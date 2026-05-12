package collectors

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type KernelSecurityCollector struct{}

func NewKernelSecurityCollector() *KernelSecurityCollector { return &KernelSecurityCollector{} }

func (c *KernelSecurityCollector) Name() string           { return "KernelSec" }
func (c *KernelSecurityCollector) Timeout() time.Duration { return 5 * time.Second }

// parseSELinuxMode normalises getenforce output to lowercase.
func parseSELinuxMode(out string) string {
	return strings.ToLower(strings.TrimSpace(out))
}

func collectSELinux(ctx context.Context) (present bool, mode string, denials int) {
	out, err := exec.CommandContext(ctx, "getenforce").Output()
	if err != nil {
		return false, "", 0
	}
	mode = parseSELinuxMode(string(out))
	present = true
	if mode != "enforcing" {
		return present, mode, 0
	}

	// Prefer reading /var/log/audit/audit.log directly — when auditd is running
	// it intercepts AVC messages at the audit socket, so they never reach journald.
	// Falling back to journald handles the rare case where auditd is absent.
	if n, ok := countAVCsFromAuditLog(1 * time.Hour); ok {
		return present, mode, n
	}

	// Fallback: journald (works only when auditd is NOT running)
	jout, err := exec.CommandContext(ctx, "journalctl",
		"--since=1 hour ago", "--no-pager", "-q").Output()
	if err != nil {
		return present, mode, 0
	}
	denials = strings.Count(string(jout), "avc:  denied")
	return present, mode, denials
}

// countAVCsFromAuditLog reads /var/log/audit/audit.log and counts type=AVC
// entries whose Unix timestamp falls within the last window duration.
// Returns (count, true) on success, (0, false) if the file is unreadable.
func countAVCsFromAuditLog(window time.Duration) (int, bool) {
	f, err := os.Open("/var/log/audit/audit.log") // #nosec G304
	if err != nil {
		return 0, false // requires root — signal caller to try fallback
	}
	defer f.Close() //nolint:errcheck

	cutoff := time.Now().Add(-window)
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "type=AVC") {
			continue
		}
		// Parse Unix timestamp from: msg=audit(1715000000.000:1)
		idx := strings.Index(line, "msg=audit(")
		if idx < 0 {
			continue
		}
		rest := line[idx+10:]
		dotIdx := strings.IndexByte(rest, '.')
		if dotIdx <= 0 {
			continue
		}
		sec, err := strconv.ParseInt(rest[:dotIdx], 10, 64)
		if err != nil {
			continue
		}
		if time.Unix(sec, 0).After(cutoff) {
			count++
		}
	}
	return count, true
}

func apparmorEnabled() bool {
	data, err := os.ReadFile("/sys/module/apparmor/parameters/enabled")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "Y"
}

// apparmorMode returns the AppArmor enforcement mode by inspecting the
// loaded profiles list. Distinguishes three outcomes:
//   - "enforce" / "complain" / "disabled": confirmed mode
//   - "unknown": cannot determine mode (typically EACCES because
//     /sys/kernel/security/apparmor/profiles is root-readable only).
//
// The EACCES distinction matters: on Ubuntu and most Debian-family
// systems the profiles file is mode 0440 root:root. As non-root, the
// previous behaviour was to silently report "disabled" — a wrong
// system-fact claim. Reporting "unknown" lets the analysis layer
// surface the privilege limitation honestly instead of producing a
// false "no kernel security module enforcing" verdict.
func apparmorMode() string {
	return apparmorModeFromPath("/sys/kernel/security/apparmor/profiles")
}

func apparmorModeFromPath(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsPermission(err) {
			return "unknown"
		}
		return "disabled"
	}
	return parseApparmorProfiles(string(data))
}

func parseApparmorProfiles(data string) string {
	for _, line := range strings.Split(data, "\n") {
		if strings.HasSuffix(line, "(enforce)") {
			return "enforce"
		}
		if strings.HasSuffix(line, "(complain)") {
			return "complain"
		}
	}
	return "disabled"
}

func (c *KernelSecurityCollector) Collect(ctx context.Context) (interface{}, error) {
	if runtime.GOOS == "darwin" {
		return &models.KernelSecurityInfo{}, nil
	}

	sePresent, seMode, seDenials := collectSELinux(ctx)
	aaPresent := apparmorEnabled()
	aaMode := ""
	if aaPresent {
		aaMode = apparmorMode()
	}

	return &models.KernelSecurityInfo{
		SELinuxPresent:  sePresent,
		SELinuxMode:     seMode,
		SELinuxDenials:  seDenials,
		AppArmorPresent: aaPresent,
		AppArmorMode:    aaMode,
	}, nil
}
