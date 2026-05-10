package collectors

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type KernelSecurityCollector struct{}

func NewKernelSecurityCollector() *KernelSecurityCollector { return &KernelSecurityCollector{} }

func (c *KernelSecurityCollector) Name() string           { return "KernelSecurity" }
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
	jout, err := exec.CommandContext(ctx, "journalctl",
		"--since=1 hour ago", "--no-pager", "-q").Output()
	if err != nil {
		return present, mode, 0
	}
	denials = strings.Count(string(jout), "avc:  denied")
	return present, mode, denials
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
