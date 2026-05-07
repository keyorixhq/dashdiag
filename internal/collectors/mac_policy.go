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

type MACPolicyCollector struct{}

func NewMACPolicyCollector() *MACPolicyCollector { return &MACPolicyCollector{} }

func (c *MACPolicyCollector) Name() string           { return "MACPolicy" }
func (c *MACPolicyCollector) Timeout() time.Duration { return 5 * time.Second }

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

func apparmorMode() string {
	data, err := os.ReadFile("/sys/kernel/security/apparmor/profiles")
	if err != nil {
		return "disabled"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasSuffix(line, "(enforce)") {
			return "enforce"
		}
		if strings.HasSuffix(line, "(complain)") {
			return "complain"
		}
	}
	return "disabled"
}

func (c *MACPolicyCollector) Collect(ctx context.Context) (interface{}, error) {
	if runtime.GOOS == "darwin" {
		return &models.MACPolicyInfo{}, nil
	}

	sePresent, seMode, seDenials := collectSELinux(ctx)
	aaPresent := apparmorEnabled()
	aaMode := ""
	if aaPresent {
		aaMode = apparmorMode()
	}

	return &models.MACPolicyInfo{
		SELinuxPresent:  sePresent,
		SELinuxMode:     seMode,
		SELinuxDenials:  seDenials,
		AppArmorPresent: aaPresent,
		AppArmorMode:    aaMode,
	}, nil
}
