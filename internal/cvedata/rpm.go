//go:build linux

package cvedata

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/platform"
)

// resolveRPM resolves "rpm" to an absolute path via platform.ResolveTrustedTool
// (trusted system dirs, never the process's inherited $PATH) — dsd routinely
// runs as root for CVE scanning, and this same binary name is what
// inventory.countRPM already resolves this way; QueryInstalledRPM previously
// didn't, exec'ing a bare "rpm" that let Go's os/exec perform its own
// untrusted $PATH search. A var so tests can point it at a fake binary.
var resolveRPM = platform.ResolveTrustedTool

// QueryInstalledRPM returns all installed RPM packages with their EVR.
// Works on SLES, openSUSE, RHEL, Rocky, Fedora.
func QueryInstalledRPM(ctx context.Context) ([]InstalledPackage, error) {
	rpmPath := resolveRPM("rpm")
	if _, err := exec.LookPath(rpmPath); err != nil {
		return nil, fmt.Errorf("rpm not available")
	}
	cmd := exec.CommandContext(ctx, rpmPath, "-qa", // NOSONAR — hardcoded binary
		"--queryformat", "%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE}\\n")
	cmd.Env = platform.HardenedEnv()
	cmd.WaitDelay = platform.ExecWaitDelay
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("rpm -qa: %w", err)
	}
	var pkgs []InstalledPackage
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		evr := parts[1]
		// rpm outputs "(none)" for missing epoch — normalise to "0"
		evr = strings.ReplaceAll(evr, "(none):", "0:")
		pkgs = append(pkgs, InstalledPackage{Name: parts[0], EVR: evr})
	}
	return pkgs, nil
}

// IsVulnerable returns true when the installed EVR is older than fixedIn, using
// a proper RPM epoch/version/release comparison (compareEVR) rather than a
// lexicographic string compare.
func IsVulnerable(installed, fixedIn string) bool {
	return compareEVR(installed, fixedIn) < 0
}
