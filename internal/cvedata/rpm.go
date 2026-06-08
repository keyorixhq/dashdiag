//go:build linux

package cvedata

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// QueryInstalledRPM returns all installed RPM packages with their EVR.
// Works on SLES, openSUSE, RHEL, Rocky, Fedora.
func QueryInstalledRPM(ctx context.Context) ([]InstalledPackage, error) {
	if _, err := exec.LookPath("rpm"); err != nil {
		return nil, fmt.Errorf("rpm not available")
	}
	cmd := exec.CommandContext(ctx, "rpm", "-qa",
		"--queryformat", "%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE}\\n")
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
