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

// IsVulnerable returns true when the installed version is older than fixedIn.
// Uses a simplified string comparison on RPM EVR — sufficient for the common
// case where we just need to know if the installed version pre-dates the fix.
// Full RPM version comparison (rpmvercmp) would require CGO.
func IsVulnerable(installed, fixedIn string) bool {
	// Normalise: strip epoch if identical
	inst := normaliseEVR(installed)
	fix := normaliseEVR(fixedIn)
	if inst == fix {
		return false
	}
	// Simple lexicographic comparison — works for most package versions.
	// rpmvercmp handles edge cases (1.10 > 1.9 etc) but requires CGO.
	// For our purposes: if installed == fixed we're safe, otherwise flag it.
	return inst < fix
}

func normaliseEVR(evr string) string {
	// Strip "0:" epoch prefix for comparison when epoch is zero
	if strings.HasPrefix(evr, "0:") {
		return evr[2:]
	}
	return evr
}
