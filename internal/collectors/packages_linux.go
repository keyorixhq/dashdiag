//go:build linux

package collectors

import (
	"context"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// PackagesCollector checks for available security updates.
// This collector intentionally shells out — there is no kernel interface
// for package state. Distro detection happens at collection time.
type PackagesCollector struct{}

func NewPackagesCollector() *PackagesCollector { return &PackagesCollector{} }

func (c *PackagesCollector) Name() string           { return "Packages" }
func (c *PackagesCollector) Timeout() time.Duration { return 30 * time.Second }

func (c *PackagesCollector) Collect(ctx context.Context) (interface{}, error) {
	// Detect package manager
	if _, err := runCmd(ctx, "dnf", "--version"); err == nil {
		return collectDNF(ctx)
	}
	if _, err := runCmd(ctx, "apt-get", "--version"); err == nil {
		return collectAPT(ctx)
	}
	return &models.PackagesInfo{PackageManager: "unknown"}, nil
}

// collectDNF parses `dnf updateinfo list security` for RHEL/Fedora/CentOS.
// Output format: "RHSA-2026:1234 Critical/Sec. package-1.2.3-4.el10.x86_64"
// dnf check-update exits 100 if updates available, 0 if up to date.
func collectDNF(ctx context.Context) (*models.PackagesInfo, error) {
	info := &models.PackagesInfo{PackageManager: "dnf"}

	out, err := runCmd(ctx, "dnf", "updateinfo", "list", "security", "--quiet")
	if err != nil {
		// dnf may not have updateinfo data without subscription — not a hard error
		info.StatusReason = "dnf updateinfo unavailable"
		return info, nil
	}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Last metadata") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		advisory := fields[0] // RHSA-2026:1234
		severity := fields[1] // Critical/Sec. or Important/Sec.
		pkg := fields[2]      // package-version.arch

		// Normalise severity
		sev := "Low"
		sevLower := strings.ToLower(severity)
		switch {
		case strings.HasPrefix(sevLower, "critical"):
			sev = "Critical"
			info.CriticalUpdates++
		case strings.HasPrefix(sevLower, "important"):
			sev = "Important"
			info.ImportantUpdates++
		case strings.HasPrefix(sevLower, "moderate"):
			sev = "Moderate"
		}

		info.SecurityUpdates++
		info.Updates = append(info.Updates, models.PackageUpdate{
			Name:     pkg,
			Severity: sev,
			Advisory: advisory,
		})
	}
	return info, nil
}

// collectAPT parses `apt-get -s upgrade` for Debian/Ubuntu security updates.
func collectAPT(ctx context.Context) (*models.PackagesInfo, error) {
	info := &models.PackagesInfo{PackageManager: "apt"}

	out, err := runCmd(ctx, "apt-get", "-s", "upgrade")
	if err != nil {
		info.StatusReason = "apt-get unavailable"
		return info, nil
	}

	for _, line := range strings.Split(out, "\n") {
		// "Inst nginx [1.18.0] (1.24.0 Ubuntu:22.04/jammy-security [amd64])"
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		if !strings.Contains(strings.ToLower(line), "security") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		info.SecurityUpdates++
		info.Updates = append(info.Updates, models.PackageUpdate{
			Name:     fields[1],
			Severity: "Unknown",
		})
	}
	return info, nil
}
