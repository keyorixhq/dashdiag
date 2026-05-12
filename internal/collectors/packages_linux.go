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
// Severity is classified by package importance since Debian does not embed
// CVE severity in apt package metadata. Critical packages (kernel, openssl,
// openssh, glibc, curl) are flagged Critical; all others are Important.
// Only packages from security repos (*-security, *-security-updates) are counted.
func collectAPT(ctx context.Context) (*models.PackagesInfo, error) {
	info := &models.PackagesInfo{PackageManager: "apt"}

	// apt-get update is NOT run here — too slow and requires root for lock.
	// Caller should ensure apt cache is fresh (e.g. via unattended-upgrades
	// or periodic cron). We read whatever is cached.
	out, err := runCmd(ctx, "apt-get", "-s", "upgrade")
	if err != nil {
		// apt-get -s (simulate) requires no lock but may fail without root
		info.StatusReason = "apt-get unavailable"
		return info, nil
	}

	// Packages considered critical — kernel, crypto, core libs, remote access
	criticalPkgs := map[string]bool{
		"linux-image": true, "linux-headers": true, "linux-libc-dev": true,
		"openssl": true, "libssl": true, "libssl3": true, "libssl3t64": true,
		"openssh-server": true, "openssh-client": true, "openssh-sftp-server": true,
		"libc6": true, "libc-bin": true, "libc-dev-bin": true,
		"curl": true, "libcurl4": true, "libcurl4t64": true,
		"wget": true, "sudo": true, "util-linux": true,
		"bash": true, "perl": true, "perl-base": true,
		"libgnutls30": true, "libgnutls30t64": true,
		"python3": true, "python3-minimal": true, "libpython3": true,
		"nss": true, "libnss3": true,
		"ca-certificates": true, "apt": true, "dpkg": true,
	}

	for _, line := range strings.Split(out, "\n") {
		// Format: "Inst pkgname [oldver] (newver Source:suite/component [arch])"
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}

		// Only count packages from security repositories
		lineLower := strings.ToLower(line)
		if !strings.Contains(lineLower, "-security") &&
			!strings.Contains(lineLower, "security-updates") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pkgName := fields[1]

		// Classify severity by package base name
		sev := "Important"
		for critPrefix := range criticalPkgs {
			if pkgName == critPrefix || strings.HasPrefix(pkgName, critPrefix+"-") {
				sev = "Critical"
				break
			}
		}

		if sev == "Critical" {
			info.CriticalUpdates++
		} else {
			info.ImportantUpdates++
		}
		info.SecurityUpdates++
		info.Updates = append(info.Updates, models.PackageUpdate{
			Name:     pkgName,
			Severity: sev,
			// No DSA advisory number in apt-get -s upgrade output.
			// Future: query security-tracker.debian.org/tracker/data/json
		})
	}

	if info.SecurityUpdates == 0 && !strings.Contains(out, "0 upgraded") {
		// apt cache may be stale — no security repo configured or cache not updated
		info.StatusReason = "no security updates found — ensure security repo is configured and apt cache is current"
	}

	return info, nil
}
