//go:build linux

package collectors

import (
	"context"
	"os"
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
	if _, err := runCmd(ctx, "zypper", "--version"); err == nil {
		return collectZypper(ctx)
	}
	if _, err := runCmd(ctx, "dnf", "--version"); err == nil {
		return collectDNF(ctx)
	}
	if _, err := runCmd(ctx, "apt-get", "--version"); err == nil {
		return collectAPT(ctx)
	}
	return &models.PackagesInfo{PackageManager: "unknown"}, nil
}

// collectDNF parses security advisories for RHEL/Rocky/Fedora/CentOS.
// DNF4 (RHEL/Rocky): dnf updateinfo list security
// DNF5 (Fedora 41+): dnf advisory list --security
func collectDNF(ctx context.Context) (*models.PackagesInfo, error) {
	info := &models.PackagesInfo{PackageManager: "dnf"}

	// Check repos
	if reposOk := dnfHasUpdateRepo(ctx); !reposOk {
		info.StatusReason = "no enabled dnf repositories found"
		return info, nil
	}
	info.HasSecurityRepo = true

	// Try DNF5 syntax first (Fedora 41+), fall back to DNF4 (RHEL/Rocky)
	out, err := runCmd(ctx, "dnf", "advisory", "list", "--security", "--quiet")
	if err != nil {
		// DNF4 fallback: RHEL/Rocky/older Fedora
		out, err = runCmd(ctx, "dnf", "updateinfo", "list", "security", "--quiet")
	}
	if err != nil {
		info.StatusReason = "dnf advisory/updateinfo unavailable"
		return info, nil
	}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Last metadata") ||
			strings.HasPrefix(line, "Updating") || strings.HasPrefix(line, "Repositories") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// DNF5 format: ADVISORY-ID  type  severity  package  date
		// DNF4 format: ADVISORY-ID  severity/Sec.  package
		advisory := fields[0]
		var severity, pkg string
		if len(fields) >= 4 && !strings.Contains(fields[1], "/") && !strings.Contains(fields[1], "Sec") {
			// DNF5: advisory type severity package date
			severity = fields[2]
			pkg = fields[3]
		} else {
			// DNF4: advisory severity/Sec. package
			severity = fields[1]
			pkg = fields[2]
		}

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

	// Check sources.list for security repos before running apt-get.
	// If no security repo is configured, apt will never show security updates
	// and the collector will silently return 0 — worse than no data at all.
	if !aptHasSecurityRepo() {
		info.Status = "no-security-repo"
		info.StatusReason = "no security repository configured in apt sources — add security.debian.org or ubuntu security mirror"
		return info, nil
	}

	// apt-get update is NOT run here — too slow and requires root for lock.
	// We read whatever is cached; caller should ensure cache is fresh.
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

// aptHasSecurityRepo checks whether a security repository is configured
// in /etc/apt/sources.list and /etc/apt/sources.list.d/*.
// Returns false when no security repo is found — in that case the collector
// should surface a WARN rather than silently returning zero updates.
//
// Recognises:
//   - Debian: security.debian.org, *-security component
//   - Ubuntu: security.ubuntu.com, *-security pocket
func aptHasSecurityRepo() bool {
	paths := []string{"/etc/apt/sources.list"}

	// Include all .list and .sources files from sources.list.d/
	entries, _ := os.ReadDir("/etc/apt/sources.list.d")
	for _, e := range entries {
		if !e.IsDir() {
			paths = append(paths, "/etc/apt/sources.list.d/"+e.Name())
		}
	}

	for _, p := range paths {
		data, err := os.ReadFile(p) // #nosec G304 -- hardcoded known paths
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}
			lower := strings.ToLower(line)
			if strings.Contains(lower, "security.debian.org") ||
				strings.Contains(lower, "security.ubuntu.com") ||
				strings.Contains(lower, "-security") {
				return true
			}
		}
	}
	return false
}

// collectZypper parses `zypper list-patches --category security` for openSUSE/SLES.
// zypper list-patches exits 0 whether or not patches are available.
// Security patches are identified by category "security" in the output.
func collectZypper(ctx context.Context) (*models.PackagesInfo, error) {
	info := &models.PackagesInfo{PackageManager: "zypper"}

	// Check for security patches
	out, err := runCmd(ctx, "zypper", "--non-interactive", "--no-color",
		"list-patches", "--category", "security")
	if err != nil {
		// zypper may require root for full repo access — not a hard error
		info.StatusReason = "zypper list-patches unavailable (try running as root)"
		info.Status = "OK"
		info.StatusReason = "unable to check security patches"
		return info, nil
	}

	// Parse output — pipe-separated table:
	// Repository | Name | Category | Severity | Interactive | Status | Summary
	// Status is "needed", "not needed", "applied", or "not applicable"
	securityNeeded := 0
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)
		// Must be a security patch
		if !strings.Contains(lower, "security") {
			continue
		}
		// Only count patches with status exactly "needed" — not "not needed"
		fields := strings.Split(line, "|")
		if len(fields) < 6 {
			continue
		}
		status := strings.TrimSpace(strings.ToLower(fields[5]))
		if status != "needed" {
			continue
		}
		securityNeeded++
		severity := strings.TrimSpace(strings.ToLower(fields[3]))
		if severity == "critical" || severity == "important" {
			info.CriticalUpdates++
		}
		name := ""
		if len(fields) >= 2 {
			name = strings.TrimSpace(fields[1])
		}
		sev := "Moderate"
		switch severity {
		case "critical":
			sev = "Critical"
		case "important":
			sev = "Important"
		}
		info.Updates = append(info.Updates, models.PackageUpdate{
			Name:     name,
			Severity: sev,
			Advisory: name,
		})
	}

	info.SecurityUpdates = securityNeeded
	// CriticalUpdates already set inline per patch

	// Check if security repos are configured
	info.HasSecurityRepo = zypperHasSecurityRepo(ctx)
	if !info.HasSecurityRepo {
		info.StatusReason = "no security repository configured — add openSUSE security or SLES update repo"
	}

	return info, nil
}

// zypperHasSecurityRepo checks if a security-related repo is enabled.
// On SLES, security patches require SUSEConnect registration.
// On openSUSE Tumbleweed, update-tumbleweed is the security channel.
func zypperHasSecurityRepo(ctx context.Context) bool {
	out, err := runCmd(ctx, "zypper", "--non-interactive", "--no-color", "repos")
	if err != nil {
		return false
	}
	lower := strings.ToLower(out)
	for _, keyword := range []string{"security", "update", "sle-module", "opensuse-update", "tumbleweed"} {
		if strings.Contains(lower, keyword) {
			return true
		}
	}

	// SLES: check if SUSEConnect is registered — without it, no security repos
	if _, err := runCmd(ctx, "SUSEConnect", "--status"); err == nil {
		// SUSEConnect present — check if system is registered
		statusOut, _ := runCmd(ctx, "SUSEConnect", "--status")
		if strings.Contains(strings.ToLower(statusOut), "registered") {
			return true
		}
	}
	return false
}

// dnfHasUpdateRepo returns true when at least one enabled dnf repo is available.
// Rocky Linux and RHEL ship security updates via baseos — no separate security repo needed.
func dnfHasUpdateRepo(ctx context.Context) bool {
	out, err := runCmd(ctx, "dnf", "repolist", "--enabled", "-q")
	if err != nil {
		return false
	}
	lines := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			lines++
		}
	}
	return lines > 0
}
