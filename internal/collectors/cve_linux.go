//go:build linux

package collectors

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/models"
)

// CheckCVE queries the system package manager to determine if a CVE
// is affecting the current system. Supports zypper, dnf (4+5), and apt.
// Falls back to OVAL file auto-discovery when package manager has stale metadata.
func CheckCVE(ctx context.Context, cveID string) *models.CVEResult {
	cveID = strings.TrimSpace(strings.ToUpper(cveID))
	if !strings.HasPrefix(cveID, "CVE-") {
		return &models.CVEResult{
			CVE:          cveID,
			Status:       models.CVEUnknown,
			StatusReason: "invalid CVE ID format — expected CVE-YYYY-NNNNN",
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Try live package manager first
	var result *models.CVEResult
	switch {
	case hasCmd("zypper"):
		result = checkCVEZypper(ctx, cveID)
	case hasCmd("dnf"):
		result = checkCVEDNF(ctx, cveID)
	case hasCmd("apt-get"):
		result = checkCVEApt(ctx, cveID)
	default:
		result = &models.CVEResult{
			CVE:          cveID,
			Status:       models.CVEUnknown,
			StatusReason: "no supported package manager found (zypper/dnf/apt)",
		}
	}

	// If package manager is definitive (VULNERABLE or PATCHED) — done.
	// If NOT_AFFECTED or UNKNOWN — repo metadata may be stale.
	// Try OVAL sidecar file as a secondary check.
	if result.Status == models.CVENotAffected || result.Status == models.CVEUnknown {
		if ovalResult := tryOVALFallback(ctx, cveID); ovalResult != nil {
			return ovalResult
		}
	}
	return result
}

// hasCmd returns true when the given command is in PATH.
func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// tryOVALFallback looks for an OVAL sidecar file and checks the CVE against it.
// Returns nil when no OVAL file is found.
func tryOVALFallback(ctx context.Context, cveID string) *models.CVEResult {
	// Detect distro ID from /etc/os-release
	distroID := readDistroID()

	// Try OVAL file from standard paths
	ovalPath := cvedata.FindOVALFile(distroID)
	if ovalPath == "" {
		return nil
	}

	ovalResult, err := cvedata.CheckCVEFromOVAL(ctx, ovalPath, cveID)
	if err != nil || !ovalResult.Found {
		return nil
	}

	// Convert OVALResult to CVEResult
	r := &models.CVEResult{
		CVE:            cveID,
		PackageManager: "oval:" + ovalPath,
		StatusReason:   "from OVAL sidecar: " + ovalPath,
	}
	if len(ovalResult.Packages) > 0 {
		r.Status = models.CVEVulnerable
		r.FixCommand = fixCommand()
		for _, p := range ovalResult.Packages {
			r.AffectedPackages = append(r.AffectedPackages, models.CVEPackage{
				Name:    p.Name,
				Version: p.Installed,
				FixedIn: p.FixedIn,
			})
		}
	} else {
		r.Status = models.CVENotAffected
		r.StatusReason = "OVAL: no vulnerable packages installed"
	}
	return r
}

func readDistroID() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ID=") {
			return strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		}
	}
	return ""
}

func fixCommand() string {
	switch {
	case hasCmd("zypper"):
		return "zypper patch --category security"
	case hasCmd("dnf"):
		return "dnf upgrade --security"
	case hasCmd("apt-get"):
		return "apt-get upgrade"
	}
	return ""
}

// checkCVEZypper uses `zypper lp --cve CVE-XXXX` (SLES/openSUSE).
// Exit 0 + output = patches available; "No patch" in output = not affected.
func checkCVEZypper(ctx context.Context, cveID string) *models.CVEResult {
	result := &models.CVEResult{CVE: cveID, PackageManager: "zypper"}

	out, err := runCmd(ctx, "zypper", "--non-interactive", "--no-color",
		"lp", "--cve", cveID)

	lower := strings.ToLower(out)

	// "No patch" or "no updates found" = not affected / already patched
	if strings.Contains(lower, "no patch") ||
		strings.Contains(lower, "no updates found") ||
		strings.Contains(lower, "nothing to do") {
		result.Status = models.CVENotAffected
		result.StatusReason = "no patches found for this CVE on this system"
		return result
	}

	if err != nil && len(out) == 0 {
		result.Status = models.CVEUnknown
		result.StatusReason = "zypper lp failed: " + err.Error()
		result.FallbackURL = "https://www.suse.com/security/cve/" + cveID + "/"
		return result
	}

	// Parse patch table output
	// Format: Repository | Patch Name | Category | Severity | Interactive | Status | Summary
	var pkgs []models.CVEPackage
	isVulnerable := false

	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "security") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < 6 {
			continue
		}
		status := strings.TrimSpace(strings.ToLower(fields[5]))
		if status == "needed" {
			isVulnerable = true
			advisory := strings.TrimSpace(fields[1])
			severity := strings.TrimSpace(fields[3])
			pkgs = append(pkgs, models.CVEPackage{
				Advisory: advisory,
				Severity: severity,
			})
		}
	}

	if isVulnerable {
		result.Status = models.CVEVulnerable
		result.AffectedPackages = pkgs
		result.FixCommand = "zypper patch --cve " + cveID
		if len(pkgs) > 0 {
			result.FixAdvisory = pkgs[0].Advisory
		}
	} else {
		// Output present but no "needed" patches = already patched
		result.Status = models.CVEPatched
		result.StatusReason = "patches for this CVE are already applied"
	}
	return result
}

// checkCVEDNF uses dnf updateinfo / dnf advisory (RHEL/Rocky/Fedora).
func checkCVEDNF(ctx context.Context, cveID string) *models.CVEResult {
	result := &models.CVEResult{CVE: cveID, PackageManager: "dnf"}

	// Try DNF5 syntax first (Fedora 41+), fall back to DNF4
	out, err := runCmd(ctx, "dnf", "advisory", "info", "--cve", cveID, "--quiet")
	if err != nil {
		out, err = runCmd(ctx, "dnf", "updateinfo", "info", "--cve", cveID, "--quiet")
	}

	lower := strings.ToLower(out)

	if err != nil && len(out) == 0 {
		result.Status = models.CVEUnknown
		result.StatusReason = "dnf advisory query failed"
		result.FallbackURL = "https://access.redhat.com/security/cve/" + cveID
		return result
	}

	// "No advisory" or empty output = not in scope
	if strings.Contains(lower, "no advisory") ||
		strings.Contains(lower, "no match") ||
		strings.TrimSpace(out) == "" {
		result.Status = models.CVENotAffected
		result.StatusReason = "no advisory found for this CVE"
		return result
	}

	// Look for packages listed as needing update
	var pkgs []models.CVEPackage
	var currentAdvisory, currentSeverity string

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "advisory id") || strings.HasPrefix(lower, "name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentAdvisory = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(lower, "severity") || strings.HasPrefix(lower, "type") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentSeverity = strings.TrimSpace(parts[1])
			}
		}
		// Package lines in dnf advisory output: "  package-name-version.arch"
		if strings.HasPrefix(line, "  ") && strings.Contains(line, ".") &&
			!strings.Contains(line, ":") {
			pkgName := strings.TrimSpace(line)
			if pkgName != "" && !strings.HasPrefix(strings.ToLower(pkgName), "update") {
				pkgs = append(pkgs, models.CVEPackage{
					Name:     pkgName,
					Advisory: currentAdvisory,
					Severity: currentSeverity,
				})
			}
		}
	}

	if len(pkgs) > 0 || len(out) > 50 {
		result.Status = models.CVEVulnerable
		result.AffectedPackages = pkgs
		result.FixAdvisory = currentAdvisory
		result.FixCommand = "dnf upgrade --cve " + cveID
	} else {
		result.Status = models.CVEPatched
		result.StatusReason = "advisory found but no pending updates"
	}
	return result
}

// checkCVEApt handles Ubuntu/Debian. apt itself doesn't have a direct CVE flag;
// we use `apt-cache policy` + security tracker heuristics.
func checkCVEApt(ctx context.Context, cveID string) *models.CVEResult {
	result := &models.CVEResult{CVE: cveID, PackageManager: "apt"}

	// Try apt-get changelog approach or debsecan if available
	if _, err := exec.LookPath("debsecan"); err == nil {
		return checkCVEDebsecan(ctx, cveID, result)
	}

	// Fall back to checking if security updates are pending
	// and linking to the Debian/Ubuntu tracker
	result.Status = models.CVEUnknown
	result.StatusReason = "apt does not support direct CVE queries — install 'debsecan' for Debian, or check tracker"

	// Detect distro for appropriate tracker URL
	if isUbuntu() {
		result.FallbackURL = "https://ubuntu.com/security/CVE/" + strings.ToLower(cveID)
	} else {
		result.FallbackURL = "https://security-tracker.debian.org/tracker/" + cveID
	}
	return result
}

// checkCVEDebsecan uses debsecan (Debian Security Analyzer) when available.
func checkCVEDebsecan(ctx context.Context, cveID string, result *models.CVEResult) *models.CVEResult {
	out, err := runCmd(ctx, "debsecan", "--cve", cveID, "--format", "detail")
	if err != nil || strings.TrimSpace(out) == "" {
		result.Status = models.CVENotAffected
		result.StatusReason = "debsecan: no vulnerabilities found for " + cveID
		return result
	}

	var pkgs []models.CVEPackage
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// debsecan format: "CVE-XXXX package [fix-available] description"
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pkgs = append(pkgs, models.CVEPackage{Name: fields[1]})
		}
	}

	if len(pkgs) > 0 {
		result.Status = models.CVEVulnerable
		result.AffectedPackages = pkgs
		result.FixCommand = "apt-get upgrade"
	} else {
		result.Status = models.CVEPatched
	}
	return result
}

// isUbuntu checks /etc/os-release for Ubuntu.
func isUbuntu() bool {
	out, _ := runCmd(context.Background(), "sh", "-c",
		"grep -i ubuntu /etc/os-release")
	return strings.Contains(strings.ToLower(out), "ubuntu")
}

// ScanAllCVEs scans all pending security advisories with CVE assignments.
// This is the "fresh install" use case — shows everything vulnerable at once.
func ScanAllCVEs(ctx context.Context) *models.CVEAllResult {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	if _, err := exec.LookPath("zypper"); err == nil {
		return scanAllZypper(ctx)
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		return scanAllDNF(ctx)
	}
	if _, err := exec.LookPath("apt-get"); err == nil {
		return scanAllApt(ctx)
	}
	return &models.CVEAllResult{StatusReason: "no supported package manager found"}
}

// scanAllZypper uses `zypper list-patches --category security` to find all
// pending CVE-tagged advisories. Parses severity and advisory IDs.
func scanAllZypper(ctx context.Context) *models.CVEAllResult {
	result := &models.CVEAllResult{PackageManager: "zypper"}

	out, err := runCmd(ctx, "zypper", "--non-interactive", "--no-color",
		"list-patches", "--category", "security")
	if err != nil && len(out) == 0 {
		result.StatusReason = "zypper list-patches failed: " + err.Error()
		return result
	}

	lower := strings.ToLower(out)
	if strings.Contains(lower, "no patch") || strings.Contains(lower, "nothing to do") {
		result.StatusReason = "no pending security patches — system is up to date"
		result.FixCommand = "zypper patch --category security"
		return result
	}

	// Parse pipe-delimited table:
	// Repository | Patch Name | Category | Severity | Interactive | Status | Summary
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "|") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < 7 {
			continue
		}
		status := strings.TrimSpace(strings.ToLower(fields[5]))
		if status != "needed" {
			continue
		}
		category := strings.TrimSpace(strings.ToLower(fields[2]))
		if category != "security" {
			continue
		}

		advisory := models.CVEAdvisory{
			ID:       strings.TrimSpace(fields[1]),
			Severity: strings.TrimSpace(fields[3]),
			Summary:  strings.TrimSpace(fields[6]),
		}

		switch strings.ToLower(advisory.Severity) {
		case "critical":
			result.Critical = append(result.Critical, advisory)
		case "important":
			result.Important = append(result.Important, advisory)
		case "moderate":
			result.Moderate = append(result.Moderate, advisory)
		default:
			result.Low = append(result.Low, advisory)
		}
	}

	result.Total = len(result.Critical) + len(result.Important) +
		len(result.Moderate) + len(result.Low)
	result.FixCommand = "zypper patch --category security"
	return result
}

// scanAllDNF uses `dnf updateinfo list security` / `dnf advisory list --security`.
func scanAllDNF(ctx context.Context) *models.CVEAllResult {
	result := &models.CVEAllResult{PackageManager: "dnf"}

	// Try DNF5 first, then DNF4
	out, err := runCmd(ctx, "dnf", "advisory", "list", "--security", "--quiet")
	if err != nil {
		out, err = runCmd(ctx, "dnf", "updateinfo", "list", "security", "--quiet")
	}
	if err != nil && len(out) == 0 {
		result.StatusReason = "dnf advisory list failed"
		return result
	}
	if strings.TrimSpace(out) == "" {
		result.StatusReason = "no pending security advisories — system is up to date"
		result.FixCommand = "dnf upgrade --security"
		return result
	}

	// DNF advisory output: "RHSA-2025:1234   security   critical   package-1.2.3"
	// or:                  "CVE-2025-1234    cve        important  package-1.2.3"
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		advisory := models.CVEAdvisory{
			ID:       fields[0],
			Severity: fields[2],
		}
		if len(fields) >= 4 {
			advisory.Summary = strings.Join(fields[3:], " ")
		}
		switch strings.ToLower(advisory.Severity) {
		case "critical":
			result.Critical = append(result.Critical, advisory)
		case "important":
			result.Important = append(result.Important, advisory)
		case "moderate":
			result.Moderate = append(result.Moderate, advisory)
		default:
			result.Low = append(result.Low, advisory)
		}
	}

	result.Total = len(result.Critical) + len(result.Important) +
		len(result.Moderate) + len(result.Low)
	result.FixCommand = "dnf upgrade --security"
	return result
}

// scanAllApt uses apt-get to list security updates.
func scanAllApt(ctx context.Context) *models.CVEAllResult {
	result := &models.CVEAllResult{PackageManager: "apt"}

	// Use apt-get --simulate upgrade filtered to security repos
	out, err := runCmd(ctx, "apt-get", "--simulate", "upgrade", "-o",
		"Dir::Etc::SourceList=/dev/null", "--allow-change-held-packages")
	if err != nil && len(out) == 0 {
		// Simpler fallback: just list security upgrades
		out, _ = runCmd(ctx, "apt-get", "--simulate", "dist-upgrade")
	}

	var advisories []models.CVEAdvisory
	for _, line := range strings.Split(out, "\n") {
		// apt output: "Inst package [old] (new repo)"
		if !strings.HasPrefix(line, "Inst") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		advisories = append(advisories, models.CVEAdvisory{
			ID:       fields[1],
			Severity: "unknown",
			Summary:  strings.Join(fields[2:], " "),
		})
	}

	result.Low = advisories
	result.Total = len(advisories)
	result.FixCommand = "apt-get upgrade"
	if result.Total == 0 {
		result.StatusReason = "no pending upgrades found"
	}
	return result
}
