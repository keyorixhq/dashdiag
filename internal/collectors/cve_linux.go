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
	case hasCmd("pacman"):
		result = checkCVEPacman(ctx, cveID)
	default:
		result = &models.CVEResult{
			CVE:          cveID,
			Status:       models.CVEUnknown,
			StatusReason: "no supported package manager found (zypper/dnf/apt/pacman)",
		}
	}

	// If package manager is definitive (VULNERABLE or PATCHED) — done.
	// If NOT_AFFECTED or UNKNOWN — repo metadata may be stale.
	// Try OVAL sidecar file, then pre-converted snapshot as fallbacks.
	if result.Status == models.CVENotAffected || result.Status == models.CVEUnknown {
		if ovalResult := tryOVALFallback(ctx, cveID); ovalResult != nil {
			return ovalResult
		}
		if snapResult := trySnapshotFallback(ctx, cveID); snapResult != nil {
			return snapResult
		}
	}

	// Enrich with CVSS score and per-product fix state from Red Hat Security API.
	// Best-effort, 5s timeout, silent on failure. Only runs on RH-family distros.
	cvedata.EnrichFromRHAPI(ctx, cveID, result)

	// Enrich with CISA KEV status — actively-exploited CVEs warrant CRIT regardless
	// of CVSS. No-op when no KEV sidecar file is present (air-gapped friendly).
	if cat, err := cvedata.LoadKEVFromStandardPaths(); err == nil {
		annotateCVEResultWithKEV(cat, result)
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
	return ReadDistroID()
}

// ReadDistroID returns the distro ID from /etc/os-release (e.g. "rhel", "ubuntu").
// Exported for use by cmd layer.
func ReadDistroID() string {
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
	case hasCmd("pacman"):
		return "pacman -Syu"
	}
	return ""
}

// checkCVEZypper uses `zypper lp --cve CVE-XXXX` (SLES/openSUSE).
// Exit 0 + output = patches available; "No patch" in output = not affected.
func checkCVEZypper(ctx context.Context, cveID string) *models.CVEResult {
	result := &models.CVEResult{CVE: cveID, PackageManager: "zypper"}

	out, err := runCmd(ctx, "zypper", "--non-interactive", "--no-color",
		"lp", "--cve="+cveID)

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
	} else if isKali() {
		result.FallbackURL = "https://security-tracker.debian.org/tracker/" + cveID
		result.StatusReason = "apt does not support direct CVE queries — Kali uses Debian tracker"
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

// isKali checks /etc/os-release for Kali Linux.
func isKali() bool {
	data, err := os.ReadFile("/etc/os-release") // #nosec G304
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "id=kali") || strings.Contains(lower, `id="kali"`)
}

// ScanAllCVEs scans all pending security advisories with CVE assignments.
// This is the "fresh install" use case — shows everything vulnerable at once.
func ScanAllCVEs(ctx context.Context) *models.CVEAllResult {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second) // 120s: list + CVE enrichment both need time
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
	if _, err := exec.LookPath("pacman"); err == nil {
		return scanAllPacman(ctx)
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
	// Repository | Patch Name | Category | Severity | Interactive | Status | Since | Summary
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
		// Summary is the last field (index 6 with 7 cols, index 7 with 8 cols)
		summary := strings.TrimSpace(fields[len(fields)-1])

		advisory := models.CVEAdvisory{
			ID:       strings.TrimSpace(fields[1]),
			Severity: strings.TrimSpace(fields[3]),
			Summary:  summary,
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

	// DNF output format varies by version and distro:
	//   DNF4/RHEL: "RHSA-2026:7383  Critical/Sec.  cockpit-344.x86_64"  (3 fields)
	//   DNF5:      "RHSA-2025:1234  security  critical  package-1.2.3"   (4 fields)
	// Both formats deduplicated by advisory ID.
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		id := fields[0]
		if seen[id] {
			continue
		}
		seen[id] = true

		// Extract severity: try fields[1] first (RHEL dnf4: "Critical/Sec."),
		// then fields[2] (dnf5: "security" "critical" "package").
		rawSev := fields[1]
		if strings.EqualFold(rawSev, "security") && len(fields) >= 3 {
			rawSev = fields[2]
		}
		// Strip "/Sec." suffix from RHEL dnf4 output
		rawSev = strings.TrimSuffix(rawSev, "/Sec.")

		advisory := models.CVEAdvisory{
			ID:       id,
			Severity: rawSev,
		}
		if len(fields) >= 3 {
			advisory.Summary = strings.Join(fields[2:], " ")
		}
		switch strings.ToLower(rawSev) {
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

	// On subscribed RHEL, enrich advisories with CVE IDs from `dnf updateinfo info`.
	// This is a best-effort pass — falls through silently if not subscribed.
	enrichDNFAdvisoryWithCVEs(ctx, result)

	return result
}

// enrichDNFAdvisoryWithCVEs runs `dnf updateinfo info --security` to extract
// the CVE ID(s) for each advisory and populates advisory.CVEs.
// Only works on subscribed RHEL/Rocky — fails silently on unregistered systems.
func enrichDNFAdvisoryWithCVEs(ctx context.Context, result *models.CVEAllResult) {
	eCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	out, err := runCmd(eCtx, "dnf", "updateinfo", "info", "--security", "--quiet")
	if err != nil || len(out) == 0 {
		result.SubscriptionNote = rhSubscriptionNote()
		return
	}

	// Parse: lines are "       CVEs: CVE-XXXX-YYYY" after an "  Update ID: RHSA-..." block
	cveMap := make(map[string]string) // advisory ID → CVE ID(s)
	currentID := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Update ID:") {
			currentID = strings.TrimSpace(strings.TrimPrefix(line, "Update ID:"))
		} else if strings.HasPrefix(line, "CVEs:") && currentID != "" {
			cve := strings.TrimSpace(strings.TrimPrefix(line, "CVEs:"))
			if cve != "" {
				if existing := cveMap[currentID]; existing != "" {
					cveMap[currentID] = existing + ", " + cve
				} else {
					cveMap[currentID] = cve
				}
			}
		}
	}
	if len(cveMap) == 0 {
		result.SubscriptionNote = rhSubscriptionNote()
		return
	}

	// Populate CVEs field on each advisory
	for i := range result.Critical {
		if cves, ok := cveMap[result.Critical[i].ID]; ok {
			result.Critical[i].CVEs = cves
		}
	}
	for i := range result.Important {
		if cves, ok := cveMap[result.Important[i].ID]; ok {
			result.Important[i].CVEs = cves
		}
	}
	for i := range result.Moderate {
		if cves, ok := cveMap[result.Moderate[i].ID]; ok {
			result.Moderate[i].CVEs = cves
		}
	}
	for i := range result.Low {
		if cves, ok := cveMap[result.Low[i].ID]; ok {
			result.Low[i].CVEs = cves
		}
	}
}

// rhSubscriptionNote returns an appropriate hint when CVE enrichment fails
// on a RHEL-family system. Distinguishes: not root, not registered, expired.
func rhSubscriptionNote() string {
	distro := strings.ToLower(ReadDistroID())
	// Fedora is free — never uses subscription-manager, skip entirely
	if strings.Contains(distro, "fedora") {
		return ""
	}
	rhFamily := strings.Contains(distro, "rhel") ||
		strings.Contains(distro, "red hat") ||
		strings.Contains(distro, "rocky") ||
		strings.Contains(distro, "alma") ||
		strings.Contains(distro, "centos")
	if !rhFamily {
		return ""
	}
	// Non-root: subscription-manager needs root to refresh repo metadata
	if os.Getuid() != 0 {
		return "ℹ️  CVE IDs require root access on RHEL — run: sudo dsd cve --all"
	}
	// Root: check for entitlement certificates — present when registered
	entries, err := os.ReadDir("/etc/pki/entitlement")
	if err != nil || len(entries) == 0 {
		return "⚠️  System not registered with Red Hat — CVE IDs unavailable\n" +
			"   → to register: subscription-manager register --username=<user> --password=<pass>\n" +
			"   → or activate: subscription-manager attach --auto"
	}
	// Has certs but no CVE data — may be expired or repos not synced
	hasPEM := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pem") && !strings.HasSuffix(e.Name(), "-key.pem") {
			hasPEM = true
			break
		}
	}
	if !hasPEM {
		return "⚠️  No entitlement certificates found — subscription may have expired\n" +
			"   → to check:  subscription-manager status\n" +
			"   → to renew:  subscription-manager attach --auto"
	}
	// Certs present but dnf returned no info — repos may need refresh
	return "ℹ️  Subscription active but CVE data unavailable — try: dnf makecache --refresh"
}

// scanAllApt uses apt-get to list security updates.
// based on the package name. Ubuntu/Debian don't expose CVSS in apt metadata,
// so we use a known-critical package list as a heuristic.
func aptPackageSeverity(pkg string) string {
	// Strip architecture suffix: libssl3t64:amd64 → libssl3t64
	if idx := strings.Index(pkg, ":"); idx > 0 {
		pkg = pkg[:idx]
	}
	// Strip version suffix: libssl3t64=3.0.13 → libssl3t64
	if idx := strings.Index(pkg, "="); idx > 0 {
		pkg = pkg[:idx]
	}
	pkgLower := strings.ToLower(pkg)

	// CRITICAL: kernel, libc, privilege escalation, code execution vectors
	criticalPrefixes := []string{
		"linux-image", "linux-kernel",
	}
	criticalContains := []string{
		"libc6", "libc-bin", "libc-dev",
		"pkexec", "polkit",
		"sudo",
		"openssh", "openssl", "libssl",
	}
	for _, p := range criticalPrefixes {
		if strings.HasPrefix(pkgLower, p) {
			return "CRITICAL"
		}
	}
	for _, c := range criticalContains {
		if strings.Contains(pkgLower, c) {
			return "CRITICAL"
		}
	}

	// HIGH: network-facing, crypto, browser engine, container runtime
	highContains := []string{
		"curl", "libcurl",
		"wget",
		"webkit", "javascript",
		"firefox", "chromium",
		"docker", "containerd", "runc",
		"libssh", "openssh",
		"nss", "libnss",
		"gnutls", "libgnutls",
		"krb5", "libkrb5",
		"bind9", "named",
		"nginx", "apache2",
		"python3", "perl", "ruby",
		"libxml2", "libexpat",
		"policykit", "libpolkit",
		"dbus", "libdbus",
	}
	for _, c := range highContains {
		if strings.Contains(pkgLower, c) {
			return "IMPORTANT"
		}
	}

	// MODERATE: system utilities with known CVE patterns
	moderateContains := []string{
		"util-linux", "bsdutils", "mount",
		"glib", "libglib",
		"freetype", "libfreetype",
		"tiff", "libtiff",
		"png", "libpng",
		"jpeg", "libjpeg",
		"avahi",
		"ntfs-3g",
		"kmod",
		"vim",
	}
	for _, c := range moderateContains {
		if strings.Contains(pkgLower, c) {
			return "MODERATE"
		}
	}

	return "LOW"
}

func scanAllApt(ctx context.Context) *models.CVEAllResult {
	result := &models.CVEAllResult{PackageManager: "apt"}

	// apt-get --simulate upgrade lists all pending upgrades.
	// We filter to security repos by matching the repo string in each line.
	out, err := runCmd(ctx, "apt-get", "--simulate", "upgrade")
	if err != nil && len(out) == 0 {
		// Reassign err so the both-failed case is distinguishable below — without
		// it, a failed apt (lock held, broken sources, no privilege) parsed to 0
		// advisories and reported "no pending upgrades found" → a green CVE OK on a
		// host we never actually scanned (false-OK).
		out, err = runCmd(ctx, "apt-get", "--simulate", "dist-upgrade")
	}

	var advisories []models.CVEAdvisory
	for _, line := range strings.Split(out, "\n") {
		// apt output: "Inst package [old] (new source/suite [arch])"
		if !strings.HasPrefix(line, "Inst") {
			continue
		}
		lineLower := strings.ToLower(line)
		// Filter to security repositories only.
		// Patterns: debian-security, ubuntu resolute-security, *-security
		if !strings.Contains(lineLower, "security") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pkg := fields[1]
		advisories = append(advisories, models.CVEAdvisory{
			ID:       pkg,
			Severity: aptPackageSeverity(pkg),
			Summary:  strings.Join(fields[2:], " "),
		})
	}

	// Bucket by severity
	result.Total = len(advisories)
	for _, a := range advisories {
		switch a.Severity {
		case "CRITICAL":
			result.Critical = append(result.Critical, a)
		case "HIGH", "IMPORTANT":
			result.Important = append(result.Important, a)
		case "MODERATE":
			result.Moderate = append(result.Moderate, a)
		default:
			result.Low = append(result.Low, a)
		}
	}
	result.FixCommand = "apt-get upgrade"
	result.StatusReason = aptScanStatusReason(result.Total, err)
	return result
}

// aptScanStatusReason picks the StatusReason for an apt scan from the advisory
// count and the final apt-get error. Zero advisories with a command error means
// apt could NOT run (lock, broken sources, no privilege) — reported as "failed"
// so the health layer surfaces INFO "scan unavailable" rather than a false-OK
// "no pending upgrades" / green CVE OK. (Mirrors the zypper/dnf failure paths;
// apt was the lone sibling that silently read clean when the scan failed.)
func aptScanStatusReason(total int, err error) string {
	if total > 0 {
		return "" // real advisories found — report them, no status note
	}
	if err != nil {
		return "apt-get --simulate upgrade failed: " + err.Error()
	}
	return "no pending upgrades found"
}

// trySnapshotFallback checks a pre-converted DashDiag snapshot file.
// The snapshot is generated by: scripts/update-cve-data.sh
// and placed in /var/lib/dsd/cvedata.json.gz (or other standard paths).
func trySnapshotFallback(ctx context.Context, cveID string) *models.CVEResult {
	snapPath := cvedata.FindSnapshot()
	if snapPath == "" {
		return nil
	}
	snap, err := cvedata.LoadSnapshot(snapPath)
	if err != nil || snap.IsEmpty() {
		return nil
	}
	entry, ok := snap.Lookup(cveID)
	if !ok {
		return nil
	}

	// Match distro key against installed distro
	distroID := readDistroID()
	distroKey := distroKeyFor(distroID)
	pkgs, ok := entry.Affected[distroKey]
	if !ok || len(pkgs) == 0 {
		return &models.CVEResult{
			CVE:          cveID,
			Status:       models.CVENotAffected,
			StatusReason: "snapshot: CVE not applicable for " + distroKey,
		}
	}

	// Compare each affected package against installed versions
	installed, err := cvedata.QueryInstalledRPM(ctx)
	if err != nil {
		return nil
	}
	installedMap := make(map[string]string, len(installed))
	for _, p := range installed {
		installedMap[p.Name] = p.EVR
	}

	var vulnerable []models.CVEPackage
	for _, p := range pkgs {
		evr, present := installedMap[p.Name]
		if !present {
			continue
		}
		if cvedata.IsVulnerable(evr, p.FixedIn) {
			vulnerable = append(vulnerable, models.CVEPackage{
				Name:    p.Name,
				Version: evr,
				FixedIn: p.FixedIn,
			})
		}
	}

	r := &models.CVEResult{
		CVE:            cveID,
		PackageManager: "snapshot:" + snapPath,
		StatusReason:   entry.Summary,
	}
	if len(vulnerable) > 0 {
		r.Status = models.CVEVulnerable
		r.AffectedPackages = vulnerable
		r.FixCommand = fixCommand()
	} else {
		r.Status = models.CVEPatched
		r.StatusReason = "snapshot: all affected packages are up to date"
	}
	return r
}

func distroKeyFor(distroID string) string {
	lower := strings.ToLower(distroID)
	switch {
	case strings.Contains(lower, "sles") || lower == "sle":
		return "sles:16"
	case strings.Contains(lower, "tumbleweed") || lower == "opensuse-tumbleweed":
		return "opensuse-tumbleweed"
	case strings.Contains(lower, "rhel") || lower == "rhel":
		return "rhel:10"
	case strings.Contains(lower, "fedora"):
		return "fedora:44"
	default:
		return lower
	}
}

// checkCVEPacman checks a specific CVE on Arch Linux using arch-audit.
// arch-audit output: "package is affected by CVE-XXXX-YYYY [Severity]: description"
// Falls back to the Arch Linux security tracker URL when arch-audit is not installed.
func checkCVEPacman(ctx context.Context, cveID string) *models.CVEResult {
	result := &models.CVEResult{CVE: cveID, PackageManager: "pacman"}

	if !hasCmd("arch-audit") {
		result.Status = models.CVEUnknown
		result.StatusReason = "install arch-audit for CVE scanning: pacman -S arch-audit"
		result.FallbackURL = "https://security.archlinux.org/" + strings.ToLower(cveID)
		return result
	}

	out, err := runCmd(ctx, "arch-audit", "--format", "%n %c %s")
	if err != nil && len(out) == 0 {
		result.Status = models.CVEUnknown
		result.StatusReason = "arch-audit failed: " + err.Error()
		result.FallbackURL = "https://security.archlinux.org/" + strings.ToLower(cveID)
		return result
	}

	// arch-audit --format "%n %c %s" output: "pkgname CVE-XXXX-YYYY,CVE-XXXX-ZZZZ severity"
	var pkgs []models.CVEPackage
	cveUpper := strings.ToUpper(cveID)

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.Contains(strings.ToUpper(line), cveUpper) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		severity := ""
		if len(fields) >= 3 {
			severity = archAuditSeverity(fields[len(fields)-1])
		}
		pkgs = append(pkgs, models.CVEPackage{
			Name:     fields[0],
			Severity: severity,
		})
	}

	if len(pkgs) > 0 {
		result.Status = models.CVEVulnerable
		result.AffectedPackages = pkgs
		result.FixCommand = "pacman -Syu"
	} else {
		result.Status = models.CVENotAffected
		result.StatusReason = "arch-audit: no installed packages affected by " + cveID
	}
	return result
}

// scanAllPacman uses arch-audit to list all vulnerable packages on Arch Linux.
// arch-audit queries the Arch Linux Security Tracker and cross-references
// installed packages.
func scanAllPacman(ctx context.Context) *models.CVEAllResult {
	result := &models.CVEAllResult{PackageManager: "pacman"}

	if !hasCmd("arch-audit") {
		result.StatusReason = "install arch-audit for CVE scanning: pacman -S arch-audit"
		return result
	}

	// arch-audit default output: "pkgname is affected by CVE-XXXX [Severity]: description"
	out, err := runCmd(ctx, "arch-audit", "-u")
	if err != nil && len(out) == 0 {
		result.StatusReason = "arch-audit failed: " + err.Error()
		return result
	}

	if strings.TrimSpace(out) == "" {
		result.StatusReason = "no vulnerable packages found — system is up to date"
		result.FixCommand = "pacman -Syu"
		return result
	}

	// arch-audit -u output: "pkgname is affected by CVE-XXXX, CVE-YYYY [Severity]: description"
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Extract package name (first word)
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		pkgName := fields[0]

		// Extract severity from "[Severity]" bracket
		severity := "unknown"
		if start := strings.Index(line, "["); start != -1 {
			if end := strings.Index(line[start:], "]"); end != -1 {
				severity = archAuditSeverity(line[start+1 : start+end])
			}
		}

		// Extract CVE IDs between "affected by" and "["
		cves := ""
		if idx := strings.Index(strings.ToLower(line), "affected by "); idx != -1 {
			rest := line[idx+len("affected by "):]
			if bracket := strings.Index(rest, "["); bracket != -1 {
				cves = strings.TrimSpace(rest[:bracket])
			}
		}

		// Extract description after "]:"
		summary := pkgName
		if idx := strings.Index(line, "]: "); idx != -1 {
			summary = strings.TrimSpace(line[idx+3:])
		}

		advisory := models.CVEAdvisory{
			ID:       pkgName,
			CVEs:     cves,
			Severity: severity,
			Summary:  summary,
		}

		switch severity {
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
	result.FixCommand = "pacman -Syu"
	return result
}

// archAuditSeverity maps arch-audit severity strings to dsd standard severities.
// arch-audit uses: Critical, High, Medium, Low
func archAuditSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "important"
	case "medium":
		return "moderate"
	case "low":
		return "low"
	default:
		return "low"
	}
}
