//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// PackagesCollector checks for available security updates.
// This collector intentionally shells out — there is no kernel interface
// for package state. Distro detection happens at collection time.
type PackagesCollector struct {
	Deep bool
}

func NewPackagesCollector() *PackagesCollector     { return &PackagesCollector{} }
func NewPackagesDeepCollector() *PackagesCollector { return &PackagesCollector{Deep: true} }

func (c *PackagesCollector) Name() string           { return "Packages" }
func (c *PackagesCollector) Timeout() time.Duration { return 8 * time.Second }

func (c *PackagesCollector) Collect(ctx context.Context) (interface{}, error) {
	var info *models.PackagesInfo
	var err error

	// Detect package manager
	if _, e := runCmd(ctx, "zypper", "--version"); e == nil {
		info, err = collectZypper(ctx)
	} else if _, e := runCmd(ctx, "dnf", "--version"); e == nil {
		info, err = collectDNF(ctx)
	} else if _, e := runCmd(ctx, "apt-get", "--version"); e == nil {
		info, err = collectAPT(ctx)
	} else {
		return &models.PackagesInfo{PackageManager: "unknown"}, nil
	}

	if err != nil || info == nil {
		return info, err
	}

	// A "0 security updates" result is only trustworthy if the update metadata is
	// fresh. apt never auto-refreshes (we deliberately don't run `apt update`), and
	// dnf/zypper can be offline or never-refreshed — so stale/absent metadata means
	// "couldn't confirm", not "up to date". Mark it unverified rather than green.
	markStaleMetadata(info)

	// Deep mode: run integrity checks (slower operations gated here)
	if c.Deep {
		info.Integrity = collectPackageIntegrity(ctx, info.PackageManager)
	}

	return info, nil
}

// packageMetadataStaleDays is the age beyond which a cached update index is treated
// as too old to trust a "0 security updates" result.
const packageMetadataStaleDays = 7

// markStaleMetadata flags a clean "0 updates" result as unverified when the update
// metadata is absent or older than packageMetadataStaleDays. Only managers whose
// cache location we can read are considered; others are left untouched (no false
// "stale"). It never overrides an existing Status (e.g. "no-security-repo").
func markStaleMetadata(info *models.PackagesInfo) {
	if info == nil || !info.Checked || info.SecurityUpdates > 0 || info.Status != "" {
		return
	}
	if !supportedMetadataManager(info.PackageManager) {
		return // manager whose cache layout we don't read — don't claim stale or fresh
	}
	age, found := packageMetadataAgeDays(info.PackageManager)
	if found && age <= packageMetadataStaleDays {
		return // metadata is fresh — the "0 updates" result is trustworthy
	}
	info.Status = "stale-metadata"
	info.MetadataAgeDays = age // -1 when no cache was found
	if !found {
		info.StatusReason = "update metadata not found — cannot confirm packages are up to date"
	} else {
		info.StatusReason = fmt.Sprintf("update metadata is %d days old — cannot confirm packages are up to date", age)
	}
}

func supportedMetadataManager(pm string) bool {
	switch pm {
	case "apt", "dnf", "yum", "zypper":
		return true
	}
	return false
}

// packageMetadataAgeDays returns the age in days of the newest update-metadata cache
// file for the given package manager, and whether any was found. Returns (-1, false)
// for managers whose cache layout we don't read (brew/pacman/unknown) so callers can
// skip them rather than mis-flag.
func packageMetadataAgeDays(pm string) (int, bool) {
	var globs []string
	switch pm {
	case "apt":
		globs = []string{"/var/lib/apt/lists/*InRelease", "/var/lib/apt/lists/*Release", "/var/lib/apt/lists/*_Packages*"}
	case "dnf", "yum":
		globs = []string{"/var/cache/dnf/*/repodata/repomd.xml", "/var/cache/yum/*/repodata/repomd.xml"}
	case "zypper":
		globs = []string{"/var/cache/zypp/raw/*/repodata/repomd.xml", "/var/cache/zypp/solv/*/solv"}
	default:
		return -1, false
	}
	var newest time.Time
	found := false
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			fi, err := os.Stat(m)
			if err != nil {
				continue
			}
			found = true
			if fi.ModTime().After(newest) {
				newest = fi.ModTime()
			}
		}
	}
	if !found {
		return -1, false
	}
	return int(time.Since(newest).Hours() / 24), true
}

// collectDNF parses security advisories for RHEL/Rocky/Fedora/CentOS.
// DNF4 (RHEL/Rocky): dnf updateinfo list security
// DNF5 (Fedora 41+): dnf advisory list --security
func collectDNF(ctx context.Context) (*models.PackagesInfo, error) {
	info := &models.PackagesInfo{Checked: true, PackageManager: "dnf"}

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
		// The advisory query failed (broken plugin, transient dnf error, permission)
		// — we did NOT learn there are 0 updates. Mark it so the verdict reports
		// "couldn't verify" instead of a silent clean 0-updates OK (false-OK).
		info.Status = "query-failed"
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
// Exception: Kali Linux uses a rolling release model where the main repo IS
// the security channel — all pending upgrades are counted.
func collectAPT(ctx context.Context) (*models.PackagesInfo, error) {
	info := &models.PackagesInfo{Checked: true, PackageManager: "apt"}

	// Kali Linux uses a rolling release — the main kali-rolling repo includes
	// all security updates. Skip the security repo check and count all upgrades.
	if isKali() {
		return collectAPTKali(ctx, info)
	}

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
		// apt-get -s (simulate) requires no lock but may fail (apt lock, broken
		// sources) — we didn't verify, so don't read as a clean 0-updates result.
		info.Status = "query-failed"
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

	// Ubuntu ESM: check for security updates gated behind Ubuntu Pro subscription.
	// These are real CVEs that standard apt cannot apply — surface them as a WARN
	// so the admin knows they exist even if they can't act without a Pro subscription.
	checkESMUpdates(ctx, info)

	return info, nil
}

// collectAPTKali counts all pending upgrades on Kali Linux.
// Kali uses a rolling release — kali-rolling IS the security channel.
// There is no separate *-security repo, so all pending upgrades are relevant.
func collectAPTKali(ctx context.Context, info *models.PackagesInfo) (*models.PackagesInfo, error) {
	info.HasSecurityRepo = true // kali-rolling is the security channel

	out, err := runCmd(ctx, "apt-get", "-s", "upgrade")
	if err != nil {
		info.StatusReason = "apt-get unavailable"
		return info, nil
	}

	criticalPkgs := map[string]bool{
		"linux-image": true, "linux-headers": true,
		"openssl": true, "libssl": true,
		"openssh-server": true, "openssh-client": true,
		"libc6": true, "libc-bin": true,
		"curl": true, "sudo": true, "bash": true,
		"libgnutls30": true, "ca-certificates": true, "apt": true, "dpkg": true,
	}

	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pkgName := fields[1]
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
		})
	}
	return info, nil
}

// checkESMUpdates detects Ubuntu Pro ESM security updates that cannot be
// applied without a Pro subscription. Uses `pro security-status --format json`
// which is available on Ubuntu 20.04+ without requiring Pro activation.
// Populates info.ESMUpdates — the heuristic surfaces these as a WARN so the
// admin knows real CVEs exist even if they can't apply them without Pro.
func checkESMUpdates(ctx context.Context, info *models.PackagesInfo) {
	out, err := runCmd(ctx, "pro", "security-status", "--format", "json")
	if err != nil {
		// pro not installed or not Ubuntu — silent skip
		return
	}

	// Parse just the summary fields we need without a full JSON library
	// to avoid import bloat — look for num_esm_*_updates in the JSON.
	esmApps := 0
	esmInfra := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, `"num_esm_apps_updates"`) {
			if n := parseJSONInt(line); n > 0 {
				esmApps = n
			}
		}
		if strings.Contains(line, `"num_esm_infra_updates"`) {
			if n := parseJSONInt(line); n > 0 {
				esmInfra = n
			}
		}
	}
	info.ESMUpdates = esmApps + esmInfra
}

// parseJSONInt extracts the integer value from a simple JSON key-value line
// like: `"num_esm_apps_updates": 3,`
func parseJSONInt(line string) int {
	// Find the colon and parse the number after it
	idx := strings.Index(line, ":")
	if idx < 0 {
		return 0
	}
	val := strings.TrimSpace(line[idx+1:])
	val = strings.TrimRight(val, ",")
	n := 0
	for _, c := range val {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else if n > 0 {
			break
		}
	}
	return n
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
	info := &models.PackagesInfo{Checked: true, PackageManager: "zypper"}

	// Check for security patches
	out, err := runCmd(ctx, "zypper", "--non-interactive", "--no-color",
		"list-patches", "--category", "security")
	if err != nil {
		// zypper may require root for full repo access. This is NOT "OK" — we
		// couldn't check, so don't claim a clean result; report it as unverified.
		info.Status = "query-failed"
		info.StatusReason = "zypper list-patches unavailable (try running as root)"
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

	// SUSE pre-migration risk check — warn about packages known to cause
	// boot failures during zypper migration between service packs.
	// Research finding: "zypper migration can brick systems if grub2-x86_64-efi
	// package is not locked beforehand" — this is a real and common data loss scenario.
	info.SUSEMigrationRisks = checkSUSEMigrationRisks(ctx)

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

// checkSUSEMigrationRisks checks for packages known to cause boot failures
// during zypper migration between SLES service packs. Returns a list of
// risk descriptions with fix commands — empty if no risks detected.
//
// Known boot-breaking migration scenarios (from SUSE support):
//  1. grub2-x86_64-efi — if this gets upgraded during migration on EFI systems
//     without first locking it, grub configuration can become inconsistent.
//  2. Unregistered system — zypper migration requires SUSEConnect registration;
//     migrating without it leaves repos in a broken state.
//  3. Pending reboots — migrating with unapplied kernel patches compounds risk.
func checkSUSEMigrationRisks(ctx context.Context) []string {
	var risks []string

	// Check 1: grub2 EFI package version lock.
	// If the package exists and is NOT locked, migration can overwrite grub config.
	// The package is arch-specific: grub2-x86_64-efi on x86, grub2-arm64-efi on ARM.
	grubPkg := "grub2-x86_64-efi"
	if runtime.GOARCH == "arm64" {
		grubPkg = "grub2-arm64-efi"
	}
	grubOut, err := runCmd(ctx, "zypper", "--non-interactive", "--no-color",
		"search", "--installed-only", grubPkg)
	if err == nil && strings.Contains(grubOut, grubPkg) {
		// Check if it's locked
		lockOut, _ := runCmd(ctx, "zypper", "--non-interactive", "--no-color", "locks")
		if !strings.Contains(lockOut, grubPkg) {
			risks = append(risks,
				grubPkg+" is installed but NOT locked — migration may overwrite grub config and break boot",
			)
		}
	}

	// Check 2: SUSEConnect registration health
	statusOut, err := runCmd(ctx, "SUSEConnect", "--status")
	if err == nil {
		lower := strings.ToLower(statusOut)
		if strings.Contains(lower, "not registered") || strings.Contains(lower, "expired") {
			risks = append(risks,
				"system is not registered with SUSE — zypper migration requires valid registration",
			)
		}
	}

	// Check 3: Pending reboot (kernel update applied but not rebooted)
	// If /boot has a newer kernel than the running one, a reboot is pending
	runningKernel, _ := runCmd(ctx, "uname", "-r")
	runningKernel = strings.TrimSpace(runningKernel)
	bootOut, _ := runCmd(ctx, "ls", "/boot")
	if runningKernel != "" && bootOut != "" {
		newerKernelFound := false
		for _, line := range strings.Split(bootOut, "\n") {
			if strings.HasPrefix(line, "vmlinuz-") {
				installedKernel := strings.TrimPrefix(line, "vmlinuz-")
				if installedKernel != runningKernel && installedKernel > runningKernel {
					newerKernelFound = true
					break
				}
			}
		}
		if newerKernelFound {
			risks = append(risks,
				"newer kernel installed but not yet booted — reboot before running zypper migration",
			)
		}
	}

	return risks
}

// ── Package integrity checks (deep mode) ─────────────────────────────────────

// collectPackageIntegrity runs dependency and shared-library integrity checks.
// All operations are capped with context timeouts to avoid blocking dsd health deep.
func collectPackageIntegrity(ctx context.Context, pm string) *models.PackageIntegrity {
	pi := &models.PackageIntegrity{}

	switch pm {
	case "dnf":
		pkgIntegrityDNF(ctx, pi)
	case "apt":
		pkgIntegrityAPT(ctx, pi)
	case "zypper":
		pkgIntegrityZypper(ctx, pi)
	}

	// ldconfig — cross-distro, fast (~0.1s)
	pkgIntegrityLdconfig(ctx, pi)

	// ldd on canary binaries — detect missing .so files
	pkgIntegrityLdd(ctx, pi)

	return pi
}

// pkgIntegrityDNF checks RHEL/Fedora package consistency.
func pkgIntegrityDNF(ctx context.Context, pi *models.PackageIntegrity) {
	// dnf check — fast dependency consistency check
	dnfCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	// `dnf check` EXITS NON-ZERO when it finds broken deps (writing them to stdout),
	// so capture stdout regardless of exit — runCmd would discard the findings and
	// the check would read clean (false-OK).
	out, _ := runCmdOutput(dnfCtx, "dnf", "check", "--quiet")
	if strings.TrimSpace(out) != "" {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if line = strings.TrimSpace(line); line != "" &&
				!strings.HasPrefix(line, "Updating Subscription") &&
				!strings.HasPrefix(line, "Last metadata") {
				pi.BrokenPackages = append(pi.BrokenPackages, line)
				if len(pi.BrokenPackages) >= 10 {
					break
				}
			}
		}
	}

	// rpm --verify on critical packages only (capped at 5s). rpm -V EXITS 1 when it
	// finds discrepancies (a modified/tampered file) and prints them to stdout — so
	// capture stdout regardless of exit, or the tamper findings vanish (false-OK).
	rpmCtx, rpmCancel := context.WithTimeout(ctx, 5*time.Second)
	defer rpmCancel()
	canary := []string{"bash", "coreutils", "systemd", "glibc", "openssl-libs"}
	rpmOut, _ := runCmdOutput(rpmCtx, "rpm", append([]string{"--verify"}, canary...)...)
	if rpmCtx.Err() != nil {
		pi.VerifyTimedOut = true
	} else if strings.TrimSpace(rpmOut) != "" {
		for _, line := range strings.Split(strings.TrimSpace(rpmOut), "\n") {
			line = strings.TrimSpace(line)
			// Skip config file modifications (expected) — lines with 'c' at position 9
			if len(line) >= 10 && line[9] == 'c' {
				continue
			}
			if line != "" {
				pi.RPMVerifyFailed = append(pi.RPMVerifyFailed, line)
			}
		}
	}
}

// pkgIntegrityAPT checks Debian/Ubuntu package consistency.
func pkgIntegrityAPT(ctx context.Context, pi *models.PackageIntegrity) {
	// dpkg --audit — immediate, < 0.5s
	aptCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, _ := runCmd(aptCtx, "dpkg", "--audit")
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			pi.BrokenPackages = append(pi.BrokenPackages, line)
		}
	}

	// apt-get check — detects unmet dependencies
	checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
	defer checkCancel()
	checkOut, _ := runCmd(checkCtx, "apt-get", "check")
	for _, line := range strings.Split(checkOut, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "unmet dep") || strings.Contains(lower, "broken package") {
			pi.UnmetDeps = append(pi.UnmetDeps, strings.TrimSpace(line))
		}
	}
}

// pkgIntegrityZypper checks SUSE/openSUSE package consistency.
func pkgIntegrityZypper(ctx context.Context, pi *models.PackageIntegrity) {
	// zypper verify (exit 1 = problems found)
	zCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, _ := runCmd(zCtx, "zypper", "--non-interactive", "verify", "--dry-run")
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "broken") || strings.Contains(lower, "missing") {
			if line = strings.TrimSpace(line); line != "" {
				pi.BrokenPackages = append(pi.BrokenPackages, line)
			}
		}
	}
}

// pkgIntegrityLdconfig verifies the shared library cache is consistent.
func pkgIntegrityLdconfig(ctx context.Context, pi *models.PackageIntegrity) {
	ldCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := runCmd(ldCtx, "ldconfig", "-p")
	pi.LdconfigOK = err == nil
}

// pkgIntegrityLdd checks canary binaries for missing shared libraries.
func pkgIntegrityLdd(ctx context.Context, pi *models.PackageIntegrity) {
	canaries := []string{"/bin/ls", "/usr/bin/ssh", "/usr/bin/python3"}
	for _, bin := range canaries {
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		lddCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		out, err := runCmd(lddCtx, "ldd", bin)
		cancel()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "not found") {
				lib := strings.TrimSpace(strings.Split(line, "=>")[0])
				pi.MissingLibs = append(pi.MissingLibs,
					lib+" (required by "+filepath.Base(bin)+")")
			}
		}
	}
}
