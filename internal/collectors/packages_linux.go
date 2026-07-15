//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	pkgQueryFailed    = "query-failed"
	pkgNoSecurityRepo = "no-security-repo"
	pkgNonInteractive = "--non-interactive"
	pkgSevCritical    = "Critical"
	pkgSevImportant   = "Important"
	pkgSevSecurity    = "security"
	pkgFlagVersion    = "--version"
	pkgFlagQ          = "-q"
	pkgCmdAptGet      = "apt-get"
	pkgFlagNoColor    = "--no-color"
	pkgFlagStatus     = "--status"
)

// PackagesCollector checks for available security updates.
// This collector intentionally shells out — there is no kernel interface
// for package state. Distro detection happens at collection time.
type PackagesCollector struct {
	Deep bool
}

func NewPackagesCollector() *PackagesCollector     { return &PackagesCollector{} }
func NewPackagesDeepCollector() *PackagesCollector { return &PackagesCollector{Deep: true} }

func (c *PackagesCollector) Name() string { return "Packages" }

// Timeout budgets the whole collector. The old flat 8s was too small for RHEL/RHUI:
// a cold `dnf updateinfo` metadata download alone routinely takes 6s+ (measured live
// on EC2 RHEL 10), so on a freshly-booted host the security scan either timed out —
// reporting a false "could not verify security updates" that HID pending critical
// advisories — or, when it barely fit, starved the deep integrity sub-checks
// (dnf check / rpm --verify / ldconfig) into false timeout WARNs. Give the scan real
// headroom (fast), and reserve extra for the integrity sub-checks that run after it
// (deep). Collectors run concurrently, so this only extends wall-clock on the rare
// cold/slow-mirror first run — and an honest-but-slow security verdict beats a fast
// false-negative.
//
// BUG-098 addendum: on a multi-repo distro (Oracle Linux's 6 default repos vs
// RHUI's 1), the FIRST dnf call of any kind pays the cold-metadata-sync cost —
// including the repolist gate check that runs BEFORE the scan's own 18s cap
// even starts. That gate call had no cap of its own, so it could eat most of
// this budget before the scan got a turn, on a fresh cloud VM. Budget now
// covers an explicit cache-warm step + the (now bounded) gate + the scan.
func (c *PackagesCollector) Timeout() time.Duration {
	if c.Deep {
		return 65 * time.Second
	}
	return 50 * time.Second
}

func (c *PackagesCollector) Collect(ctx context.Context) (interface{}, error) {
	pm := detectPackageManager(ctx)
	if pm == "" {
		return &models.PackagesInfo{PackageManager: "unknown"}, nil
	}

	// Package-DB health FIRST — it is fast (dpkg --audit / rpm -q) but MUST run before the
	// slow security-update scan below, which on a host with many pending updates can
	// consume the entire collector deadline and leave this probe ctx-cancelled. (Observed
	// live: a fresh Azure Ubuntu's apt scan hit the 8s timeout, so db_health_checked came
	// back false — the check silently didn't run.) Running it first reserves its budget;
	// the scan then uses whatever remains.
	dbChecked, dbBlocked, dbReason, dbFix := pkgDBHealth(ctx, pm)

	var info *models.PackagesInfo
	var qErr error
	switch pm {
	case "zypper":
		info, qErr = collectZypper(ctx)
	case "dnf":
		info, qErr = collectDNF(ctx)
	case "apt":
		info, qErr = collectAPT(ctx)
	case "tdnf":
		info, qErr = collectTDNF(ctx)
	}
	if info == nil {
		info = &models.PackagesInfo{PackageManager: pm}
	}
	if info.PackageManager == "" {
		info.PackageManager = pm
	}

	// Fold a hard query error into a status rather than returning it: the runner/render
	// path ignores a collector's Data when it returns an error, which would DROP the
	// DB-health verdict below — and a blocked/locked/corrupt package DB is exactly what
	// makes the query fail. Surfacing it as pkgQueryFailed keeps the result (the
	// existing query-failed handling in checkPackageUpdates renders it).
	if qErr != nil && info.Status == "" {
		info.Status = pkgQueryFailed
		info.StatusReason = "package-manager query failed: " + qErr.Error()
	}

	info.DBHealthChecked, info.DBUpdatesBlocked, info.DBBlockReason, info.DBBlockFix = dbChecked, dbBlocked, dbReason, dbFix

	// A "0 security updates" result is only trustworthy if the update metadata is
	// fresh; mark it unverified when stale/absent. Skipped on a failed query (a
	// query-failed status already says "couldn't confirm").
	if qErr == nil {
		markStaleMetadata(info)
		if c.Deep {
			info.Integrity = collectPackageIntegrity(ctx, info.PackageManager)
		}
	}

	return info, nil
}

// detectPackageManager returns the host's package manager ("zypper"/"dnf"/"apt"), or
// "" when none is recognised. Probed in the same order as before (zypper, dnf, apt).
func detectPackageManager(ctx context.Context) string {
	if _, e := runCmd(ctx, "zypper", "--version"); e == nil {
		return "zypper"
	}
	if _, e := runCmd(ctx, "dnf", pkgFlagVersion); e == nil {
		return "dnf"
	}
	if _, e := runCmd(ctx, pkgCmdAptGet, pkgFlagVersion); e == nil {
		return "apt"
	}
	// tdnf — VMware Photon OS (vCSA/Tanzu/appliances). Probed last: it is
	// Photon-specific, so the rpm-family managers above never co-exist with it.
	if _, e := runCmd(ctx, "tdnf", pkgFlagVersion); e == nil {
		return "tdnf"
	}
	return ""
}

// pkgDBHealth probes the package database / lock for a state that silently blocks all
// updates. It dispatches on the detected manager; checked is true when a probe ran.
// Each probe is read-only and works non-root (the worst class is an unprivileged
// operator getting a false "patched" reading on a host that cannot update).
func pkgDBHealth(ctx context.Context, pm string) (checked, blocked bool, reason, fix string) {
	switch pm {
	case "apt":
		return aptDBHealth(ctx)
	case "dnf", "yum", "zypper", "tdnf":
		// All are rpm-based (zypper/SLES and Photon/tdnf included) — the package DB
		// that blocks updates when corrupt is the rpmdb. A stale zypper front-end lock
		// (/run/zypp.pid) was tried and rejected: a dead-PID lock does NOT block modern
		// libzypp (verified on Leap 16 — `zypper lr` runs fine with a dead pid present),
		// so flagging it would be a false alarm.
		return rpmDBHealth(ctx)
	}
	return false, false, "", ""
}

// aptDBHealth reports an interrupted dpkg state. `dpkg --audit` lists packages left
// half-installed/half-configured by an interrupted run; any output means apt/dpkg
// operations will fail or silently no-op until `dpkg --configure -a` is run. dpkg
// --audit reads the world-readable status DB, so it works non-root and its exit code
// is 0 even when it reports problems — the OUTPUT is the signal, not the code.
func aptDBHealth(ctx context.Context) (checked, blocked bool, reason, fix string) {
	out, err := runCmd(ctx, "dpkg", "--audit")
	if err != nil {
		return false, false, "", "" // dpkg not usable — couldn't measure
	}
	if strings.TrimSpace(out) == "" {
		return true, false, "", ""
	}
	return true, true,
		"dpkg is in an interrupted state (packages left half-configured) — apt/dpkg will fail until reconfigured",
		"sudo dpkg --configure -a"
}

// rpmDBHealth reports an unreadable/corrupt or locked rpm database. Querying a known
// package (`rpm -q rpm`) fails when the rpmdb is corrupt, or blocks→times out when it
// is locked by another process; either way yum/dnf cannot proceed. A clean DB returns
// the package NVR with exit 0.
func rpmDBHealth(ctx context.Context) (checked, blocked bool, reason, fix string) {
	if _, err := lookPath("rpm"); err != nil {
		return false, false, "", "" // no rpm to probe with — couldn't measure
	}
	// A SINGLE failure is usually transient, not corruption: dnf-makecache.timer and
	// PackageKit briefly hold the rpmdb lock right after boot, so `rpm -q rpm` can fail
	// for ~a second on a perfectly healthy host (observed live on AlmaLinux 9). Retry
	// once before asserting the DB is blocked — otherwise a momentary lock reads as a
	// false "rpmdb corrupt" alarm.
	if _, err := runCmd(ctx, "rpm", pkgFlagQ, "rpm"); err == nil {
		return true, false, "", ""
	}
	if !sleepCtx(ctx, 1500*time.Millisecond) {
		return true, false, "", "" // ctx cancelled — don't assert blocked on a partial probe
	}
	if _, err := runCmd(ctx, "rpm", pkgFlagQ, "rpm"); err == nil {
		return true, false, "", "" // cleared on retry — it was a transient lock
	}
	return true, true,
		"the rpm database is not readable (corrupt, or persistently locked by another process) — yum/dnf updates will fail",
		"sudo rpm --rebuilddb   (after confirming no dnf/yum/packagekit is running)"
}

// packageMetadataStaleDays is the age beyond which a cached update index is treated
// as too old to trust a "0 security updates" result.
const packageMetadataStaleDays = 7

// markStaleMetadata flags a clean "0 updates" result as unverified when the update
// metadata is absent or older than packageMetadataStaleDays. Only managers whose
// cache location we can read are considered; others are left untouched (no false
// "stale"). It never overrides an existing Status (e.g. pkgNoSecurityRepo).
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
	case "apt", "dnf", "yum", "zypper", "tdnf":
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
	case "tdnf":
		globs = []string{"/var/cache/tdnf/*/repodata/repomd.xml"}
	default:
		return -1, false
	}
	var newest time.Time
	found := false
	for _, g := range globs {
		matches, _ := glob(g)
		for _, m := range matches {
			fi, err := statFile(m)
			if err != nil {
				continue
			}
			found = true
			if fi.ModTime.After(newest) {
				newest = fi.ModTime
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

	// BUG-098: warm the metadata cache ONCE, up front, so the repo gate check and
	// the scan below both hit a warm cache instead of each independently racing a
	// cold multi-repo sync (found on Oracle Linux's 6 default repos: the gate
	// check alone could eat the scan's entire budget before the scan got a turn).
	// Best-effort — a timeout/failure here just means the calls below pay the
	// cold-sync cost themselves, same as before this fix.
	dnfWarmCache(ctx)

	// Check repos. Bounded so a still-cold sync here (warm-up above timed out or
	// was itself slow) can't silently consume the rest of the collector budget
	// before the scan below gets a chance to run.
	repoCtx, repoCancel := context.WithTimeout(ctx, 10*time.Second)
	reposOk := dnfHasUpdateRepo(repoCtx)
	repoCancel()
	if !reposOk {
		info.Status = pkgNoSecurityRepo
		info.StatusReason = "no enabled dnf repositories found"
		return info, nil
	}
	info.HasSecurityRepo = true

	// Cap the advisory query so a slow/cold RHUI mirror can't consume the whole
	// collector budget and starve the deep integrity sub-checks (rpm --verify,
	// ldconfig) that run after it. The cap is generous (cold downloads measured at
	// 6s live, but a slow region can spike higher) yet bounded, so a wedged mirror
	// degrades to an honest "could not verify" instead of hanging the collector.
	scanCtx, scanCancel := context.WithTimeout(ctx, 18*time.Second)
	defer scanCancel()
	// Try DNF5 syntax first (Fedora 41+), fall back to DNF4 (RHEL/Rocky)
	out, err := runCmd(scanCtx, "dnf", "advisory", "list", flagSecurity, flagQuiet)
	if err != nil {
		// DNF4 fallback: RHEL/Rocky/older Fedora
		out, err = runCmd(scanCtx, "dnf", cmdUpdateinfo, "list", pkgSevSecurity, flagQuiet)
	}
	if err != nil {
		// The advisory query failed (broken plugin, transient dnf error, permission)
		// — we did NOT learn there are 0 updates. Mark it so the verdict reports
		// "couldn't verify" instead of a silent clean 0-updates OK (false-OK).
		info.Status = pkgQueryFailed
		if scanCtx.Err() != nil {
			// BUG-098: a cancelled/deadline-exceeded call is not "unavailable" —
			// it's an honest "ran out of time," almost always a cold cache. Say so.
			info.StatusReason = "dnf advisory/updateinfo scan timed out — likely a cold metadata cache or slow mirror; retry"
		} else {
			info.StatusReason = "dnf advisory/updateinfo unavailable"
		}
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
			sev = pkgSevCritical
			info.CriticalUpdates++
		case strings.HasPrefix(sevLower, "important"):
			sev = pkgSevImportant
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

// collectTDNF counts pending Photon (VMware Photon OS) security advisories via
// tdnf. Photon publishes advisories as PHSA notices with no per-package CVSS, so
// every pending advisory is classed Important (WARN-worthy) — never a name- or
// guess-minted Critical. Mirrors collectDNF's shape; reuses the shared tdnf
// updateinfo parsers in cve_linux.go. A failed query is surfaced as pkgQueryFailed
// (an unverified result), never a silent clean 0 (the false-OK this closes).
func collectTDNF(ctx context.Context) (*models.PackagesInfo, error) {
	info := &models.PackagesInfo{Checked: true, PackageManager: "tdnf"}

	// No enabled repos → `tdnf updateinfo` returns nothing because there is no
	// advisory source, not because the host is patched. Report "couldn't verify"
	// (query-failed → INFO) rather than a silent clean 0 — the false-OK guard a
	// post-Broadcom-migration host (dead packages.vmware.com repos) needs.
	if !tdnfHasEnabledRepo(ctx) {
		info.Status = pkgQueryFailed
		info.StatusReason = "no enabled tdnf repositories — security updates cannot be determined (check: tdnf repolist)"
		return info, nil
	}
	info.HasSecurityRepo = true

	out, err := runCmd(ctx, "tdnf", "-j", cmdUpdateinfo, "list", flagSecurity)
	entries, parsed := parseTDNFUpdateInfoJSON(out)
	if !parsed {
		textOut, textErr := runCmd(ctx, "tdnf", cmdUpdateinfo, "list", flagSecurity)
		entries = parseTDNFUpdateInfoText(textOut)
		if len(entries) == 0 && textErr != nil && err != nil {
			info.Status = pkgQueryFailed
			info.StatusReason = "tdnf updateinfo unavailable"
			return info, nil
		}
	}

	for _, e := range entries {
		pkg := ""
		if len(e.Packages) > 0 {
			pkg = strings.TrimSuffix(e.Packages[0], ".rpm")
		}
		info.SecurityUpdates++
		info.ImportantUpdates++ // Photon advisories carry no CVSS — never Critical
		info.Updates = append(info.Updates, models.PackageUpdate{
			Name:     pkg,
			Severity: pkgSevImportant,
			Advisory: tdnfTrimPatchPrefix(e.UpdateID),
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
		info.Status = pkgNoSecurityRepo
		info.StatusReason = "no security repository configured in apt sources — add security.debian.org or ubuntu security mirror"
		return info, nil
	}
	info.HasSecurityRepo = true

	// apt-get update is NOT run here — too slow and requires root for lock.
	// We read whatever is cached; caller should ensure cache is fresh.
	out, err := runCmd(ctx, pkgCmdAptGet, "-s", "upgrade")
	if err != nil {
		// apt-get -s (simulate) requires no lock but may fail (apt lock, broken
		// sources) — we didn't verify, so don't read as a clean 0-updates result.
		info.Status = pkgQueryFailed
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
		sev := pkgSevImportant
		for critPrefix := range criticalPkgs {
			if pkgName == critPrefix || strings.HasPrefix(pkgName, critPrefix+"-") {
				sev = pkgSevCritical
				break
			}
		}

		if sev == pkgSevCritical {
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

	out, err := runCmd(ctx, pkgCmdAptGet, "-s", "upgrade")
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
		sev := pkgSevImportant
		for critPrefix := range criticalPkgs {
			if pkgName == critPrefix || strings.HasPrefix(pkgName, critPrefix+"-") {
				sev = pkgSevCritical
				break
			}
		}
		if sev == pkgSevCritical {
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
	entries, _ := readDirEntries("/etc/apt/sources.list.d")
	for _, e := range entries {
		if !e.IsDir() {
			paths = append(paths, "/etc/apt/sources.list.d/"+e.Name())
		}
	}

	for _, p := range paths {
		data, err := readFile(p) // #nosec G304 -- hardcoded known paths
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

// zypperLocked reports whether zypper output indicates the global zypp lock
// (/run/zypp.pid) was held by another process — zypper exits 7 (ZYPP_LOCKED) and
// prints "System management is locked by the application with pid N". Transient and
// root-independent; the caller retries rather than reporting a false "unverified".
func zypperLocked(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "is locked by") ||
		strings.Contains(l, "system management is locked") ||
		strings.Contains(l, "zypp.pid")
}

// collectZypper parses `zypper list-patches --category security` for openSUSE/SLES.
// zypper list-patches exits 0 whether or not patches are available.
// Security patches are identified by category "security" in the output.
func collectZypper(ctx context.Context) (*models.PackagesInfo, error) {
	info := &models.PackagesInfo{Checked: true, PackageManager: "zypper"}

	// Check for security patches. zypper holds ONE global lock (/run/zypp.pid); dsd
	// runs collectors in parallel, so a sibling (SUSEConnect, snapper, another zypper)
	// can hold it briefly and our query exits 7 (ZYPP_LOCKED). That is transient and
	// root-INDEPENDENT — retry a few times before giving up. Without this, the loser of
	// a lock race false-reports "could not verify" while real security patches are
	// pending (found live on SLES 16: a lock race hid 28 pending security patches, with
	// a misleading "try running as root" even when already root). Mirrors the
	// retry-on-transient-lock pattern in rpmDBHealth. Combined output so the lock
	// message (on stderr) is visible for detection; the table parser below ignores
	// non-matching lines.
	var out string
	var err error
	locked := false
	for attempt := 0; attempt < 5; attempt++ {
		out, err = runCmdCombined(ctx, "zypper", pkgNonInteractive, pkgFlagNoColor,
			"list-patches", "--category", pkgSevSecurity)
		locked = err != nil && zypperLocked(out)
		if !locked {
			break
		}
		if !sleepCtx(ctx, 800*time.Millisecond) {
			break // ctx cancelled — don't spin
		}
	}
	if err != nil {
		// Couldn't check — NOT "OK"; report unverified with the accurate reason.
		info.Status = pkgQueryFailed
		switch {
		case locked:
			info.StatusReason = "zypper is locked by another process — security updates not verified"
		case os.Geteuid() != 0:
			info.StatusReason = "zypper list-patches unavailable — run as root to read security patches"
		default:
			info.StatusReason = "zypper list-patches failed — security updates not verified"
		}
		return info, nil
	}

	// Parse output — pipe-separated table:
	// Repository | Name | Category | Severity | Interactive | Status | Summary
	// Status is "needed", "not needed", "applied", or "not applicable"
	securityNeeded := 0
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)
		// Must be a security patch
		if !strings.Contains(lower, pkgSevSecurity) {
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
		// Count critical and important SEPARATELY — the other collectors (dnf etc.)
		// already do, and the heuristic renders critical→CRIT, important→WARN. Lumping
		// important into CriticalUpdates over-escalated: on SLES 16 (0 critical, 18
		// important) dsd reported "18 critical … CRIT" when the honest verdict is "18
		// important … WARN" (found when the count didn't match `zypper lp` severities).
		severity := strings.TrimSpace(strings.ToLower(fields[3]))
		switch severity {
		case "critical":
			info.CriticalUpdates++
		case "important":
			info.ImportantUpdates++
		}
		name := ""
		if len(fields) >= 2 {
			name = strings.TrimSpace(fields[1])
		}
		sev := "Moderate"
		switch severity {
		case "critical":
			sev = pkgSevCritical
		case "important":
			sev = pkgSevImportant
		}
		info.Updates = append(info.Updates, models.PackageUpdate{
			Name:     name,
			Severity: sev,
			Advisory: name,
		})
	}

	info.SecurityUpdates = securityNeeded
	// CriticalUpdates already set inline per patch

	// Check if security repos are configured. Without one, `zypper list-patches`
	// legitimately finds 0 security patches — not because the host is patched,
	// but because there's no repo to learn about updates from. Set Status (not
	// just StatusReason) so checkPackageUpdates reports it as an explicit WARN
	// instead of a silent clean 0 (the same false-OK apt already guards against).
	info.HasSecurityRepo = zypperHasSecurityRepo(ctx)
	if !info.HasSecurityRepo {
		info.Status = pkgNoSecurityRepo
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
	out, err := runCmd(ctx, "zypper", pkgNonInteractive, pkgFlagNoColor, "repos")
	if err != nil {
		return false
	}
	lower := strings.ToLower(out)
	for _, keyword := range []string{pkgSevSecurity, "update", "sle-module", "opensuse-update", "tumbleweed"} {
		if strings.Contains(lower, keyword) {
			return true
		}
	}

	// SLES: check if SUSEConnect is registered — without it, no security repos
	if _, err := runCmd(ctx, "SUSEConnect", pkgFlagStatus); err == nil {
		// SUSEConnect present — check if system is registered
		statusOut, _ := runCmd(ctx, "SUSEConnect", pkgFlagStatus)
		if strings.Contains(strings.ToLower(statusOut), "registered") {
			return true
		}
	}
	return false
}

// dnfHasUpdateRepo returns true when at least one enabled dnf repo is available.
// Rocky Linux and RHEL ship security updates via baseos — no separate security repo needed.
func dnfHasUpdateRepo(ctx context.Context) bool {
	out, err := runCmd(ctx, "dnf", "repolist", "--enabled", pkgFlagQ)
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

var dnfWarmCacheOnce sync.Once

// dnfWarmCache runs a bounded `dnf makecache` once per process so later dnf
// calls (the repo gate check, the advisory scan) hit warm metadata instead of
// each independently paying a cold sync. Both the Packages and CVE collectors
// call this concurrently; dnf's own lock file would serialize two overlapping
// `makecache` processes anyway, but doing it explicitly with sync.Once avoids
// two dnf processes actually racing for that lock — one being force-killed by
// its own context deadline while it holds (or is waiting on) the lock is exactly
// the kind of interaction that's hard to reason about, so just don't create it:
// whichever collector calls this first does the real work, the second call
// blocks until the first returns, then finds a warm cache and no-ops fast.
// Best-effort — the callers below have their own bounded timeouts and will
// honestly report "could not verify" / "timed out" if metadata genuinely can't
// be fetched.
func dnfWarmCache(ctx context.Context) {
	dnfWarmCacheOnce.Do(func() {
		warmCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		_, _ = runCmd(warmCtx, "dnf", "makecache", pkgFlagQ)
	})
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
	grubOut, err := runCmd(ctx, "zypper", pkgNonInteractive, pkgFlagNoColor,
		"search", "--installed-only", grubPkg)
	if err == nil && strings.Contains(grubOut, grubPkg) {
		// Check if it's locked
		lockOut, _ := runCmd(ctx, "zypper", pkgNonInteractive, pkgFlagNoColor, "locks")
		if !strings.Contains(lockOut, grubPkg) {
			risks = append(risks,
				grubPkg+" is installed but NOT locked — migration may overwrite grub config and break boot",
			)
		}
	}

	// Check 2: SUSEConnect registration health
	statusOut, err := runCmd(ctx, "SUSEConnect", pkgFlagStatus)
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
				if installedKernel != runningKernel && versionStringGreater(installedKernel, runningKernel) {
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

// splitVersionTokens splits a version-like string into alternating digit and
// non-digit runs, e.g. "5.14.21-150500.55.30-default" →
// ["5", ".", "14", ".", "21-150500.", "55", ".", "30", "-default"].
func splitVersionTokens(s string) []string {
	var tokens []string
	var cur strings.Builder
	isDigit := func(b byte) bool { return b >= '0' && b <= '9' }
	for i := 0; i < len(s); i++ {
		if cur.Len() > 0 && isDigit(s[i]) != isDigit(cur.String()[0]) {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
		cur.WriteByte(s[i])
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// versionStringGreater reports whether a is a newer version string than b,
// comparing digit runs as integers rather than lexicographically. A plain Go
// string `>` gets SUSE service-pack kernel versions like "...55.30-default"
// vs "...55.7-default" backwards: '3' < '7' as a character even though 30 > 7
// numerically, so a genuinely NEWER installed kernel compared as "older" and
// the pending-reboot warning was suppressed (or fired in reverse) exactly on
// the SP-update scenario it exists to catch.
func versionStringGreater(a, b string) bool {
	ta, tb := splitVersionTokens(a), splitVersionTokens(b)
	for i := 0; i < len(ta) && i < len(tb); i++ {
		if ta[i] == tb[i] {
			continue
		}
		na, errA := strconv.Atoi(ta[i])
		nb, errB := strconv.Atoi(tb[i])
		if errA == nil && errB == nil {
			return na > nb
		}
		return ta[i] > tb[i]
	}
	return len(ta) > len(tb)
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
	out, _ := runCmdOutput(dnfCtx, "dnf", "check", flagQuiet)
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
	// dpkg --audit — immediate, < 0.5s. Use runCmdOutput so its report is read
	// regardless of exit code (capture-regardless-of-exit, mirroring DNF).
	aptCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, _ := runCmdOutput(aptCtx, "dpkg", "--audit")
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			pi.BrokenPackages = append(pi.BrokenPackages, line)
		}
	}

	// apt-get check — detects unmet dependencies. It EXITS NON-ZERO (100) when it
	// finds them and writes the diagnosis to STDERR, so runCmd would discard the
	// findings → broken deps read as clean (false-OK, the same bug DNF was fixed
	// for). runCmdCombined keeps stdout+stderr regardless of exit.
	checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
	defer checkCancel()
	checkOut, _ := runCmdCombined(checkCtx, pkgCmdAptGet, "check")
	for _, line := range strings.Split(checkOut, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "unmet dep") || strings.Contains(lower, "broken package") {
			pi.UnmetDeps = append(pi.UnmetDeps, strings.TrimSpace(line))
		}
	}
}

// pkgIntegrityZypper checks SUSE/openSUSE package consistency.
func pkgIntegrityZypper(ctx context.Context, pi *models.PackageIntegrity) {
	// zypper verify (exit 1 = problems found). It EXITS NON-ZERO when it finds
	// broken/missing deps, so runCmd would discard the output and the check would
	// read clean (false-OK, same bug as APT/DNF). Capture stdout+stderr regardless
	// of exit (zypper writes its resolution to stdout; the zypp-lock message to
	// stderr).
	//
	// zypper holds ONE global lock (/run/zypp.pid); dsd runs collectors in parallel,
	// so a sibling can hold it and `zypper verify` exits 7 (ZYPP_LOCKED) with empty
	// stdout — which read as a CLEAN integrity check (a deep-mode false-OK, the
	// sibling of the security-scan lock race fixed in #480). Retry on the lock, and
	// if it stays locked report "couldn't verify" rather than a silent clean.
	zCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	var out string
	var err error
	locked := false
	for attempt := 0; attempt < 4; attempt++ {
		out, err = runCmdCombined(zCtx, "zypper", pkgNonInteractive, "verify", "--dry-run")
		// exit 1 = "problems found" (err != nil but NOT a lock — parse it); exit 7 =
		// locked. Only a lock should retry.
		locked = err != nil && zypperLocked(out)
		if !locked {
			break
		}
		if !sleepCtx(zCtx, 800*time.Millisecond) {
			break // ctx cancelled — don't spin
		}
	}
	if locked {
		pi.VerifyLocked = true // couldn't verify — do NOT read clean
		return
	}
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
		if !fileExists(bin) {
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
