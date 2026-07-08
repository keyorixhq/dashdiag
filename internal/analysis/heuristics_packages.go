package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// packageFixCommands returns the distro-correct (fix, inspect) command pair for
// a package manager, defaulting to apt's when the manager is unknown.
func packageFixCommands(pm string) (fixCmd, inspectCmd string) {
	switch pm {
	case "brew":
		return "brew upgrade", "brew outdated"
	case "dnf":
		return "dnf upgrade --security", "dnf updateinfo list security"
	case "zypper":
		return "zypper patch --category security", "zypper list-patches --category security"
	case "pacman":
		return "pacman -Syu", "checkupdates"
	case "yum":
		return "yum update --security", "yum updateinfo list security"
	case "tdnf":
		return "tdnf update --security", "tdnf updateinfo list --security"
	default:
		return "apt-get upgrade", "apt list --upgradable 2>/dev/null | grep -i security"
	}
}

// noSecurityRepoHints returns the distro-correct remediation for "no security
// repository configured". The apt-specific wording was hard-coded here even
// though dnf/zypper hosts hit this same status — a false-OK sibling fixed
// separately (they weren't setting Status at all) that would otherwise have
// surfaced a Debian/Ubuntu fix hint on a RHEL/SUSE host.
func noSecurityRepoHints(pm string) []string {
	switch pm {
	case "dnf", "yum":
		return []string{"to fix: enable a repo that carries security advisories (check: dnf repolist / yum repolist)"}
	case "zypper":
		return []string{"to fix: add openSUSE's security repo or SUSE's update repo (check: zypper repos)"}
	default:
		return []string{
			"to fix (Debian): add 'deb http://security.debian.org/debian-security <suite>-security main' to /etc/apt/sources.list",
			"to fix (Ubuntu): add 'deb http://security.ubuntu.com/ubuntu <suite>-security main' to /etc/apt/sources.list",
		}
	}
}

func checkPackages(pkg models.PackagesInfo) []models.Insight {
	// Package-DB / lock health first: an interrupted dpkg, unreadable rpmdb, or stale
	// zypper lock blocks EVERY update, so the security-update count is meaningless
	// until it's cleared — the false-OK where a host reads "patched" but can't patch.
	out := checkPackageDBHealth(pkg)

	// Security-update verdict. It may short-circuit (no-security-repo /
	// query-failed / stale-metadata / fully patched) — but that must NOT gate the
	// integrity checks below. A fully-patched OR stale-metadata host can still
	// have broken packages / unmet deps, and those were silently skipped when this
	// logic early-returned ahead of the integrity check (false-OK).
	out = append(out, checkPackageUpdates(pkg)...)

	// Package integrity (deep mode only — populated by PackagesDeepCollector).
	// Always evaluated, independent of the security-update status above.
	if pkg.Integrity != nil {
		out = append(out, checkPackageIntegrity(*pkg.Integrity)...)
	}

	out = append(out, checkPackageExtras(pkg)...)
	return out
}

// checkPackageDBHealth flags a package database / lock state that silently blocks all
// updates. It is the strongest false-OK guard in this collector: the security-update
// count can read a confident "0" while the host literally cannot apply a single update.
func checkPackageDBHealth(pkg models.PackagesInfo) []models.Insight {
	// Defensive: the collector never sets DBUpdatesBlocked without DBHealthChecked
	// also being true (verified 2026-07-08), but gate on both anyway so a future
	// collector change can't silently turn an unmeasured state into a WARN.
	if !pkg.DBHealthChecked || !pkg.DBUpdatesBlocked {
		return nil
	}
	hints := []string{}
	if pkg.DBBlockFix != "" {
		hints = append(hints, "to fix: "+pkg.DBBlockFix)
	}
	hints = append(hints, "note: the security-update count cannot be trusted until this is cleared — no update can be applied")
	reason := pkg.DBBlockReason
	if reason == "" {
		reason = "the package database is in a state that blocks updates"
	}
	return []models.Insight{insight("WARN", "Packages",
		"package updates are silently blocked: "+reason, hints)}
}

// checkPackageUpdates turns the security-update scan result into insights. Its
// early returns end only the UPDATE verdict — the caller still runs the
// integrity and extras checks regardless.
func checkPackageUpdates(pkg models.PackagesInfo) []models.Insight {
	var out []models.Insight

	// No security repo configured — warn explicitly rather than showing zero.
	if pkg.Status == "no-security-repo" {
		return []models.Insight{insight("WARN", "Packages",
			"no security repository configured — security updates cannot be detected",
			noSecurityRepoHints(pkg.PackageManager),
		)}
	}

	// The security-update query itself FAILED (dnf/zypper/apt errored — broken
	// plugin, apt lock, permission). The "0 updates" is not a real result; report
	// "couldn't verify" rather than a silent clean OK (false-OK).
	if pkg.Status == "query-failed" {
		reason := pkg.StatusReason
		if reason == "" {
			reason = "the package manager's security query failed"
		}
		return []models.Insight{insight("INFO", "Packages",
			"could not verify security updates: "+reason,
			[]string{"note: this is an unverified result, not a clean bill of health"},
		)}
	}

	// Stale/absent update metadata — the "0 updates" result was not refreshed, so
	// report it as unverified (INFO) rather than a confident "up to date".
	if pkg.Status == "stale-metadata" {
		reason := pkg.StatusReason
		if reason == "" {
			reason = "update metadata is stale — cannot confirm packages are up to date"
		}
		refresh := map[string]string{
			"apt": "apt update", "dnf": "dnf makecache", "yum": "yum makecache",
			"zypper": "zypper refresh", "tdnf": "tdnf makecache",
		}[pkg.PackageManager]
		hints := []string{"note: this is an unverified result, not a clean bill of health"}
		if refresh != "" {
			hints = append([]string{"to refresh: " + refresh + "  then re-run dsd"}, hints...)
		}
		return []models.Insight{insight("INFO", "Packages", reason, hints)}
	}

	if pkg.SecurityUpdates == 0 {
		// Check for ESM-only updates even when no standard security updates exist
		if pkg.ESMUpdates > 0 {
			return []models.Insight{insight("WARN", "Packages",
				fmt.Sprintf("%d security update(s) require Ubuntu Pro (ESM) — not visible without subscription", pkg.ESMUpdates),
				[]string{
					"to inspect: pro security-status",
					"to fix:     ubuntu.com/pro (free for up to 5 machines)",
				},
			)}
		}
		return nil
	}

	out = append(out, securityUpdateInsight(pkg)...)

	// Ubuntu ESM: surface Pro-gated security updates as INFO so the admin
	// knows real CVEs exist even without a Pro subscription.
	if pkg.ESMUpdates > 0 {
		out = append(out, insight("WARN", "Packages",
			fmt.Sprintf("%d security update(s) require Ubuntu Pro (ESM) — not applied without subscription", pkg.ESMUpdates),
			[]string{
				"to inspect: pro security-status",
				"to fix:     ubuntu.com/pro (free for up to 5 machines)",
			},
		))
	}

	return out
}

// securityUpdateInsight renders the single security-update verdict for a
// confirmed, non-empty scan. Package managers that publish NO per-package CVSS
// (apt: severity inferred from the package name; tdnf/Photon: not rated at all)
// fold to one honest WARN — a name guess or vendor "Security" tag must NOT mint a
// hard CRIT (exit 2). Managers that DO expose a real per-advisory severity
// (dnf/zypper/yum) keep the CriticalUpdates→CRIT path.
func securityUpdateInsight(pkg models.PackagesInfo) []models.Insight {
	fixCmd, inspectCmd := packageFixCommands(pkg.PackageManager)

	switch {
	case pkg.PackageManager == "apt":
		return []models.Insight{insight("WARN", "Packages",
			fmt.Sprintf("%d security update(s) available (apt) — severity inferred from package name; apt exposes no CVSS", pkg.SecurityUpdates),
			[]string{fmt.Sprintf("to fix: %s", fixCmd)},
		)}
	case pkg.PackageManager == "tdnf":
		// VMware Photon OS: PHSA advisories are vendor-confirmed but carry no CVSS.
		// (Before tdnf support, Photon read as an "unknown" package manager and these
		// advisories were INVISIBLE — a silent false-OK on VMware's own distro.)
		return []models.Insight{insight("WARN", "Packages",
			fmt.Sprintf("%d pending security update(s) (tdnf) — Photon advisories carry no CVSS, so severity is not scored", pkg.SecurityUpdates),
			[]string{fmt.Sprintf("to fix: %s", fixCmd)},
		)}
	case pkg.PackageManager == "brew":
		// Homebrew has NO security metadata at all — `brew outdated` lists every
		// outdated formula, security-relevant or not (a routine dev-Mac state, not
		// a vulnerability signal). Reporting it as a security WARN like every
		// other manager here is a false alarm; an honest INFO instead.
		return []models.Insight{insight("INFO", "Packages",
			fmt.Sprintf("%d outdated Homebrew formula(e) — brew has no security ratings, this is a routine update count", pkg.SecurityUpdates),
			[]string{fmt.Sprintf("to inspect: %s", inspectCmd), fmt.Sprintf("to update: %s", fixCmd)},
		)}
	case pkg.CriticalUpdates > 0:
		return []models.Insight{insight("CRIT", "Packages",
			fmt.Sprintf("%d critical security update(s) available (%s)", pkg.CriticalUpdates, pkg.PackageManager),
			[]string{
				fmt.Sprintf("to inspect: %s", inspectCmd),
				fmt.Sprintf("to fix: %s", fixCmd),
			},
		)}
	case pkg.ImportantUpdates > 0:
		return []models.Insight{insight("WARN", "Packages",
			fmt.Sprintf("%d important security update(s) available (%s)", pkg.ImportantUpdates, pkg.PackageManager),
			[]string{fmt.Sprintf("to fix: %s", fixCmd)},
		)}
	default:
		return []models.Insight{insight("WARN", "Packages",
			fmt.Sprintf("%d security update(s) available (%s)", pkg.SecurityUpdates, pkg.PackageManager),
			[]string{fmt.Sprintf("to fix: %s", fixCmd)},
		)}
	}
}

func checkPackageExtras(pkg models.PackagesInfo) []models.Insight {
	out := make([]models.Insight, 0, len(pkg.SUSEMigrationRisks))
	// SUSE pre-migration: warn about boot-breaking package risks before zypper migration.
	// Research finding: admins regularly brick systems during SLES service pack migration
	// because grub2-x86_64-efi is not locked, system is unregistered, or kernel not rebooted.
	for _, risk := range pkg.SUSEMigrationRisks {
		out = append(out, insight("WARN", "Packages",
			"SUSE migration risk: "+risk,
			[]string{
				"to lock grub:   zypper addlock grub2-x86_64-efi",
				"to check locks: zypper locks",
				"to register:    SUSEConnect -r <registration-code>",
				"note: resolve before running zypper migration to avoid boot failure",
			},
		))
	}
	return out
}

// checkCVEHealth turns a CVE security-advisory scan (from CVEHealthCollector,
// i.e. `dsd health --cve`) into health insights. Severity buckets map to dsd
// levels per the documented thresholds:
//
//   - any CISA KEV match     → CRIT (actively exploited in the wild, urgent)
//   - Critical-rated advisory → CRIT
//   - Important/High-rated    → WARN
//
// Moderate and Low advisories do not fire — they fall below the WARN threshold
// and would only add noise to the health summary.
//
// The bucket is the package manager's published severity RATING (dnf/zypper
// "Critical"/"Important", arch-audit "Critical"/"High"), not a CVSS score this
// scan measured: `<pkgmgr> updateinfo` reports a label, not a number, and a
// vendor's "Critical"/"Important" rating is not a strict CVSS band (Red Hat
// weighs exploitability/wormability too). So the messages say "rates these
// Critical", never "CVSS >= 9.0" — which would assert a precise score the scan
// never read. apt is one step further removed: it publishes no severity at all,
// so its bucket is inferred from the package name — capped at a single honest
// WARN (no name-only CRIT, no "CVSS >= X" claim). See the apt branch below.
func checkCVEHealth(r models.CVEAllResult) []models.Insight {
	withFix := func(hints []string) []string {
		if r.FixCommand != "" {
			hints = append(hints, "to fix: "+r.FixCommand)
		}
		return hints
	}

	// KEV takes precedence — actively-exploited CVEs are the most urgent signal,
	// regardless of the package manager's own severity label.
	if r.KEVCount > 0 {
		hints := []string{"these CVEs are in the CISA Known Exploited Vulnerabilities catalog — patch immediately"}
		if len(r.KEVCVEs) > 0 {
			hints = append(hints, "affected: "+strings.Join(r.KEVCVEs, ", "))
		}
		return []models.Insight{insight("CRIT", "CVE",
			fmt.Sprintf("%d actively-exploited CVE(s) present (CISA KEV)", r.KEVCount),
			withFix(hints),
		)}
	}

	// apt publishes no per-package CVSS, so its severities are inferred from the
	// package name (aptPackageSeverity). Don't assert a "CVSS >= X" threshold the
	// scan never measured, and don't let a name guess mint a hard CRIT — fold the
	// name-matched advisories into a single honest WARN. Managers that do expose a
	// real severity/CVSS (dnf/zypper/…) keep the CVSS-based CRIT/WARN below.
	switch r.PackageManager {
	case "apt":
		if n := len(r.Critical) + len(r.Important); n > 0 {
			return []models.Insight{insight("WARN", "CVE",
				fmt.Sprintf("%d security-relevant package update(s) pending (apt) — severity inferred from package name; apt exposes no CVSS", n),
				withFix([]string{
					"to review the list: dsd cve --all",
					"note: confirm real severity via the Debian/Ubuntu security tracker — apt does not publish CVSS",
				}),
			)}
		}
	case "tdnf":
		// VMware Photon OS: PHSA advisories are vendor-confirmed but carry no CVSS,
		// so fold to a single honest WARN (never a CRIT). scanAllTDNF buckets every
		// advisory as Important for exactly this path.
		if n := len(r.Critical) + len(r.Important); n > 0 {
			return []models.Insight{insight("WARN", "CVE",
				fmt.Sprintf("%d pending Photon security advisory(ies) (tdnf) — no CVSS published, so severity is not scored", n),
				withFix([]string{
					"to review the list: dsd cve --all",
					"note: Photon advisories (PHSA) do not publish a CVSS band; see the Photon security advisories",
				}),
			)}
		}
	default:
		if len(r.Critical) > 0 {
			return []models.Insight{insight("CRIT", "CVE",
				fmt.Sprintf("%d critical security advisory(ies) — %s rates these Critical", len(r.Critical), r.PackageManager),
				withFix(nil),
			)}
		}

		if len(r.Important) > 0 {
			return []models.Insight{insight("WARN", "CVE",
				fmt.Sprintf("%d high-severity security advisory(ies) — %s rates these High/Important", len(r.Important), r.PackageManager),
				withFix(nil),
			)}
		}
	}

	// Scan couldn't actually run (no package manager, scanner tool absent, or the
	// scan command failed) — surface as INFO, not a green "OK". A security check
	// that silently reads OK when it never ran is a false sense of security. INFO
	// does not raise the verdict.
	if cveScanUnavailable(r) {
		reason := r.StatusReason
		if reason == "" {
			reason = "no supported package manager"
		}
		return []models.Insight{insight("INFO", "CVE",
			"CVE scan unavailable: "+reason,
			[]string{"run `dsd cve --all` for details, or install a supported scanner"},
		)}
	}

	// Moderate/Low only, or clean — stays quiet (below the WARN threshold).
	return nil
}

// cveScanUnavailable reports whether the CVE scan could not actually run on this
// host — no supported package manager, the scanner tool is not installed, or the
// scan command failed — as opposed to running and finding nothing. Such a result
// must not render as a green "OK" (which reads as "no CVEs" on a host we never
// scanned). The authoritative signal is CVEAllResult.ScanFailed, set directly by
// every scanner failure path in cve_linux.go — checked first so this can't be
// silently defeated by a StatusReason wording change (BUG-098: a scanner message
// was reworded to be more honest about *why* it failed — cold cache vs generic
// failure — and that alone flipped a failed scan to render as a false "OK",
// because this function was pattern-matching the message text instead of the
// ScanFailed bool it was already given). The substrings below are kept as a
// defensive fallback for callers that only set StatusReason; the substrings here
// are pinned by TestCVEScanUnavailable.
func cveScanUnavailable(r models.CVEAllResult) bool {
	if r.PackageManager == "" || r.ScanFailed {
		return true
	}
	reason := strings.ToLower(r.StatusReason)
	return strings.Contains(reason, "failed") ||
		strings.Contains(reason, "install arch-audit") ||
		strings.Contains(reason, "not verified") // stale/absent index → couldn't confirm "no CVEs"
}

func checkPackageIntegrity(pi models.PackageIntegrity) []models.Insight {
	var out []models.Insight

	if len(pi.BrokenPackages) > 0 {
		out = append(out, insight("CRIT", "Packages",
			fmt.Sprintf("%d broken/inconsistent package(s) detected", len(pi.BrokenPackages)),
			append([]string{
				"to inspect (dnf):  dnf check",
				"to inspect (dpkg): dpkg --audit",
				"to fix (dnf):      dnf distro-sync",
				"to fix (apt):      apt --fix-broken install",
			}, pi.BrokenPackages[:min(3, len(pi.BrokenPackages))]...),
		))
	}

	if len(pi.UnmetDeps) > 0 {
		out = append(out, insight("CRIT", "Packages",
			fmt.Sprintf("%d unmet dependency/dependencies detected", len(pi.UnmetDeps)),
			append([]string{"to fix: apt --fix-broken install"}, pi.UnmetDeps...),
		))
	}

	if len(pi.RPMVerifyFailed) > 0 {
		out = append(out, insight("WARN", "Packages",
			fmt.Sprintf("%d system file(s) modified from package baseline (rpm --verify)", len(pi.RPMVerifyFailed)),
			append([]string{
				"to inspect: rpm --verify --all | grep -v '^..........  c '",
				"note:       modifications to non-config files may indicate tampering or a broken update",
			}, pi.RPMVerifyFailed[:min(3, len(pi.RPMVerifyFailed))]...),
		))
	}

	if pi.VerifyTimedOut {
		out = append(out, insight("WARN", "Packages",
			"rpm --verify timed out — system may be under heavy load or have many packages",
			[]string{"to run manually: rpm --verify --all 2>/dev/null | grep -v '^..........  c '"},
		))
	}

	if pi.VerifyLocked {
		// The integrity check couldn't run because the package manager was locked by
		// another process — report it as unverified, never a silent clean (false-OK).
		out = append(out, insight("INFO", "Packages",
			"could not verify package integrity — the package manager was locked by another process",
			[]string{"to run manually: zypper verify   (after any running zypper/packagekit finishes)"},
		))
	}

	if len(pi.MissingLibs) > 0 {
		out = append(out, insight("CRIT", "Packages",
			fmt.Sprintf("%d missing shared library/libraries detected", len(pi.MissingLibs)),
			append([]string{
				"to inspect: ldd /bin/ls /usr/bin/ssh /usr/bin/python3",
				"to fix:     reinstall the package providing the missing .so file",
			}, pi.MissingLibs...),
		))
	}

	if !pi.LdconfigOK {
		// `ldconfig -p` did not complete — could be a slow/overlay/read-only fs
		// timing out the probe (e.g. a live-USB overlay), or a permission issue —
		// NOT necessarily a broken cache. Report "couldn't verify" (INFO), not a
		// "may be corrupted" WARN, per the couldn't-run ≠ broken principle.
		out = append(out, insight("INFO", "Packages",
			"could not verify the shared library cache — ldconfig -p did not complete (slow/overlay fs or permissions); not necessarily a problem",
			[]string{"to check manually: ldconfig -p | head -20", "to rebuild if needed: sudo ldconfig"},
		))
	}

	return out
}

func checkTLS(tls models.TLSInfo) []models.Insight {
	if len(tls.Certs) == 0 && len(tls.Uncheckable) == 0 {
		return nil // nothing found and nothing failed to read — don't fire
	}
	var out []models.Insight

	// Cert files / endpoints that could NOT be read (unreadable file, unreachable
	// endpoint, garbled PEM). Surface as WARN so a "0 expired" verdict is never
	// mistaken for "all healthy" when some certs were never actually evaluated.
	for _, u := range tls.Uncheckable {
		out = append(out, insight("WARN", "TLS",
			fmt.Sprintf("certificate could not be checked: %s (%s)", u.Path, u.Error),
			[]string{fmt.Sprintf("to inspect: openssl x509 -in %s -noout -dates", u.Path)},
		))
	}

	// Expired certs — always CRIT
	for _, cert := range tls.Certs {
		if cert.ExpiresIn < 0 {
			out = append(out, insight("CRIT", "TLS",
				fmt.Sprintf("certificate expired %d day(s) ago: %s (%s)", -cert.ExpiresIn, cert.Subject, cert.Path),
				[]string{
					fmt.Sprintf("to inspect: openssl x509 -in %s -noout -dates", cert.Path),
					"to fix: renew certificate (certbot renew or manual replacement)",
				},
			))
		}
	}

	// Expiring within 7 days — CRIT
	for _, cert := range tls.Certs {
		if cert.ExpiresIn >= 0 && cert.ExpiresIn <= 7 {
			out = append(out, insight("CRIT", "TLS",
				fmt.Sprintf("certificate expires in %d day(s): %s (%s)", cert.ExpiresIn, cert.Subject, cert.Path),
				[]string{
					fmt.Sprintf("to inspect: openssl x509 -in %s -noout -dates", cert.Path),
					"to fix: renew now — certbot renew or manual replacement",
				},
			))
		}
	}

	// Expiring within 30 days — WARN
	for _, cert := range tls.Certs {
		if cert.ExpiresIn > 7 && cert.ExpiresIn <= 30 {
			out = append(out, insight("WARN", "TLS",
				fmt.Sprintf("certificate expires in %d day(s): %s (%s)", cert.ExpiresIn, cert.Subject, cert.Path),
				[]string{
					fmt.Sprintf("to inspect: openssl x509 -in %s -noout -dates", cert.Path),
					"to fix: renew soon — certbot renew or manual replacement",
				},
			))
		}
	}

	// Not yet valid — TLS handshakes fail now even though expiry is far off, so it
	// would otherwise read healthy. CRIT.
	for _, cert := range tls.Certs {
		if cert.NotYetValid {
			out = append(out, insight("CRIT", "TLS",
				fmt.Sprintf("certificate is NOT YET VALID (NotBefore in the future): %s (%s)", cert.Subject, cert.Path),
				[]string{
					fmt.Sprintf("to inspect: openssl x509 -in %s -noout -dates", cert.Path),
					"note: check the host clock (NTP) and that the correct, current cert is installed",
				},
			))
		}
	}

	return out
}
