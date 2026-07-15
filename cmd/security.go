package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

const (
	secLvlWarn  = "warn"
	secLvlInfo  = "info"
	secLvlFail  = "fail"
	secIconOK   = "✅"
	secIconWarn = "⚠️"
	secIconInfo = "ℹ️ "
	secKwSUID   = "suid"
	secRowFmt   = "  %s   %s\n"
)

func init() {
	rootCmd.AddCommand(securityCmd)
	securityCmd.Flags().Bool("deep", false, "deep mode: include SUID binary scan (slow on large filesystems)")
	securityCmd.Flags().Bool(secKwSUID, false, "alias for --deep (deprecated)")
	_ = securityCmd.Flags().MarkHidden(secKwSUID)
	securityCmd.Flags().Bool("save-baseline", false, "save current security state as drift baseline")
	securityCmd.Flags().Bool("drift", false, "compare current security state against saved baseline")
}

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Security posture — SSH, ports, logins, sudoers, SELinux",
	RunE:  runSecurity,
}

func runSecurity(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	p := output.NewCommandProgress("Security health", 10*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewSecurityCollector()}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.SecurityInfo)
	if !ok || info == nil {
		return result.Err
	}

	saveBaseline, _ := cmd.Flags().GetBool("save-baseline")
	drift, _ := cmd.Flags().GetBool("drift")
	deepFlag, _ := cmd.Flags().GetBool("deep")
	suidAlias, _ := cmd.Flags().GetBool(secKwSUID)
	if saveBaseline || drift || deepFlag || suidAlias {
		// The SUID scan is skipped by Collect() to keep `dsd health` fast; the
		// drift baseline needs it, so run it explicitly here.
		collectors.ScanSUIDBinaries(info)
	}
	switch {
	case saveBaseline:
		return runSaveBaseline(info, mode)
	case drift:
		return runDrift(info, mode)
	}

	recordResultSeverity([]runner.Result{result}) // BUG-022: honour 0/1/2 exit contract

	if mode == output.ModeJSON {
		return outputJSON(os.Stdout, info)
	}

	// Snapper runs in parallel (requires root; silently skipped if unavailable)
	snapInfo, _ := collectors.CollectSnapper(ctx)

	printSecurityReport(info, snapInfo, mode, elapsed)
	return nil
}

// runSaveBaseline persists the current security state as the drift baseline.
func runSaveBaseline(info *models.SecurityInfo, mode output.OutputMode) error {
	b := baseline.BuildSecurityBaseline(info)
	if err := baseline.SaveSecurityBaseline(b); err != nil {
		return fmt.Errorf("saving security baseline: %w", err)
	}
	fmt.Printf("%s  Security baseline saved to ~/.dsd/security-baseline.json\n", asciiOr("ok", secIconOK, mode))
	fmt.Printf("    SUID binaries: %d | Sudo NOPASSWD: %d | Suspect crons: %d | SSH configs: %d\n",
		len(b.KnownSUIDs), len(b.SudoNopasswd), len(b.SuspectCrons), len(b.SSHConfigHashes))
	return nil
}

// runDrift compares the current security state against the saved baseline.
func runDrift(info *models.SecurityInfo, mode output.OutputMode) error {
	saved, err := baseline.LoadSecurityBaseline()
	if err != nil {
		return fmt.Errorf("loading security baseline: %w", err)
	}
	if saved == nil {
		fmt.Printf("%s  No security baseline found. Run: dsd security --save-baseline\n", asciiOr(secLvlInfo, "ℹ️", mode))
		return nil
	}

	diff := baseline.DiffSecurityBaseline(saved, info)
	dateStr := diff.BaselineSavedAt.Format("2006-01-02 15:04:05")
	if !diff.HasChanges() {
		fmt.Printf("%s  No security drift detected since %s\n", asciiOr("ok", secIconOK, mode), dateStr)
		return nil
	}

	printSecurityDrift(&diff, mode)
	return nil
}

// printSecurityDrift renders the drift report when changes are detected. It
// mirrors the styling used by printSecurityReport.
func printSecurityDrift(diff *baseline.SecurityDiff, mode output.OutputMode) {
	sep := strings.Repeat("─", 56)
	dateStr := diff.BaselineSavedAt.Format("2006-01-02 15:04:05")

	fmt.Printf("\n🔍 Security drift since %s\n", dateStr)

	if len(diff.NewSUIDs) > 0 {
		fmt.Println("\nNew SUID binaries (not in baseline):")
		for _, s := range diff.NewSUIDs {
			fmt.Printf("  %s  %s  [investigate: ls -la && file]\n", asciiOr(secLvlFail, iconFail, mode), s)
		}
	}

	if len(diff.ChangedSSHFiles) > 0 {
		fmt.Println("\nChanged SSH config files:")
		for _, f := range diff.ChangedSSHFiles {
			fmt.Printf("  %s  %s  (modified since baseline)\n", asciiOr(secLvlWarn, secIconWarn, mode), f)
			fmt.Printf("     → Review changes to %s and restart sshd if intentional\n", f)
			fmt.Println("     → Or: git diff if sshd_config is version-controlled")
		}
	}

	if len(diff.AddedSSHFiles) > 0 {
		fmt.Println("\nNew SSH config files (not in baseline):")
		for _, f := range diff.AddedSSHFiles {
			fmt.Printf("  %s  %s  (added since baseline)\n", asciiOr(secLvlWarn, secIconWarn, mode), f)
			fmt.Printf("     → Inspect %s for PermitRootLogin / PasswordAuthentication overrides\n", f)
		}
	}

	if len(diff.RemovedSSHFiles) > 0 {
		fmt.Println("\nRemoved SSH config files (in baseline, now gone):")
		for _, f := range diff.RemovedSSHFiles {
			fmt.Printf("  %s  %s  (removed since baseline)\n", asciiOr(secLvlWarn, secIconWarn, mode), f)
			fmt.Printf("     → Confirm the hardening from %s is still applied elsewhere\n", f)
		}
	}

	if len(diff.NewSudoEntries) > 0 {
		fmt.Println("\nNew sudoers NOPASSWD entries:")
		for _, s := range diff.NewSudoEntries {
			// codeql[go/clear-text-logging] -- intentional: dsd security prints audit findings to the terminal
			fmt.Printf("  %s  %s\n", asciiOr(secLvlWarn, secIconWarn, mode), s)
		}
	}

	if len(diff.NewCronEntries) > 0 {
		fmt.Println("\nNew suspect cron entries:")
		for _, s := range diff.NewCronEntries {
			fmt.Printf("  %s  %s\n", asciiOr(secLvlWarn, secIconWarn, mode), s)
		}
	}

	// Drive the summary severity from the drift heuristics.
	insights := analysis.CheckSecurityDrift(diff)
	recordWorstInsight(insights) // BUG-022: new SUID = CRIT, SSH/sudo/cron change = WARN
	changes := len(diff.NewSUIDs) + len(diff.ChangedSSHFiles) +
		len(diff.AddedSSHFiles) + len(diff.RemovedSSHFiles) +
		len(diff.NewSudoEntries) + len(diff.NewCronEntries)
	baselineDate := diff.BaselineSavedAt.Format("2006-01-02")

	fmt.Println()
	fmt.Println(sep)
	summary := fmt.Sprintf("%s  %d security change(s) since baseline (%s)", asciiOr(secLvlWarn, secIconWarn, mode), changes, baselineDate)
	if hasCrit(insights) {
		summary = fmt.Sprintf("%s  %d security change(s) since baseline (%s) — includes CRITICAL drift", asciiOr(secLvlFail, iconFail, mode), changes, baselineDate)
		fmt.Println(render.StyleCrit.Render(summary))
	} else {
		fmt.Println(render.StyleWarn.Render(summary))
	}
	fmt.Println("   → Update baseline when changes are intentional: dsd security --save-baseline")
}

// hasCrit reports whether any insight is at CRIT level.
func hasCrit(insights []models.Insight) bool {
	for _, ins := range insights {
		if ins.Level == "CRIT" {
			return true
		}
	}
	return false
}

// printSecurityReport is the flat dispatcher for `dsd security`'s report.
// Each print*Section below covers one independent theme and writes straight
// to stdout with no shared buffer — split out of a single ~290-line function
// (was `//nolint:cyclop,funlen`) the same way checkSecurity was split.
func printSecurityReport(info *models.SecurityInfo, snap *models.SnapperInfo, mode output.OutputMode, elapsed time.Duration) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	printSSHConfigSection(info, mode)
	printFailedLoginsSection(info)
	printListeningPortsSection(info, mode)
	printSudoSection(info, mode)
	printFirewallSection(info, mode)
	printMacOSSecuritySection(info, mode)
	printRHELSecuritySection(info, mode)
	printSUSESecuritySection(info, mode)
	printSnapperSection(snap, mode)
	printSELinuxSection(info, mode)
	printAppArmorSection(info, mode)
	if macNotActive(info) {
		fmt.Printf("\n%s  No mandatory access control (SELinux/AppArmor) detected or active on this host\n",
			asciiOr(secLvlInfo, "ℹ️", mode))
	}
	printPAMSection(info, mode)
	printSUIDBinariesSection(info, mode)

	// Summary
	fmt.Println()
	fmt.Println(sep)
	// Verdict derived from the SAME heuristic `dsd health` uses (checkSecurity), so
	// the two can't diverge (BUG-072). The count is now WARN/CRIT insights rather
	// than a separate item tally — grouped like health (e.g. "3 unexpected ports"
	// is one concern).
	issues := analysis.SecurityConcernCount(*info)
	switch {
	case issues > 0:
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("%s  %d security concern(s) found%s", asciiOr(secLvlWarn, secIconWarn, mode), issues, timing)))
	case securityChecksLimited(info):
		// No issues — but the root-only checks (failed logins, listening-port
		// process names, SELinux audit, effective sshd config) didn't run, so we
		// verified almost nothing. Don't claim "healthy. Checks passed" (the
		// false-OK dsd health already avoids via a NeedsRoot INFO).
		fmt.Printf("%s Security checks limited — run as root (sudo dsd security) to fully verify; no issues found in what could be checked%s\n",
			asciiOr(secLvlInfo, secIconInfo, mode), timing)
	default:
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("%s Security posture healthy. Checks passed%s", asciiOr("ok", secIconOK, mode), timing)))
	}
}

// printSSHConfigSection prints the SSH Configuration section (PermitRootLogin,
// PasswordAuthentication).
func printSSHConfigSection(info *models.SecurityInfo, mode output.OutputMode) {
	// SSH Configuration
	fmt.Println("\nSSH Configuration")
	// Key on SSHPermitRoot (the same field the verdict + checkSecurity use) so the
	// detail line can't show "secure" while the verdict flags root login — e.g.
	// PermitRootLogin forced-commands-only.
	printSecItem("PermitRootLogin", !info.SSHPermitRoot, "no (secure)", "yes (INSECURE)", mode)
	printSecItem("PasswordAuthentication", !info.SSHPasswordAuth, "no (key-only)", "yes (weaker)", mode)
}

// printFailedLoginsSection prints the Failed Logins (last hour) section.
func printFailedLoginsSection(info *models.SecurityInfo) {
	// Failed logins
	fmt.Printf("\nFailed Logins (last hour): %d\n", info.FailedLogins)
	if len(info.FailedLoginIPs) > 0 {
		fmt.Println("  Top source IPs:")
		for _, ip := range info.FailedLoginIPs {
			fmt.Printf("    %s\n", ip)
		}
	}
}

// printListeningPortsSection prints the Listening Ports section.
func printListeningPortsSection(info *models.SecurityInfo, mode output.OutputMode) {
	// Listening ports
	fmt.Printf("\nListening Ports (%d total)\n", len(info.ListeningPorts))
	for _, p := range info.ListeningPorts {
		icon := asciiOr("ok", secIconOK, mode)
		tag := ""
		if !p.Expected {
			icon = asciiOr(secLvlWarn, iconWarnSp, mode)
			tag = " ← unexpected"
		}
		// Proxmox VE mandates 8006 (web UI), 3128 (spiceproxy), 111 (rpcbind) —
		// expected on PVE, never flag as unexpected (BUG-016).
		if info.IsPVE && analysis.IsPVEServicePort(p.Port) {
			icon = asciiOr("ok", secIconOK, mode)
			tag = " ← PVE service port (expected)"
		}
		proc := p.Process
		if proc == "" {
			proc = "unknown"
		}
		// Always use well-known service name for standard ports —
		// raw process names (master, systemd, python3) are less readable.
		if name := wellKnownPort(p.Port); name != "" {
			proc = name
		}
		fmt.Printf("  %s  %-6d %-5s %-20s%s\n", icon, p.Port, p.Protocol, proc, tag)
	}
}

// printSudoSection prints the Sudo NOPASSWD entries section.
func printSudoSection(info *models.SecurityInfo, mode output.OutputMode) {
	// Sudo NOPASSWD
	if len(info.SudoNopasswd) > 0 {
		fmt.Println("\nSudo NOPASSWD entries:")
		for _, entry := range info.SudoNopasswd {
			// codeql[go/clear-text-logging] -- intentional: dsd security prints audit findings to the terminal
			fmt.Printf(secRowFmt, asciiOr(secLvlWarn, secIconWarn, mode), entry)
		}
	} else if info.NeedsRoot {
		fmt.Println("\nSudo NOPASSWD entries: unknown (needs root)")
	} else {
		fmt.Println("\nSudo NOPASSWD entries: none")
	}
}

// printFirewallSection prints the Firewall section.
func printFirewallSection(info *models.SecurityInfo, mode output.OutputMode) {
	// Firewall
	if info.FirewallActive {
		sshIcon := asciiOr("ok", secIconOK, mode)
		if !info.SSHAllowed {
			sshIcon = asciiOr(secLvlFail, iconFail, mode)
		}
		zone := ""
		if info.FirewallZone != "" {
			zone = fmt.Sprintf(" (zone: %s)", info.FirewallZone)
		}
		fmt.Printf("\nFirewall: %s active%s\n", info.FirewallType, zone)
		if len(info.FirewallServices) > 0 {
			fmt.Printf("  %s  allowed: %s\n", asciiOr("ok", secIconOK, mode), strings.Join(info.FirewallServices, ", "))
		}
		fmt.Printf("  %s  SSH accessible\n", sshIcon)
	} else if info.FirewallToolingPresent {
		// Tooling installed but no active ruleset — host is unprotected. Mirror
		// the health Firewall WARN rather than reporting a benign "none detected".
		fmt.Printf("\nFirewall: %s installed but no active rules — host is unprotected\n",
			info.FirewallType)
		fmt.Printf("  %s  no active firewall rules\n", asciiOr(secLvlWarn, iconWarnSp, mode))
	} else if info.FirewallUnreadable {
		// Tooling installed but ruleset unreadable (non-root) — state unknown.
		// Report "not verified", not "none detected" (which implies no firewall).
		fmt.Printf("\nFirewall: %s state not verified — run as root to read the ruleset\n",
			info.FirewallType)
	} else {
		fmt.Println("\nFirewall: none detected")
	}
}

// printMacOSSecuritySection prints the macOS Security section (FileVault,
// SIP, Gatekeeper — darwin only).
func printMacOSSecuritySection(info *models.SecurityInfo, mode output.OutputMode) {
	// macOS Security — FileVault, SIP, Gatekeeper (darwin only)
	if info.IsDarwin {
		fmt.Println("\nmacOS Security")
		printSecItem("FileVault", info.FileVaultEnabled, "on (disk encrypted)", "off (disk not encrypted)", mode)
		printSecItem("SIP", info.SIPEnabled, "enabled", "DISABLED", mode)
		printSecItem("Gatekeeper", info.GatekeeperEnabled, "enabled", "disabled", mode)
	}
}

// printRHELSecuritySection prints the System Security section (FIPS, crypto
// policy, auditd, USBGuard, AIDE — RHEL/Rocky family).
func printRHELSecuritySection(info *models.SecurityInfo, mode output.OutputMode) {
	// RHEL/Rocky security
	if info.CryptoPolicy != "" || info.FIPSEnabled || info.AIDEInstalled || info.USBGuardActive || info.AuditRules >= 0 {
		fmt.Println("\nSystem Security")
		if info.FIPSEnabled {
			fmt.Printf("  %s  FIPS mode: enabled\n", asciiOr("ok", secIconOK, mode))
		} else if info.CryptoPolicy != "" {
			fmt.Printf("  %s   FIPS mode: disabled\n", asciiOr(secLvlInfo, "ℹ️", mode))
		}
		if info.CryptoPolicy != "" {
			policyIcon := asciiOr("ok", secIconOK, mode)
			if info.CryptoPolicy == "LEGACY" {
				policyIcon = asciiOr(secLvlWarn, iconWarnSp, mode)
			}
			fmt.Printf("  %s  Crypto policy: %s\n", policyIcon, info.CryptoPolicy)
		}
		if info.AuditRules >= 0 {
			if info.AuditRules == 0 {
				fmt.Printf("  %s  auditd: running, no rules configured\n", asciiOr(secLvlWarn, secIconWarn, mode))
			} else {
				fmt.Printf("  %s  auditd: %d rule(s) active\n", asciiOr("ok", secIconOK, mode), info.AuditRules)
			}
		}
		if info.USBGuardActive {
			fmt.Printf("  %s  USBGuard: active\n", asciiOr("ok", secIconOK, mode))
		}
		if info.AIDEInstalled {
			if !info.AIDEDBExists {
				fmt.Printf("  %s  AIDE: installed but database not initialised\n", asciiOr(secLvlWarn, secIconWarn, mode))
			} else if info.AIDELastRunDays > 7 {
				fmt.Printf("  %s  AIDE: database %d days old\n", asciiOr(secLvlWarn, secIconWarn, mode), info.AIDELastRunDays)
			} else {
				fmt.Printf("  %s  AIDE: database %d days old\n", asciiOr("ok", secIconOK, mode), info.AIDELastRunDays)
			}
		}
	}
}

// printSUSESecuritySection prints SUSE supportconfig freshness and
// SUSEConnect subscription expiry.
func printSUSESecuritySection(info *models.SecurityInfo, mode output.OutputMode) {
	// SUSE supportconfig
	if info.SupportconfigAvailable {
		fmt.Println("\nSUSE supportconfig")
		switch {
		case info.SupportconfigLastRunDays == -1:
			fmt.Printf("  %s  never run — run before contacting SUSE support\n", asciiOr(secLvlInfo, "\u2139\ufe0f", mode))
		case info.SupportconfigLastRunDays > 30:
			fmt.Printf("  %s  last run %d days ago\n", asciiOr(secLvlWarn, secIconWarn, mode), info.SupportconfigLastRunDays)
		default:
			fmt.Printf("  %s  last run %d days ago (%s)\n", asciiOr("ok", secIconOK, mode), info.SupportconfigLastRunDays, info.SupportconfigArchive)
		}
	}

	// SUSEConnect subscription
	if info.SUSEConnectRegistered {
		fmt.Println("\nSUSEConnect subscription")
		status := info.SUSEConnectStatus
		if status == "" {
			status = "unknown"
		}
		switch {
		case info.SUSEConnectExpiresDays == 0:
			fmt.Printf("  %s  EXPIRED (%s)\n", asciiOr(secLvlFail, "\U0001f534", mode), status)
		case info.SUSEConnectExpiresDays > 0 && info.SUSEConnectExpiresDays <= 14:
			fmt.Printf("  %s  expires in %d day(s) \u2014 renew immediately\n", asciiOr(secLvlFail, "\U0001f534", mode), info.SUSEConnectExpiresDays)
		case info.SUSEConnectExpiresDays > 14 && info.SUSEConnectExpiresDays <= 30:
			fmt.Printf("  %s   expires in %d day(s) \u2014 renew soon\n", asciiOr(secLvlWarn, secIconWarn, mode), info.SUSEConnectExpiresDays)
		case info.SUSEConnectExpiresDays > 30:
			fmt.Printf("  %s  active \u2014 expires in %d day(s) (%s)\n", asciiOr("ok", secIconOK, mode), info.SUSEConnectExpiresDays, status)
		default:
			fmt.Printf("  %s   registered, expiry unknown\n", asciiOr(secLvlInfo, "\u2139\ufe0f", mode))
		}
	}
}

// printSnapperSection prints the Btrfs snapshots (snapper) section
// (SLES / openSUSE).
func printSnapperSection(snap *models.SnapperInfo, mode output.OutputMode) {
	// Snapper / Btrfs snapshots (SLES / openSUSE)
	if snap != nil && snap.Available {
		fmt.Println("\nBtrfs snapshots (snapper)")
		if snap.SnapshotCount == 0 {
			fmt.Printf("  %s  no snapshots found\n", asciiOr(secLvlWarn, secIconWarn, mode))
		} else {
			spaceStr := ""
			if snap.TotalSpaceGB > 0 {
				spaceStr = fmt.Sprintf(", %.2f GiB used", snap.TotalSpaceGB)
			}
			switch {
			case snap.LastSnapshotH < 0:
				fmt.Printf("  %s  %d snapshot(s)%s — no recent snapshot\n", asciiOr(secLvlWarn, secIconWarn, mode), snap.SnapshotCount, spaceStr)
			case snap.LastSnapshotH == 0:
				fmt.Printf("  %s  %d snapshot(s)%s — last: < 1h ago\n", asciiOr("ok", secIconOK, mode), snap.SnapshotCount, spaceStr)
			default:
				fmt.Printf("  %s  %d snapshot(s)%s — last: %dh ago\n", asciiOr("ok", secIconOK, mode), snap.SnapshotCount, spaceStr, snap.LastSnapshotH)
			}
		}
	}
}

// printSELinuxSection prints the SELinux mode, denials, booleans, and AVC
// denial groups.
func printSELinuxSection(info *models.SecurityInfo, mode output.OutputMode) {
	if info.SELinuxMode != "" {
		fmt.Printf("\nSELinux mode: %s\n", info.SELinuxMode)
		switch {
		case info.SELinuxDenials > 0:
			fmt.Printf("  %s  %d denial(s) in the last hour\n", asciiOr(secLvlWarn, secIconWarn, mode), info.SELinuxDenials)
		case info.SELinuxDenials == -1:
			fmt.Printf("  %s  AVC denial data unavailable — run as root or install audit-libs\n", asciiOr(secLvlInfo, "ℹ️", mode))
		default:
			fmt.Printf("  %s  No denials in the last hour\n", asciiOr("ok", secIconOK, mode))
		}
		// SELinux booleans — show off booleans relevant to denied types
		if len(info.SELinuxBooleans) > 0 {
			fmt.Printf("\n  [SELinux booleans — check first]\n")
			for _, b := range info.SELinuxBooleans {
				fmt.Printf("  %s   %-45s = off\n", asciiOr(secLvlWarn, secIconWarn, mode), b.Name)
				fmt.Printf("       → %s\n", b.SetCmd)
			}
		}
		// AVC groups — show top 5
		if len(info.SELinuxAVCGroups) > 0 {
			fmt.Printf("\n  [AVC denials — last hour]\n")
			for i, g := range info.SELinuxAVCGroups {
				if i >= 5 {
					fmt.Printf("  ... and %d more group(s)\n", len(info.SELinuxAVCGroups)-5)
					break
				}
				perms := strings.Join(g.Perms, ",")
				fmt.Printf("  %s   ×%-4d  %-20s → %-20s  [%s] %s\n",
					asciiOr(secLvlWarn, secIconWarn, mode), g.Count, g.Scontext, g.Tcontext, g.Tclass, perms)
				if g.BooleanFix != "" {
					fmt.Printf("       → setsebool -P %s on\n", g.BooleanFix)
				} else if g.FixCmd != "" {
					fmt.Printf("       → %s\n", g.FixCmd)
				}
			}
		}
		// Port labels — proactive port-label scan (§6-add-2)
		if len(info.SELinuxUnlabeledPorts) > 0 {
			fmt.Printf("\n  [Port labels]\n")
			for _, p := range info.SELinuxUnlabeledPorts {
				proc := p.Process
				if proc == "" {
					proc = "unknown process"
				}
				fmt.Printf("  %s   %s/%-5d %s — no SELinux port label\n", asciiOr(secLvlWarn, secIconWarn, mode), p.Protocol, p.Port, proc)
				fmt.Printf("       → semanage port -a -t <service>_port_t -p %s %d\n", p.Protocol, p.Port)
			}
		}
		// File context — temporary chcon vs permanent semanage fcontext (§6-add-3)
		if len(info.SELinuxContextIssues) > 0 {
			fmt.Printf("\n  [File context — temporary chcon, not semanage]\n")
			for _, ci := range info.SELinuxContextIssues {
				fmt.Printf(secRowFmt, asciiOr(secLvlWarn, secIconWarn, mode), ci.Path)
				fmt.Printf("       actual:   %s\n", ci.ActualContext)
				fmt.Printf("       expected: %s\n", ci.ExpectedContext)
				fmt.Printf("       → semanage fcontext -a -t %s '%s'  then  restorecon -Rv %s\n",
					selinuxContextType(ci.ExpectedContext), ci.Path, ci.Path)
			}
		}
		if info.SELinuxAutoRelabel {
			fmt.Printf("\n  %s  /.autorelabel present — full filesystem relabel queued on next reboot (~15 min)\n", asciiOr(secLvlWarn, secIconWarn, mode))
		}
	}
}

// printAppArmorSection prints the AppArmor mode and denial section
// (SLES/Ubuntu/Debian).
func printAppArmorSection(info *models.SecurityInfo, mode output.OutputMode) {
	// AppArmor (SLES/Ubuntu/Debian)
	if info.AppArmorMode != "" && info.AppArmorMode != "disabled" && info.AppArmorMode != "unknown" {
		fmt.Printf("\nAppArmor mode: %s (%d profiles loaded)\n", info.AppArmorMode, info.AppArmorProfiles)
		if info.AppArmorComplain > 0 {
			fmt.Printf("  %s  %d profile(s) in complain mode\n", asciiOr(secLvlWarn, secIconWarn, mode), info.AppArmorComplain)
		} else if info.AppArmorProfiles > 0 {
			fmt.Printf("  %s  All profiles enforcing\n", asciiOr("ok", secIconOK, mode))
		}
		switch {
		case len(info.AppArmorGroups) > 0:
			fmt.Printf("  %s   %d denial group(s) in last 24h:\n", asciiOr(secLvlWarn, secIconWarn, mode), len(info.AppArmorGroups))
			for i, g := range info.AppArmorGroups {
				if i >= 3 {
					break
				}
				fmt.Printf("    ×%-3d  %-30s  %s\n", g.Count, g.Profile, g.Path)
			}
			fmt.Println("  → aa-logprof  (auto-suggest profile updates)")
		case info.AppArmorDenials > 0:
			fmt.Printf("  %s  %d denial(s) in the last hour\n", asciiOr(secLvlWarn, secIconWarn, mode), info.AppArmorDenials)
		default:
			fmt.Printf("  %s  No denials in the last 24h\n", asciiOr("ok", secIconOK, mode))
		}
	}
}

// macNotActive reports whether neither SELinux nor AppArmor produced a mode
// value worth reporting — i.e. neither printSELinuxSection nor
// printAppArmorSection printed anything. Kept in sync with those two
// functions' own gating conditions so the fallback line can't silently drift
// from what they actually print.
func macNotActive(info *models.SecurityInfo) bool {
	selinuxAbsent := info.SELinuxMode == ""
	apparmorAbsent := info.AppArmorMode == "" || info.AppArmorMode == "disabled" || info.AppArmorMode == "unknown"
	return selinuxAbsent && apparmorAbsent
}

// printPAMSection prints PAM-related findings: locked accounts (faillock)
// and, if present, grouped module-authentication failures from non-sshd
// services (su, sudo, login, cron). Combined into one section — both are
// PAM-sourced findings and a separate top-level block per finding would just
// duplicate this one.
func printPAMSection(info *models.SecurityInfo, mode output.OutputMode) {
	if len(info.PAMLockedAccounts) == 0 && len(info.PAMModuleFailures) == 0 {
		return
	}
	fmt.Println("\nPAM")
	if len(info.PAMLockedAccounts) > 0 {
		fmt.Println("  Locked accounts:")
		for _, a := range info.PAMLockedAccounts {
			fmt.Printf("    %s  %s\n", asciiOr(secLvlFail, iconFail, mode), a)
		}
		fmt.Println("    → faillock --reset --user <name>  (to unlock)")
	}
	if len(info.PAMModuleFailures) > 0 {
		fmt.Printf("  Module failures (last 24h, non-SSH services):\n")
		for i, f := range info.PAMModuleFailures {
			if i >= 5 {
				fmt.Printf("    ... and %d more\n", len(info.PAMModuleFailures)-5)
				break
			}
			fmt.Printf("    %s   %-12s %-15s ×%d\n", asciiOr(secLvlWarn, secIconWarn, mode), f.Service, f.User, f.Count)
		}
	}
}

// printSUIDBinariesSection prints the unexpected SUID binaries section.
func printSUIDBinariesSection(info *models.SecurityInfo, mode output.OutputMode) {
	// SUID binaries
	if len(info.SUIDBinaries) > 0 {
		fmt.Printf("\nUnexpected SUID binaries (%d):\n", len(info.SUIDBinaries))
		for _, b := range info.SUIDBinaries {
			fmt.Printf(secRowFmt, asciiOr(secLvlWarn, secIconWarn, mode), b)
		}
	}
}

// securityChecksLimited reports whether the standalone security audit ran with
// reduced coverage — non-root (root-only probes silently degraded) or an
// sshd_config that existed but couldn't be read. In that state a zero issue
// count means "nothing to flag in what we could see", NOT a clean bill of health.
func securityChecksLimited(info *models.SecurityInfo) bool {
	return info.NeedsRoot || (info.SSHConfigUnreadable && info.SSHAuditSource == "")
}

func printSecItem(label string, ok bool, goodVal, badVal string, mode output.OutputMode) {
	if ok {
		fmt.Printf("  %s  %-28s %s\n", asciiOr("ok", secIconOK, mode), label+":", goodVal)
	} else {
		fmt.Printf("  %s   %-28s %s\n", asciiOr(secLvlWarn, secIconWarn, mode), label+":", badVal)
	}
}

// selinuxContextType extracts the type field from a user:role:type:level
// SELinux context string, for the `semanage fcontext -a -t <type>` fix hint.
func selinuxContextType(context string) string {
	parts := strings.Split(context, ":")
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// wellKnownPort maps common port numbers to service names.
// Used to resolve ports where systemd socket activation hides the real service.
func wellKnownPort(port int) string {
	names := map[int]string{
		22:    "sshd",
		25:    "postfix", // SMTP — default MTA on openSUSE/SLES/RHEL
		53:    "dns",
		80:    "http",
		443:   "https",
		3306:  "mysql",
		5432:  "postgres",
		6379:  "redis",
		8080:  "http-alt",
		8443:  "https-alt",
		9090:  "cockpit", // RHEL/Rocky web console — socket activated via systemd
		9100:  "node-exporter",
		10250: "kubelet",
		10255: "kubelet-ro",
	}
	return names[port]
}
