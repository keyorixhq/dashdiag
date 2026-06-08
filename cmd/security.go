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

func init() {
	rootCmd.AddCommand(securityCmd)
	securityCmd.Flags().Bool("deep", false, "deep mode: include SUID binary scan (slow on large filesystems)")
	securityCmd.Flags().Bool("suid", false, "alias for --deep (deprecated)")
	_ = securityCmd.Flags().MarkHidden("suid")
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
	suidAlias, _ := cmd.Flags().GetBool("suid")
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
	fmt.Printf("%s  Security baseline saved to ~/.dsd/security-baseline.json\n", asciiOr("ok", "✅", mode))
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
		fmt.Printf("%s  No security baseline found. Run: dsd security --save-baseline\n", asciiOr("info", "ℹ️", mode))
		return nil
	}

	diff := baseline.DiffSecurityBaseline(saved, info)
	dateStr := diff.BaselineSavedAt.Format("2006-01-02 15:04:05")
	if !diff.HasChanges() {
		fmt.Printf("%s  No security drift detected since %s\n", asciiOr("ok", "✅", mode), dateStr)
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
			fmt.Printf("  %s  %s  [investigate: ls -la && file]\n", asciiOr("fail", "❌", mode), s)
		}
	}

	if len(diff.ChangedSSHFiles) > 0 {
		fmt.Println("\nChanged SSH config files:")
		for _, f := range diff.ChangedSSHFiles {
			fmt.Printf("  %s  %s  (modified since baseline)\n", asciiOr("warn", "⚠️", mode), f)
			fmt.Printf("     → Review changes to %s and restart sshd if intentional\n", f)
			fmt.Println("     → Or: git diff if sshd_config is version-controlled")
		}
	}

	if len(diff.NewSudoEntries) > 0 {
		fmt.Println("\nNew sudoers NOPASSWD entries:")
		for _, s := range diff.NewSudoEntries {
			fmt.Printf("  %s  %s\n", asciiOr("warn", "⚠️", mode), s)
		}
	}

	if len(diff.NewCronEntries) > 0 {
		fmt.Println("\nNew suspect cron entries:")
		for _, s := range diff.NewCronEntries {
			fmt.Printf("  %s  %s\n", asciiOr("warn", "⚠️", mode), s)
		}
	}

	// Drive the summary severity from the drift heuristics.
	insights := analysis.CheckSecurityDrift(diff)
	recordWorstInsight(insights) // BUG-022: new SUID = CRIT, SSH/sudo/cron change = WARN
	changes := len(diff.NewSUIDs) + len(diff.ChangedSSHFiles) +
		len(diff.NewSudoEntries) + len(diff.NewCronEntries)
	baselineDate := diff.BaselineSavedAt.Format("2006-01-02")

	fmt.Println()
	fmt.Println(sep)
	summary := fmt.Sprintf("%s  %d security change(s) since baseline (%s)", asciiOr("warn", "⚠️", mode), changes, baselineDate)
	if hasCrit(insights) {
		summary = fmt.Sprintf("%s  %d security change(s) since baseline (%s) — includes CRITICAL drift", asciiOr("fail", "❌", mode), changes, baselineDate)
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

func printSecurityReport(info *models.SecurityInfo, snap *models.SnapperInfo, mode output.OutputMode, elapsed time.Duration) { //nolint:cyclop,funlen // flat display renderer — each branch is a distinct section
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	// SSH Configuration
	fmt.Println("\nSSH Configuration")
	printSecItem("PermitRootLogin", !info.SSHRootLogin, "no (secure)", "yes (INSECURE)", mode)
	printSecItem("PasswordAuthentication", !info.SSHPasswordAuth, "no (key-only)", "yes (weaker)", mode)

	// Failed logins
	fmt.Printf("\nFailed Logins (last hour): %d\n", info.FailedLogins)
	if len(info.FailedLoginIPs) > 0 {
		fmt.Println("  Top source IPs:")
		for _, ip := range info.FailedLoginIPs {
			fmt.Printf("    %s\n", ip)
		}
	}

	// Listening ports
	fmt.Printf("\nListening Ports (%d total)\n", len(info.ListeningPorts))
	for _, p := range info.ListeningPorts {
		icon := asciiOr("ok", "✅", mode)
		tag := ""
		if !p.Expected {
			icon = asciiOr("warn", "⚠️ ", mode)
			tag = " ← unexpected"
		}
		// Proxmox VE mandates 8006 (web UI), 3128 (spiceproxy), 111 (rpcbind) —
		// expected on PVE, never flag as unexpected (BUG-016).
		if info.IsPVE && analysis.IsPVEServicePort(p.Port) {
			icon = asciiOr("ok", "✅", mode)
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

	// Sudo NOPASSWD
	if len(info.SudoNopasswd) > 0 {
		fmt.Println("\nSudo NOPASSWD entries:")
		for _, entry := range info.SudoNopasswd {
			fmt.Printf("  %s   %s\n", asciiOr("warn", "⚠️", mode), entry)
		}
	} else if info.NeedsRoot {
		fmt.Println("\nSudo NOPASSWD entries: unknown (needs root)")
	} else {
		fmt.Println("\nSudo NOPASSWD entries: none")
	}

	// Firewall
	if info.FirewallActive {
		sshIcon := asciiOr("ok", "✅", mode)
		if !info.SSHAllowed {
			sshIcon = asciiOr("fail", "❌", mode)
		}
		zone := ""
		if info.FirewallZone != "" {
			zone = fmt.Sprintf(" (zone: %s)", info.FirewallZone)
		}
		fmt.Printf("\nFirewall: %s active%s\n", info.FirewallType, zone)
		if len(info.FirewallServices) > 0 {
			fmt.Printf("  %s  allowed: %s\n", asciiOr("ok", "✅", mode), strings.Join(info.FirewallServices, ", "))
		}
		fmt.Printf("  %s  SSH accessible\n", sshIcon)
	} else {
		fmt.Println("\nFirewall: none detected")
	}

	// macOS Security — FileVault, SIP, Gatekeeper (darwin only)
	if info.IsDarwin {
		fmt.Println("\nmacOS Security")
		printSecItem("FileVault", info.FileVaultEnabled, "on (disk encrypted)", "off (disk not encrypted)", mode)
		printSecItem("SIP", info.SIPEnabled, "enabled", "DISABLED", mode)
		printSecItem("Gatekeeper", info.GatekeeperEnabled, "enabled", "disabled", mode)
	}

	// RHEL/Rocky security
	if info.CryptoPolicy != "" || info.FIPSEnabled || info.AIDEInstalled || info.USBGuardActive || info.AuditRules >= 0 {
		fmt.Println("\nSystem Security")
		if info.FIPSEnabled {
			fmt.Printf("  %s  FIPS mode: enabled\n", asciiOr("ok", "✅", mode))
		} else if info.CryptoPolicy != "" {
			fmt.Printf("  %s   FIPS mode: disabled\n", asciiOr("info", "ℹ️", mode))
		}
		if info.CryptoPolicy != "" {
			policyIcon := asciiOr("ok", "✅", mode)
			if info.CryptoPolicy == "LEGACY" {
				policyIcon = asciiOr("warn", "⚠️ ", mode)
			}
			fmt.Printf("  %s  Crypto policy: %s\n", policyIcon, info.CryptoPolicy)
		}
		if info.AuditRules >= 0 {
			if info.AuditRules == 0 {
				fmt.Printf("  %s  auditd: running, no rules configured\n", asciiOr("warn", "⚠️", mode))
			} else {
				fmt.Printf("  %s  auditd: %d rule(s) active\n", asciiOr("ok", "✅", mode), info.AuditRules)
			}
		}
		if info.USBGuardActive {
			fmt.Printf("  %s  USBGuard: active\n", asciiOr("ok", "✅", mode))
		}
		if info.AIDEInstalled {
			if !info.AIDEDBExists {
				fmt.Printf("  %s  AIDE: installed but database not initialised\n", asciiOr("warn", "⚠️", mode))
			} else if info.AIDELastRunDays > 7 {
				fmt.Printf("  %s  AIDE: database %d days old\n", asciiOr("warn", "⚠️", mode), info.AIDELastRunDays)
			} else {
				fmt.Printf("  %s  AIDE: database %d days old\n", asciiOr("ok", "✅", mode), info.AIDELastRunDays)
			}
		}
	}

	// SUSE supportconfig
	if info.SupportconfigAvailable {
		fmt.Println("\nSUSE supportconfig")
		switch {
		case info.SupportconfigLastRunDays == -1:
			fmt.Printf("  %s  never run — run before contacting SUSE support\n", asciiOr("info", "\u2139\ufe0f", mode))
		case info.SupportconfigLastRunDays > 30:
			fmt.Printf("  %s  last run %d days ago\n", asciiOr("warn", "\u26a0\ufe0f", mode), info.SupportconfigLastRunDays)
		default:
			fmt.Printf("  %s  last run %d days ago (%s)\n", asciiOr("ok", "\u2705", mode), info.SupportconfigLastRunDays, info.SupportconfigArchive)
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
			fmt.Printf("  %s  EXPIRED (%s)\n", asciiOr("fail", "\U0001f534", mode), status)
		case info.SUSEConnectExpiresDays > 0 && info.SUSEConnectExpiresDays <= 14:
			fmt.Printf("  %s  expires in %d day(s) \u2014 renew immediately\n", asciiOr("fail", "\U0001f534", mode), info.SUSEConnectExpiresDays)
		case info.SUSEConnectExpiresDays > 14 && info.SUSEConnectExpiresDays <= 30:
			fmt.Printf("  %s   expires in %d day(s) \u2014 renew soon\n", asciiOr("warn", "\u26a0\ufe0f", mode), info.SUSEConnectExpiresDays)
		case info.SUSEConnectExpiresDays > 30:
			fmt.Printf("  %s  active \u2014 expires in %d day(s) (%s)\n", asciiOr("ok", "\u2705", mode), info.SUSEConnectExpiresDays, status)
		default:
			fmt.Printf("  %s   registered, expiry unknown\n", asciiOr("info", "\u2139\ufe0f", mode))
		}
	}

	// Snapper / Btrfs snapshots (SLES / openSUSE)
	if snap != nil && snap.Available {
		fmt.Println("\nBtrfs snapshots (snapper)")
		if snap.SnapshotCount == 0 {
			fmt.Printf("  %s  no snapshots found\n", asciiOr("warn", "\u26a0\ufe0f", mode))
		} else {
			spaceStr := ""
			if snap.TotalSpaceGB > 0 {
				spaceStr = fmt.Sprintf(", %.2f GiB used", snap.TotalSpaceGB)
			}
			switch {
			case snap.LastSnapshotH < 0:
				fmt.Printf("  %s  %d snapshot(s)%s — no recent snapshot\n", asciiOr("warn", "\u26a0\ufe0f", mode), snap.SnapshotCount, spaceStr)
			case snap.LastSnapshotH == 0:
				fmt.Printf("  %s  %d snapshot(s)%s — last: < 1h ago\n", asciiOr("ok", "\u2705", mode), snap.SnapshotCount, spaceStr)
			default:
				fmt.Printf("  %s  %d snapshot(s)%s — last: %dh ago\n", asciiOr("ok", "\u2705", mode), snap.SnapshotCount, spaceStr, snap.LastSnapshotH)
			}
		}
	}
	if info.SELinuxMode != "" {
		fmt.Printf("\nSELinux mode: %s\n", info.SELinuxMode)
		switch {
		case info.SELinuxDenials > 0:
			fmt.Printf("  %s  %d denial(s) in the last hour\n", asciiOr("warn", "⚠️", mode), info.SELinuxDenials)
		case info.SELinuxDenials == -1:
			fmt.Printf("  %s  AVC denial data unavailable — run as root or install audit-libs\n", asciiOr("info", "ℹ️", mode))
		default:
			fmt.Printf("  %s  No denials in the last hour\n", asciiOr("ok", "✅", mode))
		}
		// SELinux booleans — show off booleans relevant to denied types
		if len(info.SELinuxBooleans) > 0 {
			fmt.Printf("\n  [SELinux booleans — check first]\n")
			for _, b := range info.SELinuxBooleans {
				fmt.Printf("  %s   %-45s = off\n", asciiOr("warn", "⚠️", mode), b.Name)
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
					asciiOr("warn", "⚠️", mode), g.Count, g.Scontext, g.Tcontext, g.Tclass, perms)
				if g.BooleanFix != "" {
					fmt.Printf("       → setsebool -P %s on\n", g.BooleanFix)
				} else if g.FixCmd != "" {
					fmt.Printf("       → %s\n", g.FixCmd)
				}
			}
		}
		if info.SELinuxAutoRelabel {
			fmt.Printf("\n  %s  /.autorelabel present — full filesystem relabel queued on next reboot (~15 min)\n", asciiOr("warn", "⚠️", mode))
		}
	}

	// AppArmor (SLES/Ubuntu/Debian)
	if info.AppArmorMode != "" && info.AppArmorMode != "disabled" && info.AppArmorMode != "unknown" {
		fmt.Printf("\nAppArmor mode: %s (%d profiles loaded)\n", info.AppArmorMode, info.AppArmorProfiles)
		if info.AppArmorComplain > 0 {
			fmt.Printf("  %s  %d profile(s) in complain mode\n", asciiOr("warn", "\u26a0\ufe0f", mode), info.AppArmorComplain)
		} else if info.AppArmorProfiles > 0 {
			fmt.Printf("  %s  All profiles enforcing\n", asciiOr("ok", "\u2705", mode))
		}
		switch {
		case len(info.AppArmorGroups) > 0:
			fmt.Printf("  %s   %d denial group(s) in last 24h:\n", asciiOr("warn", "⚠️", mode), len(info.AppArmorGroups))
			for i, g := range info.AppArmorGroups {
				if i >= 3 {
					break
				}
				fmt.Printf("    ×%-3d  %-30s  %s\n", g.Count, g.Profile, g.Path)
			}
			fmt.Println("  → aa-logprof  (auto-suggest profile updates)")
		case info.AppArmorDenials > 0:
			fmt.Printf("  %s  %d denial(s) in the last hour\n", asciiOr("warn", "\u26a0\ufe0f", mode), info.AppArmorDenials)
		default:
			fmt.Printf("  %s  No denials in the last 24h\n", asciiOr("ok", "\u2705", mode))
		}
	}

	// PAM locked accounts
	if len(info.PAMLockedAccounts) > 0 {
		fmt.Printf("\nPAM locked accounts:\n")
		for _, a := range info.PAMLockedAccounts {
			fmt.Printf("  %s  %s\n", asciiOr("fail", "❌", mode), a)
		}
		fmt.Println("  → faillock --reset --user <name>  (to unlock)")
	}

	// SUID binaries
	if len(info.SUIDBinaries) > 0 {
		fmt.Printf("\nUnexpected SUID binaries (%d):\n", len(info.SUIDBinaries))
		for _, b := range info.SUIDBinaries {
			fmt.Printf("  %s   %s\n", asciiOr("warn", "⚠️", mode), b)
		}
	}

	// Summary
	fmt.Println()
	fmt.Println(sep)
	issues := countSecurityIssues(info)
	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("%s Security posture healthy. Checks passed%s", asciiOr("ok", "✅", mode), timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("%s  %d security concern(s) found%s", asciiOr("warn", "⚠️", mode), issues, timing)))
	}
}

func printSecItem(label string, ok bool, goodVal, badVal string, mode output.OutputMode) {
	if ok {
		fmt.Printf("  %s  %-28s %s\n", asciiOr("ok", "✅", mode), label+":", goodVal)
	} else {
		fmt.Printf("  %s   %-28s %s\n", asciiOr("warn", "⚠️", mode), label+":", badVal)
	}
}

func countSecurityIssues(info *models.SecurityInfo) int {
	n := 0
	if info.SSHPermitRoot {
		n++
	}
	if info.SSHPasswordAuth {
		n++
	}
	if info.FailedLogins >= 5 {
		n++
	}
	for _, p := range info.ListeningPorts {
		if !p.Expected && (!info.IsPVE || !analysis.IsPVEServicePort(p.Port)) {
			n++
		}
	}
	n += len(info.SudoNopasswd)
	n += len(info.SUIDBinaries)
	if info.SELinuxDenials >= 10 {
		n++
	}
	return n
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
