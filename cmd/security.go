package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(securityCmd)
	securityCmd.Flags().Bool("suid", false, "include SUID binary scan (slow on large filesystems)")
}

var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Security posture — SSH, ports, logins, sudoers, SELinux",
	RunE:  runSecurity,
}

func runSecurity(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	mode := output.DetectMode(plain, false, "")

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

	// Snapper runs in parallel (requires root; silently skipped if unavailable)
	snapInfo, _ := collectors.CollectSnapper(ctx)

	printSecurityReport(info, snapInfo, mode, elapsed)
	return nil
}

func printSecurityReport(info *models.SecurityInfo, snap *models.SnapperInfo, mode output.OutputMode, elapsed time.Duration) { //nolint:cyclop,funlen // flat display renderer — each branch is a distinct section
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	// SSH Configuration
	fmt.Println("\nSSH Configuration")
	printSecItem("PermitRootLogin", !info.SSHRootLogin, "no (secure)", "yes (INSECURE)")
	printSecItem("PasswordAuthentication", !info.SSHPasswordAuth, "no (key-only)", "yes (weaker)")

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
		icon := "✅"
		tag := ""
		if !p.Expected {
			icon = "⚠️ "
			tag = " ← unexpected"
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
			fmt.Printf("  ⚠️   %s\n", entry)
		}
	} else if info.NeedsRoot {
		fmt.Println("\nSudo NOPASSWD entries: unknown (needs root)")
	} else {
		fmt.Println("\nSudo NOPASSWD entries: none")
	}

	// Firewall
	if info.FirewallActive {
		sshIcon := "✅"
		if !info.SSHAllowed {
			sshIcon = "❌"
		}
		zone := ""
		if info.FirewallZone != "" {
			zone = fmt.Sprintf(" (zone: %s)", info.FirewallZone)
		}
		fmt.Printf("\nFirewall: %s active%s\n", info.FirewallType, zone)
		if len(info.FirewallServices) > 0 {
			fmt.Printf("  ✅  allowed: %s\n", strings.Join(info.FirewallServices, ", "))
		}
		fmt.Printf("  %s  SSH accessible\n", sshIcon)
	} else {
		fmt.Println("\nFirewall: none detected")
	}

	// RHEL/Rocky security
	if info.CryptoPolicy != "" || info.FIPSEnabled || info.AIDEInstalled || info.USBGuardActive || info.AuditRules >= 0 {
		fmt.Println("\nSystem Security")
		if info.FIPSEnabled {
			fmt.Println("  ✅  FIPS mode: enabled")
		} else if info.CryptoPolicy != "" {
			fmt.Println("  ℹ️   FIPS mode: disabled")
		}
		if info.CryptoPolicy != "" {
			policyIcon := "✅"
			if info.CryptoPolicy == "LEGACY" {
				policyIcon = "⚠️ "
			}
			fmt.Printf("  %s  Crypto policy: %s\n", policyIcon, info.CryptoPolicy)
		}
		if info.AuditRules >= 0 {
			if info.AuditRules == 0 {
				fmt.Println("  ⚠️  auditd: running, no rules configured")
			} else {
				fmt.Printf("  ✅  auditd: %d rule(s) active\n", info.AuditRules)
			}
		}
		if info.USBGuardActive {
			fmt.Println("  ✅  USBGuard: active")
		}
		if info.AIDEInstalled {
			if !info.AIDEDBExists {
				fmt.Println("  ⚠️  AIDE: installed but database not initialised")
			} else if info.AIDELastRunDays > 7 {
				fmt.Printf("  ⚠️  AIDE: database %d days old\n", info.AIDELastRunDays)
			} else {
				fmt.Printf("  ✅  AIDE: database %d days old\n", info.AIDELastRunDays)
			}
		}
	}

	// SUSE supportconfig
	if info.SupportconfigAvailable {
		fmt.Println("\nSUSE supportconfig")
		switch {
		case info.SupportconfigLastRunDays == -1:
			fmt.Println("  \u2139\ufe0f  never run — run before contacting SUSE support")
		case info.SupportconfigLastRunDays > 30:
			fmt.Printf("  \u26a0\ufe0f  last run %d days ago\n", info.SupportconfigLastRunDays)
		default:
			fmt.Printf("  \u2705  last run %d days ago (%s)\n", info.SupportconfigLastRunDays, info.SupportconfigArchive)
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
			fmt.Printf("  \U0001f534  EXPIRED (%s)\n", status)
		case info.SUSEConnectExpiresDays > 0 && info.SUSEConnectExpiresDays <= 14:
			fmt.Printf("  \U0001f534  expires in %d day(s) \u2014 renew immediately\n", info.SUSEConnectExpiresDays)
		case info.SUSEConnectExpiresDays > 14 && info.SUSEConnectExpiresDays <= 30:
			fmt.Printf("  \u26a0\ufe0f   expires in %d day(s) \u2014 renew soon\n", info.SUSEConnectExpiresDays)
		case info.SUSEConnectExpiresDays > 30:
			fmt.Printf("  \u2705  active \u2014 expires in %d day(s) (%s)\n", info.SUSEConnectExpiresDays, status)
		default:
			fmt.Printf("  \u2139\ufe0f   registered, expiry unknown\n")
		}
	}

	// Snapper / Btrfs snapshots (SLES / openSUSE)
	if snap != nil && snap.Available {
		fmt.Println("\nBtrfs snapshots (snapper)")
		if snap.SnapshotCount == 0 {
			fmt.Printf("  \u26a0\ufe0f  no snapshots found\n")
		} else {
			spaceStr := ""
			if snap.TotalSpaceGB > 0 {
				spaceStr = fmt.Sprintf(", %.2f GiB used", snap.TotalSpaceGB)
			}
			switch {
			case snap.LastSnapshotH < 0:
				fmt.Printf("  \u26a0\ufe0f  %d snapshot(s)%s — no recent snapshot\n", snap.SnapshotCount, spaceStr)
			case snap.LastSnapshotH == 0:
				fmt.Printf("  \u2705  %d snapshot(s)%s — last: < 1h ago\n", snap.SnapshotCount, spaceStr)
			default:
				fmt.Printf("  \u2705  %d snapshot(s)%s — last: %dh ago\n", snap.SnapshotCount, spaceStr, snap.LastSnapshotH)
			}
		}
	}
	if info.SELinuxMode != "" {
		fmt.Printf("\nSELinux mode: %s\n", info.SELinuxMode)
		switch {
		case info.SELinuxDenials > 0:
			fmt.Printf("  ⚠️  %d denial(s) in the last hour\n", info.SELinuxDenials)
		case info.SELinuxDenials == -1:
			fmt.Printf("  ℹ️  AVC denial data unavailable — run as root or install audit-libs\n")
		default:
			fmt.Printf("  ✅  No denials in the last hour\n")
		}
		// SELinux booleans — show off booleans relevant to denied types
		if len(info.SELinuxBooleans) > 0 {
			fmt.Printf("\n  [SELinux booleans — check first]\n")
			for _, b := range info.SELinuxBooleans {
				fmt.Printf("  ⚠️   %-45s = off\n", b.Name)
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
				fmt.Printf("  ⚠️   ×%-4d  %-20s → %-20s  [%s] %s\n",
					g.Count, g.Scontext, g.Tcontext, g.Tclass, perms)
				if g.BooleanFix != "" {
					fmt.Printf("       → setsebool -P %s on\n", g.BooleanFix)
				} else if g.FixCmd != "" {
					fmt.Printf("       → %s\n", g.FixCmd)
				}
			}
		}
		if info.SELinuxAutoRelabel {
			fmt.Println("\n  ⚠️  /.autorelabel present — full filesystem relabel queued on next reboot (~15 min)")
		}
	}

	// AppArmor (SLES/Ubuntu/Debian)
	if info.AppArmorMode != "" && info.AppArmorMode != "disabled" && info.AppArmorMode != "unknown" {
		fmt.Printf("\nAppArmor mode: %s (%d profiles loaded)\n", info.AppArmorMode, info.AppArmorProfiles)
		if info.AppArmorComplain > 0 {
			fmt.Printf("  \u26a0\ufe0f  %d profile(s) in complain mode\n", info.AppArmorComplain)
		} else if info.AppArmorProfiles > 0 {
			fmt.Println("  \u2705  All profiles enforcing")
		}
		switch {
		case len(info.AppArmorGroups) > 0:
			fmt.Printf("  ⚠️   %d denial group(s) in last 24h:\n", len(info.AppArmorGroups))
			for i, g := range info.AppArmorGroups {
				if i >= 3 {
					break
				}
				fmt.Printf("    ×%-3d  %-30s  %s\n", g.Count, g.Profile, g.Path)
			}
			fmt.Println("  → aa-logprof  (auto-suggest profile updates)")
		case info.AppArmorDenials > 0:
			fmt.Printf("  \u26a0\ufe0f  %d denial(s) in the last hour\n", info.AppArmorDenials)
		default:
			fmt.Println("  \u2705  No denials in the last 24h")
		}
	}

	// PAM locked accounts
	if len(info.PAMLockedAccounts) > 0 {
		fmt.Printf("\nPAM locked accounts:\n")
		for _, a := range info.PAMLockedAccounts {
			fmt.Printf("  ❌  %s\n", a)
		}
		fmt.Println("  → faillock --reset --user <name>  (to unlock)")
	}

	// SUID binaries
	if len(info.SUIDBinaries) > 0 {
		fmt.Printf("\nUnexpected SUID binaries (%d):\n", len(info.SUIDBinaries))
		for _, b := range info.SUIDBinaries {
			fmt.Printf("  ⚠️   %s\n", b)
		}
	}

	// Summary
	fmt.Println()
	fmt.Println(sep)
	issues := countSecurityIssues(info)
	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("✅ Security posture healthy. Checks passed%s", timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("⚠️  %d security concern(s) found%s", issues, timing)))
	}
}

func printSecItem(label string, ok bool, goodVal, badVal string) {
	if ok {
		fmt.Printf("  ✅  %-28s %s\n", label+":", goodVal)
	} else {
		fmt.Printf("  ⚠️   %-28s %s\n", label+":", badVal)
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
		if !p.Expected {
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
