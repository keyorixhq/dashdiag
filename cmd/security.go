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

	printSecurityReport(info, mode, elapsed)
	return nil
}

func printSecurityReport(info *models.SecurityInfo, mode output.OutputMode, elapsed time.Duration) {
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
		// Resolve well-known service names — systemd socket activation
		// hides the real service name behind 'systemd'
		if proc == "systemd" || proc == "unknown" {
			if name := wellKnownPort(p.Port); name != "" {
				proc = name
			}
		}
		fmt.Printf("  %s  %-6d %-5s %-20s%s\n", icon, p.Port, p.Protocol, proc, tag)
	}

	// Sudo NOPASSWD
	if len(info.SudoNopasswd) > 0 {
		fmt.Println("\nSudo NOPASSWD entries:")
		for _, entry := range info.SudoNopasswd {
			fmt.Printf("  ⚠️   %s\n", entry)
		}
	} else {
		fmt.Println("\nSudo NOPASSWD entries: none")
	}

	// SELinux
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
		25:    "smtp",
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
