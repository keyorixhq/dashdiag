package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/render"
)

func init() {
	rootCmd.AddCommand(cveCmd)
	cveCmd.Flags().Bool("json", false, "JSON output")
	cveCmd.Flags().Bool("all", false, "scan all pending security advisories (not just a specific CVE)")
}

var cveCmd = &cobra.Command{
	Use:   "cve [CVE-YYYY-NNNNN...]",
	Short: "Check if this system is affected by one or more CVEs",
	Long: `Query the system package manager to determine if CVEs affect this host.

Supports zypper (SLES/openSUSE), dnf (RHEL/Rocky/Fedora), and apt (Ubuntu/Debian).

Examples:
  dsd cve CVE-2024-3094
  dsd cve CVE-2024-3094 CVE-2025-32462 CVE-2025-32463
  dsd cve --all                    (scan all pending security advisories)
  dsd cve --all --json`,
	Args: cobra.ArbitraryArgs,
	RunE: runCVE,
}

func runCVE(cmd *cobra.Command, args []string) error {
	jsonOut, _ := cmd.Flags().GetBool("json")
	allFlag, _ := cmd.Flags().GetBool("all")
	ctx := context.Background()

	if allFlag {
		fmt.Println("\nScanning all pending security advisories...")
		r := collectors.ScanAllCVEs(ctx)
		if jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(r)
		}
		printAllCVEs(r)
		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("specify at least one CVE ID, or use --all to scan everything")
	}

	results := make([]*models.CVEResult, 0, len(args))
	for _, cveID := range args {
		fmt.Printf("\nChecking %s ...\n", strings.ToUpper(cveID))
		r := collectors.CheckCVE(ctx, cveID)
		results = append(results, r)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if len(results) == 1 {
			return enc.Encode(results[0])
		}
		return enc.Encode(results)
	}

	for _, r := range results {
		printCVEResult(r)
	}

	if len(results) > 1 {
		vulnerable := 0
		for _, r := range results {
			if r.Status == models.CVEVulnerable {
				vulnerable++
			}
		}
		fmt.Printf("\nSummary: %d/%d CVEs require action\n", vulnerable, len(results))
	}
	return nil
}

func printCVEResult(r *models.CVEResult) {
	sep := strings.Repeat("─", 56)
	fmt.Println()
	fmt.Printf("CVE: %s   (via %s)\n", r.CVE, r.PackageManager)
	fmt.Println(sep)

	switch r.Status {
	case models.CVEVulnerable:
		fmt.Println(render.StyleCrit.Render("🔴 VULNERABLE — fix available but not installed"))
		fmt.Println()
		if len(r.AffectedPackages) > 0 {
			fmt.Println("Affected patches / packages:")
			for _, p := range r.AffectedPackages {
				line := "  • "
				if p.Advisory != "" {
					line += p.Advisory
				}
				if p.Name != "" {
					line += " " + p.Name
				}
				if p.Severity != "" {
					line += " (" + p.Severity + ")"
				}
				fmt.Println(line)
			}
			fmt.Println()
		}
		if r.FixCommand != "" {
			fmt.Printf("  to fix:    %s\n", r.FixCommand)
		}
		if r.FallbackURL != "" {
			fmt.Printf("  more info: %s\n", r.FallbackURL)
		}

	case models.CVEPatched:
		fmt.Println(render.StyleOK.Render("✅ PATCHED — fix already installed"))
		if r.StatusReason != "" {
			fmt.Printf("  %s\n", r.StatusReason)
		}

	case models.CVENotAffected:
		fmt.Println(render.StyleOK.Render("✅ NOT AFFECTED — no packages impacted on this system"))
		if r.StatusReason != "" {
			fmt.Printf("  %s\n", r.StatusReason)
		}

	case models.CVEUnknown:
		fmt.Println(render.StyleWarn.Render("⚠️  UNKNOWN — cannot determine status"))
		if r.StatusReason != "" {
			fmt.Printf("  %s\n", r.StatusReason)
		}
		if r.FallbackURL != "" {
			fmt.Printf("\n  Check manually: %s\n", r.FallbackURL)
		}
	}

	fmt.Println()
	fmt.Println(sep)
}

func printAllCVEs(r *models.CVEAllResult) {
	sep := strings.Repeat("─", 56)
	fmt.Println()
	fmt.Printf("Security advisory scan   (via %s)\n", r.PackageManager)
	fmt.Println(sep)

	if r.StatusReason != "" && r.Total == 0 {
		fmt.Printf("✅  %s\n", r.StatusReason)
		fmt.Println(sep)
		return
	}

	if r.Total == 0 {
		fmt.Println("✅  No pending security advisories — system is up to date")
		fmt.Println(sep)
		return
	}

	fmt.Printf("Found %d pending security advisory(ies)\n\n", r.Total)

	printAdvisoryGroup("🔴 CRITICAL", r.Critical)
	printAdvisoryGroup("⚠️  IMPORTANT", r.Important)
	printAdvisoryGroup("   MODERATE", r.Moderate)
	printAdvisoryGroup("   LOW", r.Low)

	fmt.Println(sep)
	if r.FixCommand != "" {
		fmt.Printf("to fix all:  %s\n", r.FixCommand)
	}
	fmt.Println()
}

func printAdvisoryGroup(label string, advisories []models.CVEAdvisory) {
	if len(advisories) == 0 {
		return
	}
	fmt.Printf("%s (%d)\n", label, len(advisories))
	for _, a := range advisories {
		line := fmt.Sprintf("  %-40s", a.ID)
		if a.Summary != "" {
			// Truncate long summaries
			summary := a.Summary
			if len(summary) > 50 {
				summary = summary[:47] + "..."
			}
			line += "  " + summary
		}
		fmt.Println(line)
	}
	fmt.Println()
}
