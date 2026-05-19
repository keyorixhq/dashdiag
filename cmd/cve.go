package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/render"
)

func init() {
	rootCmd.AddCommand(cveCmd)
	cveCmd.Flags().Bool("json", false, "JSON output")
	cveCmd.Flags().Bool("all", false, "scan all pending security advisories (not just a specific CVE)")
	cveCmd.Flags().String("oval", "", "path to OVAL file for air-gapped CVE check (e.g. /mnt/usb/sles16.oval.xml.bz2)")
	cveCmd.Flags().Bool("oval-scan", false, "scan all installed packages against OVAL feed for CVSS-scored findings")
	cveCmd.AddCommand(cveInfoCmd)
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
	ovalPath, _ := cmd.Flags().GetString("oval")
	ovalScan, _ := cmd.Flags().GetBool("oval-scan")
	ctx := context.Background()

	// --oval-scan: CVSS-scored package scan against OVAL feed
	if ovalScan {
		return runOVALScan(ctx, ovalPath, jsonOut)
	}

	// --oval: air-gapped single-CVE check
	if ovalPath != "" {
		if len(args) == 0 {
			return fmt.Errorf("specify at least one CVE ID with --oval")
		}
		fmt.Printf("\nUsing OVAL file: %s\n", ovalPath)
		for _, cveID := range args {
			fmt.Printf("Checking %s ...\n", strings.ToUpper(cveID))
			r, err := cvedata.CheckCVEFromOVAL(ctx, ovalPath, cveID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "oval error: %v\n", err)
				continue
			}
			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				_ = enc.Encode(r)
				continue
			}
			printOVALResult(r)
		}
		return nil
	}

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
	// Print CVSS enrichment line if available
	if r.CVSS3Score != "" {
		sev := r.ThreatSev
		if sev == "" {
			sev = "unknown severity"
		}
		fmt.Printf("CVSS3: %s  (%s)\n", r.CVSS3Score, sev)
	}
	if r.FixState != "" {
		pkg := ""
		if r.AffectedPkg != "" {
			pkg = " — package: " + r.AffectedPkg
		}
		fmt.Printf("Red Hat fix state: %s%s\n", r.FixState, pkg)
	}
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
	if r.SubscriptionNote != "" {
		fmt.Println()
		fmt.Println(r.SubscriptionNote)
	}
	fmt.Println()
}

func printAdvisoryGroup(label string, advisories []models.CVEAdvisory) {
	if len(advisories) == 0 {
		return
	}
	fmt.Printf("%s (%d)\n", label, len(advisories))
	for _, a := range advisories {
		line := fmt.Sprintf("  %-28s", a.ID)
		if a.CVEs != "" {
			line += "  " + a.CVEs
		} else if a.Summary != "" {
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

func printOVALResult(r *cvedata.OVALResult) {
	sep := strings.Repeat("─", 56)
	fmt.Println()
	fmt.Printf("CVE: %s   (via OVAL)\n", r.CVE)
	fmt.Println(sep)

	if !r.Found {
		fmt.Println(render.StyleOK.Render("✅ NOT IN OVAL — CVE not defined for this OS/version"))
		fmt.Println()
		fmt.Println(sep)
		return
	}

	if r.Summary != "" {
		fmt.Printf("Summary:  %s\n", r.Summary)
	}
	if r.Severity != "" {
		fmt.Printf("Severity: %s\n\n", r.Severity)
	}

	if len(r.Packages) == 0 {
		fmt.Println(render.StyleOK.Render("✅ NOT AFFECTED — no vulnerable packages installed"))
	} else {
		fmt.Println(render.StyleCrit.Render(
			fmt.Sprintf("🔴 VULNERABLE — %d package(s) need updating", len(r.Packages))))
		fmt.Println()
		for _, p := range r.Packages {
			fmt.Printf("  • %-30s installed: %-20s fix: %s\n",
				p.Name, p.Installed, p.FixedIn)
		}
		fmt.Println()
		fmt.Println("  to fix: zypper patch --category security")
		fmt.Println("       or: zypper update <package>")
	}
	fmt.Println()
	fmt.Println(sep)
}

func runCVEInfo() {
	sep := strings.Repeat("─", 56)
	fmt.Println("\nCVE data sources on this system")
	fmt.Println(sep)

	// Package manager
	for _, pm := range []string{"zypper", "dnf", "apt-get"} {
		if _, err := exec.LookPath(pm); err == nil {
			fmt.Printf("  ✅  Package manager:  %s (live queries available)\n", pm)
			break
		}
	}

	// OVAL sidecar files
	fmt.Println("\nOVAL files (place in /var/lib/dsd/oval/):")
	foundOVAL := false
	for _, dir := range cvedata.StandardOVALPaths() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(dir, e.Name())
			fi, _ := e.Info()
			age := ""
			if fi != nil {
				days := int(time.Since(fi.ModTime()).Hours() / 24)
				age = fmt.Sprintf(" (%d days old)", days)
			}
			fmt.Printf("  ✅  %s%s\n", path, age)
			foundOVAL = true
		}
	}
	if !foundOVAL {
		fmt.Println("  ─   none found")
		fmt.Println()
		fmt.Println("  Download from SUSE:")
		fmt.Println("    curl -O https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.16.xml.bz2")
		fmt.Println("    mkdir -p /var/lib/dsd/oval && mv *.xml.bz2 /var/lib/dsd/oval/")
	}

	// Pre-converted snapshot
	fmt.Println("\nPre-converted snapshot (generate with: scripts/update-cve-data.sh):")
	if snap := cvedata.FindSnapshot(); snap != "" {
		s, err := cvedata.LoadSnapshot(snap)
		if err == nil && !s.IsEmpty() {
			fmt.Printf("  ✅  %s\n", snap)
			fmt.Printf("      %d CVEs  —  generated %s\n", len(s.CVEs), s.Generated.Format("2006-01-02"))
		} else {
			fmt.Printf("  ⚠️   %s (could not load)\n", snap)
		}
	} else {
		fmt.Println("  ─   none found")
		fmt.Println("  Generate: make update-cve-data  (requires internet)")
		fmt.Printf("  Place at: %s\n", cvedata.SnapshotStandardPaths()[0])
	}

	fmt.Println()
	fmt.Println(sep)
}

var cveInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show what CVE data sources are available on this system",
	Long: `Shows available CVE data sources:
  - Package manager (zypper/dnf/apt) for live queries
  - OVAL sidecar files in standard locations
  - Pre-converted snapshot files

Examples:
  dsd cve info`,
	Args: cobra.NoArgs,
	Run:  func(_ *cobra.Command, _ []string) { runCVEInfo() },
}

// runOVALScan performs a CVSS-scored scan of installed packages against an OVAL feed.
// OVAL file is auto-detected from standard paths if not specified via --oval.
func runOVALScan(ctx context.Context, ovalPath string, jsonOut bool) error {
	// Auto-detect OVAL file if not specified
	if ovalPath == "" {
		distroID := cvedata.DetectDistroID()
		ovalPath = cvedata.FindOVALFile(distroID)
		if ovalPath == "" {
			fmt.Fprintf(os.Stderr, "No OVAL file found. Download one to a standard path:\n")
			for _, p := range cvedata.StandardOVALPaths() {
				fmt.Fprintf(os.Stderr, "  %s/\n", p)
			}
			fmt.Fprintf(os.Stderr, "\nRHEL/Rocky: curl -sL https://www.redhat.com/security/data/oval/v2/RHEL9/rhel-9-including-unpatched.oval.xml.bz2 -o /var/lib/dsd/oval/rhel-9.oval.xml.bz2\n")
			return fmt.Errorf("no OVAL file found — specify with --oval or download to a standard path")
		}
	}

	fmt.Printf("\n🔍 OVAL scan — %s\n", ovalPath)
	fmt.Printf("   Parsing OVAL feed and cross-referencing with installed packages...\n\n")

	results, err := cvedata.ScanOVALPackages(ctx, ovalPath)
	if err != nil {
		return fmt.Errorf("OVAL scan: %w", err)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	printOVALScanResults(results)
	return nil
}

// printOVALScanResults renders OVAL scan output bucketed by CVSS level.
func printOVALScanResults(results []cvedata.OVALCVSSResult) {
	if len(results) == 0 {
		fmt.Println("✅  No vulnerable packages found in OVAL feed")
		return
	}

	// Bucket by CVSS level
	type bucket struct {
		label   string
		icon    string
		entries []cvedata.OVALCVSSResult
	}
	buckets := []*bucket{
		{"Critical (CVSS ≥9.0)", "🔴", nil},
		{"High (CVSS ≥7.0)", "⚠️ ", nil},
		{"Medium (CVSS ≥4.0)", "ℹ️ ", nil},
		{"Low (CVSS <4.0)", "   ", nil},
	}
	for _, r := range results {
		switch {
		case r.CVSS3 >= 9.0:
			buckets[0].entries = append(buckets[0].entries, r)
		case r.CVSS3 >= 7.0:
			buckets[1].entries = append(buckets[1].entries, r)
		case r.CVSS3 >= 4.0:
			buckets[2].entries = append(buckets[2].entries, r)
		default:
			buckets[3].entries = append(buckets[3].entries, r)
		}
	}

	sep := strings.Repeat("─", 64)
	fmt.Println(sep)
	fmt.Printf("OVAL CVE scan — %d finding(s)\n\n", len(results))

	for _, b := range buckets {
		if len(b.entries) == 0 {
			continue
		}
		fmt.Printf("%s %s (%d)\n", b.icon, b.label, len(b.entries))
		for _, r := range b.entries {
			pkgs := strings.Join(r.Installed, ", ")
			if len(pkgs) > 50 {
				pkgs = pkgs[:48] + "…"
			}
			fmt.Printf("  %-20s  CVSS %4.1f  %-12s  %s\n",
				r.CVEID, r.CVSS3, r.Severity, pkgs)
		}
		fmt.Println()
	}
	fmt.Println(sep)
	fmt.Println("to fix: dnf upgrade --security")
	fmt.Println("note:   OVAL shows ALL known CVEs including 'Will not fix' exclusions filtered out above")
}
