package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/cis"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

const (
	cisSkipLabel       = "skip:  "
	cisUnverifiedLabel = "unverified:"
)

var cisCmd = &cobra.Command{
	Use:   "cis",
	Short: "CIS/STIG compliance benchmark",
	Long: `Evaluate this host against the CIS Ubuntu 22.04 LTS Benchmark (Level 1 by default).
Use --stig to run DISA STIG checks instead (DISA STIG Ubuntu 20.04 LTS V1R11).

Checks SSH configuration, network parameters, audit logging, file permissions,
and user account settings. Reuses the same data as dsd health — no additional
tools or network access required.

Examples:
  dsd cis                  Run CIS Level 1 checks
  dsd cis --level 2        Run Level 1 + Level 2 checks
  dsd cis --stig           Run DISA STIG checks (V-238xxx IDs)
  dsd cis --json           Machine-readable output
  dsd cis --fail-only      Show only failing checks`,
	RunE: runCIS,
}

func init() {
	rootCmd.AddCommand(cisCmd)
	cisCmd.Flags().Int("level", 1, "benchmark level (1 or 2)")
	cisCmd.Flags().Bool("fail-only", false, "show only FAIL results")
	cisCmd.Flags().Bool("stig", false, "run DISA STIG checks instead of CIS")
	cisCmd.Flags().Bool("nis2", false, "show NIS2 Article 21(2) evidence grouping")
	cisCmd.Flags().Bool("bsi", false, "show BSI IT-Grundschutz Kompendium evidence grouping (SYS.1.3 / SYS.1.1 / OPS.1.1)")
	// --plain and --json: global, no local declaration needed
}

// cisProfileName returns the benchmark profile label based on the host distro.
// The rule set covers common controls (SSH, network, MAC, audit, files) that
// apply across all major Linux distributions; the profile name reflects this.
func cisProfileName(distro string, level int, stig bool) string {
	if stig {
		return fmt.Sprintf("DISA STIG Ubuntu 20.04 LTS Level %d", level)
	}
	switch distro {
	case "rhel", "centos", "fedora", "rocky", "almalinux":
		return fmt.Sprintf("CIS RHEL/Rocky Level %d (SSH · Network · MAC · Audit · Files)", level)
	case "debian":
		return fmt.Sprintf("CIS Debian Level %d (SSH · Network · MAC · Audit · Files)", level)
	case "sles", "opensuse":
		return fmt.Sprintf("CIS SLES/openSUSE Level %d (SSH · Network · MAC · Audit · Files)", level)
	default: // ubuntu and unknown
		return fmt.Sprintf("CIS Ubuntu 22.04 LTS Level %d", level)
	}
}

func runCIS(cmd *cobra.Command, _ []string) error {
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	stig, _ := cmd.Flags().GetBool("stig")
	failOnly, _ := cmd.Flags().GetBool("fail-only")
	nis2Mode, _ := cmd.Flags().GetBool("nis2")
	bsiMode, _ := cmd.Flags().GetBool("bsi")
	level, _ := cmd.Flags().GetInt("level")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Collect security data using the same collectors as dsd health
	secC := collectors.NewSecurityCollector()
	ksC := collectors.NewKernelSecurityCollector()

	results := runner.RunAll(ctx, []runner.Collector{secC, ksC})

	sec := models.SecurityInfo{}
	ks := models.KernelSecurityInfo{}
	for r := range results {
		switch r.Name {
		case "Hardening":
			if v, ok := r.Data.(*models.SecurityInfo); ok && v != nil {
				sec = *v
			}
		case "KernelSec":
			if v, ok := r.Data.(*models.KernelSecurityInfo); ok && v != nil {
				ks = *v
			}
		}
	}

	prof := platform.Detect()
	report := cis.Evaluate(sec, ks, level, stig, prof.PackageManager)
	report.Hostname, _ = os.Hostname()
	report.Profile = cisProfileName(prof.Distro, level, stig)

	mode := output.DetectMode(plain, false, "")
	if bsiMode {
		groups := cis.GroupByBSI(report.Results)
		if jsonOut {
			if failOnly {
				for i := range groups {
					filtered := make([]models.CISResult, 0, groups[i].Fail)
					for _, r := range groups[i].Results {
						if r.Status == models.CISFail {
							filtered = append(filtered, r)
						}
					}
					groups[i].Results = filtered
				}
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(groups)
		}
		printBSIReport(groups, failOnly, mode)
		return nil
	}
	if nis2Mode {
		groups := cis.GroupByNIS2(report.Results)
		if jsonOut {
			if failOnly {
				for i := range groups {
					filtered := make([]models.CISResult, 0, groups[i].Fail)
					for _, r := range groups[i].Results {
						if r.Status == models.CISFail {
							filtered = append(filtered, r)
						}
					}
					groups[i].Results = filtered
				}
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(groups)
		}
		printNIS2Report(groups, failOnly, mode)
		return nil
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	printCISReport(report, failOnly, stig, mode)
	return nil
}

func printCISReport(report models.CISReport, failOnly, stig bool, mode output.OutputMode) {
	colour := mode == output.ModeHuman

	hostname := report.Hostname
	if hostname == "" {
		hostname = "this host"
	}

	fmt.Printf("\n%s — %s\n\n", report.Profile, hostname)

	currentSection := ""
	for _, r := range report.Results {
		if failOnly && r.Status != models.CISFail {
			continue
		}
		if r.Section != currentSection {
			currentSection = r.Section
			fmt.Printf("  ── %s\n", strings.ToUpper(currentSection))
		}
		icon := cisIcon(r, mode)
		idPad := fmt.Sprintf("%-8s", r.ID)
		fmt.Printf("  %s %s%s%s  %s\n",
			icon, colourFor(r.Status, colour), idPad, resetColour(colour), r.Description)

		if r.Status == models.CISFail {
			if r.Finding != "" {
				fmt.Printf("           %sfinding:%s %s\n", dim(colour), resetColour(colour), r.Finding)
			}
			if r.Remediation != "" {
				fmt.Printf("           %sto fix: %s %s\n", dim(colour), resetColour(colour), r.Remediation)
			}
		}
		if r.Status == models.CISManual && r.Finding != "" {
			fmt.Printf("           %scheck:  %s %s\n", dim(colour), resetColour(colour), r.Finding)
		}
		// Every skip's reason was recorded (skipr/unverifiedr always set
		// Finding) but never shown here — a false-clean-adjacent bug in its
		// own right: "sshd_config unreadable, run as root" rendered
		// identically to "rsync not installed", indistinguishable either way.
		if r.Status == models.CISSkipped && r.Finding != "" {
			label := cisSkipLabel
			if r.Unverified {
				label = cisUnverifiedLabel
			}
			fmt.Printf("           %s%s%s %s\n", dim(colour), label, resetColour(colour), r.Finding)
		}
	}

	// Summary line
	fmt.Printf("\n  %d rules", report.Pass+report.Fail+report.Manual+report.NA+report.Skipped)
	if report.Fail == 0 {
		fmt.Printf(" — %s%d pass%s", green(colour), report.Pass, resetColour(colour))
	} else {
		fmt.Printf(" — %s%d pass%s  %s%d fail%s",
			green(colour), report.Pass, resetColour(colour),
			red(colour), report.Fail, resetColour(colour))
	}
	if report.Manual > 0 {
		fmt.Printf("  %d manual", report.Manual)
	}
	if report.Skipped > 0 {
		skipped := report.Skipped - report.Unverified
		if skipped > 0 {
			fmt.Printf("  %d skipped", skipped)
		}
		if report.Unverified > 0 {
			fmt.Printf("  %s%d unverified%s", yellow(colour), report.Unverified, resetColour(colour))
		}
	}
	fmt.Println()
	if report.Fail > 0 {
		fmt.Printf("\n  Tip: %sdsd cis --fail-only%s to see only failures.", bold(colour), resetColour(colour))
		if !stig {
			fmt.Printf("  %sdsd cis --stig%s for DISA STIG IDs.", bold(colour), resetColour(colour))
		}
		fmt.Println()
	}
	fmt.Println()
}

func printNIS2Report(groups []cis.NIS2ArticleGroup, failOnly bool, mode output.OutputMode) {
	colour := mode == output.ModeHuman
	fmt.Println()
	fmt.Println("  NIS2 Directive — Article 21(2) Evidence")
	fmt.Println()
	for _, g := range groups {
		printNIS2Article(g, failOnly, colour, mode)
	}
	fmt.Printf("  Scope: %s\n", "Art.21(2) technical controls evidenced by existing CIS rules")
	fmt.Printf("  Tip: %sdsd cis --nis2 --json%s for machine-readable output\n\n",
		bold(colour), resetColour(colour))
}

func nis2StatusColour(status string, colour bool) string {
	switch status {
	case "FAIL":
		return red(colour)
	case "PARTIAL":
		return colourFor(models.CISFail, colour)
	case "UNVERIFIED":
		return yellow(colour)
	case "PASS":
		return green(colour)
	default:
		return dim(colour)
	}
}

func nis2Icon(status string, mode output.OutputMode) string {
	switch status {
	case "PASS":
		return asciiOr("ok  ", "✅  ", mode)
	case "FAIL":
		return asciiOr("fail", "❌  ", mode)
	case "PARTIAL":
		return asciiOr("warn", "⚠️  ", mode)
	case "UNVERIFIED":
		// Deliberately NOT the pass icon: this article had a pass, but some
		// sibling rules could not be checked at all — a plain ✅ here would be
		// exactly the false-clean verdict this status exists to prevent.
		return asciiOr("unverified", "❓  ", mode)
	case "SKIP":
		return asciiOr("skip", "⏭️  ", mode)
	default:
		return asciiOr("n/a ", "—   ", mode)
	}
}

func printNIS2Article(g cis.NIS2ArticleGroup, failOnly, colour bool, mode output.OutputMode) {
	sc := nis2StatusColour(g.Status, colour)
	icon := nis2Icon(g.Status, mode)
	fmt.Printf("  %s %s%s%s — %s\n",
		icon, sc, g.Article.ID, resetColour(colour), g.Article.Title)
	if g.Status == "UNMAPPED" {
		fmt.Printf("         %sNo OS-level technical controls — requires organisational policy evidence%s\n",
			dim(colour), resetColour(colour))
		fmt.Println()
		return
	}
	for _, r := range g.Results {
		if failOnly && r.Status != models.CISFail {
			continue
		}
		ruleIcon := cisIcon(r, mode)
		idPad := fmt.Sprintf("%-8s", r.ID)
		fmt.Printf("         %s %s%s%s  %s\n",
			ruleIcon, colourFor(r.Status, colour), idPad, resetColour(colour), r.Description)
		if r.Status == models.CISFail {
			if r.Finding != "" {
				fmt.Printf("                    %sfinding:%s %s\n", dim(colour), resetColour(colour), r.Finding)
			}
			if r.Remediation != "" {
				fmt.Printf("                    %sto fix: %s %s\n", dim(colour), resetColour(colour), r.Remediation)
			}
		}
		if r.Status == models.CISSkipped && r.Finding != "" {
			label := cisSkipLabel
			if r.Unverified {
				label = cisUnverifiedLabel
			}
			fmt.Printf("                    %s%s%s %s\n", dim(colour), label, resetColour(colour), r.Finding)
		}
	}
	printNIS2Summary(g, colour)
	fmt.Println()
}

func printNIS2Summary(g cis.NIS2ArticleGroup, colour bool) {
	parts := make([]string, 0, 4)
	if g.Pass > 0 {
		parts = append(parts, fmt.Sprintf("%s%d pass%s", green(colour), g.Pass, resetColour(colour)))
	}
	if g.Fail > 0 {
		parts = append(parts, fmt.Sprintf("%s%d fail%s", red(colour), g.Fail, resetColour(colour)))
	}
	if g.Manual > 0 {
		parts = append(parts, fmt.Sprintf("%d manual", g.Manual))
	}
	if skipped := g.Skipped - g.Unverified; skipped > 0 {
		parts = append(parts, fmt.Sprintf("%s%d skipped%s", dim(colour), skipped, resetColour(colour)))
	}
	if g.Unverified > 0 {
		parts = append(parts, fmt.Sprintf("%s%d unverified%s", yellow(colour), g.Unverified, resetColour(colour)))
	}
	if len(parts) > 0 {
		fmt.Printf("         %d controls: %s\n",
			g.Pass+g.Fail+g.Manual+g.Skipped, strings.Join(parts, "  "))
	}
}

func printBSIReport(groups []cis.BSIReqGroup, failOnly bool, mode output.OutputMode) {
	colour := mode == output.ModeHuman
	fmt.Println()
	fmt.Println("  BSI IT-Grundschutz Kompendium — Technische Prüfpunkte")
	fmt.Println()
	currentBaustein := ""
	for _, g := range groups {
		if g.Baustein.ID != currentBaustein {
			currentBaustein = g.Baustein.ID
			fmt.Printf("  ── %s %s ──\n", g.Baustein.ID, strings.ToUpper(g.Baustein.English))
			fmt.Println()
		}
		printBSIReq(g, failOnly, colour, mode)
	}
	fmt.Printf("  Scope: SYS.1.3 + SYS.1.1 + OPS.1.1 — OS-level technical controls evidenced by existing CIS rules\n")
	fmt.Printf("  Tip: %sdsd cis --bsi --json%s for machine-readable output\n\n",
		bold(colour), resetColour(colour))
}

func bsiStatusColour(status string, colour bool) string {
	switch status {
	case "FAIL":
		return red(colour)
	case "PARTIAL":
		return colourFor(models.CISFail, colour)
	case "UNVERIFIED":
		return yellow(colour)
	case "PASS":
		return green(colour)
	default:
		return dim(colour)
	}
}

func bsiIcon(status string, mode output.OutputMode) string {
	switch status {
	case "PASS":
		return asciiOr("ok  ", "✅  ", mode)
	case "FAIL":
		return asciiOr("fail", "❌  ", mode)
	case "PARTIAL":
		return asciiOr("warn", "⚠️  ", mode)
	case "UNVERIFIED":
		// Deliberately NOT the pass icon — see nis2Icon's comment, same reasoning.
		return asciiOr("unverified", "❓  ", mode)
	case "SKIP":
		return asciiOr("skip", "⏭️  ", mode)
	default:
		return asciiOr("n/a ", "—   ", mode)
	}
}

func printBSIReq(g cis.BSIReqGroup, failOnly, colour bool, mode output.OutputMode) {
	sc := bsiStatusColour(g.Status, colour)
	icon := bsiIcon(g.Status, mode)
	levelTag := fmt.Sprintf("[%s]", g.Req.Level)
	fmt.Printf("  %s %s%s %s%s — %s\n",
		icon, sc, levelTag, g.Req.ID, resetColour(colour), g.Req.English)
	if g.Status == "UNMAPPED" {
		fmt.Printf("         %sNo automated OS-level check — manual evidence required%s\n",
			dim(colour), resetColour(colour))
		fmt.Println()
		return
	}
	for _, r := range g.Results {
		if failOnly && r.Status != models.CISFail {
			continue
		}
		ruleIcon := cisIcon(r, mode)
		idPad := fmt.Sprintf("%-8s", r.ID)
		fmt.Printf("         %s %s%s%s  %s\n",
			ruleIcon, colourFor(r.Status, colour), idPad, resetColour(colour), r.Description)
		if r.Status == models.CISFail {
			if r.Finding != "" {
				fmt.Printf("                    %sfinding:%s %s\n", dim(colour), resetColour(colour), r.Finding)
			}
			if r.Remediation != "" {
				fmt.Printf("                    %sto fix: %s %s\n", dim(colour), resetColour(colour), r.Remediation)
			}
		}
		if r.Status == models.CISSkipped && r.Finding != "" {
			label := cisSkipLabel
			if r.Unverified {
				label = cisUnverifiedLabel
			}
			fmt.Printf("                    %s%s%s %s\n", dim(colour), label, resetColour(colour), r.Finding)
		}
	}
	printBSISummary(g, colour)
	fmt.Println()
}

func printBSISummary(g cis.BSIReqGroup, colour bool) {
	parts := make([]string, 0, 4)
	if g.Pass > 0 {
		parts = append(parts, fmt.Sprintf("%s%d pass%s", green(colour), g.Pass, resetColour(colour)))
	}
	if g.Fail > 0 {
		parts = append(parts, fmt.Sprintf("%s%d fail%s", red(colour), g.Fail, resetColour(colour)))
	}
	if g.Manual > 0 {
		parts = append(parts, fmt.Sprintf("%d manual", g.Manual))
	}
	if skipped := g.Skipped - g.Unverified; skipped > 0 {
		parts = append(parts, fmt.Sprintf("%s%d skipped%s", dim(colour), skipped, resetColour(colour)))
	}
	if g.Unverified > 0 {
		parts = append(parts, fmt.Sprintf("%s%d unverified%s", yellow(colour), g.Unverified, resetColour(colour)))
	}
	if len(parts) > 0 {
		fmt.Printf("         %d controls: %s\n",
			g.Pass+g.Fail+g.Manual+g.Skipped, strings.Join(parts, "  "))
	}
}

// cisIcon takes the whole result, not just its Status, because CISSkipped
// alone doesn't distinguish "confirmed not applicable" from "could not be
// verified" (CISResult.Unverified) — the two need visibly different icons,
// not the same ⏭️ for both.
func cisIcon(r models.CISResult, mode output.OutputMode) string {
	switch r.Status {
	case models.CISPass:
		return asciiOr("ok", "✅", mode)
	case models.CISFail:
		return asciiOr("fail", "❌", mode)
	case models.CISManual:
		return asciiOr("info", "ℹ️ ", mode)
	case models.CISSkipped:
		if r.Unverified {
			return asciiOr("unverified", "❓ ", mode)
		}
		return asciiOr("skip", "⏭️ ", mode)
	default:
		return asciiOr("unknown", "— ", mode)
	}
}

func colourFor(s models.CISStatus, on bool) string {
	if !on {
		return ""
	}
	switch s {
	case models.CISPass:
		return "\033[32m"
	case models.CISFail:
		return "\033[31m"
	case models.CISManual:
		return "\033[33m"
	default:
		return "\033[2m"
	}
}

func resetColour(on bool) string {
	if !on {
		return ""
	}
	return "\033[0m"
}
func green(on bool) string {
	if !on {
		return ""
	}
	return "\033[32m"
}
func red(on bool) string {
	if !on {
		return ""
	}
	return "\033[31m"
}
func yellow(on bool) string {
	if !on {
		return ""
	}
	return "\033[33m"
}
func dim(on bool) string {
	if !on {
		return ""
	}
	return "\033[2m"
}
func bold(on bool) string {
	if !on {
		return ""
	}
	return "\033[1m"
}
