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
	"github.com/keyorixhq/dashdiag/internal/runner"
)

var cisCmd = &cobra.Command{
	Use:   "cis",
	Short: "CIS/STIG compliance benchmark",
	Long: `Evaluate this host against the CIS Ubuntu 22.04 LTS Benchmark (Level 1 by default).

Checks SSH configuration, network parameters, audit logging, file permissions,
and user account settings. Reuses the same data as dsd health — no additional
tools or network access required.

Examples:
  dsd cis                  Run CIS Level 1 checks
  dsd cis --level 2        Run Level 1 + Level 2 checks
  dsd cis --json           Machine-readable output
  dsd cis --fail-only      Show only failing checks`,
	RunE: runCIS,
}

var (
	cisLevel    int
	cisJSON     bool
	cisFailOnly bool
	cisPlain    bool
)

func init() {
	rootCmd.AddCommand(cisCmd)
	cisCmd.Flags().IntVar(&cisLevel, "level", 1, "CIS benchmark level (1 or 2)")
	cisCmd.Flags().BoolVar(&cisJSON, "json", false, "Output JSON")
	cisCmd.Flags().BoolVar(&cisFailOnly, "fail-only", false, "Show only FAIL results")
	cisCmd.Flags().BoolVar(&cisPlain, "plain", false, "Plain text output (no colour)")
}

func runCIS(_ *cobra.Command, _ []string) error {
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

	report := cis.Evaluate(sec, ks, cisLevel, "CIS")
	report.Hostname, _ = os.Hostname()
	report.Profile = fmt.Sprintf("CIS Ubuntu 22.04 LTS Level %d", cisLevel)

	if cisJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	mode := output.DetectMode(cisPlain, false, "")
	printCISReport(report, cisFailOnly, mode)
	return nil
}

func printCISReport(report models.CISReport, failOnly bool, mode output.OutputMode) {
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
		icon := cisIcon(r.Status)
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
		fmt.Printf("  %d skipped", report.Skipped)
	}
	fmt.Println()
	if report.Fail > 0 {
		fmt.Printf("\n  Tip: %sdsd cis --fail-only%s to see only failures.\n", bold(colour), resetColour(colour))
	}
	fmt.Println()
}

func cisIcon(s models.CISStatus) string {
	switch s {
	case models.CISPass:
		return "✅"
	case models.CISFail:
		return "❌"
	case models.CISManual:
		return "ℹ️ "
	case models.CISSkipped:
		return "⏭️ "
	default:
		return "— "
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
