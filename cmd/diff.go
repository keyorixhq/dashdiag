package cmd

// diff.go — `dsd diff <baseline.tar.gz> <current.tar.gz>`
//
// A discoverable top-level alias for `dsd replay <current> --diff <baseline>`.
// Argument order follows the universal `diff old new` convention: the first
// bundle is the baseline (before), the second is the current state (after).
//
// This is the support workflow front door: a customer sends two captures of the
// same host (one healthy, one taken when it broke) and `dsd diff` shows only
// what changed — without ever touching their machine. See ADR-0003.

import (
	"fmt"

	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff <baseline.tar.gz> <current.tar.gz>",
	Short: "Diff two capture bundles — show what changed between them (offline)",
	Long: `Compare two raw capture bundles (from dsd capture --raw) of the same host
and print only what changed. Argument order is "old new" like diff/git diff:
the first bundle is the baseline, the second is the current state.

The support workflow: a customer sends a healthy capture and the one taken when
the host broke; dsd diff shows the per-check status transitions that explain the
incident — without touching their machine.

  dsd diff healthy.tar.gz broke.tar.gz          # human change report
  dsd diff healthy.tar.gz broke.tar.gz --json   # machine-readable diff

This is the same engine as 'dsd replay <current> --diff <baseline>', with the
more intuitive two-argument form.

NOTE: run inside a linux binary to exercise linux-specific parsers; the bundles
are portable but the binary is not (use an OrbStack container on macOS).`,
	Args:             cobra.ExactArgs(2),
	PersistentPreRun: func(_ *cobra.Command, _ []string) {},
	RunE:             runDiff,
}

func init() {
	rootCmd.AddCommand(diffCmd)
	diffCmd.Flags().Bool("json", false, "machine-readable diff output")
	diffCmd.Flags().Bool("gpu", false, "include GPU collector")
	diffCmd.Flags().Bool("pkg", false, "include package collector")
	diffCmd.Flags().Bool("deep", false, "include deep collectors")
	diffCmd.Flags().Bool("cve", false, "include the CVE collector (both bundles must be captured with capture --raw --cve-scan)")
	diffCmd.Flags().Bool("force", false, "diff even when a bundle's OS differs from this machine (output will NOT be faithful)")
}

func runDiff(cmd *cobra.Command, args []string) error {
	base, err := loadBundle(args[0])
	if err != nil {
		return fmt.Errorf("loading baseline bundle: %w", err)
	}
	current, err := loadBundle(args[1])
	if err != nil {
		return fmt.Errorf("loading current bundle: %w", err)
	}

	jsonOut, _ := cmd.Flags().GetBool("json")
	gpu, _ := cmd.Flags().GetBool("gpu")
	pkg, _ := cmd.Flags().GetBool("pkg")
	deep, _ := cmd.Flags().GetBool("deep")
	cve, _ := cmd.Flags().GetBool("cve")
	force, _ := cmd.Flags().GetBool("force")

	return renderCaptureDiff(base, current, deep, pkg, gpu, cve, jsonOut, force)
}
