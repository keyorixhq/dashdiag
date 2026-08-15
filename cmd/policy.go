package cmd

import (
	"fmt"
	"os"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage DashDiag policy files for CI gates",
}

var policyInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Print a starter policy YAML to stdout",
	Long: `Print a starter dsd policy file to stdout.

Redirect to a file and commit to your repo:

  dsd policy init > .dsd-policy.yaml

Then use it in CI:

  dsd health --policy .dsd-policy.yaml && echo "system healthy"

Exit codes: 0 = healthy per policy, 1 = WARN denied, 2 = CRIT`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := fmt.Print(analysis.PolicyInitTemplate)
		return err
	},
}

var policyCheckCmd = &cobra.Command{
	Use:   "check [policy-file]",
	Short: "Validate a policy YAML file without running health checks",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := analysis.LoadPolicy(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "dsd: policy invalid: %v\n", err)
			return err
		}
		printPolicyCheckResult(args[0], p)
		return nil
	},
}

// printPolicyCheckResult prints a summary of a loaded, validated policy file.
// p.Deny ultimately comes from a user-supplied YAML policy file
// (analysis.LoadPolicy normalizes it to WARN/CRIT, but that guarantee lives
// in a different layer) — %v on a []string does not escape control bytes, so
// each level is sanitized before printing rather than relying on the caller.
func printPolicyCheckResult(path string, p *analysis.PolicyFile) {
	fmt.Printf("✅  Policy file %q is valid\n", path)
	denyLevels := make([]string, len(p.Deny))
	for i, level := range p.Deny {
		denyLevels[i] = output.SanitizeControl(level)
	}
	fmt.Printf("    deny levels: %v\n", denyLevels)
	if p.RAMCritPct > 0 {
		fmt.Printf("    ram_crit_pct: %.0f%%\n", p.RAMCritPct)
	}
	if p.DiskCritPct > 0 {
		fmt.Printf("    disk_crit_pct: %.0f%%\n", p.DiskCritPct)
	}
}

func init() {
	policyCmd.AddCommand(policyInitCmd)
	policyCmd.AddCommand(policyCheckCmd)
	rootCmd.AddCommand(policyCmd)
}
