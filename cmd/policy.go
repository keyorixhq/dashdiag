package cmd

import (
	"fmt"
	"os"

	"github.com/keyorixhq/dashdiag/internal/analysis"
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
		fmt.Printf("✅  Policy file %q is valid\n", args[0])
		fmt.Printf("    deny levels: %v\n", p.Deny)
		if p.RAMCritPct > 0 {
			fmt.Printf("    ram_crit_pct: %.0f%%\n", p.RAMCritPct)
		}
		if p.DiskCritPct > 0 {
			fmt.Printf("    disk_crit_pct: %.0f%%\n", p.DiskCritPct)
		}
		return nil
	},
}

func init() {
	policyCmd.AddCommand(policyInitCmd)
	policyCmd.AddCommand(policyCheckCmd)
	rootCmd.AddCommand(policyCmd)
}
