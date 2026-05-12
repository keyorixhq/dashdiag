package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/spf13/cobra"
)

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage golden baselines for drift detection",
}

var baselineSaveCmd = &cobra.Command{
	Use:   "save [name]",
	Short: "Save current system state as a named golden baseline",
	Long: `Capture current system state and save it as a named reference point.

  dsd baseline save production     save as "production"
  dsd baseline save post-upgrade   save after a kernel upgrade

Golden baselines live in ~/.dsd/golden/ and are compared with
'dsd baseline diff <name>' to detect configuration drift.`,
	Args: cobra.ExactArgs(1),
	RunE: runBaselineSave,
}

var baselineDiffCmd = &cobra.Command{
	Use:   "diff [name]",
	Short: "Compare current state against a named golden baseline",
	Long: `Run a full health check and compare results against a saved golden baseline.

Shows:
  - Health status changes (OK → WARN, WARN → CRIT etc.)
  - Kernel parameter drift (sysctl values that changed value)

  dsd baseline diff production
  dsd baseline diff post-upgrade`,
	Args: cobra.ExactArgs(1),
	RunE: runBaselineDiff,
}

var baselineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List saved golden baselines",
	RunE: func(_ *cobra.Command, _ []string) error {
		names, err := baseline.ListGolden()
		if err != nil {
			return err
		}
		if len(names) == 0 {
			fmt.Fprintln(os.Stderr, "no golden baselines saved yet — run 'dsd baseline save <name>'")
			return nil
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	},
}

func init() {
	baselineCmd.AddCommand(baselineSaveCmd)
	baselineCmd.AddCommand(baselineDiffCmd)
	baselineCmd.AddCommand(baselineListCmd)
	rootCmd.AddCommand(baselineCmd)
}

func runBaselineSave(_ *cobra.Command, args []string) error {
	name := args[0]
	ctx := context.Background()
	ctrCtx := platform.DetectContainerContext()
	cloudEnv := platform.DetectCloudEnvironment()

	_, _, snap, _ := runHealthOnce(ctx, ctrCtx, cloudEnv, output.ModePlain, true, false, false, nil)

	if err := baseline.SaveGolden(snap, name); err != nil {
		return fmt.Errorf("saving golden baseline: %w", err)
	}
	fmt.Printf("✅  Golden baseline %q saved (%d checks)\n", name, len(snap.Checks))
	fmt.Printf("    Compare later with: dsd baseline diff %s\n", name)
	return nil
}

func runBaselineDiff(_ *cobra.Command, args []string) error {
	name := args[0]

	golden, err := baseline.LoadGolden(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dsd: "+err.Error())
		os.Exit(1)
	}

	ctx := context.Background()
	ctrCtx := platform.DetectContainerContext()
	cloudEnv := platform.DetectCloudEnvironment()

	_, _, current, _ := runHealthOnce(ctx, ctrCtx, cloudEnv, output.ModePlain, true, false, false, nil)

	// Status diff
	diffs := baseline.ComputeDiff(golden, current)

	// Sysctl value drift
	sysctlDrift := baseline.ComputeSysctlDrift(golden, current)

	// Output
	sep := strings.Repeat("─", 56)
	fmt.Printf("\n%s\n", sep)
	fmt.Printf("Drift report — %q baseline vs now\n", name)
	fmt.Printf("Golden: %s  (%s)\n", golden.Hostname, golden.Timestamp.Format("2006-01-02 15:04"))
	fmt.Printf("Now:    %s  (%s)\n", current.Hostname, current.Timestamp.Format("2006-01-02 15:04"))
	fmt.Printf("%s\n\n", sep)

	// Status changes
	changed := 0
	for _, d := range diffs {
		if !d.Changed {
			continue
		}
		changed++
		arrow := "↓"
		if d.Improved {
			arrow = "↑"
		}
		fmt.Printf("  %s  %-16s  %s → %s\n", arrow, d.Name, d.Before, d.After)
	}
	if changed == 0 {
		fmt.Println("  ✅  No status changes since golden baseline")
	} else {
		fmt.Printf("\n  %d check(s) changed status\n", changed)
	}

	// Sysctl value drift
	if len(sysctlDrift) > 0 {
		fmt.Printf("\nKernel parameter drift:\n")
		for _, d := range sysctlDrift {
			fmt.Printf("  ←  %-38s  %v → %v\n", d.Param, d.Before, d.After)
		}
	} else {
		fmt.Println("\n  ✅  No kernel parameter drift detected")
	}

	// Exit non-zero when drift found — works as CI gate
	if changed > 0 || len(sysctlDrift) > 0 {
		os.Exit(1)
	}
	return nil
}
