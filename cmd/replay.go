package cmd

// replay.go — `dsd replay <bundle>`
//
// Re-runs collectors against a raw capture bundle (from `dsd capture --raw`, or
// the file layer of an hw-snapshot.sh tarball) with a source.Replay swapped in,
// so the real collector code executes against recorded inputs — no hardware, no
// live reads. See docs/adr/0003-raw-input-capture-replay.md.
//
// Replay runs only the collectors whose inputs are routed through the source
// (Phase 2: thermal, cpufreq, and optionally gpu). Others would read the dev
// machine, so they are deliberately excluded until they migrate (Phase 3).

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/source"
)

var replayCmd = &cobra.Command{
	Use:   "replay <bundle.tar.gz>",
	Short: "Re-run collectors against a raw capture bundle (offline, no hardware)",
	Long: `Re-run collectors against a raw capture bundle produced by dsd capture --raw.

The real collector code executes against the recorded sysfs reads and command
output, so a hardware-specific bug (AMD thermal, EDAC, amdgpu) can be debugged on
any laptop. An hw-snapshot.sh tarball is also accepted (its file layer).

  dsd replay dsd-raw-host-20260614-120000.tar.gz
  dsd replay --gpu --json bundle.tar.gz`,
	Args:             cobra.ExactArgs(1),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {}, // suppress brand header
	RunE:             runReplay,
}

func init() {
	rootCmd.AddCommand(replayCmd)
	replayCmd.Flags().Bool("gpu", false, "include the GPU collector in replay")
	replayCmd.Flags().Bool("json", false, "JSON output")
}

// loadBundle reads a native raw-v1 bundle, falling back to an hw-snapshot.sh
// tarball (file layer only) when there is no manifest.
func loadBundle(path string) (*source.Bundle, error) {
	if b, err := source.LoadTarball(path); err == nil {
		return b, nil
	}
	return source.FromSnapshot(path)
}

func runReplay(cmd *cobra.Command, args []string) error {
	b, err := loadBundle(args[0])
	if err != nil {
		return fmt.Errorf("loading bundle: %w", err)
	}

	prev := collectors.SetSource(source.NewReplay(b))
	defer collectors.SetSource(prev)

	gpu, _ := cmd.Flags().GetBool("gpu")
	jsonOut, _ := cmd.Flags().GetBool("json")

	cols := []collectors.Collector{
		collectors.NewThermalCollectorWithContext(false),
		collectors.NewCPUFreqCollector(),
	}
	if gpu {
		cols = append(cols, collectors.NewGPUCollector())
	}

	ctx := context.Background()
	var results []runner.Result
	for r := range runner.RunAll(ctx, toRunnerCols(cols)) {
		results = append(results, r)
	}

	// Thresholds only tune severity, not what's read (inputs come from the
	// bundle). Use neutral defaults — the dev host's cloud/container status is
	// irrelevant to the captured host.
	var cloudEnv platform.CloudEnvironment
	thresh := analysis.DefaultThresholds(cloudEnv)
	insights := analysis.ApplyThresholds(results, thresh, cloudEnv, platform.ContainerContext{})

	if b.Manifest.Host != "" {
		fmt.Fprintf(os.Stderr, "replaying capture from %s (%s, kernel %s)\n",
			b.Manifest.Host, b.Manifest.OS, b.Manifest.Kernel)
	}
	fmt.Fprintf(os.Stderr, "replay covers %d migrated collector(s); more land as collectors migrate (ADR-0003 Phase 3)\n\n", len(cols))

	if jsonOut {
		data, err := render.RenderJSON(results, insights)
		if err != nil {
			return err
		}
		_, _ = os.Stdout.Write(data)
		return nil
	}
	renderer := render.NewRenderer(output.ModeHuman)
	renderer.PrintAll(results, insights)
	_ = renderer.PrintSummary(insights, 0)
	return nil
}
