package cmd

// replay.go — `dsd replay <bundle>`
//
// Re-runs the full collector set against a raw capture bundle (from `dsd capture
// --raw`, or the file layer of an hw-snapshot.sh tarball) with a source.Replay
// swapped in, so the real collector code executes against recorded inputs — no
// hardware, no live reads. See docs/adr/0003-raw-input-capture-replay.md.
//
// All collectors now route file reads through the active source (ADR-0003 Phase 3
// complete), so replay is comprehensive: thermal, memory, CPU, disk, network,
// GPU, EDAC, NUMA, and every other collector in the health run.
//
// NOTE: the replay binary must match the captured host's OS. Linux collectors
// are build-tagged linux. To replay a Linux bundle, run `dsd replay` inside a
// linux binary (e.g. OrbStack container on Apple Silicon). The bundle is
// portable; the binary is not.

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/source"
)

var replayCmd = &cobra.Command{
	Use:   "replay <bundle.tar.gz>",
	Short: "Re-run the full health check against a raw capture bundle (offline)",
	Long: `Re-run the full health check against a raw capture bundle produced by
dsd capture --raw. Every collector reads from the bundle instead of the live
system, so hardware-specific bugs (AMD thermal, EDAC, amdgpu, NUMA) can be
diagnosed on any machine.

An hw-snapshot.sh tarball is also accepted for the file-based collectors.

  dsd replay dsd-raw-host-20260614-120000.tar.gz
  dsd replay --json bundle.tar.gz | jq .

NOTE: run dsd replay inside a linux binary to exercise linux-specific parsers.
On macOS the linux build tags are absent; use an OrbStack container.`,
	Args:             cobra.ExactArgs(1),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {},
	RunE:             runReplay,
}

func init() {
	rootCmd.AddCommand(replayCmd)
	replayCmd.Flags().Bool("json", false, "JSON output")
	replayCmd.Flags().Bool("gpu", false, "include GPU collector")
	replayCmd.Flags().Bool("pkg", false, "include package collector")
	replayCmd.Flags().Bool("deep", false, "include deep collectors")
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

	jsonOut, _ := cmd.Flags().GetBool("json")
	gpu, _ := cmd.Flags().GetBool("gpu")
	pkg, _ := cmd.Flags().GetBool("pkg")
	deep, _ := cmd.Flags().GetBool("deep")

	ctx := context.Background()
	// Use neutral platform values — this is the dev host, not the captured host.
	ctrCtx := platform.ContainerContext{}
	cloudEnv := platform.CloudEnvironment(0)

	// runHealthOnce uses buildHealthCollectors (the full health set) and applies
	// thresholds, giving an identical diagnostic pipeline to `dsd health`.
	// Inputs come from the bundle via the swapped source.
	results, insights, _, _ := runHealthOnce(
		ctx, ctrCtx, cloudEnv, platform.Detect(),
		output.ModePlain,
		true, // terse: skip drilldown (its extra reads aren't in the bundle)
		pkg, gpu,
		false, false, false, false, // tls, deep, firmware, cve
		nil,
	)
	// Override deep so the flag is honoured.
	if deep {
		results, insights, _, _ = runHealthOnce(
			ctx, ctrCtx, cloudEnv, platform.Detect(),
			output.ModePlain,
			false, pkg, gpu, false, true, false, false, nil,
		)
	}

	if b.Manifest.Host != "" {
		fmt.Fprintf(os.Stderr, "replaying: %s  OS: %s  kernel: %s  captured: %s\n\n",
			b.Manifest.Host, b.Manifest.OS, b.Manifest.Kernel, b.Manifest.Created)
	}

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
