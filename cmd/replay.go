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

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
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

Use --diff to compare two captures of the same host and see only what changed
(the support workflow: diff a healthy capture against the one taken when it
broke). The positional bundle is "current"; --diff names the baseline:

  dsd replay broke.tar.gz --diff healthy.tar.gz        # human change report
  dsd replay broke.tar.gz --diff healthy.tar.gz --json # machine-readable diff

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
	replayCmd.Flags().String("diff", "",
		"diff this capture against a baseline capture (path to another bundle) — shows what changed")
}

// loadBundle reads a native raw-v1 bundle, falling back to an hw-snapshot.sh
// tarball (file layer only) when there is no manifest.
func loadBundle(path string) (*source.Bundle, error) {
	if b, err := source.LoadTarball(path); err == nil {
		return b, nil
	}
	return source.FromSnapshot(path)
}

// replayBundle runs the full health pipeline against a single bundle with the
// source swapped to a Replay over it, then restores the previous source. It is
// the one place replay drives runHealthOnce, so the normal and --diff paths use
// an identical pipeline (and the same flag handling).
func replayBundle(b *source.Bundle, deep, pkg, gpu bool) ([]runner.Result, []models.Insight, *baseline.Snapshot) {
	prev := collectors.SetSource(source.NewReplay(b))
	defer collectors.SetSource(prev)

	// Neutral platform values — this is the replaying host, not the captured one.
	results, insights, snap, _ := runHealthOnce(
		context.Background(), platform.ContainerContext{}, platform.CloudEnvironment(0),
		platform.Detect(), output.ModePlain,
		!deep,    // terse unless deep: drilldown's extra reads aren't in the bundle
		pkg, gpu, // includePackages, includeGPU
		false, deep, false, false, // tls, deep, firmware, cve
		nil,
	)
	return results, insights, snap
}

func runReplay(cmd *cobra.Command, args []string) error {
	b, err := loadBundle(args[0])
	if err != nil {
		return fmt.Errorf("loading bundle: %w", err)
	}

	jsonOut, _ := cmd.Flags().GetBool("json")
	gpu, _ := cmd.Flags().GetBool("gpu")
	pkg, _ := cmd.Flags().GetBool("pkg")
	deep, _ := cmd.Flags().GetBool("deep")
	diffPath, _ := cmd.Flags().GetString("diff")

	if diffPath != "" {
		return runReplayDiff(b, diffPath, deep, pkg, gpu, jsonOut)
	}

	results, insights, _ := replayBundle(b, deep, pkg, gpu)

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

// runReplayDiff replays a baseline capture and the current capture through the
// same pipeline and prints what changed between them — the support workflow:
// "diff a customer's healthy capture against the one taken when it broke".
func runReplayDiff(current *source.Bundle, baselinePath string, deep, pkg, gpu, jsonOut bool) error {
	base, err := loadBundle(baselinePath)
	if err != nil {
		return fmt.Errorf("loading baseline bundle: %w", err)
	}

	_, _, baseSnap := replayBundle(base, deep, pkg, gpu)
	_, _, curSnap := replayBundle(current, deep, pkg, gpu)

	if base.Manifest.Host != "" || current.Manifest.Host != "" {
		fmt.Fprintf(os.Stderr, "diffing baseline %s (%s) → current %s (%s)\n\n",
			base.Manifest.Host, base.Manifest.Created,
			current.Manifest.Host, current.Manifest.Created)
	}

	mode := output.ModeHuman
	if jsonOut {
		mode = output.ModeJSON
	}
	return render.PrintDiff(os.Stdout, baseSnap, curSnap, mode)
}
