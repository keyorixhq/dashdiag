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
	"runtime"

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
	replayCmd.Flags().Bool("cve", false, "include the CVE collector (reads the scan recorded by capture --raw --cve-scan)")
	replayCmd.Flags().Bool("deep", false, "include deep collectors")
	replayCmd.Flags().Bool("layered", false, "group findings by abstraction layer (hardware / platform / OS & services)")
	replayCmd.Flags().Bool("report", false, "write a shareable markdown report of the captured host")
	replayCmd.Flags().Bool("report-html", false, "write a self-contained HTML report (printable to PDF) of the captured host")
	replayCmd.Flags().Bool("force", false, "replay even when the bundle's OS differs from this machine (output will NOT be faithful)")
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
func replayBundle(b *source.Bundle, deep, pkg, gpu, cve bool) ([]runner.Result, []models.Insight, *baseline.Snapshot) {
	prev := collectors.SetSource(source.NewReplay(b))
	defer collectors.SetSource(prev)

	// Report the CAPTURED host's identity (from the manifest), not the replaying
	// machine's — so the snapshot/JSON carry the right hostname/OS (e.g. dsd diff).
	defer platform.SetIdentity(b.Manifest.Host, b.Manifest.OS)()

	// Container-context, cloud, and profile come from the bundle (recorded at
	// capture) so a captured container's cgroup limits, a cloud guest's cloud-aware
	// thresholds, and the captured host's distro all replay faithfully — instead of
	// the old hardcoded bare-metal / no-cloud / replaying-machine-distro values.
	results, insights, snap, _ := runHealthOnce(
		context.Background(), collectors.ContainerContextViaSource(), collectors.CloudEnvironmentViaSource(),
		collectors.ProfileViaSource(), output.ModePlain,
		!deep,    // terse unless deep: drilldown's extra reads aren't in the bundle
		pkg, gpu, // includePackages, includeGPU
		false, deep, false, cve, // tls, deep, firmware, cve
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
	cve, _ := cmd.Flags().GetBool("cve")
	force, _ := cmd.Flags().GetBool("force")
	diffPath, _ := cmd.Flags().GetString("diff")

	if diffPath != "" {
		return runReplayDiff(b, diffPath, deep, pkg, gpu, cve, jsonOut, force)
	}

	if err := replayPlatformGuard(b, force); err != nil {
		return err
	}

	results, insights, snap := replayBundle(b, deep, pkg, gpu, cve)

	// Keep the captured host's identity active through the render below too
	// (replayBundle restored it on return).
	defer platform.SetIdentity(b.Manifest.Host, b.Manifest.OS)()

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
	if layered, _ := cmd.Flags().GetBool("layered"); layered {
		renderer.PrintAllLayered(results, insights)
	} else {
		renderer.PrintAll(results, insights)
	}
	_ = renderer.PrintSummary(insights, 0)

	// --report / --report-html: write shareable report(s) of the CAPTURED host.
	// CVE is nil — advisories aren't in the bundle (they're scanned live).
	if reportMD, _ := cmd.Flags().GetBool("report"); reportMD && snap != nil {
		if path, err := render.GenerateReport(snap, insights, 0, nil); err != nil {
			fmt.Fprintf(os.Stderr, "report: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "\n📄 Report saved: %s\n", path)
		}
	}
	if reportHTML, _ := cmd.Flags().GetBool("report-html"); reportHTML && snap != nil {
		if path, err := render.GenerateHTMLReport(snap, insights, 0, nil); err != nil {
			fmt.Fprintf(os.Stderr, "report: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "\n📄 HTML report saved: %s\n", path)
		}
	}
	return nil
}

// runReplayDiff replays a baseline capture and the current capture through the
// same pipeline and prints what changed between them — the support workflow:
// "diff a customer's healthy capture against the one taken when it broke".
func runReplayDiff(current *source.Bundle, baselinePath string, deep, pkg, gpu, cve, jsonOut, force bool) error {
	base, err := loadBundle(baselinePath)
	if err != nil {
		return fmt.Errorf("loading baseline bundle: %w", err)
	}
	return renderCaptureDiff(base, current, deep, pkg, gpu, cve, jsonOut, force)
}

// replayPlatformGuard refuses to replay a bundle captured on a different OS family
// than the replaying machine. dsd runs the LOCAL platform's (build-tagged)
// collectors, so a Linux capture replayed on macOS reports THIS machine's findings
// under the captured host's name — a misleading "false everything" result, the more
// so when written to a report file. --force overrides for the rare deliberate case.
func replayPlatformGuard(b *source.Bundle, force bool) error {
	fam := b.Manifest.PlatformFamily()
	if fam == runtime.GOOS || force {
		return nil
	}
	//nolint:staticcheck // ST1005: intentional multi-line user-facing CLI guidance, not a wrapped error
	return fmt.Errorf(
		"bundle was captured on %s (%q) but you are replaying on %s.\n"+
			"  Cross-platform replay runs the local (%s) collectors and would report THIS\n"+
			"  machine's findings under the captured host's name — not the captured data.\n"+
			"  Replay on a %s host for a faithful result, or pass --force to override.",
		fam, b.Manifest.OS, runtime.GOOS, runtime.GOOS, fam)
}

// renderCaptureDiff replays two bundles through the identical health pipeline and
// writes the per-check delta to stdout (human or JSON). Shared by `replay --diff`
// and the top-level `dsd diff` command.
func renderCaptureDiff(base, current *source.Bundle, deep, pkg, gpu, cve, jsonOut, force bool) error {
	if err := replayPlatformGuard(current, force); err != nil {
		return err
	}
	if err := replayPlatformGuard(base, force); err != nil {
		return err
	}
	_, _, baseSnap := replayBundle(base, deep, pkg, gpu, cve)
	_, _, curSnap := replayBundle(current, deep, pkg, gpu, cve)

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
