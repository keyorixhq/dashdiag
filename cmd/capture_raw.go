package cmd

// capture_raw.go — `dsd capture --raw`
//
// Runs the full health collection with a source.Recorder swapped in, so every
// sysfs read and command output the collectors touch is recorded, then writes a
// single self-contained .tar.gz the operator hands back. One command, no
// wrappers, no separate script — the native replacement for hack/hw-snapshot.sh
// (which remains the fallback for hosts where you can't get a dsd binary on).
//
// Replay it offline with: dsd replay <bundle>      (see cmd/replay.go, ADR-0003)

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/cvedata"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/source"
	"github.com/keyorixhq/dashdiag/internal/version"
)

func init() {
	captureCmd.Flags().Bool("raw", false, "capture a raw input bundle (every sysfs read + command output) for offline replay with `dsd replay`")
	captureCmd.Flags().StringP("out", "o", "", "output path for the --raw bundle (default: dsd-raw-<host>-<timestamp>.tar.gz)")
	captureCmd.Flags().Bool("sanitize", false, "best-effort redaction of common credentials (keys, passwords, tokens) from the bundle before writing — for safe sharing")
	captureCmd.Flags().Bool("identifiers", false, "with --sanitize, also redact IPv4 addresses, MAC addresses, and the hostname (implies --sanitize)")
	captureCmd.Flags().Bool("deep", false, "also record the deep collectors (per-core CPU, smaps, cgroup slices, package integrity) so the bundle can `dsd replay --deep`")
	captureCmd.Flags().Bool("pkg", false, "also record the package collector (updates/integrity) in the bundle")
}

func runCaptureRaw(cmd *cobra.Command) error {
	ctx := context.Background()
	ctrCtx := platform.DetectContainerContext()
	cloudEnv := platform.DetectCloudEnvironment()
	profile := platform.Detect()

	// Record over the live, locale-safe source; restore on exit.
	rec := source.NewRecorder(collectors.ActiveSource())
	prev := collectors.SetSource(rec)
	defer collectors.SetSource(prev)

	// Autodetect GPU: probe /sys/class/drm for DRM card nodes — the same check
	// the GPU collector itself uses, now routed through the recorder so the probe
	// read is captured in the bundle. If no cards found, skip GPU collection
	// (avoids a confusing empty GPU section on headless servers / VMs / ARM).
	gpu := detectGPUPresence()
	if gpu {
		fmt.Fprintln(os.Stderr, "Capturing raw system inputs (running the full health check, GPU detected)…")
	} else {
		fmt.Fprintln(os.Stderr, "Capturing raw system inputs (running the full health check, no GPU detected)…")
	}

	// --deep records the deep collectors (per-core CPU, smaps, cgroup slices,
	// package integrity) so the bundle can be `dsd replay --deep`'d; --pkg adds the
	// package collector. Default stays terse (the validated, byte-stable path).
	deep, _ := cmd.Flags().GetBool("deep")
	pkg, _ := cmd.Flags().GetBool("pkg")
	// --cve-scan records the CVE/advisory verdict into the bundle so the CVE check
	// replays from the captured snapshot (CVE data is time-varying; freezing it is
	// the point). Off by default — the scan can be slow and most captures don't need it.
	cveScan, _ := cmd.Flags().GetBool("cve-scan")
	results, insights, _, _ := runHealthOnce(ctx, ctrCtx, cloudEnv, profile, output.ModePlain,
		!deep /*terse*/, pkg, gpu, false /*tls*/, deep, false /*firmware*/, cveScan /*cve*/, nil)

	b := rec.Bundle()
	b.Manifest = source.Manifest{
		Format:     source.FormatVersion,
		Host:       hostnameOr("host"),
		OS:         osPretty(),
		GOOS:       runtime.GOOS,
		DistroID:   cvedata.DetectDistroID(),
		InitSystem: profile.InitSystem,
		Kernel:     kernelRelease(),
		DsdVer:     version.Version,
		Created:    time.Now().UTC().Format(time.RFC3339),
		Note:       "dsd capture --raw",
	}

	// Embed the rendered health JSON — the report these inputs produced — so the
	// bundle carries both inputs and output for cross-checking on replay.
	if data, err := render.RenderJSON(results, insights); err == nil {
		b.PutFile("/__dsd__/health.json", data)
	}

	sanitize, _ := cmd.Flags().GetBool("sanitize")
	identifiers, _ := cmd.Flags().GetBool("identifiers")
	if identifiers {
		sanitize = true // identifiers can't be redacted without the sanitize pass
	}

	// Capture the real hostname for the default filename before sanitize may
	// replace Manifest.Host with a placeholder.
	fileHost := b.Manifest.Host

	var sanReport source.SanitizeReport
	if sanitize {
		sanReport = b.Sanitize(source.SanitizeOptions{Identifiers: identifiers})
	}

	out, _ := cmd.Flags().GetString("out")
	if out == "" {
		out = fmt.Sprintf("dsd-raw-%s-%s.tar.gz", fileHost, time.Now().Format("20060102-150405"))
	}
	if err := b.SaveTarball(out); err != nil {
		return fmt.Errorf("writing bundle: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\n✅ Raw bundle written: %s\n", out)
	fmt.Fprintf(os.Stderr, "   Replay it offline with:  dsd replay %s\n", out)
	if sanitize {
		fmt.Fprintf(os.Stderr, "   Sanitized (best-effort): %d redaction(s) across %d file(s) + %d command(s).\n",
			sanReport.TotalRedactions, sanReport.FilesRedacted, sanReport.CommandsRedacted)
		fmt.Fprintln(os.Stderr, "   NOTE: best-effort redaction only — REVIEW before sharing.")
		if identifiers {
			fmt.Fprintln(os.Stderr, "   Identifiers redacted in file contents + command output: IPv4, MAC, hostname.")
			fmt.Fprintln(os.Stderr, "   NOT redacted: IPv6, disk serials, and probe-target IPs (gateway/DNS) that")
			fmt.Fprintln(os.Stderr, "   remain in the command index as replay lookup keys — review the bundle.")
		} else {
			fmt.Fprintln(os.Stderr, "   Identifiers (hostname, IPs, serials) kept for replay — add --identifiers to redact them.")
		}
	} else {
		fmt.Fprintln(os.Stderr, "   NOTE: unredacted — contains hostname, IPs, disk serials, journald lines, and any")
		fmt.Fprintln(os.Stderr, "   secrets in captured files/commands. Re-run with --sanitize for safer sharing.")
	}
	fmt.Fprintln(os.Stderr, "   Send it through a trusted channel; don't post it publicly.")
	return nil
}

func hostnameOr(def string) string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return def
	}
	return h
}

// kernelRelease reads /proc/sys/kernel/osrelease through the active source so
// it is captured in the bundle (and replayable).
func kernelRelease() string {
	b, err := collectors.ReadFileViaSource("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// osPretty reads /etc/os-release through the active source so it is captured.
func osPretty() string {
	b, err := collectors.ReadFileViaSource("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if after, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(after, `"`)
		}
	}
	return runtime.GOOS
}

// detectGPUPresence probes /sys/class/drm for DRM card nodes using the active
// source so the directory listing is captured in the bundle. Returns true if at
// least one card node is present, false on headless/VM/ARM hosts.
func detectGPUPresence() bool {
	cards, err := collectors.GlobViaSource("/sys/class/drm/card[0-9]")
	return err == nil && len(cards) > 0
}
