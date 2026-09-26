package cmd

// share.go — `dsd share`: a local, redacted, shareable diagnosis. No backend,
// no upload, no network — the opposite end of docs/SHARE_DESIGN.md's hosted
// design (still gated, unimplemented) from this command's "Local share
// (shipped)" section. After `dsd health` finds something, `dsd share`
// produces one artifact — markdown, HTML, a short ticket-form text summary,
// or the existing --blob encoding — with secrets/PII redacted by default, fit
// to paste into a ticket, Slack, a vendor support case, or an LLM chat.
//
// Three data sources unify into the same (results, insights, snap) shape
// `dsd health` itself produces, so every downstream renderer is shared,
// unmodified code:
//   - live: run the collector pipeline now (same as `dsd health`)
//   - --from <bundle.tar.gz>: replay a captured bundle (cmd/replay.go's
//     loadBundle/replayBundle)
//   - --from <snapshot.json> / --last: reconstruct a minimal (results,
//     insights) pair from a saved baseline.Snapshot (baseline.LoadBaseline)
//
// See docs/THREAT_MODEL.md's "Local share" section for what the redaction
// pass does and does not catch.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/share"
)

func init() {
	rootCmd.AddCommand(shareCmd)
	shareCmd.Flags().String("format", "md", "output format: md|html|text|blob")
	shareCmd.Flags().String("from", "", "share a past run instead of running collectors now — a snapshot.json (dsd health --out snapshot.json) or a bundle.tar.gz (dsd capture --raw)")
	shareCmd.Flags().Bool("last", false, "share this host's most recently completed local run")
	shareCmd.Flags().Bool("stdout", false, "print the artifact to stdout instead of writing a file")
	shareCmd.Flags().Bool("no-redact", false, "disable redaction — the artifact may contain secrets, tokens, or PII; NOT recommended")
	shareCmd.Flags().Bool("keep-hostnames", false, "do not redact hostnames (for sharing within your own team)")
	shareCmd.Flags().Bool("keep-ips", false, "do not redact IP addresses (for sharing within your own team)")
	shareCmd.Flags().Bool("deep", false, "extended analysis (live run only — ignored with --from/--last)")
	shareCmd.Flags().Bool("cve", false, "include CVE security advisory scan (live run only — ignored with --from/--last)")
}

var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Produce a redacted, shareable diagnosis — paste into a ticket, Slack, or an LLM chat",
	Long: `Runs the health pipeline (or loads a past run with --from/--last) and writes
ONE artifact designed to leave this machine: secrets, tokens, hostnames, IP
addresses, and other identifiers are redacted by default.

  dsd share                          markdown report, saved to dsd-share-<host>-<date>.md
  dsd share --format text --stdout   short ticket-form summary, printed to stdout
  dsd share --format html            self-contained HTML report
  dsd share --format blob            compressed/encoded block (see dsd decode)
  dsd share --from bundle.tar.gz     share a bundle captured earlier (dsd capture --raw)
  dsd share --last                   share this host's most recently completed run

Redaction is best-effort — see docs/THREAT_MODEL.md's "Local share" section.
Free-text log lines quoted inside a finding can still carry something these
patterns miss; review the artifact before sharing it somewhere sensitive.
--no-redact disables the pass entirely (a visible warning is printed).`,
	Args: cobra.NoArgs,
	RunE: runShare,
}

// shareFormats is the set of --format values dsd share accepts.
var shareFormats = map[string]string{ // format -> file extension
	"md":   "md",
	"html": "html",
	"text": "txt",
	"blob": "txt",
}

// shareSource is the unified (results, insights, snapshot) triple every share
// format renders from, regardless of where the data came from. restore must
// always be deferred by the caller — it undoes any platform identity
// override applied while gathering data from a bundle/snapshot other than
// this machine's own live state.
type shareSource struct {
	results  []runner.Result
	insights []models.Insight
	snap     *baseline.Snapshot
	elapsed  time.Duration
	cve      *models.CVEAllResult
	osLabel  string
	restore  func()
}

func runShare(cmd *cobra.Command, _ []string) error {
	format, _ := cmd.Flags().GetString("format")
	ext, ok := shareFormats[format]
	if !ok {
		return fmt.Errorf("dsd share: unknown --format %q (want md|html|text|blob)", format)
	}

	ctx := context.Background()
	fromPath, _ := cmd.Flags().GetString("from")
	lastFlag, _ := cmd.Flags().GetBool("last")
	deepFlag, _ := cmd.Flags().GetBool("deep")
	cveFlag, _ := cmd.Flags().GetBool("cve")

	src, err := gatherShareData(ctx, fromPath, lastFlag, healthRunOpts{IncludeDeep: deepFlag, IncludeCVE: cveFlag})
	if err != nil {
		return fmt.Errorf("dsd share: %w", err)
	}
	defer src.restore()

	noRedact, _ := cmd.Flags().GetBool("no-redact")
	keepHostnames, _ := cmd.Flags().GetBool("keep-hostnames")
	keepIPs, _ := cmd.Flags().GetBool("keep-ips")
	redactOpts := share.RedactOptions{Disabled: noRedact, KeepHostnames: keepHostnames, KeepIPs: keepIPs}

	if jsonOut, _ := cmd.Flags().GetBool("json"); jsonOut {
		return writeShareJSON(src, redactOpts)
	}

	artifact, counts, err := renderShareArtifact(format, src, redactOpts)
	if err != nil {
		return fmt.Errorf("dsd share: %w", err)
	}

	return writeShareArtifact(cmd, src, artifact, ext, noRedact, counts)
}

// gatherShareData dispatches to the live/bundle/snapshot data source based on
// --from's extension and --last, returning the unified shareSource every
// format renders from.
func gatherShareData(ctx context.Context, fromPath string, last bool, opts healthRunOpts) (*shareSource, error) {
	switch {
	case fromPath != "" && isBundlePath(fromPath):
		return shareFromBundle(fromPath)
	case fromPath != "":
		return shareFromSnapshotFile(fromPath)
	case last:
		return shareFromSnapshotFile("")
	default:
		return shareFromLiveRun(ctx, opts)
	}
}

// isBundlePath reports whether path names a capture bundle (by extension)
// rather than a snapshot.json — dsd share --from dispatches on this.
func isBundlePath(path string) bool {
	return strings.HasSuffix(path, ".tar.gz") || strings.HasSuffix(path, ".tgz")
}

// shareFromLiveRun runs the collector pipeline now, same as `dsd health`.
func shareFromLiveRun(ctx context.Context, opts healthRunOpts) (*shareSource, error) {
	ctrCtx := collectors.ContainerContextViaSource()
	cloudEnv := collectors.CloudEnvironmentViaSource()
	profile := collectors.ProfileViaSource()
	results, insights, snap, elapsed := runHealthOnce(ctx, ctrCtx, cloudEnv, profile, output.ModePlain, opts, nil)
	if snap == nil {
		return nil, fmt.Errorf("no collectors ran — nothing to share")
	}
	// CVE data is collected once for both md/html renderers — mirrors
	// writeHealthReports' health.go precedent (cheap, local package-manager read).
	cve := collectors.ScanAllCVEs(ctx)
	return &shareSource{
		results: results, insights: insights, snap: snap, elapsed: elapsed,
		cve: cve, osLabel: platform.OSPrettyName(), restore: func() {},
	}, nil
}

// shareFromBundle replays a captured bundle (dsd capture --raw / dsd_capture)
// through the same pipeline `dsd replay` uses, carrying the captured host's
// identity through the returned shareSource until restore() is called.
func shareFromBundle(path string) (*shareSource, error) {
	b, err := loadBundle(path)
	if err != nil {
		return nil, fmt.Errorf("loading bundle: %w", err)
	}
	if err := replayPlatformGuard(b, false); err != nil {
		return nil, err
	}
	results, insights, snap := replayBundle(b, false, false, false, false)
	restoreIdentity := platform.SetIdentity(b.Manifest.Host, b.Manifest.OS)
	restorePlatform := platform.SetReplayPlatform(b.Manifest.DistroID, b.Manifest.InitSystem, b.Manifest.GOOS)
	return &shareSource{
		results: results, insights: insights, snap: snap,
		osLabel: b.Manifest.OS,
		restore: func() { restorePlatform(); restoreIdentity() },
	}, nil
}

// shareFromSnapshotFile loads a baseline.Snapshot (path == "" means "this
// host's most recently completed run", the --last case) and reconstructs the
// minimal (results, insights) pair the shared renderers need. A Snapshot
// only ever records the WORST insight per check (baseline.BuildSnapshot), so
// a check with multiple simultaneous findings replays as one — a known,
// disclosed limitation of sharing from a snapshot rather than a live run or
// bundle.
func shareFromSnapshotFile(path string) (*shareSource, error) {
	snap, err := baseline.LoadBaseline(path)
	if err != nil {
		return nil, fmt.Errorf("loading snapshot: %w", err)
	}
	results := make([]runner.Result, 0, len(snap.Checks))
	insights := make([]models.Insight, 0, len(snap.Checks))
	for _, c := range snap.Checks {
		results = append(results, runner.Result{Name: c.Name, Data: c.Raw})
		if c.Status == "" || c.Status == "OK" {
			continue
		}
		insights = append(insights, models.Insight{
			Level: c.Status, Check: c.Name, Message: c.Value, Unverified: c.Unverified,
		})
	}
	restore := platform.SetIdentity(snap.Hostname, "")
	return &shareSource{results: results, insights: insights, snap: snap, restore: restore}, nil
}

// renderShareArtifact builds and redacts the artifact for one format.
func renderShareArtifact(format string, src *shareSource, opts share.RedactOptions) (string, share.Counts, error) {
	switch format {
	case "md":
		raw := render.BuildMarkdownReport(src.snap, src.insights, src.elapsed, src.cve)
		red, counts := share.RedactText(raw, src.snap.Hostname, opts)
		return addShareUTM(red, false), counts, nil
	case "html":
		raw, err := render.BuildHTMLReport(src.snap, src.insights, src.elapsed, src.cve)
		if err != nil {
			return "", nil, err
		}
		red, counts := share.RedactText(raw, src.snap.Hostname, opts)
		return addShareUTM(red, true), counts, nil
	case "text":
		raw := render.RenderShareText(src.snap, src.insights, src.osLabel)
		red, counts := share.RedactText(raw, src.snap.Hostname, opts)
		return red, counts, nil
	case "blob":
		data, err := render.RenderJSON(src.results, src.insights)
		if err != nil {
			return "", nil, err
		}
		red, counts, err := share.RedactJSONBytes(data, src.snap.Hostname, opts)
		if err != nil {
			return "", nil, err
		}
		return share.Encode(red), counts, nil
	default:
		return "", nil, fmt.Errorf("unknown format %q", format)
	}
}

// addShareUTM tags the footer's dashdiag.sh link with ?src=share so footer
// hits from shared artifacts are measurable, without touching the shared
// footer string GenerateReport/GenerateHTMLReport also use for `dsd health
// --report`/`--report-html` (which stay untagged).
func addShareUTM(s string, html bool) string {
	if html {
		return strings.ReplaceAll(s, `href="https://dashdiag.sh"`, `href="https://dashdiag.sh/?src=share"`)
	}
	return strings.ReplaceAll(s, "(https://dashdiag.sh)", "(https://dashdiag.sh/?src=share)")
}

// writeShareArtifact writes the rendered artifact per --stdout/--out/default
// rules, then prints the redaction summary and paste hint to stderr.
//
//   - --out <path> (the global, persistent flag): root.go's PersistentPreRun
//     already redirected os.Stdout to that file before RunE ran, so printing
//     here writes it.
//   - --stdout: prints to the real stdout, kept clean (no stderr hints mixed
//     in) for piping.
//   - default: writes dsd-share-<host>-<date>.<ext> via the same symlink-safe
//     createOutFile root.go's --out uses.
func writeShareArtifact(cmd *cobra.Command, src *shareSource, artifact, ext string, noRedact bool, counts share.Counts) error {
	outPath, _ := cmd.Flags().GetString("out")
	stdoutFlag, _ := cmd.Flags().GetBool("stdout")

	switch {
	case outPath != "":
		fmt.Print(artifact)
		fmt.Fprintf(os.Stderr, "\n📄 Share artifact saved: %s\n", outPath)
	case stdoutFlag:
		fmt.Print(artifact)
	default:
		auto := defaultShareFilename(src.snap.Hostname, src.snap.Timestamp, ext)
		f, err := createOutFile(auto)
		if err != nil {
			return fmt.Errorf("writing %s: %w", auto, err)
		}
		if _, err := f.WriteString(artifact); err != nil {
			_ = f.Close()
			return fmt.Errorf("writing %s: %w", auto, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("writing %s: %w", auto, err)
		}
		fmt.Fprintf(os.Stderr, "📄 Share artifact saved: %s\n", auto)
	}

	if noRedact {
		fmt.Fprintln(os.Stderr, "⚠️  --no-redact: this artifact was NOT redacted and may contain secrets, tokens, or PII. Review before sharing.")
	} else {
		fmt.Fprintf(os.Stderr, "redactions: %s\n", counts.Summary())
	}
	fmt.Fprintln(os.Stderr, "Paste this into your ticket, Slack, or an LLM chat.")
	return nil
}

// defaultShareFilename builds dsd-share-<host>-<date>.<ext>, mirroring
// render.GenerateReport's dsd-report-*.md naming (same SafeHostname sanitizer
// — a snapshot/bundle's hostname is untrusted the same way a report's is).
func defaultShareFilename(hostname string, ts time.Time, ext string) string {
	return fmt.Sprintf("dsd-share-%s-%s.%s", baseline.SafeHostname(hostname), ts.Format("20060102-150405"), ext)
}

// shareJSONOutput extends the standard dsd health --json contract with two
// additive top-level fields, following demoJSONOutput's precedent (cmd/demo.go).
type shareJSONOutput struct {
	render.JSONOutput
	Redacted   bool         `json:"redacted"`
	Redactions share.Counts `json:"redactions,omitempty"`
}

// writeShareJSON handles --json: the normal dsd health --json document plus
// the additive redacted/redactions fields. The JSON payload itself goes
// through the same identifier/secret redaction as every other format — a
// consumer piping `dsd share --json` somewhere external expects the same
// guarantee the other formats make.
func writeShareJSON(src *shareSource, opts share.RedactOptions) error {
	out := render.BuildJSONOutput(src.results, src.insights)
	data, err := json.Marshal(out)
	if err != nil {
		return err
	}
	red, counts, err := share.RedactJSONBytes(data, src.snap.Hostname, opts)
	if err != nil {
		return err
	}
	var redactedOut render.JSONOutput
	if err := json.Unmarshal(red, &redactedOut); err != nil {
		return err
	}
	return outputJSON(os.Stdout, shareJSONOutput{
		JSONOutput: redactedOut, Redacted: !opts.Disabled, Redactions: counts,
	})
}
