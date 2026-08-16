package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(gcpCmd)
	gcpCmd.Flags().Bool("report-html", false,
		"write a self-contained two-block HTML report (co-brandable leave-behind, printable to PDF)")
}

var gcpCmd = &cobra.Command{
	Use:   "gcp",
	Short: "GCE guest health — guest agent, host-maintenance policy/events, OS Login, gVNIC, metadata time sync",
	Long: "Guest-side health for a Linux VM on Google Compute Engine.\n\n" +
		"Splits findings into what YOU can fix from inside the VM (the Google guest agent,\n" +
		"a TERMINATE-on-maintenance policy on a non-preemptible VM, metadata-server time\n" +
		"sync) and Google-side host activity to correlate (an in-progress host-maintenance\n" +
		"event live-migrating or stopping the VM).",
	RunE: runGCP,
}

func runGCP(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	// Gate on the same DMI signature health uses — silent/honest off GCE.
	if !collectors.GCPGuestAvailable() {
		if mode == output.ModeJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(&models.GCPInfo{})
		}
		fmt.Println()
		fmt.Println(render.StyleInfo.Render(asciiOr("info", "ℹ️  ", mode) +
			"not running on GCE — this host's DMI does not match a Google Compute Engine VM"))
		fmt.Println("   (dsd gcp is for Linux VMs on Google Compute Engine)")
		return nil
	}

	if reportHTML, _ := cmd.Flags().GetBool("report-html"); reportHTML {
		view, err := gcpGuestView(ctx)
		if err != nil {
			return err
		}
		path, err := writeGuestReportHTML(view)
		if err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "📄 HTML report saved: %s\n", path)
		return nil
	}

	col := collectors.NewGCPCollector()
	p := output.NewCommandProgress("GCE guest health", 10*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{col}) {
		p.Step(r.Name)
		result = r
	}
	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.GCPInfo)
	if !ok || info == nil {
		return result.Err
	}

	if mode == output.ModeJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	printGCPReport(os.Stdout, info, elapsed, mode)
	return nil
}

// gcpConcerns counts the actionable GCE issues for the standalone verdict, from the
// SAME heuristic `dsd health` runs (analysis.GCPInsights) so the two cannot drift.
func gcpConcerns(info *models.GCPInfo) int {
	n := 0
	for _, in := range analysis.GCPInsights(*info) {
		if in.Level == "WARN" || in.Level == "CRIT" {
			n++
		}
	}
	return n
}

// gcpInsightProviderSide reports whether a finding is Google-side host activity (an
// in-progress host-maintenance event live-migrating/stopping the VM), as opposed to
// in-guest config the operator fixes themselves (the guest agent, the maintenance
// POLICY, time sync). Keyed on a stable token we own; unmatched findings fall into
// the self-serve block, so nothing is dropped.
func gcpInsightProviderSide(msg string) bool {
	return strings.Contains(msg, "maintenance event is in progress")
}

// isGCPRecognitionLine matches the all-clean "GCP VM — …" INFO that checkGCP emits
// only when everything it could verify is clean; folded away (the command prints its
// own header + clean summary).
func isGCPRecognitionLine(msg string) bool {
	return strings.HasPrefix(msg, "GCP VM")
}

func printGCPReport(w io.Writer, info *models.GCPInfo, elapsed time.Duration, mode output.OutputMode) {
	sep := strings.Repeat("─", 60)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	net := "synthetic"
	if info.UsesGVNIC {
		net = "gVNIC"
	} else if info.NICDriver != "" {
		// NICDriver is a /sys/class/net/*/device/driver symlink basename —
		// treated as untrusted per this review's threat model — sanitize
		// before it reaches the terminal header.
		net = output.SanitizeControl(info.NICDriver)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%sGCE VM   (networking: %s)\n", asciiOr("info", "🟥 ", mode), net)

	var guest, provider []models.Insight
	for _, in := range analysis.GCPInsights(*info) {
		if isGCPRecognitionLine(in.Message) {
			continue
		}
		if gcpInsightProviderSide(in.Message) {
			provider = append(provider, in)
		} else {
			guest = append(guest, in)
		}
	}

	printGuestBlock(w, "Your VM — you can fix these", guest, mode)
	printGuestBlock(w, "Host-side — Google Cloud activity to correlate", provider, mode)

	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
	if gcpConcerns(info) == 0 {
		base := healthySummary(
			"GCE guest healthy — no guest-side config or host-maintenance issues found",
			analysis.GCPInsights(*info))
		fmt.Fprintln(w, render.StyleOK.Render(fmt.Sprintf("%s%s%s", asciiOr("ok", "✅ ", mode), base, timing)))
	} else {
		fmt.Fprintln(w, render.StyleWarn.Render(fmt.Sprintf(
			"%s%d GCE issue(s) found%s", asciiOr("warn", "⚠️  ", mode), gcpConcerns(info), timing)))
	}
}
