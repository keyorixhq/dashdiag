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
	rootCmd.AddCommand(ociCmd)
	ociCmd.Flags().Bool("report-html", false,
		"write a self-contained two-block HTML report (co-brandable leave-behind, printable to PDF)")
}

var ociCmd = &cobra.Command{
	Use:   "oci",
	Short: "OCI guest health — IMDS v2 posture, cloud agent, time sync, VNIC ring health",
	Long: "Guest-side health for a Linux instance on Oracle Cloud Infrastructure.\n\n" +
		"Checks the IMDS v2 security posture (legacy unauthenticated access should be\n" +
		"blocked), oracle-cloud-agent health (Run Command/monitoring/OS Management Hub\n" +
		"depend on it), NTP against OCI's metadata NTP server, and VNIC ring-buffer drop\n" +
		"counters that the generic NIC-error check doesn't catch.",
	RunE: runOCI,
}

func runOCI(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	// Gate on the same DMI signature health uses — silent/honest off OCI.
	if !collectors.OCIGuestAvailable() {
		if mode == output.ModeJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(&models.OCIInfo{})
		}
		fmt.Println()
		fmt.Println(render.StyleInfo.Render(asciiOr("info", "ℹ️  ", mode) +
			"not running on OCI — this host does not look like an Oracle Cloud Infrastructure instance"))
		fmt.Println("   (dsd oci is for Linux guests on Oracle Cloud Infrastructure)")
		return nil
	}

	if reportHTML, _ := cmd.Flags().GetBool("report-html"); reportHTML {
		view, err := ociGuestView(ctx)
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

	col := collectors.NewOCICollector()
	p := output.NewCommandProgress("OCI guest health", 10*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{col}) {
		p.Step(r.Name)
		result = r
	}
	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.OCIInfo)
	if !ok || info == nil {
		return result.Err
	}

	if mode == output.ModeJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	printOCIReport(os.Stdout, info, elapsed, mode)
	return nil
}

// ociConcerns counts the actionable OCI issues for the standalone verdict, from
// the SAME heuristic `dsd health` runs (analysis.OCIInsights) so the two cannot
// drift.
func ociConcerns(info *models.OCIInfo) int {
	n := 0
	for _, in := range analysis.OCIInsights(*info) {
		if in.Level == "WARN" || in.Level == "CRIT" {
			n++
		}
	}
	return n
}

func printOCIReport(w io.Writer, info *models.OCIInfo, elapsed time.Duration, mode output.OutputMode) {
	sep := strings.Repeat("─", 60)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	shape := ociShapeLabel(info)

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%sOCI instance — %s\n", asciiOr("info", "🔴 ", mode), shape)

	var guest, provider []models.Insight
	for _, in := range analysis.OCIInsights(*info) {
		if isOCIRecognitionLine(in.Message) {
			continue
		}
		if ociInsightProviderSide(in.Message) {
			provider = append(provider, in)
		} else {
			guest = append(guest, in)
		}
	}

	printGuestBlock(w, "Your instance — you can fix these", guest, mode)
	printGuestBlock(w, "Provider-imposed — evidence to share with Oracle support", provider, mode)

	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
	if ociConcerns(info) == 0 {
		base := healthySummary(
			"OCI instance healthy — no guest-side posture issues found",
			analysis.OCIInsights(*info))
		fmt.Fprintln(w, render.StyleOK.Render(fmt.Sprintf("%s%s%s", asciiOr("ok", "✅ ", mode), base, timing)))
	} else {
		fmt.Fprintln(w, render.StyleWarn.Render(fmt.Sprintf(
			"%s%d OCI issue(s) found%s", asciiOr("warn", "⚠️  ", mode), ociConcerns(info), timing)))
	}
}
