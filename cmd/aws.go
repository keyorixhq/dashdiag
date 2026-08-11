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
	rootCmd.AddCommand(awsCmd)
	awsCmd.Flags().Bool("report-html", false,
		"write a self-contained two-block HTML report (co-brandable leave-behind, printable to PDF)")
}

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "EC2 guest health — ENA/EBS silent throttles, IMDS posture, spot rebalance, time sync, SSM",
	Long: "Guest-side health for a Linux EC2 instance.\n\n" +
		"Splits findings into what YOU can fix from inside the instance (IMDSv2 posture,\n" +
		"Amazon Time Sync, the SSM agent) and AWS-imposed limits that are evidence to take\n" +
		"to AWS support (ENA network-allowance throttling, EBS volume/instance performance\n" +
		"limits, an active spot rebalance recommendation).",
	RunE: runAWS,
}

func runAWS(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	// Gate on the same DMI/IMDS signature health uses — silent/honest off EC2.
	if !collectors.AWSGuestAvailable() {
		if mode == output.ModeJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(&models.AWSInfo{})
		}
		fmt.Println()
		fmt.Println(render.StyleInfo.Render(asciiOr("info", "ℹ️  ", mode) +
			"not running on EC2 — this host does not look like an Amazon EC2 instance"))
		fmt.Println("   (dsd aws is for Linux guests on Amazon EC2)")
		return nil
	}

	if reportHTML, _ := cmd.Flags().GetBool("report-html"); reportHTML {
		path, err := writeGuestReportHTML(awsGuestView(ctx))
		if err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "📄 HTML report saved: %s\n", path)
		return nil
	}

	col := collectors.NewAWSCollector()
	p := output.NewCommandProgress("EC2 guest health", 10*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{col}) {
		p.Step(r.Name)
		result = r
	}
	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.AWSInfo)
	if !ok || info == nil {
		return result.Err
	}

	if mode == output.ModeJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	printAWSReport(os.Stdout, info, elapsed, mode)
	return nil
}

// awsConcerns counts the actionable EC2 issues for the standalone verdict, from the
// SAME heuristic `dsd health` runs (analysis.AWSInsights) so the two cannot drift.
func awsConcerns(info *models.AWSInfo) int {
	n := 0
	for _, in := range analysis.AWSInsights(*info) {
		if in.Level == "WARN" || in.Level == "CRIT" {
			n++
		}
	}
	return n
}

// awsInsightProviderSide reports whether a finding is an AWS-imposed limit/signal
// (ENA allowance throttling, EBS performance throttling, a spot rebalance
// recommendation, or "couldn't read EBS stats"), as opposed to in-guest posture the
// operator can fix themselves. Drives the two-block split: self-serve fixes vs.
// evidence to hand AWS support. Keyed on stable tokens we own; anything unmatched
// falls into the self-serve block, so nothing is dropped.
func awsInsightProviderSide(msg string) bool {
	for _, tok := range []string{"allowance", "EBS", "rebalance recommendation"} {
		if strings.Contains(msg, tok) {
			return true
		}
	}
	return false
}

// isAWSRecognitionLine matches the all-clean "EC2 <type> — …" INFO that checkAWS
// emits only when everything it could verify is clean. The command prints its own
// identity header + clean summary, so this line is folded away.
//
// The real "EC2 rebalance recommendation is active — …" WARN (awsRebalanceInsights)
// also starts with "EC2 " — a bare prefix match folds that WARN away too, silently
// dropping the only actionable line from both report blocks while the summary count
// still says "1 EC2 issue(s) found". Exclude it explicitly.
func isAWSRecognitionLine(msg string) bool {
	return strings.HasPrefix(msg, "EC2 ") && !strings.HasPrefix(msg, "EC2 rebalance recommendation")
}

func printAWSReport(w io.Writer, info *models.AWSInfo, elapsed time.Duration, mode output.OutputMode) {
	sep := strings.Repeat("─", 60)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	itype := info.InstanceType
	if itype == "" {
		itype = "instance"
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%sEC2 guest — %s\n", asciiOr("info", "🟧 ", mode), itype)

	var guest, provider []models.Insight
	for _, in := range analysis.AWSInsights(*info) {
		if isAWSRecognitionLine(in.Message) {
			continue
		}
		if awsInsightProviderSide(in.Message) {
			provider = append(provider, in)
		} else {
			guest = append(guest, in)
		}
	}

	printGuestBlock(w, "Your instance — you can fix these", guest, mode)
	printGuestBlock(w, "AWS-imposed limits — evidence to share with AWS support", provider, mode)

	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
	if awsConcerns(info) == 0 {
		base := healthySummary(
			"EC2 guest healthy — no guest-side throttling or posture issues found",
			analysis.AWSInsights(*info))
		fmt.Fprintln(w, render.StyleOK.Render(fmt.Sprintf("%s%s%s", asciiOr("ok", "✅ ", mode), base, timing)))
	} else {
		fmt.Fprintln(w, render.StyleWarn.Render(fmt.Sprintf(
			"%s%d EC2 issue(s) found%s", asciiOr("warn", "⚠️  ", mode), awsConcerns(info), timing)))
	}
}
