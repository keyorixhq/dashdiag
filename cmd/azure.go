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
	rootCmd.AddCommand(azureCmd)
}

var azureCmd = &cobra.Command{
	Use:   "azure",
	Short: "Azure VM health — Accelerated Networking datapath, waagent, Hyper-V PTP, temp disk, host caching",
	Long: "Guest-side health for a Linux VM on Azure.\n\n" +
		"Splits findings into what YOU can fix from inside the VM (waagent, Hyper-V PTP\n" +
		"time sync, persistent data on the ephemeral temp disk, NVMe io_timeout, data-disk\n" +
		"host caching) and the Accelerated-Networking datapath — the portal-says-enabled\n" +
		"but-the-VF-never-attached false-green that is evidence to take to Azure support.",
	RunE: runAzure,
}

func runAzure(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	// Gate on the same DMI signature health uses — silent/honest off Azure.
	if !collectors.AzureGuestAvailable() {
		if mode == output.ModeJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(&models.AzureInfo{})
		}
		fmt.Println()
		fmt.Println(render.StyleInfo.Render(asciiOr("info", "ℹ️  ", mode) +
			"not running on Azure — this host's DMI does not match an Azure VM"))
		fmt.Println("   (dsd azure is for Linux VMs on Microsoft Azure)")
		return nil
	}

	col := collectors.NewAzureCollector()
	p := output.NewCommandProgress("Azure VM health", 10*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{col}) {
		p.Step(r.Name)
		result = r
	}
	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.AzureInfo)
	if !ok || info == nil {
		return result.Err
	}

	if mode == output.ModeJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	printAzureReport(os.Stdout, info, elapsed, mode)
	return nil
}

// azureConcerns counts the actionable Azure issues for the standalone verdict, from
// the SAME heuristic `dsd health` runs (analysis.AzureInsights) so the two can't drift.
func azureConcerns(info *models.AzureInfo) int {
	n := 0
	for _, in := range analysis.AzureInsights(*info) {
		if in.Level == "WARN" || in.Level == "CRIT" {
			n++
		}
	}
	return n
}

// azureInsightProviderSide reports whether a finding is the Accelerated-Networking
// datapath false-green (the portal says AN is enabled but the VF isn't bonded/up) —
// evidence to escalate to Azure once guest-side bonding is confirmed correct — as
// opposed to in-guest config the operator fixes themselves. Azure exposes no
// guest-side disk-throttle telemetry (managed disks have no vendor log page), so AN
// is the platform-evidence block. Keyed on a stable token we own; unmatched findings
// fall into the self-serve block, so nothing is dropped.
func azureInsightProviderSide(msg string) bool {
	return strings.Contains(msg, "Accelerated Networking")
}

// isAzureRecognitionLine matches the all-clean "Azure VM — …" INFO that checkAzure
// emits only when everything it could verify is clean; folded away (the command
// prints its own header + clean summary).
func isAzureRecognitionLine(msg string) bool {
	return strings.HasPrefix(msg, "Azure VM")
}

func printAzureReport(w io.Writer, info *models.AzureInfo, elapsed time.Duration, mode output.OutputMode) {
	sep := strings.Repeat("─", 60)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	an := "unknown"
	switch {
	case info.HasVF:
		an = "active"
	case len(info.SyntheticNICs) > 0:
		an = "synthetic path (no VF)"
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%sAzure VM   (Accelerated Networking: %s)\n", asciiOr("info", "🔷 ", mode), an)

	var guest, provider []models.Insight
	for _, in := range analysis.AzureInsights(*info) {
		if isAzureRecognitionLine(in.Message) {
			continue
		}
		if azureInsightProviderSide(in.Message) {
			provider = append(provider, in)
		} else {
			guest = append(guest, in)
		}
	}

	printGuestBlock(w, "Your VM — you can fix these", guest, mode)
	printGuestBlock(w, "Accelerated networking — evidence to share with Azure support", provider, mode)

	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
	if azureConcerns(info) == 0 {
		base := healthySummary(
			"Azure VM healthy — no guest-side config or datapath issues found",
			analysis.AzureInsights(*info))
		fmt.Fprintln(w, render.StyleOK.Render(fmt.Sprintf("%s%s%s", asciiOr("ok", "✅ ", mode), base, timing)))
	} else {
		fmt.Fprintln(w, render.StyleWarn.Render(fmt.Sprintf(
			"%s%d Azure issue(s) found%s", asciiOr("warn", "⚠️  ", mode), azureConcerns(info), timing)))
	}
}
