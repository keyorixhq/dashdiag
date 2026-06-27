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
	rootCmd.AddCommand(vmwareCmd)
}

var vmwareCmd = &cobra.Command{
	Use:   "vmware",
	Short: "VMware guest health — guest tools, paravirtual NICs, SCSI timeouts, EnableUUID, host limits/ballooning",
	Long: "Guest-side health for a Linux VM running under VMware (vSphere / VMware Cloud / VCD).\n\n" +
		"Splits findings into what YOU can fix from inside the guest (NIC type, SCSI\n" +
		"timeout, disk.EnableUUID, guest tools) and host-side pressure that is evidence\n" +
		"to take to your cloud provider (ballooning, host-swap, a binding CPU/memory cap).",
	RunE: runVMware,
}

func runVMware(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	// Gate on the same DMI signature health uses — silent/honest on non-VMware hosts.
	if !collectors.VMwareGuestAvailable() {
		if mode == output.ModeJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(&models.VMwareInfo{})
		}
		fmt.Println()
		fmt.Println(render.StyleInfo.Render(asciiOr("info", "ℹ️  ", mode) +
			"not running under VMware — this host's DMI does not match a VMware guest"))
		fmt.Println("   (dsd vmware is for Linux VMs on vSphere / VMware Cloud / VCD)")
		return nil
	}

	col := collectors.NewVMwareCollector()
	p := output.NewCommandProgress("VMware guest health", 10*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{col}) {
		p.Step(r.Name)
		result = r
	}
	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.VMwareInfo)
	if !ok || info == nil {
		return result.Err
	}

	if mode == output.ModeJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	printVMwareReport(os.Stdout, info, elapsed, mode)
	return nil
}

// vmwareConcerns counts the actionable VMware issues for the standalone verdict.
// It counts WARN/CRIT from the SAME heuristic `dsd health` runs (checkVMware via
// analysis.VMwareInsights), so the two can't drift — the cmd↔health consistency
// invariant (cmd_health_consistency_test.go), here satisfied by construction
// rather than by a re-derived field tally.
func vmwareConcerns(info *models.VMwareInfo) int {
	n := 0
	for _, in := range analysis.VMwareInsights(*info) {
		if in.Level == "WARN" || in.Level == "CRIT" {
			n++
		}
	}
	return n
}

// vmwareInsightHostSide reports whether a VMware finding is host-imposed pressure
// (ballooning, host-swap, a configured CPU/memory limit, or "couldn't verify those"),
// as opposed to a guest-side config the operator can fix themselves. Drives the
// two-block split that is the point of this command: self-serve fixes vs. evidence
// to hand the cloud provider. Keyed on stable tokens in the message (we own the
// strings); anything unmatched falls into the guest block, so nothing is dropped.
func vmwareInsightHostSide(msg string) bool {
	for _, tok := range []string{"balloon", "swapped", "memory limit", "CPU limit", "resource-pressure stats"} {
		if strings.Contains(msg, tok) {
			return true
		}
	}
	return false
}

// isVMwareRecognitionLine matches the all-clean "VMware guest (...) — open-vm-tools
// running; NICs: ..." INFO that checkVMware emits only when everything is in order.
// The command shows its own identity header + clean summary, so this line is folded
// away rather than printed as a finding.
func isVMwareRecognitionLine(msg string) bool {
	return strings.Contains(msg, "open-vm-tools running; NICs")
}

func printVMwareReport(w io.Writer, info *models.VMwareInfo, elapsed time.Duration, mode output.OutputMode) {
	sep := strings.Repeat("─", 60)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	name := info.ProductName
	if name == "" {
		name = "VMware"
	}
	tools := "NOT installed"
	switch {
	case info.ToolsRunning:
		tools = "running"
	case info.ToolsInstalled:
		tools = "installed but stopped"
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%sVMware guest — %s   (open-vm-tools: %s)\n",
		asciiOr("info", "🟦 ", mode), name, tools)

	var guest, host []models.Insight
	for _, in := range analysis.VMwareInsights(*info) {
		if isVMwareRecognitionLine(in.Message) {
			continue
		}
		if vmwareInsightHostSide(in.Message) {
			host = append(host, in)
		} else {
			guest = append(guest, in)
		}
	}

	printGuestBlock(w, "Your VM — you can fix these", guest, mode)
	printGuestBlock(w, "Host-side — evidence to share with your cloud provider", host, mode)

	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
	if vmwareConcerns(info) == 0 {
		fmt.Fprintln(w, render.StyleOK.Render(fmt.Sprintf(
			"%sVMware guest healthy — guest tools running, paravirtual drivers in use, no host pressure%s",
			asciiOr("ok", "✅ ", mode), timing)))
	} else {
		fmt.Fprintln(w, render.StyleWarn.Render(fmt.Sprintf(
			"%s%d VMware config issue(s) found%s", asciiOr("warn", "⚠️  ", mode), vmwareConcerns(info), timing)))
	}
}

// printGuestBlock prints one titled group of findings (with their fix hints),
// or a short "all clear" line when the group is empty so the operator sees that
// dsd actually checked that side rather than silently omitting it.
func printGuestBlock(w io.Writer, title string, ins []models.Insight, mode output.OutputMode) {
	arrow := "→"
	if mode == output.ModePlain {
		arrow = "->"
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, render.StyleDim.Render("── "+title+" "+strings.Repeat("─", max(0, 56-len([]rune(title))))))
	if len(ins) == 0 {
		fmt.Fprintf(w, "  %s nothing flagged\n", asciiOr("ok", "✅", mode))
		return
	}
	for _, in := range ins {
		icon := asciiOr("info", "ℹ️ ", mode)
		switch in.Level {
		case "CRIT":
			icon = asciiOr("fail", "❌", mode)
		case "WARN":
			icon = asciiOr("warn", "⚠️ ", mode)
		}
		fmt.Fprintf(w, "  %s %s\n", icon, in.Message)
		for _, h := range in.Hints {
			fmt.Fprintf(w, "       %s %s\n", arrow, h)
		}
	}
}
