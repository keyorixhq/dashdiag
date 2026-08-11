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
	rootCmd.AddCommand(kvmGuestCmd)
}

var kvmGuestCmd = &cobra.Command{
	Use:    "kvm-guest",
	Hidden: true, // superseded by `dsd guest` (auto-detects); kept working, out of help
	Short:  "KVM/Proxmox guest health — guest agent, paravirtual NIC/disk, CPU steal (the tenant view)",
	Long: "Guest-side health for a Linux VM running under QEMU/KVM (Proxmox VE, oVirt, libvirt).\n\n" +
		"This is the tenant view — for someone handed a VM with no hypervisor console.\n" +
		"(The node operator's view is `dsd kvm`.) Findings split into what YOU can fix\n" +
		"inside the guest (qemu-guest-agent, VirtIO NIC/disk drivers) and host-side\n" +
		"pressure that is evidence for whoever runs the hypervisor (CPU steal).",
	RunE: runKVMGuest,
}

func runKVMGuest(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	if !collectors.KVMGuestAvailable() {
		if mode == output.ModeJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(&models.KVMGuestInfo{})
		}
		fmt.Println()
		fmt.Println(render.StyleInfo.Render(asciiOr("info", "ℹ️  ", mode) +
			"not running under QEMU/KVM — this host's DMI vendor is not QEMU"))
		fmt.Println("   (dsd kvm-guest is for Linux VMs on Proxmox / oVirt / libvirt)")
		return nil
	}

	col := collectors.NewKVMGuestCollector()
	p := output.NewCommandProgress("KVM/Proxmox guest health", 8*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{col}) {
		p.Step(r.Name)
		result = r
	}
	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.KVMGuestInfo)
	if !ok || info == nil {
		return result.Err
	}

	// BUG-022 class: honour the 0/1/2 exit contract. Uses the SAME insight
	// source (analysis.KVMGuestInsights) kvmGuestConcerns already scores the
	// printed verdict from — not recordResultSeverity's generic ApplyThresholds
	// path, which doesn't know about KVMGuestInfo.
	recordWorstInsight(analysis.KVMGuestInsights(*info))

	if mode == output.ModeJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	printKVMGuestReport(os.Stdout, info, elapsed, mode)
	return nil
}

// kvmGuestConcerns counts WARN/CRIT from the SAME heuristic `dsd health` runs
// (checkKVMGuest via analysis.KVMGuestInsights), so the standalone verdict can't
// drift from health — cmd↔health consistency by construction.
func kvmGuestConcerns(info *models.KVMGuestInfo) int {
	n := 0
	for _, in := range analysis.KVMGuestInsights(*info) {
		if in.Level == "WARN" || in.Level == "CRIT" {
			n++
		}
	}
	return n
}

// kvmGuestInsightHostSide reports whether a finding is host-imposed (CPU steal, or
// the host not having enabled the guest-agent channel) vs a guest-side config the
// tenant can fix. Keyed on stable tokens we own; anything else falls into the guest
// block, so nothing is dropped.
func kvmGuestInsightHostSide(msg string) bool {
	return strings.Contains(msg, "CPU steal") || strings.Contains(msg, "has not enabled")
}

// isKVMGuestRecognitionLine matches the all-clean recognition INFO, folded away in
// favour of the command's own identity header + clean summary.
func isKVMGuestRecognitionLine(msg string) bool {
	return strings.Contains(msg, "paravirtual NIC+disk in use")
}

func printKVMGuestReport(w io.Writer, info *models.KVMGuestInfo, elapsed time.Duration, mode output.OutputMode) {
	sep := strings.Repeat("─", 60)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	name := info.ProductName
	if name == "" {
		name = "QEMU/KVM"
	}
	qga := "no agent channel"
	switch {
	case info.QGAChannelPresent && info.QGAInstalled && info.QGARunning:
		qga = "running"
	case info.QGAChannelPresent:
		qga = "channel present, agent NOT running"
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%sQEMU/KVM guest — %s   (qemu-guest-agent: %s)\n",
		asciiOr("info", "🟦 ", mode), name, qga)

	var guest, host []models.Insight
	for _, in := range analysis.KVMGuestInsights(*info) {
		if isKVMGuestRecognitionLine(in.Message) {
			continue
		}
		if kvmGuestInsightHostSide(in.Message) {
			host = append(host, in)
		} else {
			guest = append(guest, in)
		}
	}

	printGuestBlock(w, "Your VM — you can fix these", guest, mode)
	printGuestBlock(w, "Host-side — evidence for whoever runs your hypervisor", host, mode)

	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
	if kvmGuestConcerns(info) == 0 {
		fmt.Fprintln(w, render.StyleOK.Render(fmt.Sprintf(
			"%sKVM guest healthy — VirtIO NIC+disk, qemu-guest-agent running, no host pressure%s",
			asciiOr("ok", "✅ ", mode), timing)))
	} else {
		fmt.Fprintln(w, render.StyleWarn.Render(fmt.Sprintf(
			"%s%d KVM guest issue(s) found%s", asciiOr("warn", "⚠️  ", mode), kvmGuestConcerns(info), timing)))
	}
}
