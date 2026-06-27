package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(guestCmd)
}

var guestCmd = &cobra.Command{
	Use:   "guest",
	Short: "Tenant health — auto-detects whether you're in a container, a VM, or on bare metal",
	Long: "One command for \"am I a healthy tenant, and what's the host's fault?\" — whether you're\n" +
		"inside a container (Docker/Podman/LXC/Kubernetes) or a VM (VMware/KVM/Proxmox).\n" +
		"You don't need to know which: dsd detects it and adapts. Findings split into what\n" +
		"YOU can fix vs. host-imposed pressure that's evidence for whoever runs your platform.\n\n" +
		"(Pair: `dsd kvm` = you run the hypervisor; `dsd guest` = you're inside one.)",
	RunE: runGuest,
}

// guestView is the platform-agnostic shape `dsd guest` renders: an identity line,
// the insights, and the per-platform classifiers that sort them into the two blocks.
type guestView struct {
	identity   string
	jsonData   interface{}
	insights   []models.Insight
	hostSide   func(string) bool
	recognized func(string) bool
	guestTitle string
	hostTitle  string
	healthyMsg string
}

func runGuest(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	mode := output.DetectMode(plain, false, map[bool]string{true: "json"}[jsonOut])

	view, found := detectGuestView(ctx)
	if !found {
		if mode == output.ModeJSON {
			return json.NewEncoder(os.Stdout).Encode(map[string]bool{"in_guest": false})
		}
		fmt.Println()
		fmt.Println(render.StyleInfo.Render(asciiOr("info", "ℹ️  ", mode) +
			"bare metal — not inside a container or VM, so there's no host above you"))
		fmt.Println("   run `dsd health` for full system health")
		return nil
	}

	if mode == output.ModeJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(view.jsonData)
	}
	printGuestView(os.Stdout, view, mode)
	return nil
}

// detectGuestView resolves the INNERMOST isolation layer first — a container on a
// VM reports as the container (its limits bite first), with the VM noted as a
// breadcrumb. Then VM, then bare metal.
func detectGuestView(ctx context.Context) (guestView, bool) {
	switch {
	case collectors.ContainerGuestAvailable():
		return containerGuestView(ctx), true
	case collectors.VMwareGuestAvailable():
		return vmwareGuestView(ctx), true
	case collectors.KVMGuestAvailable():
		return kvmGuestView(ctx), true
	default:
		return guestView{}, false
	}
}

func vmwareGuestView(ctx context.Context) guestView {
	info := runGuestCollector(ctx, collectors.NewVMwareCollector()).(*models.VMwareInfo)
	name := info.ProductName
	if name == "" {
		name = "VMware"
	}
	return guestView{
		identity:   "🟦 VMware guest — " + name,
		jsonData:   info,
		insights:   analysis.VMwareInsights(*info),
		hostSide:   vmwareInsightHostSide,
		recognized: isVMwareRecognitionLine,
		guestTitle: "Your VM — you can fix these",
		hostTitle:  "Host-side — evidence to share with your cloud provider",
		healthyMsg: "VMware guest healthy — guest tools running, paravirtual drivers in use, no host pressure",
	}
}

func kvmGuestView(ctx context.Context) guestView {
	info := runGuestCollector(ctx, collectors.NewKVMGuestCollector()).(*models.KVMGuestInfo)
	name := info.ProductName
	if name == "" {
		name = "QEMU/KVM"
	}
	return guestView{
		identity:   "🟦 QEMU/KVM (Proxmox/libvirt) guest — " + name,
		jsonData:   info,
		insights:   analysis.KVMGuestInsights(*info),
		hostSide:   kvmGuestInsightHostSide,
		recognized: isKVMGuestRecognitionLine,
		guestTitle: "Your VM — you can fix these",
		hostTitle:  "Host-side — evidence for whoever runs your hypervisor",
		healthyMsg: "KVM guest healthy — VirtIO NIC+disk, qemu-guest-agent running, no host pressure",
	}
}

func containerGuestView(ctx context.Context) guestView {
	info := runGuestCollector(ctx, collectors.NewContainerGuestCollector()).(*models.ContainerGuestInfo)
	rt := info.Runtime
	if rt == "" {
		rt = "container"
	}
	id := "📦 Container (" + rt + ")"
	if info.UnderlyingVM != "" {
		id += "  →  on a " + info.UnderlyingVM + " VM"
	}
	return guestView{
		identity:   id,
		jsonData:   info,
		insights:   analysis.ContainerGuestInsights(*info),
		hostSide:   containerInsightHostSide,
		recognized: isContainerRecognitionLine,
		guestTitle: "Your container — you can fix these",
		hostTitle:  "Resource limits — enforced against you",
		healthyMsg: "container healthy — limits set, non-root, no throttling or OOM-kills",
	}
}

// containerInsightHostSide: throttling, OOM-kills, and memory-near-limit are the
// limits being enforced against the workload; everything else is spec the deployer
// owns.
func containerInsightHostSide(msg string) bool {
	return strings.Contains(msg, "throttled") || strings.Contains(msg, "OOM-kill") || strings.Contains(msg, "memory at")
}

func isContainerRecognitionLine(msg string) bool {
	return strings.Contains(msg, "limits set, non-root")
}

func runGuestCollector(ctx context.Context, col runner.Collector) interface{} {
	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{col}) {
		result = r
	}
	return result.Data
}

func guestConcerns(view guestView) int {
	n := 0
	for _, in := range view.insights {
		if in.Level == "WARN" || in.Level == "CRIT" {
			n++
		}
	}
	return n
}

func printGuestView(w io.Writer, view guestView, mode output.OutputMode) {
	sep := strings.Repeat("─", 60)
	fmt.Fprintln(w)
	fmt.Fprintln(w, view.identity)

	var guest, host []models.Insight
	for _, in := range view.insights {
		if view.recognized(in.Message) {
			continue
		}
		if view.hostSide(in.Message) {
			host = append(host, in)
		} else {
			guest = append(guest, in)
		}
	}

	printGuestBlock(w, view.guestTitle, guest, mode)
	printGuestBlock(w, view.hostTitle, host, mode)

	fmt.Fprintln(w)
	fmt.Fprintln(w, sep)
	if guestConcerns(view) == 0 {
		fmt.Fprintln(w, render.StyleOK.Render(asciiOr("ok", "✅ ", mode)+view.healthyMsg))
	} else {
		fmt.Fprintln(w, render.StyleWarn.Render(fmt.Sprintf("%s%d issue(s) found",
			asciiOr("warn", "⚠️  ", mode), guestConcerns(view))))
	}
}
