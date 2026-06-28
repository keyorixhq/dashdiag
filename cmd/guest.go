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
// breadcrumb. Then cloud (the most specific VM view — AWS/Azure/GCP, each gated on
// its own DMI so they don't overlap and KVM-guest already excludes the clouds), then
// a generic VMware/KVM VM, then bare metal.
func detectGuestView(ctx context.Context) (guestView, bool) {
	switch {
	case collectors.ContainerGuestAvailable():
		return containerGuestView(ctx), true
	case collectors.AWSGuestAvailable():
		return awsGuestView(ctx), true
	case collectors.AzureGuestAvailable():
		return azureGuestView(ctx), true
	case collectors.GCPGuestAvailable():
		return gcpGuestView(ctx), true
	case collectors.VMwareGuestAvailable():
		return vmwareGuestView(ctx), true
	case collectors.KVMGuestAvailable():
		return kvmGuestView(ctx), true
	default:
		return guestView{}, false
	}
}

func awsGuestView(ctx context.Context) guestView {
	info := runGuestCollector(ctx, collectors.NewAWSCollector()).(*models.AWSInfo)
	itype := info.InstanceType
	if itype == "" {
		itype = "instance"
	}
	return guestView{
		identity:   "🟧 EC2 guest — " + itype,
		jsonData:   info,
		insights:   analysis.AWSInsights(*info),
		hostSide:   awsInsightProviderSide,
		recognized: isAWSRecognitionLine,
		guestTitle: "Your instance — you can fix these",
		hostTitle:  "AWS-imposed limits — evidence to share with AWS support",
		healthyMsg: "EC2 guest healthy — no guest-side throttling or posture issues found",
	}
}

func azureGuestView(ctx context.Context) guestView {
	info := runGuestCollector(ctx, collectors.NewAzureCollector()).(*models.AzureInfo)
	an := "unknown"
	switch {
	case info.HasVF:
		an = "active"
	case len(info.SyntheticNICs) > 0:
		an = "synthetic path (no VF)"
	}
	return guestView{
		identity:   "🔷 Azure VM   (Accelerated Networking: " + an + ")",
		jsonData:   info,
		insights:   analysis.AzureInsights(*info),
		hostSide:   azureInsightProviderSide,
		recognized: isAzureRecognitionLine,
		guestTitle: "Your VM — you can fix these",
		hostTitle:  "Accelerated networking — evidence to share with Azure support",
		healthyMsg: "Azure VM healthy — no guest-side config or datapath issues found",
	}
}

func gcpGuestView(ctx context.Context) guestView {
	info := runGuestCollector(ctx, collectors.NewGCPCollector()).(*models.GCPInfo)
	net := "synthetic"
	if info.UsesGVNIC {
		net = "gVNIC"
	} else if info.NICDriver != "" {
		net = info.NICDriver
	}
	return guestView{
		identity:   "🟥 GCE VM   (networking: " + net + ")",
		jsonData:   info,
		insights:   analysis.GCPInsights(*info),
		hostSide:   gcpInsightProviderSide,
		recognized: isGCPRecognitionLine,
		guestTitle: "Your VM — you can fix these",
		hostTitle:  "Host-side — Google Cloud activity to correlate",
		healthyMsg: "GCE guest healthy — no guest-side config or host-maintenance issues found",
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
	// Claim "no throttling or OOM-kills" only when those signals were actually read —
	// v2 (read inline) or v1 with readable counters. On a v1 host where the counters
	// couldn't be read, drop the claim (the unverified-negative false-OK; cf. #589).
	healthyMsg := "container healthy — limits set, non-root, no throttling or OOM-kills"
	if !info.CgroupV2 && !info.CgroupV1Measured {
		healthyMsg = "container healthy — limits set, non-root (throttle/OOM not readable on this cgroup v1 host)"
	}
	return guestView{
		identity:   id,
		jsonData:   info,
		insights:   analysis.ContainerGuestInsights(*info),
		hostSide:   containerInsightHostSide,
		recognized: isContainerRecognitionLine,
		guestTitle: "Your container — you can fix these",
		hostTitle:  "Resource limits — enforced against you",
		healthyMsg: healthyMsg,
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

// hostPressureUnverified reports whether a finding says host pressure couldn't be
// measured (e.g. the VMware stat interface was unavailable — old tools / no perms).
// That case is an INFO (no concern), so the verdict is still "healthy" — but a
// "no host pressure" claim in the all-clear line would over-state an unverified
// negative, the same false-OK class this command exists to avoid.
func hostPressureUnverified(insights []models.Insight) bool {
	for _, in := range insights {
		if strings.Contains(in.Message, "NOT verified") {
			return true
		}
	}
	return false
}

// healthySummary returns the all-clear line, but demotes a "no host pressure" claim
// to an honest "host pressure not verified" when the stats were unavailable.
func healthySummary(base string, insights []models.Insight) string {
	if hostPressureUnverified(insights) && strings.Contains(base, "no host pressure") {
		return strings.Replace(base, "no host pressure", "host pressure not verified (stats unavailable — see above)", 1)
	}
	return base
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
		fmt.Fprintln(w, render.StyleOK.Render(asciiOr("ok", "✅ ", mode)+healthySummary(view.healthyMsg, view.insights)))
	} else {
		fmt.Fprintln(w, render.StyleWarn.Render(fmt.Sprintf("%s%d issue(s) found",
			asciiOr("warn", "⚠️  ", mode), guestConcerns(view))))
	}
}
