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
	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

const guestSectionVM = "Your VM — you can fix these"

func init() {
	rootCmd.AddCommand(guestCmd)
	guestCmd.Flags().Bool("report-html", false,
		"write a self-contained two-block HTML report (co-brandable leave-behind, printable to PDF)")
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
	jsonData   any
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

	if reportHTML, _ := cmd.Flags().GetBool("report-html"); reportHTML {
		path, err := writeGuestReportHTML(view)
		if err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "📄 HTML report saved: %s\n", path)
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

// splitGuestInsights sorts a view's insights into the self-serve and host/provider
// blocks (recognition lines folded away), the shared split behind both the terminal
// render and the HTML report.
func splitGuestInsights(view guestView) (guest, host []models.Insight) {
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
	return guest, host
}

// writeGuestReportHTML renders the two-block view to a self-contained HTML file in
// the working dir and returns its path — the co-brandable leave-behind.
func writeGuestReportHTML(view guestView) (string, error) {
	guest, host := splitGuestInsights(view)
	level, text := "ok", healthySummary(view.healthyMsg, view.insights)
	if c := guestConcerns(view); c > 0 {
		level, text = "warn", fmt.Sprintf("%d issue(s) found", c)
		for _, in := range view.insights {
			if in.Level == "CRIT" {
				level = "crit"
				break
			}
		}
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "guest"
	}
	now := time.Now()
	htmlStr := render.GuestReportHTML(view.identity, hostname, now.Format("2006-01-02 15:04 MST"),
		[]render.GuestReportBlock{
			{Title: view.guestTitle, Issues: guest},
			{Title: view.hostTitle, Issues: host},
		}, level, text)
	filename := guestReportFilename(hostname, now)
	if err := writeFileNoFollow(filename, []byte(htmlStr), 0o644); err != nil {
		return "", err
	}
	return filename, nil
}

// guestReportFilename builds writeGuestReportHTML's output filename.
// hostname can come from an untrusted source (a rogue DHCP option 12, a
// VM/container image's hostname metadata, cloud-init user-data supplied by a
// hosting provider) — sanitize before it reaches a filename, same as
// baseline.SafeHostname's own doc comment names this threat. Split out of
// writeGuestReportHTML (which also calls os.Hostname() directly) so this
// path-safety property is unit-testable without depending on the real
// kernel hostname.
func guestReportFilename(hostname string, now time.Time) string {
	return fmt.Sprintf("dsd-guest-report-%s-%s.html", baseline.SafeHostname(hostname), now.Format("20060102-150405"))
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
	case collectors.OCIGuestAvailable():
		return ociGuestView(ctx), true
	case collectors.VMwareGuestAvailable():
		return vmwareGuestView(ctx), true
	case collectors.KVMGuestAvailable():
		return kvmGuestView(ctx), true
	default:
		return guestView{}, false
	}
}

// awsInstanceTypeLabel returns the EC2 instance type, or a generic fallback
// when the collector couldn't read it (metadata service unreachable/non-AWS).
// info.InstanceType comes from IMDS — untrusted per this review's threat
// model (cmd-01-02) — sanitize before it reaches the identity header.
func awsInstanceTypeLabel(info *models.AWSInfo) string {
	if info.InstanceType == "" {
		return "instance"
	}
	return output.SanitizeControl(info.InstanceType)
}

func awsGuestView(ctx context.Context) guestView {
	info := runGuestCollector(ctx, collectors.NewAWSCollector()).(*models.AWSInfo)
	itype := awsInstanceTypeLabel(info)
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

// azureAcceleratedNetworkingLabel describes the state of Azure Accelerated
// Networking from the guest side: a real SR-IOV VF, a synthetic NIC fallback
// (AN enabled but the VF didn't attach), or unknown (no NIC info at all).
func azureAcceleratedNetworkingLabel(info *models.AzureInfo) string {
	switch {
	case info.HasVF:
		return "active"
	case len(info.SyntheticNICs) > 0:
		return "synthetic path (no VF)"
	default:
		return "unknown"
	}
}

func azureGuestView(ctx context.Context) guestView {
	info := runGuestCollector(ctx, collectors.NewAzureCollector()).(*models.AzureInfo)
	an := azureAcceleratedNetworkingLabel(info)
	return guestView{
		identity:   "🔷 Azure VM   (Accelerated Networking: " + an + ")",
		jsonData:   info,
		insights:   analysis.AzureInsights(*info),
		hostSide:   azureInsightProviderSide,
		recognized: isAzureRecognitionLine,
		guestTitle: guestSectionVM,
		hostTitle:  "Accelerated networking — evidence to share with Azure support",
		healthyMsg: "Azure VM healthy — no guest-side config or datapath issues found",
	}
}

// gcpNetworkingLabel names the GCE guest's NIC driver: gVNIC when active, the
// detected driver name otherwise, or "synthetic" when neither was read.
func gcpNetworkingLabel(info *models.GCPInfo) string {
	switch {
	case info.UsesGVNIC:
		return "gVNIC"
	case info.NICDriver != "":
		// NICDriver is a /sys/class/net/*/device/driver symlink basename —
		// untrusted per this review's threat model (cmd-01-02) — sanitize
		// before it reaches the identity header.
		return output.SanitizeControl(info.NICDriver)
	default:
		return "synthetic"
	}
}

func gcpGuestView(ctx context.Context) guestView {
	info := runGuestCollector(ctx, collectors.NewGCPCollector()).(*models.GCPInfo)
	net := gcpNetworkingLabel(info)
	return guestView{
		identity:   "🟥 GCE VM   (networking: " + net + ")",
		jsonData:   info,
		insights:   analysis.GCPInsights(*info),
		hostSide:   gcpInsightProviderSide,
		recognized: isGCPRecognitionLine,
		guestTitle: guestSectionVM,
		hostTitle:  "Host-side — Google Cloud activity to correlate",
		healthyMsg: "GCE guest healthy — no guest-side config or host-maintenance issues found",
	}
}

// ociShapeLabel returns the reported OCI shape, or a generic fallback when
// IMDS couldn't be read. info.Shape is IMDS-reported — untrusted per this
// review's threat model (cmd-01-02) — sanitize before it reaches the
// identity header.
func ociShapeLabel(info *models.OCIInfo) string {
	if info.Shape == "" {
		return "instance"
	}
	return output.SanitizeControl(info.Shape)
}

// ociInsightProviderSide always returns false: unlike AWS/Azure/GCP, this
// collector currently has no OCI-imposed-limit signal (no throttle counters) —
// every OCI insight (IMDS posture, agent health, time sync, VNIC ring drops)
// is guest-fixable. Kept as a real function (not a nil hostSide) so the shared
// two-block guestView shape stays uniform and this can grow a provider-side
// signal later without a shape change.
func ociInsightProviderSide(string) bool { return false }

func ociGuestView(ctx context.Context) guestView {
	info := runGuestCollector(ctx, collectors.NewOCICollector()).(*models.OCIInfo)
	shape := ociShapeLabel(info)
	return guestView{
		identity:   "🔴 OCI instance — " + shape,
		jsonData:   info,
		insights:   analysis.OCIInsights(*info),
		hostSide:   ociInsightProviderSide,
		recognized: isOCIRecognitionLine,
		guestTitle: "Your instance — you can fix these",
		hostTitle:  "Provider-imposed — evidence to share with Oracle support",
		healthyMsg: "OCI instance healthy — no guest-side posture issues found",
	}
}

// isOCIRecognitionLine matches the all-clean "OCI <shape> — …" INFO that
// checkOCI emits only when everything it could verify is clean.
func isOCIRecognitionLine(msg string) bool {
	return strings.HasPrefix(msg, "OCI ")
}

// vmwareProductLabel returns the reported VMware product name, or a generic
// fallback when DMI didn't expose one. info.ProductName is DMI/firmware-
// reported — untrusted per this review's threat model (cmd-01-02) —
// sanitize before it reaches the identity header.
func vmwareProductLabel(info *models.VMwareInfo) string {
	if info.ProductName == "" {
		return "VMware"
	}
	return output.SanitizeControl(info.ProductName)
}

func vmwareGuestView(ctx context.Context) guestView {
	info := runGuestCollector(ctx, collectors.NewVMwareCollector()).(*models.VMwareInfo)
	name := vmwareProductLabel(info)
	return guestView{
		identity:   "🟦 VMware guest — " + name,
		jsonData:   info,
		insights:   analysis.VMwareInsights(*info),
		hostSide:   vmwareInsightHostSide,
		recognized: isVMwareRecognitionLine,
		guestTitle: guestSectionVM,
		hostTitle:  "Host-side — evidence to share with your cloud provider",
		healthyMsg: "VMware guest healthy — guest tools running, paravirtual drivers in use, no host pressure",
	}
}

// kvmGuestProductLabel returns the reported KVM/QEMU product name, or a
// generic fallback when DMI didn't expose one. info.ProductName is
// DMI/firmware-reported — untrusted per this review's threat model
// (cmd-01-02) — sanitize before it reaches the identity header.
func kvmGuestProductLabel(info *models.KVMGuestInfo) string {
	if info.ProductName == "" {
		return "QEMU/KVM"
	}
	return output.SanitizeControl(info.ProductName)
}

func kvmGuestView(ctx context.Context) guestView {
	info := runGuestCollector(ctx, collectors.NewKVMGuestCollector()).(*models.KVMGuestInfo)
	name := kvmGuestProductLabel(info)
	return guestView{
		identity:   "🟦 QEMU/KVM (Proxmox/libvirt) guest — " + name,
		jsonData:   info,
		insights:   analysis.KVMGuestInsights(*info),
		hostSide:   kvmGuestInsightHostSide,
		recognized: isKVMGuestRecognitionLine,
		guestTitle: guestSectionVM,
		hostTitle:  "Host-side — evidence for whoever runs your hypervisor",
		healthyMsg: "KVM guest healthy — VirtIO NIC+disk, qemu-guest-agent running, no host pressure",
	}
}

// containerGuestIdentity names the container runtime and, when the container
// is itself running inside a VM, the enclosing VM type. Runtime and
// UnderlyingVM are detected from the local environment (cgroup/mount
// heuristics) — untrusted per this review's threat model (cmd-01-02) —
// sanitize before they reach the identity header.
func containerGuestIdentity(info *models.ContainerGuestInfo) string {
	rt := output.SanitizeControl(info.Runtime)
	if rt == "" {
		rt = "container"
	}
	id := "📦 Container (" + rt + ")"
	if info.UnderlyingVM != "" {
		id += "  →  on a " + output.SanitizeControl(info.UnderlyingVM) + " VM"
	}
	return id
}

// containerHealthyMsg claims "no throttling or OOM-kills" only when those
// signals were actually read — cgroup v2 (read inline) or cgroup v1 with
// readable counters. On a v1 host where the counters couldn't be read, the
// claim is dropped (the unverified-negative false-OK; cf. #589).
func containerHealthyMsg(info *models.ContainerGuestInfo) string {
	if !info.CgroupV2 && !info.CgroupV1Measured {
		return "container healthy — limits set, non-root (throttle/OOM not readable on this cgroup v1 host)"
	}
	return "container healthy — limits set, non-root, no throttling or OOM-kills"
}

func containerGuestView(ctx context.Context) guestView {
	info := runGuestCollector(ctx, collectors.NewContainerGuestCollector()).(*models.ContainerGuestInfo)
	return guestView{
		identity:   containerGuestIdentity(info),
		jsonData:   info,
		insights:   analysis.ContainerGuestInsights(*info),
		hostSide:   containerInsightHostSide,
		recognized: isContainerRecognitionLine,
		guestTitle: "Your container — you can fix these",
		hostTitle:  "Resource limits — enforced against you",
		healthyMsg: containerHealthyMsg(info),
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

func runGuestCollector(ctx context.Context, col runner.Collector) any {
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

// someCheckUnverified reports whether a finding says a check could NOT be measured
// (the VMware stat interface unavailable, AWS EBS performance stats needing root or
// failing to read, etc.). Those are INFO (no concern), so the verdict stays
// "healthy" — but a clean all-clear line would over-state an unverified negative,
// the false-OK class these commands exist to avoid. Keyed on the honest
// couldn't-measure phrasings the heuristics emit (we own the strings).
func someCheckUnverified(insights []models.Insight) bool {
	for _, in := range insights {
		m := in.Message
		if strings.Contains(m, "NOT verified") || strings.Contains(m, "need root") ||
			strings.Contains(m, "could not read") || strings.Contains(m, "could not verify") {
			return true
		}
	}
	return false
}

// healthySummary returns the all-clear line, but never lets it imply an unverified
// check came back clean. VMware keeps its specific "host pressure not verified"
// phrasing; every other platform (AWS/Azure/GCP) gets a generic caveat so e.g.
// "EC2 guest healthy — no guest-side throttling" doesn't claim no throttling when
// the EBS throttle check needed root and never ran.
func healthySummary(base string, insights []models.Insight) string {
	if !someCheckUnverified(insights) {
		return base
	}
	if strings.Contains(base, "no host pressure") {
		return strings.Replace(base, "no host pressure", "host pressure not verified (stats unavailable — see above)", 1)
	}
	return base + " — but some checks could not be verified (see above)"
}

func printGuestView(w io.Writer, view guestView, mode output.OutputMode) {
	sep := strings.Repeat("─", 60)
	fmt.Fprintln(w)
	fmt.Fprintln(w, view.identity)

	guest, host := splitGuestInsights(view)
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
