package render

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// TestPrintAllLayered_Grouping verifies the three-layer grouping: a hardware
// collector, a platform collector (VMware), and an OS collector each land under
// the right header, in stack order (hardware → platform → OS), with the verdict
// tally on top and the VMware zoom-in hint present.
func TestPrintAllLayered_Grouping(t *testing.T) {
	r := NewRenderer(output.ModePlain)
	results := []runner.Result{
		{Name: "Systemd"}, // OS — deliberately first to prove regrouping, not input order
		{Name: "Memory"},  // hardware
		{Name: "VMware"},  // platform
	}
	insights := []models.Insight{
		{Level: "OK", Check: "Systemd"},
		{Level: "OK", Check: "Memory"},
		{Level: "WARN", Check: "VMware", Message: "emulated NIC"},
	}

	out := captureStdout(t, func() { r.PrintAllLayered(results, insights) })

	hw := strings.Index(out, "Hardware & storage")
	plat := strings.Index(out, "Platform")
	os := strings.Index(out, "OS & services")
	if hw < 0 || plat < 0 || os < 0 {
		t.Fatalf("all three layer headers must be present:\n%s", out)
	}
	if hw >= plat || plat >= os {
		t.Errorf("layers out of stack order: hw=%d platform=%d os=%d", hw, plat, os)
	}

	// Each collector must sit under its own layer's header.
	mem := strings.Index(out, "Memory")
	vmw := strings.Index(out, "VMware")
	sysd := strings.Index(out, "Systemd")
	if hw >= mem || mem >= plat {
		t.Errorf("Memory must render under Hardware (hw=%d mem=%d platform=%d)", hw, mem, plat)
	}
	if plat >= vmw || vmw >= os {
		t.Errorf("VMware must render under Platform (platform=%d vmw=%d os=%d)", plat, vmw, os)
	}
	if sysd < os {
		t.Errorf("Systemd must render under OS & services (os=%d sysd=%d)", os, sysd)
	}

	if !strings.Contains(out, "0 critical · 1 warnings · 0 info") {
		t.Errorf("verdict tally missing/incorrect:\n%s", out)
	}
	if !strings.Contains(out, "full detail: dsd vmware") {
		t.Errorf("VMware zoom-in hint missing:\n%s", out)
	}
	if strings.Contains(out, "Other") {
		t.Errorf("no collector should fall into Other here:\n%s", out)
	}
}

// TestPrintAllLayered_BareMetal: with no platform collector, the Platform layer
// shows the explicit bare-metal note rather than silently vanishing.
func TestPrintAllLayered_BareMetal(t *testing.T) {
	r := NewRenderer(output.ModePlain)
	results := []runner.Result{{Name: "Memory"}, {Name: "Systemd"}}
	insights := []models.Insight{{Level: "OK", Check: "Memory"}, {Level: "OK", Check: "Systemd"}}

	out := captureStdout(t, func() { r.PrintAllLayered(results, insights) })

	if !strings.Contains(out, "bare metal — no hypervisor/cloud layer") {
		t.Errorf("bare-metal Platform note missing:\n%s", out)
	}
	if strings.Contains(out, "full detail: dsd vmware") {
		t.Errorf("must not show the VMware hint with no VMware collector present")
	}
}

// TestHealthLayers_NoOverlap: no collector may be listed in more than one layer.
// An overlap is a latent bug — the row would render under whichever layer the
// scan reaches first, masking the duplicate listing.
func TestHealthLayers_NoOverlap(t *testing.T) {
	seen := map[string]string{}
	for _, layer := range healthLayers {
		for _, m := range layer.members {
			if prev, dup := seen[m]; dup {
				t.Errorf("collector %q listed in both %q and %q", m, prev, layer.title)
			}
			seen[m] = layer.title
		}
	}
}

// TestHealthLayers_CoverRegisteredCollectors guards against the "Other" dumping
// ground silently growing: every collector that `dsd health` can register must be
// mapped to a layer. The canonical names below mirror the Name() of each collector
// in cmd.buildHealthCollectors (kept here, not imported, to avoid a render→cmd
// dependency). DBus is the canary — it is registered unconditionally, so a gap here
// puts it in "Other" on every Linux host. When you add a health collector, add its
// Name() to a layer and to this list.
func TestHealthLayers_CoverRegisteredCollectors(t *testing.T) {
	covered := map[string]bool{}
	for _, layer := range healthLayers {
		for _, m := range layer.members {
			covered[m] = true
		}
	}
	// Names returned by Name() for every collector cmd.buildHealthCollectors wires in.
	registered := []string{
		// always / core
		"CPU Load", "Memory", "Disk", "Swap", "IO", "Network", "Clock", "FDLimits",
		"Processes", "Systemd", "DBus", "Sysctl", "KernelSec", "Entropy", "Logs",
		"Hardening", "CPU Thermal", "Battery", "Launchd", "Drives", "OOM", "Firewall",
		"Auth", "HugePages", "Sessions",
		// gate-detected platform / storage
		"Fstab", "Root FS",
		"Snapshots", "Subscription", "Packages", "RAID", "ZFS", "LVM", "DRBD", "PVE",
		"Bonding", "IPMI", "HBA", "Pressure", "Multipath", "Ceph", "CloudMeta",
		"CloudInit", "VMware", "Networkd", "KVMGuest", "AWS", "Azure", "GCP",
		"PostBoot", "Auditd", "NUMA", "VLAN", "iSCSI", "InfiniBand", "SRIOV", "Nspawn",
		"Docker", "Containerd", "K8s", "KVM", "SteamOS", "CPUFreq",
		// flag-gated
		"GPU", "TLS", "CPUDeep", "Firmware", "CVE",
		// gate-detected service workloads
		"Postgres", "MySQL", "Redis", "Memcached", "Nginx", "Apache", "HAProxy",
		"RabbitMQ", "Elasticsearch", "MongoDB", "Kafka", "Prometheus", "Alertmanager",
		"Grafana", "Traefik", "Envoy",
	}
	for _, name := range registered {
		if !covered[name] {
			t.Errorf("collector %q is registered by dsd health but maps to no layer (would fall into Other)", name)
		}
	}
}
