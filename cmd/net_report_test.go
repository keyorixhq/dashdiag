package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

// Golden-output tests for net.go's report renderers — plain data structs, no
// live I/O (netReadTCPStates reads /proc directly and is exercised indirectly
// through printNetReport, not called standalone). No t.Parallel() (corrupts
// captureStdout's shared os.Stdout swap).

func TestPrintNetMetric(t *testing.T) {
	unreachable := captureStdout(t, func() { printNetMetric("Gateway ping", -1, "ms", 50, 200, output.ModePlain) })
	if !strings.Contains(unreachable, "unreachable") {
		t.Errorf("a negative value should render unreachable, got:\n%s", unreachable)
	}

	crit := captureStdout(t, func() { printNetMetric("Gateway ping", 250, "ms", 50, 200, output.ModePlain) })
	if !strings.Contains(crit, "CRIT") {
		t.Errorf("a value above crit should render CRIT, got:\n%s", crit)
	}

	warn := captureStdout(t, func() { printNetMetric("Gateway ping", 60, "ms", 50, 200, output.ModePlain) })
	if !strings.Contains(warn, "WARN") {
		t.Errorf("a value above warn should render WARN, got:\n%s", warn)
	}
}

func TestPrintTCPCounter(t *testing.T) {
	if out := captureStdout(t, func() { printTCPCounter("TIME_WAIT", 0, 500, 1000) }); out != "" {
		t.Errorf("a zero counter should be skipped, got:\n%s", out)
	}
	crit := captureStdout(t, func() { printTCPCounter("TIME_WAIT", 1500, 500, 1000) })
	if !strings.Contains(crit, "❌") {
		t.Errorf("a counter above crit should render the fail icon, got:\n%s", crit)
	}
}

func TestPrintTCPCounterLevel(t *testing.T) {
	if out := captureStdout(t, func() { printTCPCounterLevel("SYN retrans", 0, "CRIT") }); out != "" {
		t.Errorf("a zero counter should be skipped regardless of level, got:\n%s", out)
	}
	for _, c := range []struct{ level, icon string }{
		{"CRIT", "❌"}, {"WARN", "⚠️"}, {"INFO", "ℹ️"}, {"", "✅"},
	} {
		out := captureStdout(t, func() { printTCPCounterLevel("SYN retrans", 5, c.level) })
		if !strings.Contains(out, c.icon) {
			t.Errorf("level %q should render icon %q, got:\n%s", c.level, c.icon, out)
		}
	}
}

func TestPrintNetBonds(t *testing.T) {
	if out := captureStdout(t, func() { printNetBonds(&models.NetworkInfo{}) }); out != "" {
		t.Errorf("no bonds should print nothing, got:\n%s", out)
	}

	allDown := captureStdout(t, func() {
		printNetBonds(&models.NetworkInfo{Bonds: []models.BondInterface{{Name: "bond0", AllDown: true}}})
	})
	if !strings.Contains(allDown, "ALL SLAVES DOWN") {
		t.Errorf("an all-down bond should say so, got:\n%s", allDown)
	}

	degraded := captureStdout(t, func() {
		printNetBonds(&models.NetworkInfo{Bonds: []models.BondInterface{{
			Name: "bond0", Degraded: true, DownSlaves: 1,
			Slaves: []models.BondSlave{{Name: "eth0", MIIStatus: "up"}, {Name: "eth1", MIIStatus: "down"}},
		}}})
	})
	if !strings.Contains(degraded, "DEGRADED") || !strings.Contains(degraded, "1/2 slaves up") {
		t.Errorf("a degraded bond should show the up/total slave count, got:\n%s", degraded)
	}

	singleSlave := captureStdout(t, func() {
		printNetBonds(&models.NetworkInfo{Bonds: []models.BondInterface{{
			Name: "bond0", Slaves: []models.BondSlave{{Name: "eth0", MIIStatus: "up"}},
		}}})
	})
	if !strings.Contains(singleSlave, "no redundancy") {
		t.Errorf("a single-slave bond should warn of no redundancy, got:\n%s", singleSlave)
	}

	activeMarker := captureStdout(t, func() {
		printNetBonds(&models.NetworkInfo{Bonds: []models.BondInterface{{
			Name: "bond0", ActiveSlave: "eth0",
			Slaves: []models.BondSlave{{Name: "eth0", MIIStatus: "up"}, {Name: "eth1", MIIStatus: "up"}},
		}}})
	})
	if !strings.Contains(activeMarker, "← active") {
		t.Errorf("the active-backup slave should be marked, got:\n%s", activeMarker)
	}
}

func TestPrintNetSteamOSWifi(t *testing.T) {
	conflict := captureStdout(t, func() {
		printNetSteamOSWifi(&models.NetworkInfo{SteamOSWifi: &models.SteamOSWifi{BothBackends: true}})
	})
	if !strings.Contains(conflict, "conflict") {
		t.Errorf("both Wi-Fi backends active should be flagged as a conflict, got:\n%s", conflict)
	}

	ssidConflict := captureStdout(t, func() {
		printNetSteamOSWifi(&models.NetworkInfo{SteamOSWifi: &models.SteamOSWifi{SSIDConflict: true, ConflictSSID: "HomeNet"}})
	})
	if !strings.Contains(ssidConflict, "HomeNet") {
		t.Errorf("an SSID conflict should name the SSID, got:\n%s", ssidConflict)
	}

	slowCDN := captureStdout(t, func() {
		printNetSteamOSWifi(&models.NetworkInfo{SteamOSWifi: &models.SteamOSWifi{CDNDNSKnown: true, CDNDNSms: 800}})
	})
	if !strings.Contains(slowCDN, "slow") {
		t.Errorf("slow Steam CDN DNS should be flagged, got:\n%s", slowCDN)
	}

	notConnected := captureStdout(t, func() {
		printNetSteamOSWifi(&models.NetworkInfo{SteamOSWifi: &models.SteamOSWifi{Connected: false}})
	})
	if !strings.Contains(notConnected, "not connected") {
		t.Errorf("a disconnected Wi-Fi should say so and skip the link-quality profile, got:\n%s", notConnected)
	}
	if strings.Contains(notConnected, "Remote Play profile]") {
		t.Errorf("disconnected Wi-Fi must not render the link-quality section, got:\n%s", notConnected)
	}

	connected := captureStdout(t, func() {
		printNetSteamOSWifi(&models.NetworkInfo{SteamOSWifi: &models.SteamOSWifi{
			Connected: true, BandGHz: 2.4, WidthMHz: 20, SignalDBm: -80,
		}})
	})
	if !strings.Contains(connected, "2.4GHz") {
		t.Errorf("the connected band should be labeled, got:\n%s", connected)
	}
}

func TestPrintNFSReport(t *testing.T) {
	if out := captureStdout(t, func() { printNFSReport(&models.NFSInfo{}, output.ModePlain) }); out != "" {
		t.Errorf("no mounts should print nothing, got:\n%s", out)
	}

	stale := captureStdout(t, func() {
		printNFSReport(&models.NFSInfo{Mounts: []models.NFSMount{
			{Mount: "/mnt/data", Server: "nfs01", Export: "/export", Stale: true, ServerReachable: false, NFSPortOpen: false},
		}}, output.ModePlain)
	})
	if !strings.Contains(stale, "STALE") || !strings.Contains(stale, "unreachable") {
		t.Errorf("a stale mount should show the server/port sub-diagnostics, got:\n%s", stale)
	}

	// rpcbind inactive with an NFSv3 mount present must WARN (NFS client ops may
	// fail); the same inactive state on an NFSv4-only host must be a benign INFO.
	v3NoRpcbind := captureStdout(t, func() {
		printNFSReport(&models.NFSInfo{Mounts: []models.NFSMount{
			{Mount: "/mnt/data", Server: "nfs01", Export: "/export", FSType: "nfs", Healthy: true},
		}, RpcbindActive: false}, output.ModePlain)
	})
	if !strings.Contains(v3NoRpcbind, "NFS client operations may fail") {
		t.Errorf("rpcbind inactive with an NFSv3 mount must warn, got:\n%s", v3NoRpcbind)
	}

	v4NoRpcbind := captureStdout(t, func() {
		printNFSReport(&models.NFSInfo{Mounts: []models.NFSMount{
			{Mount: "/mnt/data", Server: "nfs01", Export: "/export", FSType: "nfs4", Healthy: true},
		}, RpcbindActive: false}, output.ModePlain)
	})
	if !strings.Contains(v4NoRpcbind, "not required") {
		t.Errorf("rpcbind inactive on an NFSv4-only host must not false-alarm, got:\n%s", v4NoRpcbind)
	}
}

func TestPrintBINDReport(t *testing.T) {
	unverifiedPorts := captureStdout(t, func() {
		printBINDReport(&models.BINDInfo{PortsChecked: false, ConfigOK: true})
	})
	if !strings.Contains(unverifiedPorts, "not verified") {
		t.Errorf("unverified ports (ss unavailable) must not claim NOT listening, got:\n%s", unverifiedPorts)
	}

	notListening := captureStdout(t, func() {
		printBINDReport(&models.BINDInfo{PortsChecked: true, Port53TCP: false, Port53UDP: false, ConfigOK: true})
	})
	if !strings.Contains(notListening, "NOT listening") {
		t.Errorf("neither TCP nor UDP listening should say NOT listening, got:\n%s", notListening)
	}

	zoneFailed := captureStdout(t, func() {
		printBINDReport(&models.BINDInfo{ConfigOK: true, PortsChecked: true, Port53TCP: true, Port53UDP: true,
			Zones: []models.BINDZone{{Name: "example.com", OK: false, Error: "syntax error", File: "/zones/example.com.db"}}})
	})
	if !strings.Contains(zoneFailed, "FAILED") || !strings.Contains(zoneFailed, "syntax error") {
		t.Errorf("a failed zone should show its error and remediation, got:\n%s", zoneFailed)
	}

	queryNotTested := captureStdout(t, func() {
		printBINDReport(&models.BINDInfo{ConfigOK: true, PortsChecked: true, QueryTested: false})
	})
	if !strings.Contains(queryNotTested, "not run") {
		t.Errorf("an untested query must not claim named is not answering, got:\n%s", queryNotTested)
	}
	if strings.Contains(queryNotTested, "not answering") {
		t.Errorf("an untested query must not claim named is not answering, got:\n%s", queryNotTested)
	}

	queryFailed := captureStdout(t, func() {
		printBINDReport(&models.BINDInfo{ConfigOK: true, PortsChecked: true, QueryTested: true, QueryOK: false})
	})
	if !strings.Contains(queryFailed, "not answering queries") {
		t.Errorf("a genuinely failed query test should say named is not answering, got:\n%s", queryFailed)
	}
}

func TestPrintResolverIdentityAndConfMode(t *testing.T) {
	active := captureStdout(t, func() {
		printResolverIdentity(&models.ResolverAuditInfo{ResolverType: "systemd-resolved", ResolverActive: true})
	})
	if !strings.Contains(active, "active") {
		t.Errorf("an active resolver should say so, got:\n%s", active)
	}

	uplink := captureStdout(t, func() { printResolverIdentity(&models.ResolverAuditInfo{ResolvConfMode: "uplink"}) })
	if !strings.Contains(uplink, "bypasses stub") {
		t.Errorf("uplink mode should warn of losing split-DNS, got:\n%s", uplink)
	}

	// resolv.conf custom while systemd-resolved is supposedly managing it is a
	// real inconsistency (WARN); the same custom file when resolved isn't even
	// active is benign (INFO).
	customManaged := captureStdout(t, func() {
		printResolverIdentity(&models.ResolverAuditInfo{ResolverType: "systemd-resolved", ResolverActive: true, ResolvConfMode: "custom"})
	})
	if !strings.Contains(customManaged, "not managing it") {
		t.Errorf("a custom resolv.conf under an active resolved should flag the inconsistency, got:\n%s", customManaged)
	}
	customUnmanaged := captureStdout(t, func() {
		printResolverIdentity(&models.ResolverAuditInfo{ResolverType: "NetworkManager", ResolvConfMode: "custom"})
	})
	if strings.Contains(customUnmanaged, "not managing it") {
		t.Errorf("a custom resolv.conf when resolved isn't active must not flag the resolved-specific inconsistency, got:\n%s", customUnmanaged)
	}
}

func TestPrintResolverDNSSEC(t *testing.T) {
	degraded := captureStdout(t, func() {
		printResolverDNSSEC(&models.ResolverAuditInfo{DNSSECDegraded: true, DNSSECConfigured: "yes", DNSSECDegradedReason: "resolver ignores AD bit"})
	})
	if !strings.Contains(degraded, "degraded in practice") || !strings.Contains(degraded, "resolver ignores AD bit") {
		t.Errorf("degraded DNSSEC should show the reason, got:\n%s", degraded)
	}
}

func TestPrintResolverDNSSECTest(t *testing.T) {
	if out := captureStdout(t, func() { printResolverDNSSECTest(&models.ResolverAuditInfo{DNSSECTestRan: false}) }); out != "" {
		t.Errorf("an untested DNSSEC validation should print nothing, got:\n%s", out)
	}
	timeout := captureStdout(t, func() {
		printResolverDNSSECTest(&models.ResolverAuditInfo{DNSSECTestRan: true, DNSSECTestPassed: false, DNSSECTestError: "timeout: no route"})
	})
	if !strings.Contains(timeout, "skipped") {
		t.Errorf("a timeout must read as skipped, not a validation failure, got:\n%s", timeout)
	}
	failed := captureStdout(t, func() {
		printResolverDNSSECTest(&models.ResolverAuditInfo{DNSSECTestRan: true, DNSSECTestPassed: false, DNSSECTestError: "SERVFAIL"})
	})
	if !strings.Contains(failed, "⚠️") {
		t.Errorf("a genuine DNSSEC validation failure should warn, got:\n%s", failed)
	}
}

func TestPrintResolverVPN(t *testing.T) {
	notApplicable := captureStdout(t, func() { printResolverVPN(&models.ResolverAuditInfo{}) })
	if !strings.Contains(notApplicable, "not applicable") {
		t.Errorf("no VPN interface should say not applicable, got:\n%s", notApplicable)
	}

	integrated := true
	ok := captureStdout(t, func() {
		printResolverVPN(&models.ResolverAuditInfo{VPNInterface: "wg0", VPNDNSIntegrated: &integrated})
	})
	if !strings.Contains(ok, "routed through wg0") {
		t.Errorf("integrated VPN DNS should say so, got:\n%s", ok)
	}

	notIntegrated := false
	leak := captureStdout(t, func() {
		printResolverVPN(&models.ResolverAuditInfo{VPNInterface: "wg0", VPNDNSIntegrated: &notIntegrated})
	})
	if !strings.Contains(leak, "is up but DNS is not routed") {
		t.Errorf("a VPN up but not carrying DNS (a leak) must be flagged, got:\n%s", leak)
	}
}

func TestPrintResolverNextGating(t *testing.T) {
	if out := captureStdout(t, func() {
		printResolverNext(&models.ResolverAuditInfo{ResolverType: "NetworkManager"})
	}); out != "" {
		t.Errorf("next-steps commands are resolvectl-specific and must not show for a non-systemd-resolved host, got:\n%s", out)
	}
	out := captureStdout(t, func() {
		printResolverNext(&models.ResolverAuditInfo{ResolverType: "systemd-resolved", ResolverActive: true})
	})
	if !strings.Contains(out, "resolvectl status") {
		t.Errorf("an active systemd-resolved host should show the resolvectl commands, got:\n%s", out)
	}
}

// TestPrintNetReportVerdict pins the top-level healthy/concern tally and the
// interface-visibility filter (unconfigured non-primary interfaces suppressed).
func TestPrintNetReportVerdict(t *testing.T) {
	healthy := captureStdout(t, func() {
		printNetReport(&models.NetworkInfo{PrimaryInterface: "eth0", Interfaces: []models.InterfaceInfo{
			{Name: "eth0", IP: "10.0.0.5", Up: true},
		}}, output.ModePlain, 0, platform.ContainerContext{})
	})
	if !strings.Contains(healthy, "Network healthy") {
		t.Errorf("no concerns should read healthy, got:\n%s", healthy)
	}
	if !strings.Contains(healthy, "eth0") {
		t.Errorf("the primary interface should be listed, got:\n%s", healthy)
	}

	// A down, unconfigured, non-primary interface (e.g. idle Wi-Fi on a server)
	// must be suppressed from the interface list — it's not interesting.
	suppressed := captureStdout(t, func() {
		printNetReport(&models.NetworkInfo{PrimaryInterface: "eth0", Interfaces: []models.InterfaceInfo{
			{Name: "eth0", IP: "10.0.0.5", Up: true},
			{Name: "wlan0", IP: "", Up: false},
		}}, output.ModePlain, 0, platform.ContainerContext{})
	})
	if strings.Contains(suppressed, "wlan0") {
		t.Errorf("an unconfigured non-primary interface must be suppressed, got:\n%s", suppressed)
	}
	if !strings.Contains(suppressed, "Interfaces (1)") {
		t.Errorf("the interface count should reflect only the visible interfaces, got:\n%s", suppressed)
	}

	concern := captureStdout(t, func() {
		printNetReport(&models.NetworkInfo{PrimaryInterfaceDown: true}, output.ModePlain, 0, platform.ContainerContext{})
	})
	if !strings.Contains(concern, "network concern(s) found") {
		t.Errorf("a down primary interface should surface as a concern, got:\n%s", concern)
	}

	inContainer := captureStdout(t, func() {
		printNetReport(&models.NetworkInfo{}, output.ModePlain, 0, platform.ContainerContext{InContainer: true})
	})
	if !strings.Contains(inContainer, "Running inside a container") {
		t.Errorf("container context should be surfaced, got:\n%s", inContainer)
	}
}
