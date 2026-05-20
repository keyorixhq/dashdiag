package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(netCmd)
	netCmd.AddCommand(netDeepCmd)
	netCmd.AddCommand(netDNSCmd)
	netCmd.Flags().Bool("deep", false, "deep scan — jitter, TCP retransmissions, TIME_WAIT, SYN backlog, conntrack")
}

var netCmd = &cobra.Command{
	Use:   "net",
	Short: "Network health — interfaces, latency, DNS, connections",
	RunE:  runNet,
}

// netDeepCmd is `dsd net deep` — equivalent to `dsd net --deep`.
var netDeepCmd = &cobra.Command{
	Use:   "deep",
	Short: "Deep network scan — jitter, TCP counters, conntrack (~30s)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := cmd.Parent().Flags().Set("deep", "true"); err != nil {
			return err
		}
		return runNet(cmd.Parent(), args)
	},
}

func runNet(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	deepFlag, _ := cmd.Flags().GetBool("deep")
	mode := output.DetectMode(plain, false, "")
	ctrCtx := platform.DetectContainerContext()

	label := "Network health"
	var col runner.Collector = collectors.NewNetworkCollector()
	if deepFlag {
		label = "Network health (deep)"
		col = collectors.NewNetworkDeepCollector()
	}

	cols := []runner.Collector{col}
	if deepFlag {
		cols = append(cols, collectors.NewNFSCollector())
		cols = append(cols, collectors.NewBINDCollector())
	}

	p := output.NewCommandProgress(label, 30*time.Second, mode, len(cols))
	p.Start()
	defer p.Done()

	var netResult runner.Result
	var nfsInfo *models.NFSInfo
	var bindInfo *models.BINDInfo
	for r := range runner.RunAll(ctx, cols) {
		p.Step(r.Name)
		switch v := r.Data.(type) {
		case *models.NetworkInfo:
			netResult = r
		case *models.NFSInfo:
			nfsInfo = v
		case *models.BINDInfo:
			bindInfo = v
		}
	}

	elapsed := p.Elapsed()

	info, ok := netResult.Data.(*models.NetworkInfo)
	if !ok || info == nil {
		return netResult.Err
	}

	printNetReport(info, mode, elapsed, ctrCtx)
	if nfsInfo != nil {
		printNFSReport(nfsInfo, mode)
	}
	if bindInfo != nil && bindInfo.Detected {
		printBINDReport(bindInfo)
	}
	return nil
}

func printNetReport(info *models.NetworkInfo, mode output.OutputMode, elapsed time.Duration, ctrCtx platform.ContainerContext) { //nolint:cyclop,funlen // report renderer — each branch is a distinct display condition
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	// Interfaces — skip unconfigured down interfaces (e.g. WiFi with no IP)
	visible := make([]models.InterfaceInfo, 0, len(info.Interfaces))
	for _, iface := range info.Interfaces {
		// Skip interfaces that are unconfigured and not the primary:
		// - no IP assigned, AND
		// - either down or no carrier (operstate check)
		// This suppresses WiFi interfaces that are administratively up
		// but have no carrier/connection (common on server installs).
		if iface.IP == "" && iface.Name != info.PrimaryInterface {
			continue // no IP, not primary — not interesting
		}
		visible = append(visible, iface)
	}
	fmt.Printf("\nInterfaces (%d)\n", len(visible))
	for _, iface := range visible {
		statusIcon := "✅"
		if !iface.Up {
			statusIcon = "❌"
		}
		details := iface.IP
		if iface.SpeedMbps > 0 {
			details += fmt.Sprintf("  %d Mbps", iface.SpeedMbps)
		}
		if iface.IsUSB {
			if iface.Driver != "" {
				details += fmt.Sprintf("  [USB:%s]", iface.Driver)
			} else {
				details += "  [USB]"
			}
		}
		if iface.RxDrops > 0 || iface.TxDrops > 0 {
			details += fmt.Sprintf("  drops rx:%d tx:%d", iface.RxDrops, iface.TxDrops)
		}
		if iface.RxErrors > 0 || iface.TxErrors > 0 {
			details += fmt.Sprintf("  errors rx:%d tx:%d", iface.RxErrors, iface.TxErrors)
		}
		// WiFi: show signal + SSID instead of speed
		if iface.WiFi != nil {
			wifiDetails := ""
			if iface.WiFi.RateMbps > 0 {
				wifiDetails += fmt.Sprintf("  %d Mbps", iface.WiFi.RateMbps)
			}
			if iface.WiFi.FreqGHz > 0 {
				wifiDetails += fmt.Sprintf("  %.2fGHz", iface.WiFi.FreqGHz)
			} else if iface.WiFi.Band != "" {
				wifiDetails += fmt.Sprintf("  %s", iface.WiFi.Band)
			}
			if iface.WiFi.SignalDBm != 0 {
				sigIcon := "✅"
				if iface.WiFi.SignalDBm < -70 {
					sigIcon = "❌"
				} else if iface.WiFi.SignalDBm < -60 {
					sigIcon = "⚠️ "
				}
				wifiDetails += fmt.Sprintf("  %s signal:%ddBm", sigIcon, iface.WiFi.SignalDBm)
			}
			if iface.WiFi.SSID != "" {
				wifiDetails += fmt.Sprintf("  \"%s\"", iface.WiFi.SSID)
			}
			details += wifiDetails
		}
		primary := ""
		if iface.Name == info.PrimaryInterface {
			primary = "  ← primary"
		}
		fmt.Printf("  %s  %-12s %s%s\n", statusIcon, iface.Name, details, primary)
	}

	// Bond interfaces
	printNetBonds(info)

	// Connectivity
	fmt.Println("\nConnectivity")
	printNetMetric("Gateway ping", info.GatewayPingMs, "ms", 50, 200)
	printNetMetric("Internet ping", info.InternetPingMs, "ms", 50, 200)
	printNetMetric("DNS resolution", info.DNSResolvesMs, "ms", 100, 500)
	if info.JitterMs > 0 {
		printNetMetric("Jitter", info.JitterMs, "ms", 20, 50)
	}
	if info.GatewayPacketLossPct > 0 {
		printNetMetric("Packet loss (gw)", info.GatewayPacketLossPct, "%", 1, 5)
	}
	if info.InternetPacketLossPct > 0 {
		printNetMetric("Packet loss (net)", info.InternetPacketLossPct, "%", 1, 5)
	}
	if info.ICMPBlocked {
		fmt.Println("  ℹ️   ICMP blocked — using TCP fallback for ping")
	}

	// TCP connection states
	fmt.Println("\nTCP States")
	states := netReadTCPStates()
	if len(states) == 0 {
		fmt.Println("  ✅  no active connections")
	} else {
		for state, count := range states {
			icon := "✅"
			if state == "CLOSE-WAIT" && count > 100 {
				icon = "⚠️ "
			} else if state == "TIME-WAIT" && count > 500 {
				icon = "⚠️ "
			}
			fmt.Printf("  %s  %-16s %d\n", icon, state, count)
		}
	}

	// Extra info
	if info.NATDetected {
		fmt.Println("\n  ℹ️   NAT detected — behind router or in container")
	}

	// Deep TCP metrics — shown when collected by NetworkDeepCollector
	if info.SynRetransCount > 0 || info.ListenOverflows > 0 || info.RetransFailCount > 0 || info.TimeWaitCount > 0 {
		fmt.Println("\nTCP Kernel Counters")
		printTCPCounter("SYN retransmissions", info.SynRetransCount, 100, 500)
		printTCPCounter("Listen queue overflows", info.ListenOverflows, 1, 10)
		printTCPCounter("Retransmit failures", info.RetransFailCount, 10, 50)
		printTCPCounter("TIME_WAIT sockets", info.TimeWaitCount, 1000, 5000)
		if info.ConntrackUsedPct > 0 {
			printNetMetric("Conntrack used", info.ConntrackUsedPct, "%", 60, 80)
		}
	}
	if ctrCtx.InContainer {
		fmt.Println("\n  ℹ️   Running inside a container")
	}

	// Summary
	fmt.Println()
	fmt.Println(sep)
	issues := 0
	if info.PrimaryInterfaceDown {
		issues++
	}
	if info.GatewayPingMs > 200 || info.GatewayPingMs < 0 {
		issues++
	}
	if info.GatewayPacketLossPct > 5 {
		issues++
	}
	if info.DNSFailed {
		issues++
	}
	if info.CloseWaitCount > 100 {
		issues++
	}
	if info.ListenOverflows > 0 {
		issues++
	}
	if info.SynRetransCount > 100 {
		issues++
	}
	if info.RetransFailCount > 10 {
		issues++
	}
	if info.ConntrackUsedPct >= 80 {
		issues++
	}

	if issues == 0 {
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("✅ Network healthy. Checks passed%s", timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("⚠️  %d network concern(s) found%s", issues, timing)))
	}
}

func printNetMetric(label string, val float64, unit string, warn, crit float64) {
	if val < 0 {
		fmt.Printf("  ❌  %-24s unreachable\n", label+":")
		return
	}
	icon := "✅"
	if val >= crit {
		icon = "❌"
	} else if val >= warn {
		icon = "⚠️ "
	}
	fmt.Printf("  %s  %-24s %.1f %s\n", icon, label+":", val, unit)
}

func printTCPCounter(label string, val int, warn, crit int) {
	if val == 0 {
		return // skip zero counters
	}
	icon := "✅"
	if val >= crit {
		icon = "❌"
	} else if val >= warn {
		icon = "⚠️ "
	}
	fmt.Printf("  %s  %-24s %d\n", icon, label+":", val)
}

func netReadTCPStates() map[string]int {
	states := make(map[string]int)
	tcpStateNames := map[string]string{
		"01": "ESTAB", "02": "SYN-SENT", "03": "SYN-RECV",
		"04": "FIN-WAIT-1", "05": "FIN-WAIT-2", "06": "TIME-WAIT",
		"07": "CLOSE", "08": "CLOSE-WAIT", "09": "LAST-ACK",
		"0B": "CLOSING",
	}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path) // #nosec G304 -- hardcoded /proc path
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			if name, ok := tcpStateNames[fields[3]]; ok {
				states[name]++
			}
		}
	}
	return states
}

// ── dsd net dns ───────────────────────────────────────────────────────────────

var netDNSCmd = &cobra.Command{
	Use:   "dns",
	Short: "DNS resolver audit — config source, nameservers, resolution test, quality checks",
	RunE:  runNetDNS,
}

func runNetDNS(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Parent().Flags().GetBool("plain")
	jsonOut, _ := cmd.Parent().Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	p := output.NewCommandProgress("DNS resolver audit", 8*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewDNSCollector()}) {
		p.Step(r.Name)
		result = r
	}

	info, ok := result.Data.(*models.DNSResolverInfo)
	if !ok || info == nil {
		return result.Err
	}

	if mode == output.ModeJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(info)
		return nil
	}

	printDNS(info, mode)
	return nil
}

func printNetBonds(info *models.NetworkInfo) {
	if len(info.Bonds) == 0 {
		return
	}
	fmt.Printf("\nBond interfaces (%d)\n", len(info.Bonds))
	for _, b := range info.Bonds {
		icon := "✅"
		statusStr := ""
		if b.AllDown {
			icon = "❌"
			statusStr = "  ALL SLAVES DOWN"
		} else if b.Degraded {
			icon = "⚠️ "
			statusStr = fmt.Sprintf("  DEGRADED — %d/%d slaves up", len(b.Slaves)-b.DownSlaves, len(b.Slaves))
		} else if len(b.Slaves) < 2 {
			icon = "⚠️ "
			statusStr = "  only 1 slave — no redundancy"
		}
		modeStr := b.ModeShort
		if modeStr == "" {
			modeStr = b.Mode
		}
		fmt.Printf("  %s  %-12s  %s%s\n", icon, b.Name, modeStr, statusStr)
		for _, s := range b.Slaves {
			slaveIcon := "  ✅"
			if s.MIIStatus != "up" {
				slaveIcon = "  ❌"
			}
			speedStr := ""
			if s.SpeedMbps > 0 {
				speedStr = fmt.Sprintf("  %d Mbps", s.SpeedMbps)
			}
			usbStr := ""
			if isUSBSlave(s.Name) {
				usbStr = "  [USB]"
			}
			linkFails := ""
			if s.LinkFails > 0 {
				linkFails = fmt.Sprintf("  %d link failures", s.LinkFails)
			}
			activeStr := ""
			if b.ActiveSlave == s.Name {
				activeStr = "  ← active"
			}
			fmt.Printf("    %s  %-14s  MII:%-4s%s%s%s%s\n",
				slaveIcon, s.Name, s.MIIStatus, speedStr, usbStr, linkFails, activeStr)
		}
	}
}

// isUSBSlave checks if a network interface is USB-based via sysfs.
func isUSBSlave(iface string) bool {
	link, err := os.Readlink(fmt.Sprintf("/sys/class/net/%s/device/subsystem", iface))
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(link), "usb")
}

func printDNS(info *models.DNSResolverInfo, mode output.OutputMode) {
	human := mode == output.ModeHuman
	if human {
		fmt.Fprintln(os.Stdout, "\n🔍  DNS resolver audit")
	}

	// Manager + config source
	printLine(mode, "info", "Manager", info.Manager)
	if info.ConfigFile != "" && info.ConfigFile != "/etc/resolv.conf" {
		printLine(mode, "info", "resolv.conf →", info.ConfigFile)
	}
	if info.StubMode {
		printLine(mode, "ok", "Stub mode", "systemd-resolved stub (127.0.0.53)")
	}

	// Nameservers
	if len(info.Nameservers) > 0 {
		printLine(mode, "info", "Nameservers",
			strings.Join(info.Nameservers, "  "))
	} else {
		printLine(mode, "warn", "Nameservers", "none configured")
	}

	// Search domains
	if len(info.SearchDomains) > 0 {
		printLine(mode, "info", "Search domains",
			strings.Join(info.SearchDomains, "  "))
	}

	// Options
	if len(info.Options) > 0 {
		printLine(mode, "info", "Options", strings.Join(info.Options, "  "))
	}

	// Resolution test
	if info.ExternalResolvesOK {
		printLine(mode, "ok", "External resolution",
			fmt.Sprintf("ok  %dms", info.ExternalLatencyMs))
	} else {
		printLine(mode, "fail", "External resolution", "FAILED")
		if info.ResolvTestError != "" {
			fmt.Printf("     → %s\n", info.ResolvTestError)
		}
	}

	if info.InternalResolvesOK {
		printLine(mode, "ok", "Internal (hostname)", "ok")
	} else {
		printLine(mode, "warn", "Internal (hostname)", "could not resolve own hostname")
	}

	// Quality flags
	if info.TooManyNameservers {
		printLine(mode, "warn", "Nameserver count",
			fmt.Sprintf("%d — libc silently ignores >3", len(info.Nameservers)))
	}
	if info.HasLoopback {
		printLine(mode, "warn", "Loopback NS", "127.x present but stub not active")
	}
	if info.NdotsHigh > 0 {
		printLine(mode, "warn", "ndots",
			fmt.Sprintf("%d — high, may cause excessive lookups", info.NdotsHigh))
	}
	if info.IPv6Only {
		printLine(mode, "warn", "IPv6-only", "no IPv4 fallback resolver")
	}
	if len(info.DuplicateNameserver) > 0 {
		printLine(mode, "info", "Duplicates",
			strings.Join(info.DuplicateNameserver, ", "))
	}
	if info.PublicFallback {
		printLine(mode, "info", "Public DNS", "8.8.8.8/1.1.1.1 in resolver list")
	}
}

// printNFSReport renders the NFS mounts section appended to dsd net deep output.
func printNFSReport(info *models.NFSInfo, mode output.OutputMode) {
	if len(info.Mounts) == 0 {
		return
	}
	fmt.Printf("\n[NFS mounts] — %d found\n", len(info.Mounts))
	for _, m := range info.Mounts {
		icon := "✅"
		status := fmt.Sprintf("healthy (%dms)", m.LatencyMs)
		if m.Stale {
			icon = "❌"
			status = "STALE (timeout after 2s)"
		} else if !m.Healthy {
			icon = "⚠️ "
			status = "error"
		}
		fmt.Printf("  %s %-22s  %s:%s  %s\n",
			icon, m.Mount, m.Server, m.Export, status)
		if m.Stale {
			srvIcon := "❌"
			if m.ServerReachable {
				srvIcon = "✅"
			}
			fmt.Printf("       %s server %s: %s\n", srvIcon, m.Server,
				map[bool]string{true: "reachable", false: "unreachable (ping timeout)"}[m.ServerReachable])
			portIcon := map[bool]string{true: "✅", false: "❌"}[m.NFSPortOpen]
			fmt.Printf("       %s NFS port 2049: %s\n", portIcon,
				map[bool]string{true: "open", false: "unreachable"}[m.NFSPortOpen])
		}
		for _, warn := range m.OptionsWarnings {
			fmt.Printf("       ⚠️   mount option: %s\n", warn)
		}
	}

	fmt.Printf("\n  [rpcbind] ")
	if info.RpcbindActive {
		fmt.Println("✅ active")
	} else {
		fmt.Println("⚠️  inactive — NFS client operations may fail")
	}

	if info.RetransPerMin > 0 || info.ReadOpsPerMin > 0 {
		fmt.Printf("\n  [NFS stats]\n")
		if info.RetransPerMin > 0 {
			icon := "✅"
			if info.RetransPerMin > 100 {
				icon = "⚠️ "
			}
			fmt.Printf("  %s Retransmissions:  %.0f\n", icon, info.RetransPerMin)
		}
		if info.ReadOpsPerMin > 0 || info.WriteOpsPerMin > 0 {
			fmt.Printf("     Read ops:        %.0f\n", info.ReadOpsPerMin)
			fmt.Printf("     Write ops:       %.0f\n", info.WriteOpsPerMin)
		}
	}
	_ = mode
}

// printBINDReport renders the BIND/named section appended to dsd net deep output.
func printBINDReport(info *models.BINDInfo) {
	verStr := ""
	if info.Version != "" {
		verStr = fmt.Sprintf("  [BIND %s", info.Version)
		if info.Uptime != "" {
			verStr += ", up " + info.Uptime
		}
		verStr += "]"
	}
	fmt.Printf("\n[DNS server (BIND)]%s\n", verStr)

	// Service
	svcIcon := map[bool]string{true: "✅", false: "❌"}[info.ServiceActive]
	fmt.Printf("  %s named: %s\n", svcIcon,
		map[bool]string{true: "active", false: "inactive"}[info.ServiceActive])

	// Port 53
	portIcon := "✅"
	portStr := "listening (TCP + UDP)"
	if !info.Port53TCP || !info.Port53UDP {
		portIcon = "⚠️ "
		if !info.Port53TCP && !info.Port53UDP {
			portStr = "NOT listening on port 53"
		} else if !info.Port53TCP {
			portStr = "UDP only (TCP not listening)"
		} else {
			portStr = "TCP only (UDP not listening)"
		}
	}
	fmt.Printf("  %s Port 53: %s\n", portIcon, portStr)

	// Config check
	cfgIcon := map[bool]string{true: "✅", false: "❌"}[info.ConfigOK]
	cfgStatus := "no syntax errors"
	if !info.ConfigOK {
		cfgStatus = info.ConfigError
	}
	fmt.Printf("  %s named-checkconf: %s\n", cfgIcon, cfgStatus)

	// Zone validation
	if len(info.Zones) > 0 {
		for _, z := range info.Zones {
			if z.OK {
				fmt.Printf("  ✅ Zone %-30s OK\n", z.Name)
			} else {
				fmt.Printf("  ❌ Zone %-30s FAILED\n", z.Name)
				if z.Error != "" {
					fmt.Printf("       Error: %s\n", z.Error)
				}
				fmt.Printf("     → named-checkzone %s %s\n", z.Name, z.File)
				fmt.Printf("     → rndc reload %s  (after fixing)\n", z.Name)
			}
		}
	}

	// DNS query test
	queryIcon := map[bool]string{true: "✅", false: "❌"}[info.QueryOK]
	queryStr := fmt.Sprintf("localhost resolves in %dms", info.QueryLatencyMs)
	if !info.QueryOK {
		queryStr = "FAILED — named running but not answering queries"
	}
	fmt.Printf("  %s DNS query test: %s\n", queryIcon, queryStr)

	// Query stats from rndc
	if info.QueryCount > 0 {
		fmt.Printf("     Queries served: %d\n", info.QueryCount)
	}
}
