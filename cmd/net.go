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

// netJSONResult is the machine-readable shape of `dsd net --json`. The deep-mode
// sub-collectors (NFS / BIND / DNS resolver) are included only when they ran.
type netJSONResult struct {
	Network  *models.NetworkInfo       `json:"network"`
	NFS      *models.NFSInfo           `json:"nfs,omitempty"`
	BIND     *models.BINDInfo          `json:"bind,omitempty"`
	Resolver *models.ResolverAuditInfo `json:"resolver,omitempty"`
}

func runNet(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	deepFlag, _ := cmd.Flags().GetBool("deep")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)
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
		cols = append(cols, collectors.NewDNSResolverCollector())
	}

	p := output.NewCommandProgress(label, 30*time.Second, mode, len(cols))
	p.Start()
	defer p.Done()

	var netResult runner.Result
	var nfsInfo *models.NFSInfo
	var bindInfo *models.BINDInfo
	var resolverInfo *models.ResolverAuditInfo
	var allResults []runner.Result
	for r := range runner.RunAll(ctx, cols) {
		p.Step(r.Name)
		allResults = append(allResults, r)
		switch v := r.Data.(type) {
		case *models.NetworkInfo:
			netResult = r
		case *models.NFSInfo:
			nfsInfo = v
		case *models.BINDInfo:
			bindInfo = v
		case *models.ResolverAuditInfo:
			resolverInfo = v
		}
	}

	elapsed := p.Elapsed()

	info, ok := netResult.Data.(*models.NetworkInfo)
	if !ok || info == nil {
		return netResult.Err
	}
	recordResultSeverity(allResults)

	if mode == output.ModeJSON {
		return outputJSON(os.Stdout, netJSONResult{
			Network:  info,
			NFS:      nfsInfo,
			BIND:     bindInfo,
			Resolver: resolverInfo,
		})
	}

	printNetReport(info, mode, elapsed, ctrCtx)
	if nfsInfo != nil {
		printNFSReport(nfsInfo, mode)
	}
	if bindInfo != nil && bindInfo.Detected {
		printBINDReport(bindInfo)
	}
	if resolverInfo != nil && resolverInfo.Detected {
		printResolverAudit(resolverInfo)
	}
	return nil
}

// netMark returns the status marker for a net report line. In --plain mode it
// returns an ASCII token (OK/WARN/CRIT/INFO) so the output is emoji-free and
// machine-parseable like `dsd health --plain`; in human/report mode it returns
// the exact glyph the report has always used (output stays byte-identical).
func netMark(level string, mode output.OutputMode) string {
	if mode == output.ModePlain {
		switch level {
		case "ok":
			return "OK"
		case "warn":
			return "WARN"
		case "fail":
			return "CRIT"
		case "info":
			return "INFO"
		}
		return level
	}
	switch level {
	case "ok":
		return "✅"
	case "warn":
		return "⚠️ "
	case "fail":
		return "❌"
	case "info":
		return "ℹ️ "
	}
	return ""
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
		statusIcon := netMark("ok", mode)
		if !iface.Up {
			statusIcon = netMark("fail", mode)
		}

		primary := ""
		if iface.Name == info.PrimaryInterface {
			primary = "  ← primary"
		}

		if iface.WiFi != nil {
			// WiFi interface: IP  "SSID"  band  speed  signal
			details := iface.IP
			if iface.WiFi.SSID != "" {
				details += fmt.Sprintf("  \"%s\"", iface.WiFi.SSID)
			}
			if iface.WiFi.Band != "" {
				details += fmt.Sprintf("  %s", iface.WiFi.Band)
			} else if iface.WiFi.FreqGHz > 0 {
				details += fmt.Sprintf("  %.2fGHz", iface.WiFi.FreqGHz)
			}
			if iface.WiFi.RateMbps > 0 {
				details += fmt.Sprintf("  %d Mbps", iface.WiFi.RateMbps)
			}
			if iface.WiFi.SignalDBm != 0 {
				var sigIcon string
				switch {
				case iface.WiFi.SignalDBm >= -60:
					sigIcon = "▲▲▲"
				case iface.WiFi.SignalDBm >= -70:
					sigIcon = "▲▲ "
				case iface.WiFi.SignalDBm >= -80:
					sigIcon = "▲  "
				default:
					sigIcon = "!  "
				}
				details += fmt.Sprintf("  %s %ddBm", sigIcon, iface.WiFi.SignalDBm)
			}
			if iface.RxDrops > 0 {
				details += fmt.Sprintf("  drops:%d", iface.RxDrops)
			}
			fmt.Printf("  %s  %-12s %s%s\n", statusIcon, iface.Name, details, primary)
		} else {
			// Wired interface: IP  speed  [USB]  drops  errors
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
			fmt.Printf("  %s  %-12s %s%s\n", statusIcon, iface.Name, details, primary)
		}
	}

	// Bond interfaces
	printNetBonds(info)

	// Connectivity
	fmt.Println("\nConnectivity")
	printNetMetric("Gateway ping", info.GatewayPingMs, "ms", 50, 200, mode)
	printNetMetric("Internet ping", info.InternetPingMs, "ms", 50, 200, mode)
	printNetMetric("DNS resolution", info.DNSResolvesMs, "ms", 100, 500, mode)
	if info.JitterMs > 0 {
		printNetMetric("Jitter", info.JitterMs, "ms", 20, 50, mode)
	}
	if info.GatewayPacketLossPct > 0 {
		printNetMetric("Packet loss (gw)", info.GatewayPacketLossPct, "%", 1, 5, mode)
	}
	if info.InternetPacketLossPct > 0 {
		printNetMetric("Packet loss (net)", info.InternetPacketLossPct, "%", 1, 5, mode)
	}
	if info.ICMPBlocked {
		fmt.Printf("  %s  ICMP blocked — using TCP fallback for ping\n", netMark("info", mode))
	}

	// TCP connection states
	fmt.Println("\nTCP States")
	states := netReadTCPStates()
	if len(states) == 0 {
		fmt.Printf("  %s  no active connections\n", netMark("ok", mode))
	} else {
		for state, count := range states {
			icon := netMark("ok", mode)
			if state == "CLOSE-WAIT" && count > 100 {
				icon = netMark("warn", mode)
			} else if state == "TIME-WAIT" && count > 500 {
				icon = netMark("warn", mode)
			}
			fmt.Printf("  %s  %-16s %d\n", icon, state, count)
		}
	}

	// Extra info
	if info.NATDetected {
		fmt.Printf("\n  %s  NAT detected — behind router or in container\n", netMark("info", mode))
	}

	// Deep TCP metrics — shown when collected by NetworkDeepCollector
	if info.SynRetransCount > 0 || info.ListenOverflows > 0 || info.RetransFailCount > 0 || info.TimeWaitCount > 0 {
		fmt.Println("\nTCP Kernel Counters")
		printTCPCounter("SYN retransmissions", info.SynRetransCount, 100, 500)
		printTCPCounter("Listen queue overflows", info.ListenOverflows, 1, 10)
		printTCPCounter("Retransmit failures", info.RetransFailCount, 10, 50)
		printTCPCounter("TIME_WAIT sockets", info.TimeWaitCount, 1000, 5000)
		if info.ConntrackUsedPct > 0 {
			printNetMetric("Conntrack used", info.ConntrackUsedPct, "%", 60, 80, mode)
		}
	}
	if ctrCtx.InContainer {
		fmt.Println("\n  ℹ️   Running inside a container")
	}

	printNetSteamOSWifi(info)

	// Summary
	fmt.Println()
	fmt.Println(sep)
	issues := 0
	issues += countSteamOSWifiIssues(info.SteamOSWifi)
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
		fmt.Println(render.StyleOK.Render(fmt.Sprintf("%s Network healthy. Checks passed%s", netMark("ok", mode), timing)))
	} else {
		fmt.Println(render.StyleWarn.Render(fmt.Sprintf("%s %d network concern(s) found%s", netMark("warn", mode), issues, timing)))
	}
}

// printNetSteamOSWifi renders the SteamOS Wi-Fi + Remote Play profile section
// (Spec 20 + 22B). Absent on non-SteamOS systems.
func printNetSteamOSWifi(info *models.NetworkInfo) {
	w := info.SteamOSWifi
	if w == nil {
		return
	}
	fmt.Println("\n[SteamOS Wi-Fi]")
	backend := w.Backend
	if backend == "" {
		backend = "unknown"
	}
	switch {
	case w.BothBackends:
		fmt.Printf("  ⚠️  Backend: iwd + wpa_supplicant both active (conflict)\n")
	case w.DevMode:
		fmt.Printf("  ℹ️  Backend: %s (dev-mode workaround)\n", backend)
	default:
		fmt.Printf("  ✅ Backend: %s\n", backend)
	}
	if w.SSIDConflict {
		fmt.Printf("  ⚠️  SSID conflict: %q on both 2.4GHz and 5GHz — rename one band\n", w.ConflictSSID)
	}
	switch {
	case !w.CDNDNSKnown:
		// CDN DNS not measured — stay quiet
	case w.CDNDNSms > 500:
		fmt.Printf("  ⚠️  Steam CDN DNS: %dms (slow — set DNS to 1.1.1.1/8.8.8.8)\n", w.CDNDNSms)
	default:
		fmt.Printf("  ✅ Steam CDN DNS: %dms\n", w.CDNDNSms)
	}

	if !w.Connected {
		fmt.Println("  ℹ️  Wi-Fi not connected — Remote Play profile unavailable")
		return
	}
	fmt.Println("\n[Wi-Fi — Remote Play profile]")
	fmt.Printf("  %s Band:    %s\n", iconBand(w.BandGHz), bandLabel(w.BandGHz))
	if w.Channel != 0 {
		fmt.Printf("  ℹ️  Channel: %d (%d MHz)\n", w.Channel, w.FrequencyMHz)
	}
	fmt.Printf("  %s Width:   %d MHz\n", iconWidth(w.WidthMHz), w.WidthMHz)
	if w.SignalDBm != 0 {
		fmt.Printf("  %s Signal:  %d dBm\n", iconSignal(w.SignalDBm), w.SignalDBm)
	}
}

func bandLabel(ghz float64) string {
	switch ghz {
	case 2.4:
		return "2.4GHz"
	case 5:
		return "5GHz"
	case 6:
		return "6GHz"
	default:
		return "unknown"
	}
}

func iconBand(ghz float64) string {
	if ghz == 2.4 {
		return "⚠️ "
	}
	return "✅"
}

func iconWidth(mhz int) string {
	if mhz == 20 {
		return "⚠️ "
	}
	return "✅"
}

func iconSignal(dbm int) string {
	switch {
	case dbm < -75:
		return "❌"
	case dbm <= -65:
		return "⚠️ "
	default:
		return "✅"
	}
}

// countSteamOSWifiIssues counts SteamOS Wi-Fi concerns for the net summary line.
func countSteamOSWifiIssues(w *models.SteamOSWifi) int {
	if w == nil {
		return 0
	}
	n := 0
	if w.BothBackends {
		n++
	}
	if w.SSIDConflict {
		n++
	}
	if w.CDNDNSKnown && w.CDNDNSms > 500 {
		n++
	}
	if w.Connected {
		if w.BandGHz == 2.4 {
			n++
		}
		if w.WidthMHz == 20 {
			n++
		}
		if w.SignalDBm != 0 && w.SignalDBm <= -65 {
			n++
		}
	}
	return n
}

func printNetMetric(label string, val float64, unit string, warn, crit float64, mode output.OutputMode) {
	if val < 0 {
		fmt.Printf("  %s  %-24s unreachable\n", netMark("fail", mode), label+":")
		return
	}
	icon := netMark("ok", mode)
	if val >= crit {
		icon = netMark("fail", mode)
	} else if val >= warn {
		icon = netMark("warn", mode)
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

// printResolverAudit renders the [DNS Resolver] section appended to dsd net deep.
func printResolverAudit(info *models.ResolverAuditInfo) {
	fmt.Println("\n[DNS Resolver]")
	printResolverIdentity(info)

	if info.ResolverType == "systemd-resolved" && info.ResolverActive {
		printResolverDNSSEC(info)
		printResolverDoT(info)
		printResolverDNSSECTest(info)
	} else if info.FallbackNote != "" {
		fmt.Printf("  ℹ️  %s\n", info.FallbackNote)
		if len(info.NMNameservers) > 0 {
			fmt.Printf("  ✅ DNS servers: %s\n", strings.Join(info.NMNameservers, "  "))
		}
	}

	printResolverVPN(info)
	printResolverNext(info)
}

// printResolverIdentity renders the resolver type and resolv.conf mode lines.
func printResolverIdentity(info *models.ResolverAuditInfo) {
	if info.ResolverActive {
		fmt.Printf("  ✅ Resolver: %s (active)\n", info.ResolverType)
	} else {
		// Not having systemd-resolved is not an error — INFO, never WARN.
		fmt.Printf("  ℹ️  Resolver: %s\n", info.ResolverType)
	}

	switch info.ResolvConfMode {
	case "stub":
		fmt.Printf("  ✅ resolv.conf: stub mode (correct — %s)\n", info.ResolvConfTarget)
	case "uplink":
		fmt.Printf("  ⚠️  resolv.conf: uplink mode (bypasses stub — loses split-DNS)\n")
	default:
		if info.ResolverType == "systemd-resolved" && info.ResolverActive {
			fmt.Println("  ⚠️  resolv.conf: custom file — systemd-resolved is not managing it")
		} else {
			fmt.Println("  ℹ️  resolv.conf: custom/unmanaged file")
		}
	}
}

// printResolverDNSSEC renders the DNSSEC configured/effective line.
func printResolverDNSSEC(info *models.ResolverAuditInfo) {
	if info.DNSSECDegraded {
		fmt.Printf("  ⚠️  DNSSEC: configured %s, but degraded in practice\n", info.DNSSECConfigured)
		if info.DNSSECDegradedReason != "" {
			fmt.Printf("     Reason: %s\n", info.DNSSECDegradedReason)
		}
		return
	}
	state := info.DNSSECActive
	if state == "" {
		state = info.DNSSECConfigured
	}
	fmt.Printf("  ✅ DNSSEC: %s\n", state)
}

// printResolverDoT renders the DNS-over-TLS line when known.
func printResolverDoT(info *models.ResolverAuditInfo) {
	switch info.DoTStatus {
	case "", "no":
		fmt.Println("  ℹ️  DNS-over-TLS: off")
	case "opportunistic":
		fmt.Println("  ✅ DNS-over-TLS: opportunistic")
	default:
		fmt.Printf("  ✅ DNS-over-TLS: %s\n", info.DoTStatus)
	}
}

// printResolverDNSSECTest renders the live DNSSEC validation test result.
func printResolverDNSSECTest(info *models.ResolverAuditInfo) {
	if !info.DNSSECTestRan {
		return
	}
	if info.DNSSECTestPassed {
		fmt.Println("  ✅ DNSSEC validation test: passed (sigok.verteiltesysteme.net)")
		return
	}
	if strings.HasPrefix(info.DNSSECTestError, "timeout") {
		fmt.Printf("  ℹ️  DNSSEC validation test: skipped — %s\n", info.DNSSECTestError)
		return
	}
	fmt.Printf("  ⚠️  DNSSEC validation test: %s\n", info.DNSSECTestError)
}

// printResolverVPN renders the VPN DNS routing line.
func printResolverVPN(info *models.ResolverAuditInfo) {
	switch {
	case info.VPNInterface == "":
		fmt.Println("  ✅ VPN DNS routing: not applicable (no VPN interface detected)")
	case info.VPNDNSIntegrated == nil:
		fmt.Printf("  ℹ️  VPN DNS routing: %s up — cannot verify without systemd-resolved\n", info.VPNInterface)
	case *info.VPNDNSIntegrated:
		fmt.Printf("  ✅ VPN DNS routing: DNS routed through %s\n", info.VPNInterface)
	default:
		fmt.Printf("  ⚠️  VPN DNS routing: %s is up but DNS is not routed through it\n", info.VPNInterface)
	}
}

// printResolverNext prints the investigation commands.
func printResolverNext(info *models.ResolverAuditInfo) {
	if info.ResolverType != "systemd-resolved" || !info.ResolverActive {
		return
	}
	fmt.Println("\nNext:")
	fmt.Println("  → resolvectl status")
	fmt.Println("  → resolvectl query sigok.verteiltesysteme.net")
}
