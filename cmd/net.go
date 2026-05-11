package cmd

import (
	"context"
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
}

var netCmd = &cobra.Command{
	Use:   "net",
	Short: "Network health — interfaces, latency, DNS, connections",
	RunE:  runNet,
}

func runNet(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	mode := output.DetectMode(plain, false, "")
	ctrCtx := platform.DetectContainerContext()

	p := output.NewCommandProgress("Network health", 10*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewNetworkCollector()}) {
		p.Step(r.Name)
		result = r
	}

	elapsed := p.Elapsed()

	info, ok := result.Data.(*models.NetworkInfo)
	if !ok || info == nil {
		return result.Err
	}

	printNetReport(info, mode, elapsed, ctrCtx)
	return nil
}

func printNetReport(info *models.NetworkInfo, mode output.OutputMode, elapsed time.Duration, ctrCtx platform.ContainerContext) {
	sep := strings.Repeat("─", 56)
	timing := fmt.Sprintf(" in %.1fs", elapsed.Seconds())

	// Interfaces
	fmt.Printf("\nInterfaces (%d)\n", len(info.Interfaces))
	for _, iface := range info.Interfaces {
		statusIcon := "✅"
		if !iface.Up {
			statusIcon = "❌"
		}
		details := iface.IP
		if iface.SpeedMbps > 0 {
			details += fmt.Sprintf("  %d Mbps", iface.SpeedMbps)
		}
		if iface.RxDrops > 0 || iface.TxDrops > 0 {
			details += fmt.Sprintf("  drops rx:%d tx:%d", iface.RxDrops, iface.TxDrops)
		}
		primary := ""
		if iface.Name == info.PrimaryInterface {
			primary = "  ← primary"
		}
		fmt.Printf("  %s  %-12s %s%s\n", statusIcon, iface.Name, details, primary)
	}

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
