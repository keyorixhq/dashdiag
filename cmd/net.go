package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(netCmd)
	netCmd.AddCommand(netDeepCmd)
}

var netCmd = &cobra.Command{
	Use:   "net",
	Short: "Network snapshot — interfaces, gateway, internet (~3s)",
	RunE:  runNet,
}

var netDeepCmd = &cobra.Command{
	Use:   "deep",
	Short: "Deep network analysis — jitter, bonds, wireless (~30s)",
	RunE:  runNetDeep,
}

func runNet(cmd *cobra.Command, _ []string) error {
	return runNetWith(cmd, collectors.NewNetworkCollector(), "Network snapshot", 3*time.Second)
}

func runNetDeep(cmd *cobra.Command, _ []string) error {
	p := output.NewCommandProgress("Deep network analysis", 30*time.Second, output.ModeHuman, 1)
	p.Note("ℹ️  Traceroute only runs if problem detected")
	return runNetWith(cmd, collectors.NewNetworkDeepCollector(), "Deep network analysis", 30*time.Second)
}

func runNetWith(cmd *cobra.Command, col collectors.Collector, label string, estimate time.Duration) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	p := output.NewCommandProgress(label, estimate, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{col}) {
		p.Step(r.Name)
		result = r
	}

	if result.Err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", result.Err)
		return result.Err
	}

	info, ok := result.Data.(*models.NetworkInfo)
	if !ok || info == nil {
		return nil
	}

	printNetworkInfo(info, mode)
	return nil
}

func printNetworkInfo(info *models.NetworkInfo, mode output.OutputMode) {
	hostname, _ := os.Hostname()
	fmt.Printf("\nNetwork — %s\n\n", hostname)

	for _, iface := range info.Interfaces {
		statusKey := "ok"
		if !iface.Up {
			statusKey = "warn"
		}
		icon := output.StatusIcon(statusKey, mode)
		ip := iface.IP
		if ip == "" {
			ip = "no IP"
		}
		state := "up"
		if !iface.Up {
			state = "down"
		}
		fmt.Printf("  %-14s %s  %-18s %s\n", iface.Name, icon, ip, state)
	}

	fmt.Println()
	fmtMs := func(ms float64) string {
		if ms < 0 {
			return "unreachable"
		}
		return fmt.Sprintf("%.1fms", ms)
	}
	fmt.Printf("  %-14s %s\n", "Gateway:", fmtMs(info.GatewayPingMs))
	fmt.Printf("  %-14s %s\n", "Internet:", fmtMs(info.InternetPingMs))
	fmt.Printf("  %-14s %s\n", "DNS:", fmtMs(info.DNSResolvesMs))
	if info.JitterMs > 0 {
		fmt.Printf("  %-14s %.2fms (stddev over 20 samples)\n", "Jitter:", info.JitterMs)
	}
	if info.CloseWaitCount > 0 {
		fmt.Printf("  %-14s %d\n", "CLOSE_WAIT:", info.CloseWaitCount)
	}
	fmt.Println()

	if info.GatewayPingMs < 0 && info.InternetPingMs < 0 {
		fmt.Println("  ❌  No network connectivity")
	} else {
		fmt.Println("  ✅  Network healthy")
	}
}
