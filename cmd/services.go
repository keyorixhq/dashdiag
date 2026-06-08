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
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(servicesCmd)
	servicesCmd.AddCommand(servicesDeepCmd)
}

var servicesCmd = &cobra.Command{
	Use:   "services",
	Short: "Check configured service endpoints",
	RunE:  runServices,
}

var servicesDeepCmd = &cobra.Command{
	Use:   "deep",
	Short: "Systemd failure diagnosis — failed units, boot offenders, journal health (~10s)",
	RunE:  runServicesDeep,
}

func runServices(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	jsonOut, _ := cmd.Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	p := output.NewCommandProgress("Service health", 10*time.Second, mode, 1)
	p.Start()
	defer p.Done()

	var result runner.Result
	for r := range runner.RunAll(ctx, []runner.Collector{collectors.NewServicesCollector()}) {
		p.Step(r.Name)
		result = r
	}

	info, ok := result.Data.(*models.ServicesInfo)
	if !ok || info == nil {
		return result.Err
	}
	recordResultSeverity([]runner.Result{result})

	if mode == output.ModeJSON {
		data, err := json.MarshalIndent(info, "", "  ")
		if err == nil {
			_, _ = os.Stdout.Write(data)
			_, _ = os.Stdout.Write([]byte("\n"))
		}
		return nil
	}

	if len(info.Results) == 0 {
		printServicesEmpty(mode)
		return nil
	}

	printServicesResults(info.Results, mode)
	return nil
}

func runServicesDeep(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Parent().Flags().GetBool("plain")
	jsonOut, _ := cmd.Parent().Flags().GetBool("json")
	outputFmt := ""
	if jsonOut {
		outputFmt = "json"
	}
	mode := output.DetectMode(plain, false, outputFmt)

	cols := []runner.Collector{
		collectors.NewServicesCollector(),
		collectors.NewServicesDeepCollector(),
	}
	p := output.NewCommandProgress("Services deep", 15*time.Second, mode, len(cols))
	p.Start()
	defer p.Done()

	results := make(map[string]runner.Result)
	for r := range runner.RunAll(ctx, cols) {
		p.Step(r.Name)
		results[r.Name] = r
	}

	// Port health from existing services collector
	var portResults []models.ServiceResult
	if r, ok := results["Services"]; ok {
		if info, ok := r.Data.(*models.ServicesInfo); ok && info != nil {
			portResults = info.Results
		}
	}

	// Systemd deep from new collector
	var deep *models.ServicesDeepInfo
	if r, ok := results["ServicesDeep"]; ok {
		if info, ok := r.Data.(*models.ServicesDeepInfo); ok {
			deep = info
			deep.PortResults = portResults
		}
	}
	if deep == nil {
		deep = &models.ServicesDeepInfo{PortResults: portResults, JournalHealthy: true}
	}

	deepResults := make([]runner.Result, 0, len(results))
	for _, r := range results {
		deepResults = append(deepResults, r)
	}
	recordResultSeverity(deepResults) // port checks via the shared heuristic
	// ServicesDeepInfo has no shared heuristic — its severity is rendered straight
	// from the data, so mirror the renderer's worst signals into the exit code.
	if len(deep.FailedUnits) > 0 {
		recordExitCode(2)
	}
	if !deep.JournalHealthy {
		recordExitCode(1)
	}

	if mode == output.ModeJSON {
		data, err := json.MarshalIndent(deep, "", "  ")
		if err == nil {
			_, _ = os.Stdout.Write(data)
			_, _ = os.Stdout.Write([]byte("\n"))
		}
		return nil
	}

	printServicesDeep(deep, mode)
	return nil
}

// ── renderers ────────────────────────────────────────────────────────────────

func printServicesEmpty(mode output.OutputMode) {
	if mode == output.ModeHuman {
		fmt.Fprintln(os.Stdout, "ℹ️  No services configured yet.")
	} else {
		fmt.Fprintln(os.Stdout, "INFO: No services configured yet.")
	}
	fmt.Fprintln(os.Stdout, "    Add to ~/.dsd.yaml:")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "    services:")
	fmt.Fprintln(os.Stdout, "      - name: nginx")
	fmt.Fprintln(os.Stdout, "        host: localhost")
	fmt.Fprintln(os.Stdout, "        port: 80")
	fmt.Fprintln(os.Stdout, "        protocol: http")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "    Or run: dsd init  to configure automatically.")
}

func printServicesResults(results []models.ServiceResult, mode output.OutputMode) {
	for _, r := range results {
		statusKey := "ok"
		if !r.Reachable {
			statusKey = "warn"
		}
		if r.Status == "CRIT" {
			statusKey = "fail"
		}
		icon := output.StatusIcon(statusKey, mode)
		detail := fmt.Sprintf("%s:%d", r.Host, r.Port)
		if r.Reachable {
			detail += fmt.Sprintf("  %.0fms", r.LatencyMs)
			if r.StatusCode > 0 {
				detail += fmt.Sprintf("  HTTP %d", r.StatusCode)
			}
		} else if r.Error != "" {
			detail += "  " + r.Error
		}
		fmt.Printf("  %-16s %s  %s\n", r.Name, icon, detail)
	}
}

func printServicesDeep(info *models.ServicesDeepInfo, mode output.OutputMode) {
	human := mode == output.ModeHuman

	if len(info.PortResults) > 0 {
		if human {
			fmt.Fprintln(os.Stdout, "\n⚙️  Services deep")
			fmt.Fprintln(os.Stdout, "[Port health]")
		}
		printServicesResults(info.PortResults, mode)
	}

	if human {
		fmt.Fprintln(os.Stdout, "\n[Systemd health]")
	}
	printSystemdHealth(info, mode)
}

func printSystemdHealth(info *models.ServicesDeepInfo, mode output.OutputMode) {
	human := mode == output.ModeHuman

	if len(info.FailedUnits) == 0 {
		printLine(mode, "ok", "Failed units", "none")
	} else {
		printLine(mode, "fail", "Failed units", fmt.Sprintf("%d", len(info.FailedUnits)))
		for _, u := range info.FailedUnits {
			exitStr := ""
			if u.ExitCode != 0 {
				exitStr = fmt.Sprintf(" (exit %d)", u.ExitCode)
			}
			fmt.Printf("     %-40s %s%s\n", u.Name, u.SubState, exitStr)
			for _, line := range u.LastLogLines {
				if line == "" {
					continue
				}
				fmt.Printf("       → %s\n", truncate(line, 100))
			}
		}
	}

	if len(info.NeedsDaemonReload) == 0 {
		printLine(mode, "ok", "Daemon-reload", "not needed")
	} else {
		printLine(mode, "warn", "Daemon-reload needed", strings.Join(info.NeedsDaemonReload, ", "))
		if human {
			fmt.Fprintln(os.Stdout, "     → systemctl daemon-reload")
		}
	}

	if len(info.MaskedUnits) == 0 {
		printLine(mode, "ok", "Masked units", "none")
	} else {
		printLine(mode, "info", "Masked units",
			fmt.Sprintf("%d: %s", len(info.MaskedUnits), strings.Join(capSlice(info.MaskedUnits, 3), ", ")))
	}

	if info.JournalHealthy {
		printLine(mode, "ok", "Journal", "healthy")
	} else {
		printLine(mode, "warn", "Journal", "corruption detected")
		if info.JournalLastValid != "" {
			fmt.Printf("     last valid: %s\n", info.JournalLastValid)
		}
		if human {
			fmt.Fprintln(os.Stdout, "     → journalctl --verify")
			fmt.Fprintln(os.Stdout, "     → journalctl --rotate && journalctl --vacuum-time=1s")
		}
	}

	if len(info.BootOffenders) > 0 {
		if human {
			fmt.Fprintln(os.Stdout, "\n[Boot top offenders — real services only]")
		}
		for _, o := range info.BootOffenders {
			fmt.Printf("  %6dms  %s\n", o.DurationMs, o.Unit)
		}
	}

	// User units
	if info.UserUnits != nil {
		if !info.UserUnits.Available {
			printLine(mode, "info", "User units", "no user systemd daemon running")
		} else if len(info.UserUnits.Failed) == 0 {
			printLine(mode, "ok", "User units", "none failed")
		} else {
			printLine(mode, "warn", "User units",
				fmt.Sprintf("%d failed", len(info.UserUnits.Failed)))
			for _, u := range info.UserUnits.Failed {
				fmt.Printf("     %s\n", u.Name)
				for _, line := range u.LastLogLines {
					fmt.Printf("       → %s\n", truncate(line, 100))
				}
			}
		}
	}

	// Next steps for failed units
	if human && len(info.FailedUnits) > 0 {
		fmt.Fprintln(os.Stdout, "\nNext:")
		for _, u := range info.FailedUnits {
			fmt.Printf("  → systemctl status %s\n", u.Name)
			fmt.Printf("  → journalctl -u %s -n 50 --no-pager\n", u.Name)
		}
	}
}

func printLine(mode output.OutputMode, level, label, value string) {
	icon := output.StatusIcon(level, mode)
	fmt.Printf("  %s  %-30s %s\n", icon, label, value)
}

// truncate shortens s to at most n runes with an ellipsis, slicing by rune (not
// byte) so a multibyte character at the boundary is never split.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// capSlice returns at most n elements from ss.
func capSlice(ss []string, n int) []string {
	if len(ss) <= n {
		return ss
	}
	return ss[:n]
}
