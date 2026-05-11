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
	rootCmd.AddCommand(servicesCmd)
}

var servicesCmd = &cobra.Command{
	Use:   "services",
	Short: "Check configured service endpoints",
	RunE:  runServices,
}

func runServices(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	plain, _ := cmd.Flags().GetBool("plain")
	mode := output.DetectMode(plain, false, "")

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

	if len(info.Results) == 0 {
		printServicesEmpty(mode)
		return nil
	}

	printServicesResults(info.Results, mode)
	return nil
}

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
