package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func init() {
	rootCmd.AddCommand(cronCmd)
}

var cronCmd = &cobra.Command{
	Use:   "cron",
	Short: "Cron health — daemon status, job failures, quality issues, anacron staleness (~5s)",
	RunE:  runCron,
}

func runCron(cmd *cobra.Command, _ []string) error {
	return runDiagnostic(cmd, diagnostic{
		label:   "Cron health",
		timeout: 10 * time.Second,
		cols:    []runner.Collector{collectors.NewCronCollector()},
		jsonValue: func(r []runner.Result) (any, error) {
			info := resultData[*models.CronInfo](r)
			if info == nil {
				return nil, firstErr(r)
			}
			return info, nil
		},
		render: func(r []runner.Result, mode output.OutputMode, _ time.Duration) error {
			info := resultData[*models.CronInfo](r)
			if info == nil {
				return firstErr(r)
			}
			printCron(info, mode)
			return nil
		},
	})
}

func printCron(info *models.CronInfo, mode output.OutputMode) {
	human := mode == output.ModeHuman

	if human {
		fmt.Fprintln(os.Stdout, "\n⏰  Cron")
	}

	// Daemon status
	if info.DaemonActive {
		printLine(mode, "ok", "Daemon", info.DaemonName+" active")
	} else if info.AnacronPresent {
		printLine(mode, "info", "Daemon", "anacron only (no persistent cron daemon)")
	} else {
		printLine(mode, "warn", "Daemon", "not running")
		if info.SystemdTimers > 0 {
			fmt.Printf("     ℹ️  %d systemd timer(s) active\n", info.SystemdTimers)
		}
	}

	if info.AnacronPresent {
		printLine(mode, "ok", "Anacron", "present")
	}

	// Recent failures
	if len(info.Failures) == 0 {
		printLine(mode, "ok", "Failures (24h)", "none")
	} else {
		printLine(mode, "warn", "Failures (24h)", fmt.Sprintf("%d job(s)", len(info.Failures)))
		for _, f := range info.Failures {
			ago := "?"
			if f.AgoMin > 0 {
				ago = fmt.Sprintf("%dm ago", f.AgoMin)
			}
			fmt.Printf("     %-40s %s\n", truncate(f.Job, 40), ago)
			if human && f.Message != "" {
				fmt.Printf("       → %s\n", truncate(f.Message, 100))
			}
		}
	}

	// Quality issues
	if len(info.QualityIssues) == 0 {
		printLine(mode, "ok", "Quality", "no issues found")
	} else {
		printLine(mode, "warn", "Quality issues", fmt.Sprintf("%d file(s)", len(info.QualityIssues)))
		for _, j := range info.QualityIssues {
			fmt.Printf("     %s\n", j.Source)
			for _, issue := range j.Issues {
				fmt.Printf("       → %s\n", issue)
			}
		}
	}

	// Anacron staleness
	if len(info.AnacronJobs) > 0 {
		if human {
			fmt.Fprintln(os.Stdout, "\n[Anacron schedules]")
		}
		for _, j := range info.AnacronJobs {
			switch {
			case j.LastRunH < 0:
				printLine(mode, "warn", "cron."+j.Name, "never run")
			case j.OverdueH > 0:
				printLine(mode, "warn", "cron."+j.Name,
					fmt.Sprintf("overdue by %dh (last: %dh ago)", j.OverdueH, j.LastRunH))
			default:
				if j.LastRunH < 48 {
					printLine(mode, "ok", "cron."+j.Name,
						fmt.Sprintf("ran %dh ago", j.LastRunH))
				} else {
					printLine(mode, "ok", "cron."+j.Name,
						fmt.Sprintf("ran %dd ago", j.LastRunH/24))
				}
			}
		}
	}

	// Next steps for failures
	if human && (len(info.Failures) > 0 || !info.DaemonActive) {
		fmt.Fprintln(os.Stdout, "\nNext:")
		if !info.DaemonActive {
			fmt.Fprintln(os.Stdout, "  → "+analysis.PlatformServiceCmdSudo("systemctl enable --now crond"))
		}
		if len(info.Failures) > 0 {
			fmt.Fprintln(os.Stdout, "  → journalctl -u crond --since '24 hours ago' | grep -i failed")
		}
	}
}

// capSlice is defined in services.go — reused here via same package
var _ = strings.Join // ensure strings is used
