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

const (
	cronSectionDaemon   = "Daemon"
	cronPfxCron         = "cron."
	cronSectionFailures = "Failures (24h)"
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
		printLine(mode, "ok", cronSectionDaemon, info.DaemonName+" active")
	} else if info.AnacronPresent {
		printLine(mode, "info", cronSectionDaemon, "anacron only (no persistent cron daemon)")
	} else if info.SystemdTimers > 0 {
		// No cron daemon, but systemd timers handle scheduling — a legitimate modern
		// setup (Photon and other systemd-only images ship no cron at all). Not a
		// fault, so INFO not WARN. Mirrors checkCron's heuristic so cmd↔health agree.
		printLine(mode, "info", cronSectionDaemon,
			fmt.Sprintf("no cron daemon — %d systemd timer(s) handle scheduling", info.SystemdTimers))
	} else {
		printLine(mode, "warn", cronSectionDaemon,
			"not running — no cron daemon, anacron, or systemd timers; scheduled jobs will not run")
	}

	if info.AnacronPresent {
		printLine(mode, "ok", "Anacron", "present")
	}

	// Recent failures
	if len(info.Failures) == 0 && !info.FailureScanOK {
		// Neither journalctl nor /var/log/cron* was readable — an empty list means
		// "couldn't look", not "no failures". Don't render the green "none" (false-OK);
		// mirrors the health heuristic's "failure history not readable" INFO.
		printLine(mode, "info", cronSectionFailures, "not readable — recent job failures could be hidden (run as root / check journalctl)")
	} else if len(info.Failures) == 0 {
		printLine(mode, "ok", cronSectionFailures, "none")
	} else {
		printLine(mode, "warn", cronSectionFailures, fmt.Sprintf("%d job(s)", len(info.Failures)))
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
				// health logs never-run anacron as INFO (machine may simply have been
				// off at the scheduled time), not WARN — keep the two in step.
				printLine(mode, "info", cronPfxCron+j.Name, "never run")
			case j.OverdueH > 0:
				printLine(mode, "warn", cronPfxCron+j.Name,
					fmt.Sprintf("overdue by %dh (last: %dh ago)", j.OverdueH, j.LastRunH))
			default:
				if j.LastRunH < 48 {
					printLine(mode, "ok", cronPfxCron+j.Name,
						fmt.Sprintf("ran %dh ago", j.LastRunH))
				} else {
					printLine(mode, "ok", cronPfxCron+j.Name,
						fmt.Sprintf("ran %dd ago", j.LastRunH/24))
				}
			}
		}
	}

	// Next steps. Only suggest enabling crond when nothing schedules jobs (no
	// daemon, no anacron, no timers) — on a timers-only or anacron host that advice
	// is noise (and wrong: the host deliberately has no cron).
	noScheduler := !info.DaemonActive && !info.AnacronPresent && info.SystemdTimers == 0
	if human && (len(info.Failures) > 0 || noScheduler) {
		fmt.Fprintln(os.Stdout, "\nNext:")
		if noScheduler {
			fmt.Fprintln(os.Stdout, "  → "+analysis.PlatformServiceCmdSudo("systemctl enable --now crond"))
		}
		if len(info.Failures) > 0 {
			fmt.Fprintln(os.Stdout, "  → journalctl -u crond --since '24 hours ago' | grep -i failed")
		}
	}
}

// capSlice is defined in services.go — reused here via same package
var _ = strings.Join // ensure strings is used
