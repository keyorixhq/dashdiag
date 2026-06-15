package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ── Cron heuristics (Spec 9) ─────────────────────────────────────────────────

func checkCron(c models.CronInfo) []models.Insight {
	var out []models.Insight

	if !c.DaemonActive && c.AnacronPresent {
		out = append(out, insight("INFO", "Cron",
			"no persistent cron daemon — anacron only (jobs run when machine is up, not on exact schedule)",
			[]string{
				"to install persistent cron: dnf install cronie  (RHEL/Fedora)",
				"to install persistent cron: apt install cron    (Debian/Ubuntu)",
			},
		))
	} else if !c.DaemonActive && !c.AnacronPresent {
		if c.SystemdTimers > 0 {
			out = append(out, insight("INFO", "Cron",
				fmt.Sprintf("no cron daemon installed — %d systemd timer(s) active instead", c.SystemdTimers),
				[]string{"to inspect: systemctl list-timers"},
			))
		} else {
			out = append(out, insight("WARN", "Cron",
				"no cron daemon and no anacron — scheduled jobs will not run",
				[]string{
					"to install: dnf install cronie  (RHEL/Fedora)",
					"to install: apt install cron    (Debian/Ubuntu)",
				},
			))
		}
		return out
	}

	if len(c.Failures) > 0 {
		names := make([]string, 0, len(c.Failures))
		for _, f := range c.Failures {
			names = append(names, f.Job)
		}
		out = append(out, insight("WARN", "Cron",
			fmt.Sprintf("%d cron job failure(s) in the last 24h: %s",
				len(c.Failures), strings.Join(firstN(names, 3), ", ")),
			[]string{
				"to inspect: journalctl -u crond --since '24 hours ago' | grep -i failed",
				"to inspect: grep FAILED /var/log/cron",
			},
		))
	}

	out = append(out, checkCronQuality(c.QualityIssues)...)
	out = append(out, checkAnacronSchedules(c.AnacronJobs)...)

	return out
}

func checkCronQuality(issues []models.CronJob) []models.Insight {
	if len(issues) == 0 {
		return nil
	}
	var out []models.Insight
	var missingCmds, noPATH []string
	for _, j := range issues {
		for _, issue := range j.Issues {
			if strings.Contains(issue, "not found") {
				missingCmds = append(missingCmds, j.Source)
			} else if strings.Contains(issue, "PATH") {
				noPATH = append(noPATH, j.Source)
			}
		}
	}
	if len(missingCmds) > 0 {
		out = append(out, insight("WARN", "Cron",
			fmt.Sprintf("crontab references missing command(s) in: %s",
				strings.Join(firstN(missingCmds, 3), ", ")),
			[]string{
				"to inspect: grep -n '' /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null",
				"note: missing binaries cause silent failures — cron sends no warning",
			},
		))
	}
	if len(noPATH) > 0 {
		out = append(out, insight("INFO", "Cron",
			fmt.Sprintf("%d crontab file(s) use relative paths without PATH= set — jobs may fail with 'command not found'",
				len(noPATH)),
			[]string{
				"to fix: add PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin at the top of the crontab",
			},
		))
	}
	return out
}

func checkAnacronSchedules(jobs []models.AnacronJob) []models.Insight {
	var out []models.Insight
	for _, j := range jobs {
		if j.LastRunH < 0 {
			out = append(out, insight("INFO", "Cron",
				fmt.Sprintf("anacron cron.%s has never run — machine may not have been on at scheduled time", j.Name),
				[]string{fmt.Sprintf("to run now: anacron -f -n cron.%s", j.Name)},
			))
		} else if j.OverdueH > 0 {
			out = append(out, insight("WARN", "Cron",
				fmt.Sprintf("anacron cron.%s is %dh overdue (last run: %dh ago)", j.Name, j.OverdueH, j.LastRunH),
				[]string{
					fmt.Sprintf("to run now: anacron -f -n cron.%s", j.Name),
					"note: machine was likely off during scheduled window",
				},
			))
		}
	}
	return out
}
