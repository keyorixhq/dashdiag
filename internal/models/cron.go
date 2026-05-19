package models

// CronJob is a parsed crontab entry with quality issues detected.
type CronJob struct {
	Source string   `json:"source"`           // file path or "user:<name>"
	Line   string   `json:"line"`             // original line (truncated)
	Issues []string `json:"issues,omitempty"` // quality problems found
}

// CronFailure is a recent job failure extracted from cron log or journal.
type CronFailure struct {
	Job     string `json:"job"`     // command or cron entry description
	Message string `json:"message"` // last log line mentioning failure
	AgoMin  int    `json:"ago_min"` // minutes since failure
}

// AnacronJob tracks the last-run timestamp for an anacron period.
type AnacronJob struct {
	Name     string `json:"name"`       // "daily", "weekly", "monthly"
	LastRunH int    `json:"last_run_h"` // hours since last run (-1 = never run)
	OverdueH int    `json:"overdue_h"`  // 0 = not overdue
}

// CronInfo is the output of CronCollector (`dsd cron`).
type CronInfo struct {
	DaemonActive   bool          `json:"daemon_active"`
	DaemonName     string        `json:"daemon_name"` // "crond", "cron", "fcron"
	AnacronPresent bool          `json:"anacron_present"`
	SystemdTimers  int           `json:"systemd_timers,omitempty"` // active timers count when cron not installed
	QualityIssues  []CronJob     `json:"quality_issues,omitempty"`
	Failures       []CronFailure `json:"failures,omitempty"`
	AnacronJobs    []AnacronJob  `json:"anacron_jobs,omitempty"`
}
