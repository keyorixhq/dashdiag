package models

// TimelineHint is a structured hint block for a known event pattern.
// Mirrors the dsd health hint contract: explain → inspect → fix → persist.
type TimelineHint struct {
	Explain string `json:"explain,omitempty"` // what the message means
	Inspect string `json:"inspect,omitempty"` // command to diagnose further
	Fix     string `json:"fix,omitempty"`     // command to remediate
	Persist string `json:"persist,omitempty"` // command to make fix permanent
}

// TimelineEvent is a single event in the unified incident timeline.
type TimelineEvent struct {
	TimestampUnix int64         `json:"timestamp_unix"`
	TimeStr       string        `json:"time_str"`       // human-readable
	Source        string        `json:"source"`         // "journal", "dmesg", "kernel"
	Level         string        `json:"level"`          // "CRIT", "WARN", "INFO"
	Unit          string        `json:"unit,omitempty"` // systemd unit or kernel subsystem
	Message       string        `json:"message"`
	Count         int           `json:"count,omitempty"` // deduplicated repeat count
	Hint          *TimelineHint `json:"hint,omitempty"`  // structured fix hint
}

// TimelineInfo holds merged system events for dsd timeline.
type TimelineInfo struct {
	WindowHours int             `json:"window_hours"`
	Events      []TimelineEvent `json:"events"`
	CritCount   int             `json:"crit_count"`
	WarnCount   int             `json:"warn_count"`
	// Load average spikes sampled at /proc/loadavg-like intervals
	LoadSpikes []LoadSpike `json:"load_spikes,omitempty"`
}

// LoadSpike is a point-in-time load average reading from sar or /proc/loadavg.
type LoadSpike struct {
	TimestampUnix int64   `json:"timestamp_unix"`
	TimeStr       string  `json:"time_str"`
	Load1         float64 `json:"load1"`
	Load5         float64 `json:"load5"`
	Load15        float64 `json:"load15"`
}
