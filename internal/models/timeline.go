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

// TimelineIncident is a cluster of events that occurred close together in time —
// the "what happened" story, distilled from the raw event stream so an operator
// sees a handful of incidents instead of a wall of individual lines.
type TimelineIncident struct {
	StartUnix   int64  `json:"start_unix"`
	EndUnix     int64  `json:"end_unix"`
	StartStr    string `json:"start_str"`
	DurationSec int64  `json:"duration_sec"`
	Level       string `json:"level"`       // worst level in the cluster
	Summary     string `json:"summary"`     // one-line headline (worst event, with unit)
	EventCount  int    `json:"event_count"` // total events (incl. dedup repeat counts)
	Sources     int    `json:"sources,omitempty"`
}

// TimelineInfo holds merged system events for dsd timeline.
type TimelineInfo struct {
	WindowHours int                `json:"window_hours"`
	Events      []TimelineEvent    `json:"events"`
	Incidents   []TimelineIncident `json:"incidents,omitempty"` // events clustered into incidents
	CritCount   int                `json:"crit_count"`
	WarnCount   int                `json:"warn_count"`
	// SourcesUnavailable is true when BOTH event sources (journald and the kernel
	// ring buffer) failed to read — typically a non-root run under
	// kernel.dmesg_restrict=1 with restricted journal access. Zero events then means
	// "no source was read", not "no incidents", so the renderer must say so rather
	// than report a clean timeline.
	SourcesUnavailable bool `json:"sources_unavailable,omitempty"`
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
