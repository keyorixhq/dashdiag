package models

// Details holds inline drill-down data for WARN/CRIT insights.
// Type values: "process_table", "tcp_states", "ping_stats", "directory_sizes",
// "kv_table", "log_tail", "sysctl_table", "policy_table".
type Details struct {
	Type    string            `json:"type"`
	Title   string            `json:"title"`
	Columns []string          `json:"columns,omitempty"`
	Rows    [][]string        `json:"rows,omitempty"`
	KV      map[string]string `json:"kv,omitempty"`
	Note    string            `json:"note,omitempty"`
}

type Insight struct {
	Level   string   `json:"level"`
	Check   string   `json:"check"`
	Message string   `json:"message"`
	Hints   []string `json:"hints"`
	Details *Details `json:"details,omitempty"`

	// Unverified marks an insight whose Level reflects a downgrade because the
	// underlying data could NOT be read/measured this run (permission denied,
	// unreadable file, collector error) — not a genuine "nothing wrong here"
	// observation. Consumers that diff two runs (internal/baseline) must never
	// treat a transition into or out of an Unverified insight as an improvement:
	// a prior CRIT that reads as an Unverified INFO this run (e.g. re-run
	// non-root) has not been resolved, it simply couldn't be checked.
	Unverified bool `json:"unverified,omitempty"`

	// NeedsRoot refines Unverified: the check could not run ONLY because dsd was
	// not root (a root-only file, log or ioctl). It is set only on a non-root
	// run; the same read failing as root stays a plain Unverified. A needs-root
	// insight is shown ("needs root: N checks skipped — re-run with sudo") but
	// does not by itself floor the verdict, so an ordinary non-root run on a
	// stock distro is not "Not fully verified" forever. Any other unverified
	// insight still floors at WARN.
	NeedsRoot bool `json:"needs_root,omitempty"`

	// UnverifiedReason says why an Unverified insight could not look (one of
	// UnverifiedReasons: needs_root, timeout, unreadable, collector_error, parse,
	// not_recorded). Set only where Unverified is; render.Coverage maps it to
	// coverage_reason. Empty on an insight from older data: the reader falls back
	// to "unverified".
	UnverifiedReason string `json:"unverified_reason,omitempty"`
}
