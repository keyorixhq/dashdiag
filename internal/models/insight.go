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
}
