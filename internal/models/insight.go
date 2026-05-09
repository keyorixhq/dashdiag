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
}
