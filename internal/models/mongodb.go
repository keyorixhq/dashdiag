package models

// MongoDBInfo holds guest-side health for a local MongoDB server. Gated on the
// mongo port answering with the mongo shell present. The headline is replica-set
// health: a set with no PRIMARY can't accept writes (election in progress or
// quorum lost). Needs shell access (no auth, or credentials); when metrics can't
// be read, MetricsRead stays false — never a false green.
type MongoDBInfo struct {
	Detected       bool   `json:"detected"`
	Version        string `json:"version,omitempty"`
	IsReplicaSet   bool   `json:"is_replica_set,omitempty"`
	ReplicaSetName string `json:"replica_set_name,omitempty"`

	MetricsRead bool `json:"metrics_read"`
	// ReplStatusRead is true only when rs.status() actually returned. It can throw
	// (auth-gated separately from db.hello()) even on a healthy primary, so without
	// this flag HasPrimary defaults false and the no-primary CRIT fires from a
	// FAILED read — a false-CRIT crying wolf on a healthy set.
	ReplStatusRead bool `json:"repl_status_read,omitempty"`
	HasPrimary     bool `json:"has_primary,omitempty"`
	DownMembers    int  `json:"down_members,omitempty"`
	Members        int  `json:"members,omitempty"`

	ConnCurrent   int `json:"conn_current,omitempty"`
	ConnAvailable int `json:"conn_available,omitempty"`

	StatusReason string `json:"status_reason,omitempty"`
}
