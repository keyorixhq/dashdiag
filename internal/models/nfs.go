package models

// NFSMount holds health data for a single NFS mount point.
type NFSMount struct {
	Mount           string   `json:"mount"`
	Server          string   `json:"server"`  // IP or hostname
	Export          string   `json:"export"`  // server-side path
	FSType          string   `json:"fs_type"` // nfs or nfs4
	Options         string   `json:"options,omitempty"`
	Healthy         bool     `json:"healthy"`    // passed non-blocking stat check
	Stale           bool     `json:"stale"`      // timed out (2s)
	LatencyMs       int      `json:"latency_ms"` // stat() round-trip, 0 if stale
	ServerReachable bool     `json:"server_reachable"`
	NFSPortOpen     bool     `json:"nfs_port_open"` // TCP 2049 reachable
	OptionsWarnings []string `json:"options_warnings,omitempty"`
	RetransPerMin   float64  `json:"retrans_per_min,omitempty"`
}

// NFSInfo holds aggregate NFS health for the system.
type NFSInfo struct {
	Mounts         []NFSMount `json:"mounts"`
	StaleMounts    int        `json:"stale_mounts"`
	RpcbindActive  bool       `json:"rpcbind_active"`
	ReadOpsPerMin  float64    `json:"read_ops_per_min,omitempty"`
	WriteOpsPerMin float64    `json:"write_ops_per_min,omitempty"`
	RetransPerMin  float64    `json:"retrans_per_min,omitempty"`
}
