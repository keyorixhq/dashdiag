package models

// ProcMemMap is the breakdown from /proc/<PID>/smaps_rollup (or smaps sum).
type ProcMemMap struct {
	RSSKb          int `json:"rss_kb"`
	PssDirtyKb     int `json:"pss_dirty_kb"`     // true unique RAM footprint
	PrivateDirtyKb int `json:"private_dirty_kb"` // writable private pages
	PrivateCleanKb int `json:"private_clean_kb"` // read-only mapped files
	SharedCleanKb  int `json:"shared_clean_kb"`  // shared libraries etc.
	SharedDirtyKb  int `json:"shared_dirty_kb"`
	SwapKb         int `json:"swap_kb"`
}

// ProcOpenFile categorises a single entry from /proc/<PID>/fd.
type ProcOpenFile struct {
	FD      int    `json:"fd"`
	Type    string `json:"type"`    // file, socket, pipe, anon, eventfd, etc.
	Target  string `json:"target"`  // symlink target
	Deleted bool   `json:"deleted"` // path contains " (deleted)"
}

// ProcNetConn is a network connection extracted from /proc/net/tcp[6].
type ProcNetConn struct {
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
}

// ProcInfo is the output of `dsd proc <PID>`.
type ProcInfo struct {
	// Identity
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	Name       string `json:"name"`
	Cmdline    string `json:"cmdline"`
	User       string `json:"user"`
	ParentName string `json:"parent_name,omitempty"`
	CgroupName string `json:"cgroup_name,omitempty"` // last component of cgroup path
	UptimeSec  int    `json:"uptime_sec"`

	// State
	State  string `json:"state"`   // R, S, D, Z, T
	WChan  string `json:"wchan"`   // kernel function blocked on (D-state)
	DState bool   `json:"d_state"` // true when State == "D" (uninterruptible sleep)

	// Resources
	CPUSec     float64 `json:"cpu_sec"` // total CPU time (utime+stime)
	Threads    int     `json:"threads"`
	RSSMB      float64 `json:"rss_mb"`
	SwapMB     float64 `json:"swap_mb"`
	FDCount    int     `json:"fd_count"`
	FDLimit    int     `json:"fd_limit"`
	FDPressure bool    `json:"fd_pressure"` // FDCount > 80% of FDLimit

	// Memory map (from smaps_rollup or smaps)
	MemMap *ProcMemMap `json:"mem_map,omitempty"`

	// Open files (categorised)
	OpenFiles   []ProcOpenFile `json:"open_files,omitempty"`
	DeletedLibs []string       `json:"deleted_libs,omitempty"` // .so with "(deleted)"
	SocketCount int            `json:"socket_count"`
	FileCount   int            `json:"file_count"`
	PipeCount   int            `json:"pipe_count"`

	// Network connections for this process's sockets
	Connections []ProcNetConn `json:"connections,omitempty"`

	// Top-list mode (no PID given)
	TopProcs []ProcessMemStat `json:"top_procs,omitempty"`
}
