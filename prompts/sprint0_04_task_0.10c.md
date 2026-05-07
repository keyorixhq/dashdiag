# DashDiag — Sprint 0: Tasks 0.10 Part C
## Collectors: clock, fdlimits, processes, systemd, sysctl, mac_policy
## Paste into Claude Code

---

## TASK 0.10 Part C — 6 remaining collectors

Paste this into Claude Code:

```
Create these 6 collectors. Each follows the same injectable reader pattern.
Build tags: //go:build linux on any Linux-specific file, //go:build darwin on macOS-specific.
Run: go build ./... && go test ./internal/collectors/... -v -race when done.

---

FILE: internal/collectors/clock.go
Name: "Clock", Timeout: 2s

From SPEC.md ClockInfo model:
type ClockInfo struct {
    Synced        bool    `json:"synced"`
    OffsetMs      float64 `json:"offset_ms"`       // -1 if unavailable (macOS)
    Source        string  `json:"source"`           // timedatectl / chronyc / systemsetup
    Status        string  `json:"status"`
    StatusReason  string  `json:"status_reason"`
}

// NetworkInfo — result model for network quick check.
// Lives in internal/models/network.go
type NetworkInfo struct {
    Interfaces    []InterfaceInfo `json:"interfaces"`
    GatewayPingMs float64         `json:"gateway_ping_ms"`
    InternetPingMs float64        `json:"internet_ping_ms"`
    DNSResolvesMs  float64        `json:"dns_resolves_ms"`
    CloseWaitCount int             `json:"close_wait_count"`
    NATDetected    bool            `json:"nat_detected"`
    Status         string          `json:"status"`
    StatusReason   string          `json:"status_reason"`
}

type InterfaceInfo struct {

Implementation:
- parseTimedatectl(r io.Reader) (synced bool, offsetMs float64, err error)
  Parse lines: "NTPSynchronized=yes" → synced=true
               "NTPOffsetUsec=12345" → offsetMs = 12345/1000.0
- Linux primary: exec.CommandContext(ctx, "timedatectl", "show",
    "--property=NTPSynchronized,NTPOffset")
- Linux fallback (if timedatectl fails): exec chronyc tracking
    Parse "System time offset" line: "System time offset    :   0.000123456 seconds"
    offsetMs = parsed_value * 1000
- macOS: exec.CommandContext(ctx, "systemsetup", "-getusingnetworktime")
    Parse "Network Time: On" → synced=true, OffsetMs=-1 (not available)
- Return *models.ClockInfo — never crash if command not found (graceful degradation)

testdata/fixtures/clock/timedatectl_healthy.txt:
  NTPSynchronized=yes
  NTPOffsetUsec=4231

testdata/fixtures/clock/timedatectl_unsynced.txt:
  NTPSynchronized=no
  NTPOffsetUsec=0

FuzzParseTimedatectl test.

---

FILE: internal/collectors/fdlimits.go
Name: "FDLimits", Timeout: 1s

From SPEC.md FDInfo model:
type FDInfo struct {
    OpenCount         uint64         `json:"open_count"`          // system-wide open FDs
    MaxCount          uint64         `json:"max_count"`           // kernel maximum
    UsedPct           float64        `json:"used_pct"`
    HotProcesses      []FDProcessInfo `json:"hot_processes"`      // processes near per-process limit
    DeletedOpenFiles  int            `json:"deleted_open_files"`  // deleted-but-open count
    DeletedOpenSizeGB float64        `json:"deleted_open_size_gb"` // disk held by deleted files
    Status            string         `json:"status"`
    StatusReason      string         `json:"status_reason"`
}

type FDProcessInfo struct {
    PID       int     `json:"pid"`
    Name      string  `json:"name"`
    OpenFDs   int     `json:"open_fds"`
    SoftLimit int     `json:"soft_limit"`
    UsedPct   float64 `json:"used_pct"`
}
```

**Output:**
```
✅ File descriptors: 4,821 / 524,288  (1%)

# Per-process saturation:
⚠️  nginx (PID 1234): 982/1024 FDs (96% of ulimit) ← about to hit limit
   → cat /proc/1234/limits | grep "open files"
   → ls /proc/1234/fd | wc -l
   → lsof -p 1234 | tail -20

# Deleted-but-open files (ghost space):
⚠️  3 deleted file(s) holding 4.2GB — df shows full but du doesn't
   → lsof +L1  (find which processes hold deleted files)
   → restart the holding process to reclaim disk space

Implementation:
- System FD: read /proc/sys/fs/file-nr
  Format: "open_fds unused_fds max_fds"
  OpenCount = field[0], MaxCount = field[2], UsedPct = OpenCount/MaxCount*100
- Per-process hot detection (scan /proc/[0-9]*/):
  Read /proc/PID/limits, find "Max open files" row, parse soft limit
  Count entries in /proc/PID/fd/ (os.ReadDir)
  Flag as hot if fdCount/softLimit > 0.8
  Collect top 5 hottest processes into HotProcesses []FDProcessInfo
- Deleted-but-open: check symlink targets in /proc/PID/fd/* for "(deleted)" suffix
  Count and sum sizes via /proc/PID/fdinfo/* (line "size:")
- macOS: sysctl kern.maxfiles for MaxCount, skip /proc scanning

testdata/fixtures/fdlimits/file_nr.txt:
  4821  0  1048576

---

FILE: internal/collectors/processes.go
Name: "Processes", Timeout: 2s

From SPEC.md ProcessState model:
type ProcessState struct {
    PID         int     `json:"pid"`
    Name        string  `json:"name"`
    State       string  `json:"state"`   // "Z" = zombie, "D" = hung (uninterruptible)
    PPID        int     `json:"ppid"`
    CPU         float64 `json:"cpu_pct"`
    MemMB       float64 `json:"mem_mb"`
    WChan       string  `json:"wchan"`   // kernel function process is waiting in (D-state only)
    //   read from /proc/<PID>/wchan — world-readable, single word
    //   examples: "io_schedule" (disk wait), "nfs_wait" (NFS stale), "futex_wait" (lock)
}

type ProcessInfo struct {
    ZombieCount   int            `json:"zombie_count"`
    HungCount     int            `json:"hung_count"`   // D-state processes
    ZombieProcs   []ProcessState `json:"zombie_procs"`
    HungProcs     []ProcessState `json:"hung_procs"`
    Status        string         `json:"status"`
    StatusReason  string         `json:"status_reason"`
}
```

**`internal/models/disk.go` — add filesystem health fields:**

Implementation:
- parseProcStat(data []byte) (name, state string, err error)
  Parse /proc/PID/stat: name is between ( ), state is next field
- Scan /proc/[0-9]* directories (filepath.Glob)
- Read /proc/PID/stat for each — parse name, state
- Z = zombie (collect into slice)
- D = uninterruptible sleep
  For D-state: read /proc/PID/wchan (kernel function name)
- Return []models.ProcessState (only zombies and D-state processes)
  If empty slice returned, analysis layer marks as OK
- macOS: exec ps -eo pid,ppid,comm,stat — parse State column for Z/D

testdata/fixtures/processes/stat_running.txt:
  1234 (nginx) S 1 1234 1234 0 -1 ...

testdata/fixtures/processes/stat_zombie.txt:
  5678 (defunct) Z 1234 5678 5678 0 -1 ...

FuzzParseProcStat test (must handle malformed input without panic).

---

FILE: internal/collectors/systemd.go
Name: "Systemd", Timeout: 3s

From SPEC.md SystemdInfo model:
type SystemdInfo struct {
    Available    bool     `json:"available"`     // false on non-systemd systems
    FailedUnits  []string `json:"failed_units"`  // units in state=failed
    StuckUnits   []string `json:"stuck_units"`   // units stuck in state=activating
    Status       string   `json:"status"`
    StatusReason string   `json:"status_reason"`
}
```

**`internal/models/sysctl.go`:**

```go
package models

type SysctlInfo struct {
    VMSwappiness int    `json:"vm_swappiness"`
    NetSomaxconn int    `json:"net_core_somaxconn"`
    FSFileMax    int    `json:"fs_file_max"`
    KernelPIDMax int    `json:"kernel_pid_max"`
    PIDCount     int    `json:"pid_count"`       // current live process count
    Status       string `json:"status"`
    StatusReason string `json:"status_reason"`
}
```

**`internal/models/mac_policy.go`:**


Implementation:
- Check platform.SystemdAvailable() first
  If false: return &models.SystemdInfo{Available: false}, nil
- exec.CommandContext(ctx, "systemctl", "list-units", "--state=failed",
    "--no-legend", "--no-pager", "--plain")
  Parse each line: first field is unit name
- exec.CommandContext(ctx, "systemctl", "list-units", "--state=activating",
    "--no-legend", "--no-pager", "--plain")
  Parse same way
- macOS: return &models.SystemdInfo{Available: false}, nil (no systemd)
- Return *models.SystemdInfo

---

FILE: internal/collectors/sysctl.go
Name: "Sysctl", Timeout: 1s

From SPEC.md SysctlInfo model:
type SysctlInfo struct {
    VMSwappiness int    `json:"vm_swappiness"`
    NetSomaxconn int    `json:"net_core_somaxconn"`
    FSFileMax    int    `json:"fs_file_max"`
    KernelPIDMax int    `json:"kernel_pid_max"`
    PIDCount     int    `json:"pid_count"`       // current live process count
    Status       string `json:"status"`
    StatusReason string `json:"status_reason"`
}
```

**`internal/models/mac_policy.go`:**

```go
package models

type MACPolicyInfo struct {
    SELinuxPresent  bool   `json:"selinux_present"`
    SELinuxMode     string `json:"selinux_mode"`    // "enforcing" / "permissive" / "disabled"
    SELinuxDenials  int    `json:"selinux_denials"` // AVC denials in last hour
    AppArmorPresent bool   `json:"apparmor_present"`
    AppArmorMode    string `json:"apparmor_mode"`   // "enforce" / "complain" / "disabled"
    Status          string `json:"status"`
    StatusReason    string `json:"status_reason"`

Implementation:
- Linux: read /proc/sys/net/core/somaxconn (parse as int)
- Linux: read /proc/sys/kernel/pid_max and count /proc/[0-9]* entries for PIDUsedPct
- Linux: read /proc/sys/vm/swappiness
- macOS: exec sysctl -n kern.ipc.somaxconn for somaxconn
         exec sysctl -n kern.maxproc for pid_max, ps -A | wc -l for pid count
- Return *models.SysctlInfo

---

FILE: internal/collectors/mac_policy.go
Name: "MACPolicy", Timeout: 5s

From SPEC.md MACPolicyInfo model:
type MACPolicyInfo struct {
    SELinuxPresent  bool   `json:"selinux_present"`
    SELinuxMode     string `json:"selinux_mode"`    // "enforcing" / "permissive" / "disabled"
    SELinuxDenials  int    `json:"selinux_denials"` // AVC denials in last hour
    AppArmorPresent bool   `json:"apparmor_present"`
    AppArmorMode    string `json:"apparmor_mode"`   // "enforce" / "complain" / "disabled"
    Status          string `json:"status"`
    StatusReason    string `json:"status_reason"`
}
```

---

**`internal/collectors/systemd.go` — failed and stuck unit detection:**

```go
package collectors

import (
    "context"
    "fmt"
    "os/exec"
    "strings"
    "time"

    "github.com/yourusername/dashdiag/internal/models"
)


Implementation:
- SELinux detection:
  exec.CommandContext(ctx, "getenforce") → parse "Enforcing"/"Permissive"/"Disabled"
  If enforcing: exec journalctl --since="1 hour ago" | grep -c "avc:  denied"
    (use exec with pipeline: count lines matching pattern)
  If getenforce not found: SELinuxPresent=false
- AppArmor detection:
  Read /sys/module/apparmor/parameters/enabled → "Y" = enabled
  If enabled: count lines in /sys/kernel/security/apparmor/profiles for profile count
- macOS: return &models.MACPolicyInfo{} with all fields false/empty (not applicable)
- Return *models.MACPolicyInfo

For ALL 6 collectors:
- Table-driven parser unit tests (t.Parallel())
- FuzzParse<Name> for any text parser
- testdata/fixtures/<name>/linux_healthy.txt
```

