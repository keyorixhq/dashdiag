package collectors

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type SysctlCollector struct{}

func NewSysctlCollector() *SysctlCollector { return &SysctlCollector{} }

func (c *SysctlCollector) Name() string           { return "Sysctl" }
func (c *SysctlCollector) Timeout() time.Duration { return 1 * time.Second }

// readIntFile reads a single integer from a file (e.g. /proc/sys/* files).
func readIntFile(path string) (int, error) {
	data, err := readFile(filepath.Clean(path))
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", path, err)
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", path, err)
	}
	return v, nil
}

func countProcDirs() int {
	dirs, _ := glob("/proc/[0-9]*")
	return len(dirs)
}

// readTaskCount returns the total number of tasks (processes AND threads)
// currently active, parsed from /proc/loadavg's "running/total" field (e.g.
// "0.52 0.43 0.32 3/412 8932" → 412). kernel.pid_max governs this whole task
// space — every CLONE_THREAD thread consumes its own slot under
// /proc/<pid>/task/<tid> — so countProcDirs() (top-level processes only)
// understates real PID-space usage on a thread-heavy host (JVM/Go clone
// storm), which could be at genuine task exhaustion (fork/clone EAGAIN) while
// reading a small, unconcerning percentage. Falls back to countProcDirs if
// /proc/loadavg is unreadable or unexpectedly formatted.
func readTaskCount() int {
	data, err := readFile("/proc/loadavg")
	if err != nil {
		return countProcDirs()
	}
	fields := strings.Fields(string(data))
	if len(fields) < 4 {
		return countProcDirs()
	}
	parts := strings.SplitN(fields[3], "/", 2)
	if len(parts) != 2 {
		return countProcDirs()
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return countProcDirs()
	}
	return n
}

func (c *SysctlCollector) Collect(ctx context.Context) (any, error) {
	if runtime.GOOS == "darwin" {
		return c.collectDarwin(ctx)
	}
	return c.collectLinux(ctx)
}

func (c *SysctlCollector) collectLinux(ctx context.Context) (*models.SysctlInfo, error) {
	info := &models.SysctlInfo{Available: true}
	// Best-effort reads — partial data is still useful
	// internal-collectors-32-01: a failed read must not silently become 0 — every
	// VMSwappiness heuristic below is a "> N" high-value check, so a read failure
	// masquerading as 0 reads as "swappiness is great" instead of "unmeasured",
	// hiding a real misconfiguration behind a false-OK. -1 is the same "unknown"
	// sentinel TCPTWReuse already uses below; every "> N" comparison naturally
	// treats it as below threshold, so it can never itself trigger a false WARN.
	if v, err := readIntFile("/proc/sys/vm/swappiness"); err == nil {
		info.VMSwappiness = v
	} else {
		info.VMSwappiness = -1
	}
	info.NetSomaxconn, _ = readIntFile("/proc/sys/net/core/somaxconn")
	info.FSFileMax, _ = readIntFile("/proc/sys/fs/file-max")
	info.KernelPIDMax, _ = readIntFile("/proc/sys/kernel/pid_max")
	info.PIDCount = readTaskCount()

	// Extended tuning fields
	info.NetRmemMax, _ = readIntFile("/proc/sys/net/core/rmem_max")
	info.NetWmemMax, _ = readIntFile("/proc/sys/net/core/wmem_max")
	// tcp_tw_reuse heuristic warns on the value 0 ("disabled"), so a failed read
	// (readIntFile returns 0) would be indistinguishable from a real 0 and could
	// false-warn. Use -1 as an "unknown" sentinel that the heuristic ignores.
	if v, err := readIntFile("/proc/sys/net/ipv4/tcp_tw_reuse"); err == nil {
		info.TCPTWReuse = v
	} else {
		info.TCPTWReuse = -1
	}
	info.TCPSynBacklog, _ = readIntFile("/proc/sys/net/ipv4/tcp_max_syn_backlog")
	info.VMMaxMapCount, _ = readIntFile("/proc/sys/vm/max_map_count")
	// internal-collectors-32-01: same "> N" false-OK risk as VMSwappiness above —
	// a failed read must not masquerade as a healthy 0.
	if v, err := readIntFile("/proc/sys/vm/dirty_ratio"); err == nil {
		info.VMDirtyRatio = v
	} else {
		info.VMDirtyRatio = -1
	}
	info.VMDirtyBackgroundRatio, _ = readIntFile("/proc/sys/vm/dirty_background_ratio")
	info.VMOvercommit, _ = readIntFile("/proc/sys/vm/overcommit_memory")
	info.FSInotifyWatches, _ = readIntFile("/proc/sys/fs/inotify/max_user_watches")

	// Uptime — used by correlation engine for sysctl-drift-after-reboot detection.
	if data, err := readFile("/proc/uptime"); err == nil {
		if fields := strings.Fields(string(data)); len(fields) >= 1 {
			if f, err := strconv.ParseFloat(fields[0], 64); err == nil {
				info.UptimeSeconds = int64(f)
			}
		}
	}

	// Detect workload from running process names
	info.Workload = detectWorkload(ctx)

	return info, nil
}

// detectWorkload scans /proc/*/comm to identify the primary workload.
func detectWorkload(ctx context.Context) string {
	procs := make(map[string]bool)
	dirs, _ := glob("/proc/[0-9]*")
	for _, dir := range dirs {
		// internal-collectors-32-02: dirs can hold up to maxCappedDirEntries
		// (200k) PIDs on a busy host, each requiring a comm-file read — without
		// a ctx check here, this loop can run well past the collector's own
		// advertised Timeout() (1s) with no way for the runner to preempt it
		// (same concern as processes.go's identical /proc/[0-9]* scan).
		if err := ctx.Err(); err != nil {
			break
		}
		comm, err := readFile(filepath.Join(dir, "comm")) // #nosec G304
		if err != nil {
			continue
		}
		procs[strings.TrimSpace(string(comm))] = true
	}

	switch {
	case procs["kubelet"] || procs["k3s"] || procs["k3s-server"]:
		return "k8s"
	case procs["nginx"] || procs["apache2"] || procs["httpd"] || procs["caddy"] || procs["haproxy"]:
		return "webserver"
	case procs["postgres"] || procs["mysqld"] || procs["mongod"] || procs["redis-server"] || procs["mariadbd"]:
		return "database"
	case procs["java"] && (procs["elasticsearch"] || procs["kibana"]):
		return "elasticsearch"
	case procs["dockerd"] || procs["containerd"]:
		return "container"
	default:
		return "default"
	}
}

func (c *SysctlCollector) collectDarwin(_ context.Context) (*models.SysctlInfo, error) {
	// macOS sysctl parameters are defaults and rarely misconfigured.
	// No actionable checks to surface — hide the row.
	return &models.SysctlInfo{Available: false}, nil
}
