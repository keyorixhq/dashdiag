package collectors

import (
	"context"
	"fmt"
	"os"
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
	data, err := os.ReadFile(filepath.Clean(path))
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
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	return len(dirs)
}

func (c *SysctlCollector) Collect(ctx context.Context) (interface{}, error) {
	if runtime.GOOS == "darwin" {
		return c.collectDarwin(ctx)
	}
	return c.collectLinux()
}

func (c *SysctlCollector) collectLinux() (*models.SysctlInfo, error) {
	info := &models.SysctlInfo{}
	// Best-effort reads — partial data is still useful
	info.VMSwappiness, _ = readIntFile("/proc/sys/vm/swappiness")
	info.NetSomaxconn, _ = readIntFile("/proc/sys/net/core/somaxconn")
	info.FSFileMax, _ = readIntFile("/proc/sys/fs/file-max")
	info.KernelPIDMax, _ = readIntFile("/proc/sys/kernel/pid_max")
	info.PIDCount = countProcDirs()

	// Extended tuning fields
	info.NetRmemMax, _ = readIntFile("/proc/sys/net/core/rmem_max")
	info.NetWmemMax, _ = readIntFile("/proc/sys/net/core/wmem_max")
	info.TCPTWReuse, _ = readIntFile("/proc/sys/net/ipv4/tcp_tw_reuse")
	info.TCPSynBacklog, _ = readIntFile("/proc/sys/net/ipv4/tcp_max_syn_backlog")
	info.VMMaxMapCount, _ = readIntFile("/proc/sys/vm/max_map_count")
	info.VMDirtyRatio, _ = readIntFile("/proc/sys/vm/dirty_ratio")
	info.VMDirtyBackgroundRatio, _ = readIntFile("/proc/sys/vm/dirty_background_ratio")
	info.VMOvercommit, _ = readIntFile("/proc/sys/vm/overcommit_memory")
	info.FSInotifyWatches, _ = readIntFile("/proc/sys/fs/inotify/max_user_watches")

	// Detect workload from running process names
	info.Workload = detectWorkload()

	return info, nil
}

// detectWorkload scans /proc/*/comm to identify the primary workload.
func detectWorkload() string {
	procs := make(map[string]bool)
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, dir := range dirs {
		comm, err := os.ReadFile(filepath.Join(dir, "comm")) // #nosec G304
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

func readSysctlInt(ctx context.Context, key string) int {
	out, err := runCmd(ctx, "sysctl", "-n", key) // #nosec G204 -- command is hardcoded "sysctl"; key is from internal constant list, not user input
	if err != nil {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0
	}
	return v
}

func (c *SysctlCollector) collectDarwin(ctx context.Context) (*models.SysctlInfo, error) {
	info := &models.SysctlInfo{
		KernelPIDMax: readSysctlInt(ctx, "kern.maxproc"),
		FSFileMax:    readSysctlInt(ctx, "kern.maxfiles"),
		VMSwappiness: -1,
	}
	out, err := runCmd(ctx, "ps", "-A")
	if err == nil {
		lines := strings.Count(out, "\n")
		if lines > 1 {
			info.PIDCount = lines - 1
		}
	}
	return info, nil
}
