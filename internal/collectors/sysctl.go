package collectors

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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
	return info, nil
}

func readSysctlInt(ctx context.Context, key string) int {
	out, err := exec.CommandContext(ctx, "sysctl", "-n", key).Output() // #nosec G204 -- command is hardcoded "sysctl"; key is from internal constant list, not user input
	if err != nil {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0
	}
	return v
}

func (c *SysctlCollector) collectDarwin(ctx context.Context) (*models.SysctlInfo, error) {
	info := &models.SysctlInfo{
		// NetSomaxconn intentionally omitted — kern.ipc.somaxconn (macOS default 128)
		// is not comparable to Linux net.core.somaxconn; analysis thresholds are Linux-only.
		KernelPIDMax: readSysctlInt(ctx, "kern.maxproc"),
		FSFileMax:    readSysctlInt(ctx, "kern.maxfiles"),
		VMSwappiness: -1,
	}
	out, err := exec.CommandContext(ctx, "ps", "-A").Output()
	if err == nil {
		lines := strings.Count(string(out), "\n")
		if lines > 1 {
			info.PIDCount = lines - 1 // subtract header
		}
	}
	return info, nil
}
