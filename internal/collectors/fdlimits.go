package collectors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type FDLimitsCollector struct {
	fileNrPath string
}

func NewFDLimitsCollector() *FDLimitsCollector {
	return &FDLimitsCollector{fileNrPath: "/proc/sys/fs/file-nr"}
}

func (c *FDLimitsCollector) Name() string           { return "FDLimits" }
func (c *FDLimitsCollector) Timeout() time.Duration { return 1 * time.Second }

// parseFileNr parses /proc/sys/fs/file-nr: "open_fds  unused_fds  max_fds"
func parseFileNr(r io.Reader) (open, max uint64, err error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return 0, 0, fmt.Errorf("empty file-nr")
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 3 {
		return 0, 0, fmt.Errorf("file-nr: expected 3 fields, got %d", len(fields))
	}
	open, err = strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing open count: %w", err)
	}
	max, err = strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing max count: %w", err)
	}
	return open, max, scanner.Err()
}

// parseSoftLimit finds the "Max open files" soft limit in /proc/PID/limits.
func parseSoftLimit(r io.Reader) int {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Max open files") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return -1
		}
		if fields[3] == "unlimited" {
			return math.MaxInt32
		}
		v, err := strconv.Atoi(fields[3])
		if err != nil {
			return -1
		}
		return v
	}
	return -1
}

// deletedFilesFromEntries scans a process's already-read fd entries for
// open-but-deleted files (the classic "disk full but du shows space" cause).
// Takes the entries from the caller's single ReadDir to avoid re-reading.
func deletedFilesFromEntries(pid string, fds []os.DirEntry) (count int, sizeGB float64) {
	for _, fd := range fds {
		target, err := os.Readlink("/proc/" + pid + "/fd/" + fd.Name())
		if err != nil || !strings.HasSuffix(target, "(deleted)") {
			continue
		}
		fi, err := os.Stat("/proc/" + pid + "/fd/" + fd.Name())
		if err != nil {
			count++
			continue
		}
		count++
		sizeGB += float64(fi.Size()) / 1e9
	}
	return count, sizeGB
}

func hotProcInfo(pid string, fdCount int) (models.FDProcessInfo, bool) {
	f, err := os.Open(filepath.Join("/proc", pid, "limits")) // #nosec G304 -- root is hardcoded to /proc; pid is from OS directory listing, not user input
	if err != nil {
		return models.FDProcessInfo{}, false
	}
	softLimit := parseSoftLimit(f)
	_ = f.Close()
	if softLimit <= 0 {
		return models.FDProcessInfo{}, false
	}
	usedPct := float64(fdCount) / float64(softLimit) * 100
	if usedPct <= 70 {
		return models.FDProcessInfo{}, false
	}
	// Skip socket-activated transient helpers (sshd-auth, systemd per-connection
	// units) that have artificially low soft limits set by their service config.
	// These are not real FD exhaustion risks.
	if softLimit <= 16 && fdCount <= 32 {
		return models.FDProcessInfo{}, false
	}
	pidInt, _ := strconv.Atoi(pid)
	nameData, _ := os.ReadFile(filepath.Join("/proc", pid, "comm")) // #nosec G304 -- root is hardcoded to /proc; pid is from OS directory listing, not user input
	name := strings.TrimSpace(string(nameData))
	return models.FDProcessInfo{
		PID:       pidInt,
		Name:      name,
		OpenFDs:   fdCount,
		SoftLimit: softLimit,
		UsedPct:   usedPct,
	}, true
}

func (c *FDLimitsCollector) Collect(ctx context.Context) (interface{}, error) {
	if runtime.GOOS == "darwin" {
		return c.collectDarwin(ctx)
	}
	return c.collectLinux(ctx)
}

func (c *FDLimitsCollector) collectLinux(ctx context.Context) (*models.FDInfo, error) {
	f, err := os.Open(c.fileNrPath)
	if err != nil {
		return nil, fmt.Errorf("opening file-nr: %w", err)
	}
	open, max, err := parseFileNr(f)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("parsing file-nr: %w", err)
	}

	info := &models.FDInfo{OpenCount: open, MaxCount: max}
	if max > 0 {
		info.UsedPct = float64(open) / float64(max) * 100
	}

	dirs, _ := filepath.Glob("/proc/[0-9]*")
	var hot []models.FDProcessInfo
	for _, dir := range dirs {
		// The per-process scan is best-effort and scales with process count. The
		// system-wide FD usage above is the primary signal and is already set, so
		// on a big/busy host we bail with what we have rather than blow the 1s
		// budget — which would make the runner abandon the WHOLE result and drop
		// the system-wide usage too. Cheap check; runs before each process.
		if ctx.Err() != nil {
			break
		}
		pid := filepath.Base(dir)
		// Read each process's fd dir ONCE and reuse it for both the hot-process
		// FD count and the deleted-open-files scan (previously two ReadDirs/proc).
		// A non-root run can't read other users' fd dirs — that fails cheaply here.
		fdEntries, err := os.ReadDir(filepath.Join("/proc", pid, "fd"))
		if err != nil {
			continue
		}
		if p, ok := hotProcInfo(pid, len(fdEntries)); ok {
			hot = append(hot, p)
		}
		dc, ds := deletedFilesFromEntries(pid, fdEntries)
		info.DeletedOpenFiles += dc
		info.DeletedOpenSizeGB += ds
	}
	sort.Slice(hot, func(i, j int) bool { return hot[i].UsedPct > hot[j].UsedPct })
	if len(hot) > 5 {
		hot = hot[:5]
	}
	info.HotProcesses = hot
	return info, nil
}

func (c *FDLimitsCollector) collectDarwin(ctx context.Context) (*models.FDInfo, error) {
	out, err := localeSafeCmd(ctx, "sysctl", "-n", "kern.maxfiles").Output()
	if err != nil {
		return &models.FDInfo{}, nil
	}
	max, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return &models.FDInfo{}, nil
	}
	return &models.FDInfo{MaxCount: max}, nil
}
