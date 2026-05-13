package collectors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
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

func fdCountForPID(pid string) int {
	entries, err := os.ReadDir("/proc/" + pid + "/fd")
	if err != nil {
		return 0
	}
	return len(entries)
}

func deletedFilesForPID(pid string) (count int, sizeGB float64) {
	fds, err := os.ReadDir("/proc/" + pid + "/fd")
	if err != nil {
		return 0, 0
	}
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

func hotProcInfo(pid string) (models.FDProcessInfo, bool) {
	f, err := os.Open(filepath.Join("/proc", pid, "limits")) // #nosec G304 -- root is hardcoded to /proc; pid is from OS directory listing, not user input
	if err != nil {
		return models.FDProcessInfo{}, false
	}
	softLimit := parseSoftLimit(f)
	_ = f.Close()
	if softLimit <= 0 {
		return models.FDProcessInfo{}, false
	}
	fdCount := fdCountForPID(pid)
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
	return c.collectLinux()
}

func (c *FDLimitsCollector) collectLinux() (*models.FDInfo, error) {
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
		pid := filepath.Base(dir)
		if p, ok := hotProcInfo(pid); ok {
			hot = append(hot, p)
		}
		dc, ds := deletedFilesForPID(pid)
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
	out, err := exec.CommandContext(ctx, "sysctl", "-n", "kern.maxfiles").Output()
	if err != nil {
		return &models.FDInfo{}, nil
	}
	max, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return &models.FDInfo{}, nil
	}
	return &models.FDInfo{MaxCount: max}, nil
}
