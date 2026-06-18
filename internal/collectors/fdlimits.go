package collectors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
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
func deletedFilesFromEntries(pid string, fds []string) (count int, sizeGB float64) {
	for _, fd := range fds {
		target, err := readLink("/proc/" + pid + "/fd/" + fd)
		if err != nil || !strings.HasSuffix(target, "(deleted)") {
			continue
		}
		fi, err := statFile("/proc/" + pid + "/fd/" + fd)
		if err != nil {
			count++
			continue
		}
		count++
		sizeGB += float64(fi.Size) / 1e9
	}
	return count, sizeGB
}

func hotProcInfo(pid string, fdCount int) (models.FDProcessInfo, bool) {
	f, err := openFile(filepath.Join("/proc", pid, "limits")) // #nosec G304 -- root is hardcoded to /proc; pid is from OS directory listing, not user input
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
	nameData, _ := readFile(filepath.Join("/proc", pid, "comm")) // #nosec G304 -- root is hardcoded to /proc; pid is from OS directory listing, not user input
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
	f, err := openFile(c.fileNrPath)
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

	// The per-process scan is wall-clock-bounded (the ctx budget below) and walks a
	// live process list, so its result is inherently timing-dependent: under load two
	// passes scan a different subset of /proc and surface different hot processes /
	// deleted-file totals. Route the DERIVED result through Source.Cached so capture
	// records it once and `dsd replay` reproduces it verbatim — no re-scan, no timing.
	// Without this, two replays of one bundle disagreed (the FDLimits hot-process
	// table flickered) on a busy host — a replay hermeticity regression. On an older
	// bundle without the recorded key, cachedJSON errors and we keep the system-wide
	// FD usage (the primary signal), just without the per-process detail.
	var scan fdProcScan
	if err := cachedJSON("fdlimits/proc-scan", func() (any, error) {
		return c.scanProcesses(ctx), nil
	}, &scan); err == nil {
		info.HotProcesses = scan.Hot
		info.DeletedOpenFiles = scan.DeletedOpenFiles
		info.DeletedOpenSizeGB = scan.DeletedOpenSizeGB
	}
	return info, nil
}

// fdProcScan is the derived result of the per-process FD scan — the part that is
// timing-dependent and so must be recorded/replayed as a unit (see collectLinux).
type fdProcScan struct {
	Hot               []models.FDProcessInfo `json:"hot"`
	DeletedOpenFiles  int                    `json:"deleted_open_files"`
	DeletedOpenSizeGB float64                `json:"deleted_open_size_gb"`
}

// scanProcesses walks /proc for FD-hungry processes and open-but-deleted files.
// It is best-effort and ctx-budget-bounded: the system-wide FD usage is the primary
// signal (already set by the caller), so on a big/busy host we bail with what we have
// rather than blow the 1s budget — which would make the runner abandon the WHOLE
// result. The caller records this via Source.Cached so the budget-dependent subset is
// frozen at capture and replays identically.
func (c *FDLimitsCollector) scanProcesses(ctx context.Context) fdProcScan {
	var s fdProcScan
	dirs, _ := glob("/proc/[0-9]*")
	for _, dir := range dirs {
		if ctx.Err() != nil {
			break
		}
		pid := filepath.Base(dir)
		// Read each process's fd dir ONCE and reuse it for both the hot-process
		// FD count and the deleted-open-files scan (previously two ReadDirs/proc).
		// A non-root run can't read other users' fd dirs — that fails cheaply here.
		fdEntries, err := readDirNames(filepath.Join("/proc", pid, "fd"))
		if err != nil {
			continue
		}
		if p, ok := hotProcInfo(pid, len(fdEntries)); ok {
			s.Hot = append(s.Hot, p)
		}
		dc, ds := deletedFilesFromEntries(pid, fdEntries)
		s.DeletedOpenFiles += dc
		s.DeletedOpenSizeGB += ds
	}
	// Sort by FD pressure desc, PID asc as a tiebreaker so equal-pressure processes
	// order stably (and the top-5 cut is deterministic).
	sort.Slice(s.Hot, func(i, j int) bool {
		if s.Hot[i].UsedPct != s.Hot[j].UsedPct {
			return s.Hot[i].UsedPct > s.Hot[j].UsedPct
		}
		return s.Hot[i].PID < s.Hot[j].PID
	})
	if len(s.Hot) > 5 {
		s.Hot = s.Hot[:5]
	}
	return s
}

func (c *FDLimitsCollector) collectDarwin(ctx context.Context) (*models.FDInfo, error) {
	out, err := runCmd(ctx, "sysctl", "-n", "kern.maxfiles")
	if err != nil {
		return &models.FDInfo{}, nil
	}
	max, err := strconv.ParseUint(strings.TrimSpace(out), 10, 64)
	if err != nil {
		return &models.FDInfo{}, nil
	}
	return &models.FDInfo{MaxCount: max}, nil
}
