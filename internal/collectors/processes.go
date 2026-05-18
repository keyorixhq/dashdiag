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

type ProcessesCollector struct{}

func NewProcessesCollector() *ProcessesCollector { return &ProcessesCollector{} }

func (c *ProcessesCollector) Name() string           { return "Processes" }
func (c *ProcessesCollector) Timeout() time.Duration { return 2 * time.Second }

// parseProcStat extracts name, state, and ppid from /proc/PID/stat content.
// Name lives between the first '(' and last ')' to handle spaces and special chars.
func parseProcStat(data []byte) (name, state string, ppid int, err error) {
	s := string(data)
	start := strings.Index(s, "(")
	end := strings.LastIndex(s, ")")
	if start < 0 || end <= start {
		return "", "", 0, fmt.Errorf("malformed stat: no name field")
	}
	name = s[start+1 : end]
	rest := strings.TrimSpace(s[end+1:])
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return "", "", 0, fmt.Errorf("malformed stat: too few fields after name")
	}
	state = fields[0]
	ppid, err = strconv.Atoi(fields[1])
	if err != nil {
		return "", "", 0, fmt.Errorf("parsing ppid: %w", err)
	}
	return name, state, ppid, nil
}

func pidFromDir(dir string) int {
	v, _ := strconv.Atoi(filepath.Base(dir))
	return v
}

func readWchan(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/wchan", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readComm(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)) // #nosec G703 -- pid is an integer from /proc glob, not user input
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (c *ProcessesCollector) Collect(ctx context.Context) (interface{}, error) {
	if runtime.GOOS == "darwin" {
		return c.collectDarwin(ctx)
	}
	return c.collectLinux()
}

func (c *ProcessesCollector) collectLinux() (*models.ProcessInfo, error) {
	dirs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return nil, fmt.Errorf("globbing /proc: %w", err)
	}

	info := &models.ProcessInfo{
		Total:       len(dirs),
		ZombieProcs: make([]models.ProcessState, 0),
		HungProcs:   make([]models.ProcessState, 0),
	}
	for _, dir := range dirs {
		data, err := os.ReadFile(filepath.Join(dir, "stat")) // #nosec G304 -- root is hardcoded to /proc; dir is from filepath.Glob("/proc/[0-9]*"), not user input
		if err != nil {
			continue
		}
		name, state, ppid, err := parseProcStat(data)
		if err != nil || (state != "Z" && state != "D") {
			continue
		}
		// Skip kernel threads — they legitimately run in D state
		// (jbd2, kworker, kswapd, ksoftirqd, migration, etc.)
		if ppid == 2 || isKernelThread(name) {
			continue
		}
		pid := pidFromDir(dir)
		ps := models.ProcessState{PID: pid, PPID: ppid, Name: name, State: state}
		switch state {
		case "Z":
			ps.ParentName = readComm(ppid)
			info.ZombieCount++
			info.ZombieProcs = append(info.ZombieProcs, ps)
		case "D":
			ps.WChan = readWchan(pid)
			info.HungCount++
			info.HungProcs = append(info.HungProcs, ps)
		}
	}
	return info, nil
}

// collectDarwin uses ps to find zombie and D-state processes on macOS.
// stat is placed before comm so spaces in process names never shift its column position.
func (c *ProcessesCollector) collectDarwin(ctx context.Context) (*models.ProcessInfo, error) {
	out, err := exec.CommandContext(ctx, "ps", "axo", "pid,ppid,stat,comm").Output()
	if err != nil {
		return &models.ProcessInfo{}, nil
	}
	lines := strings.Split(string(out), "\n")
	info := &models.ProcessInfo{
		Total:       len(lines) - 1, // subtract header line
		ZombieProcs: make([]models.ProcessState, 0),
		HungProcs:   make([]models.ProcessState, 0),
	}

	// Build pid→name map so we can resolve parent names.
	pidName := make(map[int]string, len(lines))
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		pidName[pid] = fields[3]
	}

	selfPID := os.Getpid()

	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		stat := fields[2]
		if !strings.HasPrefix(stat, "Z") && !strings.HasPrefix(stat, "D") {
			continue
		}
		// Skip zombies that are direct children of dsd itself — these are
		// subprocesses (ps, brew, etc.) that dsd spawned and hasn't reaped yet.
		// They are not real zombies; they disappear within milliseconds.
		if ppid == selfPID {
			continue
		}
		ps := models.ProcessState{
			PID:        pid,
			PPID:       ppid,
			Name:       pidName[pid],
			ParentName: pidName[ppid],
			State:      string(stat[0]),
		}
		if strings.HasPrefix(stat, "Z") {
			info.ZombieCount++
			info.ZombieProcs = append(info.ZombieProcs, ps)
		} else {
			info.HungCount++
			info.HungProcs = append(info.HungProcs, ps)
		}
	}
	return info, nil
}

// isKernelThread returns true if the process name matches known kernel thread patterns.
// These always run in D state legitimately and should not be flagged as hung.
func isKernelThread(name string) bool {
	kernelPrefixes := []string{
		"jbd2/", "kworker/", "kswapd", "ksoftirqd/", "migration/",
		"rcu_", "kthreadd", "kcompact", "kdevtmpfs", "netns",
		"khungtaskd", "oom_reaper", "writeback", "kblockd",
		"md", "edac-poller", "devfreq_", "watchdogd",
	}
	for _, prefix := range kernelPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
