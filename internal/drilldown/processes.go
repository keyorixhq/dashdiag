package drilldown

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	colParentPID = "PARENT_PID"
	colParentCmd = "PARENT_CMD"
)

// HungProcesses returns processes in uninterruptible sleep (state D).
func HungProcesses(ctx context.Context) (*models.Details, error) {
	if runtime.GOOS == "darwin" {
		return &models.Details{
			Type:  "kv_table",
			Title: "Hung processes",
			Note:  "Uninterruptible process listing not available on macOS.",
		}, nil
	}
	return hungProcessesLinuxAt(ctx, "/proc")
}

// procStatEntry is a minimal parsed /proc/PID/stat result.
type procStatEntry struct {
	pid  int
	name string
	ppid int
}

// walkProcsByState returns all processes whose /proc/PID/stat state field equals
// stateChar ('D' = uninterruptible, 'Z' = zombie, etc.). Processes that exit
// between directory listing and stat read are silently skipped.
func walkProcsByState(ctx context.Context, procRoot, stateChar string) ([]procStatEntry, error) {
	var mu sync.Mutex
	var entries []procStatEntry
	err := walkProcs(ctx, procRoot, func(pid int) error {
		path := filepath.Join(procRoot, fmt.Sprintf("%d", pid), "stat")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		name, rest, ok := parseProcStatComm(string(data))
		if !ok || len(rest) < 2 {
			return nil
		}
		if rest[0] != stateChar {
			return nil
		}
		ppid, _ := strconv.Atoi(rest[1])
		mu.Lock()
		entries = append(entries, procStatEntry{pid: pid, name: name, ppid: ppid})
		mu.Unlock()
		return nil
	})
	return entries, err
}

func hungProcessesLinuxAt(ctx context.Context, procRoot string) (*models.Details, error) {
	entries, err := walkProcsByState(ctx, procRoot, "D")
	if err != nil && len(entries) == 0 {
		return nil, err
	}

	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, []string{
			fmt.Sprintf("%d", e.pid),
			e.name,
			fmt.Sprintf("%d", e.ppid),
			procComm(procRoot, e.ppid),
		})
	}

	if len(rows) == 0 {
		return &models.Details{
			Type:  "kv_table",
			Title: "Hung (uninterruptible) processes",
			Note:  "processes exited D state before capture — D state is transient, run: ps aux | grep ' D '",
		}, nil
	}

	return &models.Details{
		Type:    tableProcesses,
		Title:   "Hung (uninterruptible) processes",
		Columns: []string{"PID", "NAME", colParentPID, colParentCmd},
		Rows:    rows,
	}, nil
}

// ZombiesWithParent returns zombie processes with their parent process info.
func ZombiesWithParent(ctx context.Context) (*models.Details, error) {
	if runtime.GOOS == "darwin" {
		return zombiesWithParentMac(ctx)
	}
	return zombiesWithParentLinux(ctx)
}

func zombiesWithParentLinux(ctx context.Context) (*models.Details, error) {
	return zombiesWithParentLinuxAt(ctx, "/proc")
}

func zombiesWithParentLinuxAt(ctx context.Context, procRoot string) (*models.Details, error) {
	entries, err := walkProcsByState(ctx, procRoot, "Z")
	if err != nil && len(entries) == 0 {
		return nil, err
	}

	rows := make([][]string, 0, len(entries))
	for _, z := range entries {
		rows = append(rows, []string{
			fmt.Sprintf("%d", z.pid),
			z.name,
			fmt.Sprintf("%d", z.ppid),
			procComm(procRoot, z.ppid),
		})
	}

	return &models.Details{
		Type:    tableProcesses,
		Title:   "Zombie processes (parent is the reaping offender)",
		Columns: []string{"ZOMBIE_PID", "ZOMBIE_NAME", colParentPID, colParentCmd},
		Rows:    rows,
	}, nil
}

func zombiesWithParentMac(ctx context.Context) (*models.Details, error) {
	out, err := runCmd(ctx, "ps", "-axo", "pid,stat,ppid,comm")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	rows := make([][]string, 0)

	// Build pid→comm index first
	pidComm := make(map[string]string)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pidComm[fields[0]] = strings.Join(fields[3:], " ")
	}

	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if !strings.Contains(fields[1], "Z") {
			continue
		}
		pid, stat, ppid := fields[0], fields[1], fields[2]
		_ = stat
		cmd := strings.Join(fields[3:], " ")
		parentCmd := pidComm[ppid]
		if parentCmd == "" {
			parentCmd = "?"
		}
		rows = append(rows, []string{pid, cmd, ppid, parentCmd})
	}

	return &models.Details{
		Type:    tableProcesses,
		Title:   "Zombie processes (parent is the reaping offender)",
		Columns: []string{"ZOMBIE_PID", "ZOMBIE_NAME", colParentPID, colParentCmd},
		Rows:    rows,
	}, nil
}
