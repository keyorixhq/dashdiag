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

// HungProcesses returns processes in uninterruptible sleep (state D).
func HungProcesses(ctx context.Context) (*models.Details, error) {
	if runtime.GOOS == "darwin" {
		return &models.Details{
			Type:  "kv_table",
			Title: "Hung processes",
			Note:  "Uninterruptible process listing not available on macOS.",
		}, nil
	}
	var mu sync.Mutex
	type hungInfo struct {
		pid  int
		name string
		ppid int
	}
	var hung []hungInfo

	err := walkProcs(ctx, func(pid int) error {
		path := filepath.Join("/proc", fmt.Sprintf("%d", pid), "stat")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		name, rest, ok := parseProcStatComm(string(data))
		if !ok || len(rest) < 2 {
			return nil
		}
		if rest[0] != "D" { // stat field 3 = state
			return nil
		}
		ppid, _ := strconv.Atoi(rest[1]) // stat field 4
		mu.Lock()
		hung = append(hung, hungInfo{pid: pid, name: name, ppid: ppid})
		mu.Unlock()
		return nil
	})
	if err != nil && len(hung) == 0 {
		return nil, err
	}

	rows := make([][]string, 0, len(hung))
	for _, h := range hung {
		parentCmd := procComm(h.ppid)
		rows = append(rows, []string{
			fmt.Sprintf("%d", h.pid),
			h.name,
			fmt.Sprintf("%d", h.ppid),
			parentCmd,
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
		Type:    "process_table",
		Title:   "Hung (uninterruptible) processes",
		Columns: []string{"PID", "NAME", "PARENT_PID", "PARENT_CMD"},
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

type zombieInfo struct {
	pid       int
	name      string
	ppid      int
	parentCmd string
}

func zombiesWithParentLinux(ctx context.Context) (*models.Details, error) {
	var mu sync.Mutex
	var zombies []zombieInfo

	err := walkProcs(ctx, func(pid int) error {
		path := filepath.Join("/proc", fmt.Sprintf("%d", pid), "stat")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		name, rest, ok := parseProcStatComm(string(data))
		if !ok || len(rest) < 2 {
			return nil
		}
		if rest[0] != "Z" { // stat field 3 = state
			return nil
		}
		ppid, _ := strconv.Atoi(rest[1]) // stat field 4

		parentComm := procComm(ppid)
		mu.Lock()
		zombies = append(zombies, zombieInfo{
			pid: pid, name: name, ppid: ppid, parentCmd: parentComm,
		})
		mu.Unlock()
		return nil
	})
	if err != nil && len(zombies) == 0 {
		return nil, err
	}

	rows := make([][]string, 0, len(zombies))
	for _, z := range zombies {
		rows = append(rows, []string{
			fmt.Sprintf("%d", z.pid),
			z.name,
			fmt.Sprintf("%d", z.ppid),
			z.parentCmd,
		})
	}

	return &models.Details{
		Type:    "process_table",
		Title:   "Zombie processes (parent is the reaping offender)",
		Columns: []string{"ZOMBIE_PID", "ZOMBIE_NAME", "PARENT_PID", "PARENT_CMD"},
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
		Type:    "process_table",
		Title:   "Zombie processes (parent is the reaping offender)",
		Columns: []string{"ZOMBIE_PID", "ZOMBIE_NAME", "PARENT_PID", "PARENT_CMD"},
		Rows:    rows,
	}, nil
}
