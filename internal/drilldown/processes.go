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
		fields := strings.Fields(string(data))
		if len(fields) < 5 {
			return nil
		}
		state := fields[2]
		if state != "Z" {
			return nil
		}
		name := strings.Trim(fields[1], "()")
		ppid, _ := strconv.Atoi(fields[3])

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
