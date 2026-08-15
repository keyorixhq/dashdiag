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
	data, err := readFile(fmt.Sprintf("/proc/%d/wchan", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readComm(pid int) string {
	data, err := readFile(fmt.Sprintf("/proc/%d/comm", pid)) // #nosec G703 -- pid is an integer from /proc glob, not user input
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (c *ProcessesCollector) Collect(ctx context.Context) (any, error) {
	if runtime.GOOS == "darwin" {
		return c.collectDarwin(ctx)
	}
	return c.collectLinux(ctx)
}

func (c *ProcessesCollector) collectLinux(ctx context.Context) (*models.ProcessInfo, error) {
	dirs, err := glob("/proc/[0-9]*")
	if err != nil {
		return nil, fmt.Errorf("globbing /proc: %w", err)
	}

	info := &models.ProcessInfo{
		Total:       len(dirs),
		ZombieProcs: make([]models.ProcessState, 0),
		HungProcs:   make([]models.ProcessState, 0),
	}
	selfPID := os.Getpid()
	for _, dir := range dirs {
		// internal-collectors-27-03: dirs can hold up to maxCappedDirEntries
		// (200k) PIDs on a busy host — without a ctx check here, this loop (and
		// the goroutine running it) outlives both the caller's cancellation and
		// the collector's own advertised Timeout().
		if err := ctx.Err(); err != nil {
			break
		}
		data, err := readFile(filepath.Join(dir, "stat")) // #nosec G304 -- root is hardcoded to /proc; dir is from glob("/proc/[0-9]*"), not user input
		if err != nil {
			continue
		}
		name, state, ppid, err := parseProcStat(data)
		if err != nil || (state != "Z" && state != "D") {
			continue
		}
		// Skip kernel threads — they legitimately run in D state
		// (jbd2, kworker, kswapd, ksoftirqd, migration, etc.). ppid==2
		// (kthreadd) and the kernel-set PF_KTHREAD flag are both read from
		// data the kernel controls, not the process's self-reported comm
		// name (spoofable via prctl(PR_SET_NAME) — a userspace process can
		// rename itself "kworker/0:1" and be silently exempted from
		// HungProcs otherwise).
		if ppid == 2 || isKernelThreadByFlag(data) {
			continue
		}
		// Skip processes that are direct children of dsd itself. dsd spawns
		// subprocesses (ss, journalctl, smartctl, …) and there is a brief window
		// between a child exiting and dsd reaping it where it shows as a zombie.
		// Counting our own transient children produced an intermittent false
		// "N zombie process(es)" WARN — ps run afterwards showed none. Mirrors
		// the darwin path's selfPID skip.
		if ppid == selfPID {
			continue
		}
		pid := pidFromDir(dir)
		// Skip shell-parented zombies — transient, always self-healing.
		// Verified via /proc/<ppid>/exe (kernel-set, not the spoofable comm
		// name) — see isVerifiedShellParent.
		if isVerifiedShellParent(ppid) {
			continue
		}
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
	// runCmd (Source.Run) so the process snapshot is captured and replayed
	// hermetically — a direct exec here re-counts the live process table on replay.
	out, err := runCmd(ctx, "ps", "axo", "pid,ppid,stat,comm")
	if err != nil {
		return &models.ProcessInfo{}, nil
	}
	lines := strings.Split(out, "\n")
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
		if ppid == selfPID {
			continue
		}
		// Skip zombies whose parent is an interactive shell.
		// Shells create brief zombies between fork() and wait() for every command
		// they run — these are transient and always self-healing.
		if isShell(pidName[ppid]) {
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

// procFlagKthread is PF_KTHREAD (include/linux/sched.h), the bit in
// /proc/<pid>/stat's flags field (field 9) the kernel sets exclusively for
// genuine kernel threads. Unlike the process's self-reported comm name
// (spoofable via prctl(PR_SET_NAME)), this is kernel-controlled and cannot be
// set by userspace.
const procFlagKthread = 0x00200000

// isKernelThreadByFlag reports whether data (the raw /proc/<pid>/stat content
// already read by the caller) has PF_KTHREAD set. Returns false — not proven
// a kernel thread — on any parse failure, so the caller's ppid==2 (kthreadd)
// check remains the fallback signal rather than this silently exempting an
// unparseable entry.
func isKernelThreadByFlag(data []byte) bool {
	s := string(data)
	end := strings.LastIndex(s, ")")
	if end < 0 {
		return false
	}
	fields := strings.Fields(s[end+1:])
	if len(fields) < 7 {
		return false
	}
	flags, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return false
	}
	return flags&procFlagKthread != 0
}

// isShell returns true for common interactive shells.
// Shells routinely create transient zombie children between fork() and wait().
// These self-heal within milliseconds and are never actionable.
func isShell(name string) bool {
	switch name {
	case "bash", "sh", "zsh", "fish", "tcsh", "csh", "dash", "ksh", "ash":
		return true
	}
	return false
}

// isVerifiedShellParent reports whether ppid's actual executable (not its
// self-reported comm name) is a known shell. internal-collectors-27-02: comm
// is spoofable via prctl(PR_SET_NAME) — a process could rename itself "bash"
// to exempt its own zombie/hung children from ever being reported, hiding a
// real leak. /proc/<pid>/exe is a symlink the kernel sets at exec() time and
// userspace cannot rewrite, so it's the kernel-verified signal isKernelThreadByFlag
// uses for the analogous kernel-thread exemption above. Returns false (not
// exempted) when the link can't be read — an unreadable parent must count
// its zombie/hung child rather than silently trust an unverifiable comm name.
func isVerifiedShellParent(ppid int) bool {
	target, err := readLink(fmt.Sprintf("/proc/%d/exe", ppid))
	if err != nil {
		return false
	}
	return isShell(filepath.Base(target))
}
