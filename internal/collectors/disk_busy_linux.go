//go:build linux

package collectors

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// fsBusyUsedPctGate mirrors analysis.DefaultDiskWarnPct (80.0). Collectors
// cannot import analysis (forbidden: collectors->analysis) and a config-
// lowered threshold can't reach this layer either, so the gate is a fixed,
// slightly-generous constant rather than the live configured value — it only
// bounds which mounts pay the fuser/proc-fd scan cost, never a verdict.
const fsBusyUsedPctGate = 80.0

// fsBusyMaxProcs caps the number of busy-process entries returned per
// filesystem, so a mount with hundreds of openers doesn't blow up the scan
// cost (proc/fd fallback) or the output.
const fsBusyMaxProcs = 50

// fsBusyInherentlyReadOnly mirrors analysis.IsInherentlyReadOnlyFS: image
// filesystems that are always full and always read-only by design never need
// a busy-process scan. Duplicated rather than imported — see fsBusyUsedPctGate.
func fsBusyInherentlyReadOnly(fsType string) bool {
	switch fsType {
	case "iso9660", "squashfs", "erofs", "cramfs":
		return true
	}
	return false
}

// needsBusyCheck reports whether fs is at risk enough (near-full, or
// unexpectedly read-only) to justify the cost of a busy-process scan.
func needsBusyCheck(fs models.FilesystemInfo) bool {
	if fsBusyInherentlyReadOnly(fs.FSType) {
		return false
	}
	return fs.UsedPct >= fsBusyUsedPctGate || fs.ReadOnly
}

// collectBusyFilesystems populates BusyProcesses/BusyCheckNeedsRoot in place
// for every at-risk filesystem. Cheap no-op for healthy mounts — needsBusyCheck
// gates before any fuser/proc scan runs (Spec 4 addendum, §4-add).
func collectBusyFilesystems(filesystems []models.FilesystemInfo) {
	nonRoot := os.Geteuid() != 0
	for i := range filesystems {
		fs := &filesystems[i]
		if !needsBusyCheck(*fs) {
			continue
		}
		fs.BusyProcesses = collectBusyProcesses(fs.Mount)
		fs.BusyCheckNeedsRoot = nonRoot
	}
}

// collectBusyProcesses lists which PIDs hold files open on mountpoint.
// Prefers `fuser -m`; falls back to a /proc/*/fd scan (same technique dsd
// proc uses for open-file detection) when fuser is not installed — e.g.
// busybox systems and minimal containers, where psmisc is typically absent.
func collectBusyProcesses(mountpoint string) []models.FSBusyProcess {
	if _, err := lookPath("fuser"); err == nil {
		return fuserBusyProcesses(mountpoint)
	}
	return procFDBusyProcesses(mountpoint)
}

// fuserBusyProcesses uses `fuser -m` only to discover which PIDs touch
// mountpoint — its most basic, stable contract. Name/user/write-status are
// then resolved from /proc, exactly like the no-fuser fallback below, rather
// than trusting fuser's own per-PID access-mode annotations: verified live
// (Debian 13/psmisc, 2026-07-07) that `fuser -m` omits the access suffix
// entirely, and that `fuser -v -m`'s USER/PID/ACCESS table is split across
// stdout (bare PID token, mid-line) and stderr (everything else) — two
// separately-buffered streams that can't be reassembled in the right order,
// so neither mode's annotations are trustworthy input.
func fuserBusyProcesses(mountpoint string) []models.FSBusyProcess {
	// fuser exits non-zero when it finds nothing to report; stdout is still the
	// authoritative answer either way (mirrors the smartctl exit-code handling in
	// collectSMART — parse output, don't gate on exit status).
	out, _ := runCmdTimeout(3*time.Second, "fuser", "-m", mountpoint)
	prefix := strings.TrimSuffix(mountpoint, "/") + "/"
	pids := parseFuserPIDs(out)
	procs := make([]models.FSBusyProcess, 0, len(pids))
	for _, pid := range pids {
		base := "/proc/" + strconv.Itoa(pid)
		write, _ := fdMatchesMount(base, mountpoint, prefix)
		procs = append(procs, models.FSBusyProcess{
			PID: pid, Command: procComm(base), User: procUser(base), Write: write,
		})
		if len(procs) >= fsBusyMaxProcs {
			break
		}
	}
	return procs
}

// parseFuserPIDs extracts the PID set from `fuser -m <mountpoint>` output:
// one or more lines of "<mountpoint>: PID1[suffix] PID2[suffix] ...". Any
// trailing access-mode letters are discarded (see fuserBusyProcesses doc).
func parseFuserPIDs(out string) []int {
	var pids []int
	seen := map[int]bool{}
	for _, line := range strings.Split(out, "\n") {
		if idx := strings.IndexByte(line, ':'); idx >= 0 {
			line = line[idx+1:]
		}
		for _, tok := range strings.Fields(line) {
			end := 0
			for end < len(tok) && tok[end] >= '0' && tok[end] <= '9' {
				end++
			}
			if end == 0 {
				continue
			}
			pid, err := strconv.Atoi(tok[:end])
			if err != nil || seen[pid] {
				continue
			}
			seen[pid] = true
			pids = append(pids, pid)
		}
	}
	return pids
}

// procComm reads /proc/<PID>/comm for a short process name.
func procComm(base string) string {
	data, err := readFile(base + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// procFDBusyProcesses is the fallback busy-process scan when fuser is not
// installed: walk every /proc/<pid>/fd and match each open file's target
// against mountpoint. Same technique as dsd proc's own open-file detection
// (collectOpenFiles in proc_linux.go), applied filesystem-wide instead of
// per-PID. Visibility is bounded by privilege — see BusyCheckNeedsRoot.
func procFDBusyProcesses(mountpoint string) []models.FSBusyProcess {
	pidDirs, err := readDirNames("/proc")
	if err != nil {
		return nil
	}
	prefix := strings.TrimSuffix(mountpoint, "/") + "/"
	var procs []models.FSBusyProcess
	for _, name := range pidDirs {
		pid, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		base := "/proc/" + name
		write, matched := fdMatchesMount(base, mountpoint, prefix)
		if !matched {
			continue
		}
		procs = append(procs, models.FSBusyProcess{
			PID: pid, Command: procComm(base), User: procUser(base), Write: write,
		})
		if len(procs) >= fsBusyMaxProcs {
			break
		}
	}
	return procs
}

// fdMatchesMount reports whether any fd of the process at base points inside
// mountpoint, and whether any such fd is open for writing.
func fdMatchesMount(base, mountpoint, prefix string) (write, matched bool) {
	names, err := readDirNames(base + "/fd")
	if err != nil {
		return false, false // different UID or process exited — invisible, not "clean"
	}
	for _, fd := range names {
		target, err := readLink(base + "/fd/" + fd)
		if err != nil {
			continue
		}
		if target != mountpoint && !strings.HasPrefix(target, prefix) {
			continue
		}
		matched = true
		if fdOpenForWrite(base, fd) {
			write = true
		}
	}
	return write, matched
}

// fdOpenForWrite reads /proc/<pid>/fdinfo/<fd> and checks whether it is open
// for writing.
func fdOpenForWrite(base, fd string) bool {
	data, err := readFile(base + "/fdinfo/" + fd)
	if err != nil {
		return false
	}
	return parseFdFlagsWrite(string(data))
}

// parseFdFlagsWrite checks the O_ACCMODE bits of the "flags:" field in
// /proc/<pid>/fdinfo/<fd> content for O_WRONLY(1) or O_RDWR(2).
func parseFdFlagsWrite(data string) bool {
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "flags:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return false
		}
		flags, err := strconv.ParseInt(fields[1], 8, 64)
		if err != nil {
			return false
		}
		return flags&3 == 1 || flags&3 == 2
	}
	return false
}
