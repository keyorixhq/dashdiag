package init_pkg

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// psTimeout bounds the `ps aux` call in darwinProcessNames. RunWizard has no
// ambient context to thread through this one-shot `dsd init` detection step,
// but a bare exec.Command with no deadline at all can hang forever if ps ever
// wedges (a stuck kernel table lock, a pathological process count) — directly
// at odds with dsd's "completes in under 35s, never hangs" contract. A var
// (not const) so tests can shrink it rather than waiting out the real value.
var psTimeout = 5 * time.Second

// DetectServerProfile returns the best-guess server profile and whether the
// process list itself was actually readable. ok=false means the process
// scan failed entirely (ReadDir("/proc") error, or `ps aux` errored/timed
// out on macOS) — classifyProfile(nil) then falls through to the same
// "general" default a genuinely daemon-free host also produces, so callers
// must check ok rather than trusting the profile string alone.
func DetectServerProfile() (profile string, ok bool) {
	names, ok := runningProcessNames()
	return classifyProfile(names), ok
}

func classifyProfile(procs []string) string {
	switch {
	case containsAny(procs, "nginx", "apache2", "caddy", "httpd"):
		return "web"
	case containsAny(procs, "postgres", "mysqld", "redis-server", "mongod"):
		return "database"
	case containsAny(procs, "kubelet"):
		return "kubernetes"
	case containsAny(procs, "pvecheckd", "pvedaemon"):
		return "proxmox"
	default:
		return "general"
	}
}

// runningProcessNames returns the host's process list and whether the scan
// itself succeeded. ok=false (scan failed) and "genuinely zero/unrecognized
// processes" (scan succeeded, ok=true, names empty or none matched) must stay
// distinguishable — both previously collapsed to the same nil slice.
func runningProcessNames() (names []string, ok bool) {
	if runtime.GOOS == "linux" {
		return linuxProcessNames()
	}
	return darwinProcessNames()
}

func linuxProcessNames() ([]string, bool) {
	return linuxProcessNamesFrom("/proc")
}

func linuxProcessNamesFrom(procDir string) ([]string, bool) {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, false
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(procDir, e.Name(), "comm"))
		if err == nil {
			names = append(names, strings.TrimSpace(string(data)))
		}
	}
	return names, true
}

func darwinProcessNames() ([]string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), psTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ps", "aux") // NOSONAR — hardcoded binary
	cmd.WaitDelay = 100 * time.Millisecond       // force-kill after context cancel (matches localeSafeExec)
	out, err := cmd.Output()
	if err != nil {
		return nil, false
	}
	var names []string
	for line := range strings.SplitSeq(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 11 {
			parts := strings.Split(fields[10], "/")
			names = append(names, parts[len(parts)-1])
		}
	}
	return names, true
}

func containsAny(list []string, targets ...string) bool {
	for _, item := range list {
		for _, t := range targets {
			if strings.EqualFold(item, t) {
				return true
			}
		}
	}
	return false
}
