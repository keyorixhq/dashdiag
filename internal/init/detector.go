package init_pkg

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func DetectServerProfile() string {
	procs := runningProcessNames()
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

func runningProcessNames() []string {
	if runtime.GOOS == "linux" {
		return linuxProcessNames()
	}
	return darwinProcessNames()
}

func linuxProcessNames() []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err == nil {
			names = append(names, strings.TrimSpace(string(data)))
		}
	}
	return names
}

func darwinProcessNames() []string {
	out, err := exec.Command("ps", "aux").Output()
	if err != nil {
		return nil
	}
	var names []string
	for line := range strings.SplitSeq(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 11 {
			parts := strings.Split(fields[10], "/")
			names = append(names, parts[len(parts)-1])
		}
	}
	return names
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
