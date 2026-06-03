//go:build linux

package collectors

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ctrBinaries are the known names/paths for the containerd CLI tool.
// openSUSE ships it as containerd-ctr; Debian/Ubuntu/k3s use ctr.
var ctrBinaries = []string{
	"ctr",
	"containerd-ctr",
	"/usr/local/bin/ctr",       // k3s installs here
	"/usr/sbin/containerd-ctr", // openSUSE
}

// findCtr returns the first usable ctr binary path, or "" if none found.
func findCtr() string {
	for _, bin := range ctrBinaries {
		if out, err := runCmd(context.Background(), bin, "version"); err == nil && out != "" {
			return bin
		}
	}
	return ""
}

// containerdSocketCandidates are the known socket paths for standalone containerd.
var containerdSocketCandidates = []string{
	"/run/containerd/containerd.sock",
	"/var/run/containerd/containerd.sock",
}

// ContainerdAvailable returns true when a containerd socket is reachable.
func ContainerdAvailable() bool {
	return detectContainerdSocket() != ""
}

// detectContainerdSocket returns the first connectable containerd socket path.
func detectContainerdSocket() string {
	for _, path := range containerdSocketCandidates {
		conn, err := net.DialTimeout("unix", path, 300*time.Millisecond)
		if err == nil {
			conn.Close() //nolint:errcheck
			return path
		}
	}
	return ""
}

// ContainerdCollector collects health data from a standalone containerd runtime.
type ContainerdCollector struct{}

func NewContainerdCollector() *ContainerdCollector { return &ContainerdCollector{} }

func (c *ContainerdCollector) Name() string           { return "Containerd" }
func (c *ContainerdCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *ContainerdCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.ContainerdInfo{}

	info.SocketPath = detectContainerdSocket()
	if info.SocketPath == "" {
		info.Status = "unavailable"
		info.StatusReason = "containerd socket not found"
		return info, nil
	}
	info.Available = true
	info.ServiceState = containerdServiceState(ctx)

	ctrBin := findCtr()
	if ctrBin != "" {
		info.Version = containerdVersion(ctx, ctrBin)
		info.Namespaces = containerdNamespaces(ctx, ctrBin)
		for _, ns := range info.Namespaces {
			info.TotalContainers += ns.ContainerCount
		}
	}

	return info, nil
}

// containerdServiceState returns the systemd ActiveState for containerd.service.
func containerdServiceState(ctx context.Context) string {
	sCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := runCmd(sCtx, "systemctl", "show", "containerd", "--property=ActiveState")
	if err != nil || out == "" {
		return "unknown"
	}
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ActiveState="); ok {
			return strings.TrimSpace(v)
		}
	}
	return "unknown"
}

// containerdVersion returns the containerd server version from ctr version output.
func containerdVersion(ctx context.Context, ctrBin string) string {
	vCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := runCmd(vCtx, ctrBin, "version")
	if err != nil || out == "" {
		return ""
	}
	// Parse Server: / Version: block — return the running server version.
	inServer := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Server:") {
			inServer = true
			continue
		}
		if inServer {
			if v, ok := strings.CutPrefix(trimmed, "Version:"); ok {
				return strings.TrimSpace(v)
			}
			if !strings.HasPrefix(line, " ") && trimmed != "" {
				break
			}
		}
	}
	return ""
}

// containerdNamespaces lists containerd namespaces and container counts.
func containerdNamespaces(ctx context.Context, ctrBin string) []models.ContainerdNamespace {
	nsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := runCmd(nsCtx, ctrBin, "namespaces", "list", "-q")
	if err != nil || out == "" {
		return nil
	}
	var result []models.ContainerdNamespace
	for _, ns := range strings.Split(strings.TrimSpace(out), "\n") {
		ns = strings.TrimSpace(ns)
		if ns == "" {
			continue
		}
		result = append(result, models.ContainerdNamespace{
			Name:           ns,
			ContainerCount: containerdContainerCount(ctx, ctrBin, ns),
		})
	}
	return result
}

// containerdContainerCount counts containers in one containerd namespace.
func containerdContainerCount(ctx context.Context, ctrBin, ns string) int {
	cCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := runCmd(cCtx, ctrBin, "-n", ns, "containers", "list", "-q")
	if err != nil || out == "" {
		return 0
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}
