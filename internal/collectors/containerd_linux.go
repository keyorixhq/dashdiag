//go:build linux

package collectors

import (
	"context"
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
func findCtr(ctx context.Context) string {
	for _, bin := range ctrBinaries {
		if out, err := runCmd(ctx, bin, "version"); err == nil && out != "" {
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

// k8sManagedContainerdSockets are containerd sockets owned by a Kubernetes distro
// (k3s/RKE2 bundle their own containerd at a private path). They are deliberately
// NOT in containerdSocketCandidates: that runtime is Kubernetes-managed — `dsd k8s`
// already covers it via its OS-layer checks, it speaks through the bundled `k3s ctr`
// (no standalone `ctr`), and its only namespace is k8s.io. The standalone containerd
// command should point the user at `dsd k8s` rather than report "not detected"
// (a false negative — containerd IS running) or half-report k8s internals.
var k8sManagedContainerdSockets = []string{
	"/run/k3s/containerd/containerd.sock",
}

// ContainerdAvailable returns true when a standalone containerd socket is
// reachable OR present but permission-denied (installed, not absent) — so a
// non-root `dsd health` still registers the collector and surfaces an honest
// "needs root" state instead of silently omitting the section (false-OK by
// omission, matching Docker's identical DetectContainerSocket behavior).
func ContainerdAvailable() bool {
	path, _ := detectContainerdSocket()
	return path != ""
}

// ContainerdK8sManaged reports whether containerd is running but managed by a
// Kubernetes distro (k3s/RKE2) — present at a bundle socket, not a standalone one.
func ContainerdK8sManaged() bool {
	for _, path := range k8sManagedContainerdSockets {
		if dialReachable("unix", path, 300*time.Millisecond) {
			return true
		}
	}
	return false
}

// detectContainerdSocket returns the first known socket path found (reachable
// OR permission-denied — distinct from genuinely absent) and whether dialing
// it was refused. A 0660 root:root socket makes a non-root dial
// permission-denied, which dialReachable alone collapses into "unreachable" —
// indistinguishable from containerd simply not being installed.
func detectContainerdSocket() (path string, permDenied bool) {
	for _, p := range containerdSocketCandidates {
		switch dialOutcome("unix", p, 300*time.Millisecond) {
		case dialOK:
			return p, false
		case dialPermission:
			return p, true
		}
	}
	return "", false
}

// ContainerdCollector collects health data from a standalone containerd runtime.
type ContainerdCollector struct{}

func NewContainerdCollector() *ContainerdCollector { return &ContainerdCollector{} }

func (c *ContainerdCollector) Name() string           { return "Containerd" }
func (c *ContainerdCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *ContainerdCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.ContainerdInfo{}

	socket, permDenied := detectContainerdSocket()
	info.SocketPath = socket
	if socket == "" {
		info.Status = "unavailable"
		info.StatusReason = "containerd socket not found"
		return info, nil
	}
	if permDenied {
		info.SocketPermDenied = true
		info.Status = "unavailable"
		info.StatusReason = collectSocketPermReason(socket, "containerd")
		return info, nil
	}
	info.Available = true
	info.ServiceState = containerdServiceState(ctx)

	ctrBin := findCtr(ctx)
	info.CtrBinaryFound = ctrBin != ""
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
