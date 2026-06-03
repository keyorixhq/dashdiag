//go:build linux || darwin

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const crashLoopRestartThreshold = 5

// DockerCollector reads container health from the Docker or Podman socket.
// Uses direct Unix socket HTTP — no Docker SDK dependency.
type DockerCollector struct{ Deep bool }

func NewDockerCollector() *DockerCollector     { return &DockerCollector{} }
func NewDockerDeepCollector() *DockerCollector { return &DockerCollector{Deep: true} }

func (c *DockerCollector) Name() string           { return "Docker" }
func (c *DockerCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *DockerCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.DockerInfo{}

	// Try Docker socket first, then Podman
	socket, runtime, permDenied := detectContainerSocket()
	if socket == "" && !permDenied {
		// No API socket — but Podman may still manage containers via systemd
		// quadlets, which are invisible to the socket. Surface them before
		// declaring the runtime unavailable.
		if podmanInstalled() {
			if quads := collectPodmanQuadlets(ctx); len(quads) > 0 {
				info.Available = true
				info.Runtime = "podman"
				info.PodmanQuadlets = quads
				return info, nil
			}
		}
		info.Status = "unavailable"
		info.StatusReason = "no Docker or Podman socket found"
		// Check if Docker is installed but daemon not running
		if dockerInstalled() {
			info.StatusReason = "Docker installed but daemon not running"
			if isRHEL10Plus() {
				info.StatusReason = "Docker installed but daemon not running — on RHEL/Rocky 10+ add '{\"iptables\": false}' to /etc/docker/daemon.json (iptables-legacy removed in RHEL 10)"
			}
		}
		return info, nil
	}
	// 7h: socket exists but permission denied
	if permDenied {
		info.SocketPermDenied = true
		info.Status = "unavailable"
		info.StatusReason = collectSocketPermReason(socket, runtime)
		return info, nil
	}
	info.Available = true
	info.Runtime = runtime

	client := socketClient(socket)

	// Daemon health — version, storage driver, recent errors
	info.Daemon = collectDaemonHealth(ctx, client, info.Runtime)

	// Containers list
	if err := collectContainers(ctx, client, info); err != nil {
		info.Status = "error"
		info.StatusReason = fmt.Sprintf("failed to list containers: %v", err)
		return info, nil
	}

	// Podman quadlets — systemd-managed containers/pods defined as .container/.pod
	// files. These are NOT visible via the Podman socket, so scan whenever Podman
	// is installed (not just when the active runtime is Podman).
	if info.Runtime == "podman" || podmanInstalled() {
		info.PodmanQuadlets = collectPodmanQuadlets(ctx)
	}

	// System disk usage
	collectDiskUsage(ctx, client, info)

	// Images
	collectImages(ctx, client, info)

	// Volumes
	collectVolumes(ctx, client, info)

	// Network backend + MTU checks
	collectNetworkHealth(ctx, client, info)

	// 7g: DNS trap — host loopback in resolv.conf breaks container DNS
	collectDNSTrap(ctx, client, info)

	// Recent events (die, oom, kill in last 1h)
	collectDockerEvents(ctx, client, info)

	// 7i: image architecture mismatch — detect amd64 image on arm64 host (or vice versa)
	if info.Daemon != nil && info.Daemon.Architecture != "" {
		info.HostArch = info.Daemon.Architecture
		collectArchMismatch(ctx, client, info)
	}

	// Deep: log driver config + container log file sizes (Docker only)
	if c.Deep && info.Runtime == "docker" {
		info.LogDriver = collectLogDriverHealth(info)
	}

	// On RHEL/Rocky 10+ with zero images and containers, daemon likely failed
	// to start due to missing iptables-legacy — add actionable hint.
	if info.TotalContainers == 0 && info.ImagesCount == 0 && isRHEL10Plus() {
		info.StatusReason = "Docker daemon may have failed to start — on RHEL/Rocky 10+ add '{\"iptables\": false}' to /etc/docker/daemon.json (iptables-legacy removed in RHEL 10)"
	}

	return info, nil
}

// DetectContainerSocket returns the first available container runtime socket
// and its runtime name ("docker" or "podman"). Exported so cmd/health.go
// can gate inclusion without importing the whole collector on non-Linux.
func DetectContainerSocket() (string, string) {
	path, runtime, _ := detectContainerSocket()
	return path, runtime
}

// detectContainerSocket returns the first available socket and its runtime name.
// Returns ("", "", true) when a socket file exists but connection is permission-denied.
func detectContainerSocket() (path, runtime string, permDenied bool) {
	candidates := []struct{ path, runtime string }{
		{"/var/run/docker.sock", "docker"},
		{"/run/docker.sock", "docker"},
		{"/run/podman/podman.sock", "podman"},
		{"/var/run/podman/podman.sock", "podman"},
		{"/var/run/crio/crio.sock", "crio"},
		{"/run/crio/crio.sock", "crio"},
	}

	// Also check user-mode Podman socket (rootless, XDG_RUNTIME_DIR)
	// Common path: /run/user/<uid>/podman/podman.sock
	if uid := os.Getuid(); uid > 0 {
		xdgPath := fmt.Sprintf("/run/user/%d/podman/podman.sock", uid)
		candidates = append(candidates, struct{ path, runtime string }{xdgPath, "podman"})
	}

	for _, c := range candidates {
		// Check if socket file exists before attempting connection (7h)
		if _, statErr := os.Stat(c.path); statErr != nil {
			continue // file doesn't exist — try next
		}
		conn, err := net.DialTimeout("unix", c.path, 500*time.Millisecond)
		if err == nil {
			conn.Close() //nolint:errcheck
			return c.path, c.runtime, false
		}
		if strings.Contains(err.Error(), "permission denied") {
			return c.path, c.runtime, true
		}
	}
	return "", "", false
}

// socketClient creates an HTTP client that communicates over a Unix socket.
func socketClient(socket string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
		Timeout: 8 * time.Second,
	}
}

// apiGet makes a GET request to the Docker/Podman API.
func apiGet(ctx context.Context, client *http.Client, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://localhost"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	var buf []byte
	b := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(b)
		if n > 0 {
			buf = append(buf, b[:n]...)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

func collectContainers(ctx context.Context, client *http.Client, info *models.DockerInfo) error {
	data, err := apiGet(ctx, client, "/containers/json?all=true&size=false")
	if err != nil {
		return err
	}

	var raw []struct {
		ID         string            `json:"Id"`
		Names      []string          `json:"Names"`
		Image      string            `json:"Image"`
		State      string            `json:"State"`
		Status     string            `json:"Status"`
		Labels     map[string]string `json:"Labels"`
		HostConfig struct {
			RestartPolicy struct {
				MaxRetries int `json:"MaximumRetryCount"`
			} `json:"RestartPolicy"`
		} `json:"HostConfig"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	info.TotalContainers = len(raw)
	for _, c := range raw {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		state := strings.ToLower(c.State)
		if state == "running" {
			info.RunningCount++
		} else {
			info.StoppedCount++
			info.Stopped++
		}

		// Fetch detailed inspect — one API call for all security + health data
		det := containerDetail(ctx, client, c.ID[:12])
		if det.health == "unhealthy" {
			info.UnhealthyCount++
			info.Unhealthy = append(info.Unhealthy, name)
		}
		if det.restarts >= crashLoopRestartThreshold {
			info.CrashLoopCount++
			info.CrashLooping = append(info.CrashLooping, name)
		}
		if len(det.secrets) > 0 {
			info.ContainersWithSecrets++
		}
		if det.socketMounted {
			info.SocketMountedCount++
		}
		if det.runsAsRoot && state == "running" {
			info.RunningAsRootCount++
		}

		ci := models.ContainerInfo{
			ID:                  c.ID[:12],
			Name:                name,
			Image:               c.Image,
			State:               state,
			Health:              det.health,
			Restart:             det.restarts,
			PlaintextSecrets:    det.secrets,
			RunsAsRoot:          det.runsAsRoot,
			User:                det.user,
			DockerSocketMounted: det.socketMounted,
		}
		if state != "running" && det.exitCode != 0 {
			ci.ExitCode = det.exitCode
			ci.ExitLabel = dockerExitLabel(det.exitCode)
		}
		info.Containers = append(info.Containers, ci)
	}
	return nil
}

type containerDetailResult struct {
	health        string
	restarts      int
	exitCode      int
	secrets       []string
	runsAsRoot    bool
	user          string
	socketMounted bool
}

func containerDetail(ctx context.Context, client *http.Client, id string) containerDetailResult {
	data, err := apiGet(ctx, client, "/containers/"+id+"/json")
	if err != nil {
		return containerDetailResult{health: "none"}
	}
	var detail struct {
		RestartCount int `json:"RestartCount"`
		State        struct {
			ExitCode int `json:"ExitCode"`
			Health   struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
		Config struct {
			Env  []string `json:"Env"`
			User string   `json:"User"`
		} `json:"Config"`
		HostConfig struct {
			Binds []string `json:"Binds"`
		} `json:"HostConfig"`
	}
	if err := json.Unmarshal(data, &detail); err != nil {
		return containerDetailResult{health: "none"}
	}
	h := detail.State.Health.Status
	if h == "" {
		h = "none"
	}
	u := strings.ToLower(strings.TrimSpace(detail.Config.User))
	runsAsRoot := u == "" || u == "0" || u == "root" || u == "root:root"
	socketMounted := false
	for _, bind := range detail.HostConfig.Binds {
		if strings.Contains(bind, "docker.sock") {
			socketMounted = true
			break
		}
	}
	return containerDetailResult{
		health:        h,
		restarts:      detail.RestartCount,
		exitCode:      detail.State.ExitCode,
		secrets:       detectPlaintextSecrets(detail.Config.Env),
		runsAsRoot:    runsAsRoot,
		user:          detail.Config.User,
		socketMounted: socketMounted,
	}
}

// dockerExitLabel returns a human-readable label for common container exit codes.
func dockerExitLabel(code int) string {
	labels := map[int]string{
		0:   "clean exit",
		1:   "application error",
		125: "Docker daemon error",
		126: "command not executable",
		127: "command not found in image",
		130: "SIGINT (Ctrl+C)",
		137: "OOM kill (SIGKILL)",
		139: "segfault (SIGSEGV)",
		143: "graceful shutdown (SIGTERM)",
	}
	if l, ok := labels[code]; ok {
		return l
	}
	return ""
}

// secretPatterns are case-insensitive substrings matched against env var names.
// Only the variable name is checked — values are never logged.
var secretPatterns = []string{
	"PASSWORD", "PASSWD", "PWD",
	"SECRET", "TOKEN", "APIKEY", "API_KEY",
	"PRIVATE_KEY", "SIGNING_KEY", "ENCRYPTION_KEY",
	"CREDENTIALS", "ACCESS_KEY", "AUTH_TOKEN",
	"DATABASE_URL",
}

// detectPlaintextSecrets scans env var names (not values) for secret patterns.
// Returns a list of variable names that match — never the values.
func detectPlaintextSecrets(env []string) []string {
	var found []string
	trivial := map[string]bool{"true": true, "false": true, "0": true, "1": true, "": true}
	for _, kv := range env {
		idx := strings.Index(kv, "=")
		if idx < 0 {
			continue
		}
		name := strings.ToUpper(kv[:idx])
		val := kv[idx+1:]
		// Skip obviously non-secret values
		if trivial[strings.ToLower(val)] || strings.HasPrefix(val, "/") {
			continue
		}
		for _, pat := range secretPatterns {
			if strings.Contains(name, pat) {
				found = append(found, kv[:idx]) // name only
				break
			}
		}
	}
	return found
}

// collectDockerEvents fetches die/oom/kill events from the last hour.
// Uses /events?filters= with since/until time window.
func collectDockerEvents(ctx context.Context, client *http.Client, info *models.DockerInfo) {
	since := fmt.Sprintf("%d", timeNow().Add(-1*time.Hour).Unix())
	until := fmt.Sprintf("%d", timeNow().Unix())
	path := fmt.Sprintf("/events?since=%s&until=%s&filters=%s",
		since, until,
		`{"type":["container"],"event":["die","oom","kill"]}`)
	data, err := apiGet(ctx, client, path)
	if err != nil {
		return
	}
	// Events are newline-delimited JSON objects (not an array)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var ev struct {
			Action string `json:"Action"`
			Actor  struct {
				Attributes map[string]string `json:"Attributes"`
			} `json:"Actor"`
			Time int64 `json:"time"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		name := ev.Actor.Attributes["name"]
		if name == "" {
			name = ev.Actor.Attributes["containerName"]
		}
		info.RecentEvents = append(info.RecentEvents, models.DockerEvent{
			Action:   ev.Action,
			Actor:    name,
			TimeUnix: ev.Time,
		})
		// Docker emits a separate "oom" event; Podman encodes OOM as "die"
		// with exitCode=137 in Actor.Attributes (confirmed on Podman 5.6 / RHEL 10.1).
		exitCode := ev.Actor.Attributes["exitCode"]
		if exitCode == "" {
			exitCode = ev.Actor.Attributes["containerExitCode"]
		}
		if ev.Action == "oom" || (ev.Action == "die" && exitCode == "137") {
			info.OOMEvents++
		}
		if len(info.RecentEvents) >= 10 {
			break
		}
	}
}

// timeNow is a variable so tests can override it.
var timeNow = func() time.Time { return time.Now() }

// collectDNSTrap checks /etc/resolv.conf for loopback nameservers (127.x or ::1).
// Containers inherit the host resolv.conf but cannot reach the host loopback —
// Docker silently falls back to 8.8.8.8 which is often blocked by corporate firewalls.
// Spec 7g.
func collectDNSTrap(ctx context.Context, client *http.Client, info *models.DockerInfo) {
	data, err := os.ReadFile("/etc/resolv.conf") // #nosec G304
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver ") {
			continue
		}
		ns := strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
		if strings.HasPrefix(ns, "127.") || ns == "::1" {
			info.DNSTrap = true
			if info.DNSTrapServer == "" {
				info.DNSTrapServer = ns
			}
		}
	}
	if !info.DNSTrap {
		return
	}
	// Read daemon DNS from /info to see if an explicit fallback is configured.
	infoData, err := apiGet(ctx, client, "/info")
	if err != nil {
		return
	}
	var infoResp struct {
		DNS []string `json:"DNS"`
	}
	if json.Unmarshal(infoData, &infoResp) == nil && len(infoResp.DNS) > 0 {
		info.DaemonDNSServers = infoResp.DNS
		info.DaemonDNSConfigured = true
	}
}

// normalizeArch maps kernel arch names to OCI arch names.
// x86_64 → amd64, aarch64 → arm64, armv7l → arm.
var archNorm = map[string]string{
	"x86_64":  "amd64",
	"aarch64": "arm64",
	"armv7l":  "arm",
	"armv6l":  "arm",
	"s390x":   "s390x",
	"ppc64le": "ppc64le",
}

func normalizeArch(arch string) string {
	if n, ok := archNorm[arch]; ok {
		return n
	}
	return strings.ToLower(arch)
}

// collectImageArch fetches the architecture of an image by name/ID.
// Returns empty string on error or if the image has no architecture field.
// Spec 7i.
func collectImageArch(ctx context.Context, client *http.Client, imageName string) string {
	data, err := apiGet(ctx, client, "/images/"+imageName+"/json")
	if err != nil {
		return ""
	}
	var img struct {
		Architecture string `json:"Architecture"`
	}
	if err := json.Unmarshal(data, &img); err != nil {
		return ""
	}
	return normalizeArch(img.Architecture)
}

// collectLogDriverHealth checks /etc/docker/daemon.json and scans container log file sizes.
// Only called for Docker runtime in deep mode.
func collectLogDriverHealth(info *models.DockerInfo) *models.DockerLogDriverInfo {
	ld := &models.DockerLogDriverInfo{}

	// Read daemon.json
	data, err := os.ReadFile("/etc/docker/daemon.json") // #nosec G304
	if err == nil {
		ld.DaemonJSONExists = true
		var cfg struct {
			LogDriver string            `json:"log-driver"`
			LogOpts   map[string]string `json:"log-opts"`
		}
		if json.Unmarshal(data, &cfg) == nil {
			ld.Driver = cfg.LogDriver
			if ld.Driver == "" {
				ld.Driver = "json-file" // default when not set
			}
			_, ld.MaxSizeSet = cfg.LogOpts["max-size"]
			_, ld.MaxFileSet = cfg.LogOpts["max-file"]
		}
	} else {
		// No daemon.json → all defaults → json-file, unbounded
		ld.Driver = "json-file"
	}

	// Scan container log files under /var/lib/docker/containers/*/
	if ld.Driver == "json-file" {
		ld.ContainerLogs = collectContainerLogSizes(info)
		for _, cl := range ld.ContainerLogs {
			if cl.SizeMB >= 500 {
				ld.LargeLogCount++
			}
		}
	}

	return ld
}

// collectContainerLogSizes scans /var/lib/docker/containers/ for *-json.log files.
// Maps container ID prefix to name using already-fetched container list.
func collectContainerLogSizes(info *models.DockerInfo) []models.DockerContainerLogFile {
	// Build id→name map from collected containers
	idToName := make(map[string]string, len(info.Containers))
	for _, c := range info.Containers {
		idToName[c.ID] = c.Name
	}

	entries, err := os.ReadDir("/var/lib/docker/containers") // #nosec G304
	if err != nil {
		return nil
	}

	var logs []models.DockerContainerLogFile
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		logPath := "/var/lib/docker/containers/" + e.Name() + "/" + e.Name() + "-json.log"
		fi, err := os.Stat(logPath) // #nosec G304
		if err != nil {
			continue
		}
		name := idToName[e.Name()[:12]]
		if name == "" {
			name = e.Name()[:12]
		}
		logs = append(logs, models.DockerContainerLogFile{
			Name:   name,
			SizeMB: float64(fi.Size()) / (1024 * 1024),
		})
	}
	return logs
}

// collectDaemonHealth fetches /info and /version for daemon-level health.
func collectDaemonHealth(ctx context.Context, client *http.Client, runtime string) *models.DockerDaemon {
	d := &models.DockerDaemon{Responding: true}

	// GET /info — storage driver, swarm state, architecture
	infoData, err := apiGet(ctx, client, "/info")
	if err == nil {
		var info struct {
			Driver       string `json:"Driver"`
			Architecture string `json:"Architecture"`
			Swarm        struct {
				LocalNodeState   string `json:"LocalNodeState"`
				ControlAvailable bool   `json:"ControlAvailable"`
			} `json:"Swarm"`
		}
		if json.Unmarshal(infoData, &info) == nil {
			d.StorageDriver = info.Driver
			d.SwarmState = info.Swarm.LocalNodeState
			d.Architecture = normalizeArch(info.Architecture)
			if info.Swarm.LocalNodeState == "active" {
				if info.Swarm.ControlAvailable {
					d.SwarmRole = "manager"
				} else {
					d.SwarmRole = "worker"
				}
			}
		}
	}

	// GET /version — server version + API version
	verData, err := apiGet(ctx, client, "/version")
	if err == nil {
		var ver struct {
			Version    string `json:"Version"`
			APIVersion string `json:"ApiVersion"`
		}
		if json.Unmarshal(verData, &ver) == nil {
			d.Version = ver.Version
			d.APIVersion = ver.APIVersion
		}
	}

	// Daemon journal errors (last 10 minutes) — Docker only, not Podman
	if runtime == "docker" {
		collectDaemonJournalErrors(ctx, d)
	}

	return d
}

// collectDaemonJournalErrors reads recent error/warning lines from docker service journal.
func collectDaemonJournalErrors(ctx context.Context, d *models.DockerDaemon) {
	jCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := runCmd(jCtx, "journalctl", "-u", "docker",
		"-n", "30", "--no-pager", "--since", "10 minutes ago", "--output=short")
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "level=error") || strings.Contains(lower, "level=warning") ||
			(strings.Contains(lower, "error") && strings.Contains(lower, "docker")) {
			d.RecentErrors++
			// Keep last meaningful error message (truncated)
			msg := extractJournalMessage(line)
			if msg != "" {
				d.LastDaemonError = msg
			}
		}
	}
}

// extractJournalMessage strips the timestamp prefix from a journalctl line.
func extractJournalMessage(line string) string {
	// journalctl short format: "May 19 14:05:46 hostname docker[pid]: message"
	parts := strings.SplitN(line, ": ", 2)
	if len(parts) == 2 {
		msg := strings.TrimSpace(parts[1])
		if len(msg) > 120 {
			return msg[:120] + "…"
		}
		return msg
	}
	return ""
}

func collectDiskUsage(ctx context.Context, client *http.Client, info *models.DockerInfo) {
	data, err := apiGet(ctx, client, "/system/df")
	if err != nil {
		return
	}
	var df struct {
		LayersSize int64 `json:"LayersSize"`
		Volumes    []struct {
			UsageData struct {
				Size int64 `json:"Size"`
			} `json:"UsageData"`
		} `json:"Volumes"`
	}
	if err := json.Unmarshal(data, &df); err != nil {
		return
	}
	total := df.LayersSize
	for _, v := range df.Volumes {
		if v.UsageData.Size > 0 {
			total += v.UsageData.Size
		}
	}
	info.DiskUsageGB = float64(total) / 1024 / 1024 / 1024
}

func collectImages(ctx context.Context, client *http.Client, info *models.DockerInfo) {
	data, err := apiGet(ctx, client, "/images/json?all=false")
	if err != nil {
		return
	}
	var images []struct {
		RepoTags []string `json:"RepoTags"`
	}
	if err := json.Unmarshal(data, &images); err != nil {
		return
	}
	info.ImagesCount = len(images)
	for _, img := range images {
		if len(img.RepoTags) == 0 || img.RepoTags[0] == "<none>:<none>" {
			info.DanglingImages++
		}
	}
}

func collectVolumes(ctx context.Context, client *http.Client, info *models.DockerInfo) {
	data, err := apiGet(ctx, client, "/volumes")
	if err != nil {
		return
	}
	var vols struct {
		Volumes []struct{} `json:"Volumes"`
	}
	if err := json.Unmarshal(data, &vols); err != nil {
		return
	}
	info.VolumesCount = len(vols.Volumes)
}

// dockerInstalled returns true if the docker binary is present on PATH.
func dockerInstalled() bool {
	_, err := runCmd(context.Background(), "docker", "--version")
	return err == nil
}

// podmanInstalled returns true if the podman binary is present on PATH.
// Used to scan quadlets even when the Podman API socket is inactive.
func podmanInstalled() bool {
	_, err := exec.LookPath("podman")
	return err == nil
}

// PodmanQuadletsPresent reports whether any Podman quadlet files exist in the
// system quadlet directory (/etc/containers/systemd). It is a fast file-existence
// check — no systemctl, no subprocess — so the health collector build path can
// cheaply decide whether to run the Docker collector on a socket-inactive
// Podman host. Exported for cmd/health.go.
func PodmanQuadletsPresent() bool {
	return quadletFilesPresent("/etc/containers/systemd")
}

// quadletFilesPresent returns true if dir holds at least one .container or .pod
// file. A missing or unreadable directory yields false (not an error).
func quadletFilesPresent(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".container") || strings.HasSuffix(n, ".pod") {
			return true
		}
	}
	return false
}

// isRHEL10Plus returns true when running on RHEL, Rocky, AlmaLinux or
// compatible distro at major version 10 or above.
// Reads /etc/os-release which is present on all modern Linux distros.
func isRHEL10Plus() bool {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}
	content := strings.ToLower(string(data))
	// Must be a RHEL-family distro
	rhel := strings.Contains(content, "rhel") ||
		strings.Contains(content, "rocky") ||
		strings.Contains(content, "almalinux") ||
		strings.Contains(content, "centos")
	if !rhel {
		return false
	}
	// Extract VERSION_ID and check major version >= 10
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VERSION_ID=") {
			ver := strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
			parts := strings.SplitN(ver, ".", 2)
			if len(parts) > 0 {
				major := 0
				if _, err := fmt.Sscanf(parts[0], "%d", &major); err == nil {
					return major >= 10
				}
			}
		}
	}
	return false
}

// collectSocketPermReason builds the human-readable status reason for 7h.
// Checks if the current user is in the socket's group.
func collectSocketPermReason(socketPath, runtime string) string {
	fi, err := os.Stat(socketPath)
	if err != nil {
		return fmt.Sprintf("%s socket found at %s but permission denied", runtime, socketPath)
	}
	gidStr := ""
	if stat, ok := fi.Sys().(interface{ Gid() uint32 }); ok {
		gidStr = fmt.Sprintf(" (GID %d)", stat.Gid())
		socketGID := int(stat.Gid())
		if groups, gErr := os.Getgroups(); gErr == nil {
			for _, gid := range groups {
				if gid == socketGID {
					return fmt.Sprintf(
						"%s socket found at %s — group membership present but session not refreshed%s — log out and reconnect",
						runtime, socketPath, gidStr)
				}
			}
		}
	}
	return fmt.Sprintf(
		"%s socket found at %s but user not in socket group%s — run: sudo usermod -aG %s $USER then log out and reconnect",
		runtime, socketPath, gidStr, runtime)
}

// collectArchMismatch checks each container's image architecture against the host. Spec 7i.
// Uses a per-image cache to avoid duplicate API calls.
func collectArchMismatch(ctx context.Context, client *http.Client, info *models.DockerInfo) {
	hostArch := info.HostArch
	cache := make(map[string]string) // image name → normalized arch
	for i, c := range info.Containers {
		if c.Image == "" {
			continue
		}
		imgArch, seen := cache[c.Image]
		if !seen {
			imgArch = collectImageArch(ctx, client, c.Image)
			cache[c.Image] = imgArch
		}
		if imgArch == "" || imgArch == hostArch {
			continue
		}
		info.Containers[i].ImageArch = imgArch
		info.Containers[i].ArchMismatch = true
		info.ArchMismatchCount++
	}
}

// quadletDirs are the directories scanned for Podman quadlet files.
// System quadlets live in /etc/containers/systemd; the root user's quadlets
// live in /root/.config/containers/systemd.
var quadletDirs = []string{
	"/etc/containers/systemd",
	"/root/.config/containers/systemd",
}

// quadletFile is a discovered quadlet file (base name + full path).
type quadletFile struct {
	name string // e.g. "test-nginx.container"
	path string // e.g. "/etc/containers/systemd/test-nginx.container"
}

// collectPodmanQuadlets scans the quadlet directories for .container/.pod files
// and reports the systemd unit state for each. Linux-only — systemd quadlets
// don't exist elsewhere. Returns nil when no quadlet files are found.
func collectPodmanQuadlets(ctx context.Context) []models.PodmanQuadlet {
	if goruntime.GOOS != "linux" {
		return nil
	}
	files := scanQuadletFiles(quadletDirs)
	if len(files) == 0 {
		return nil
	}
	out := make([]models.PodmanQuadlet, 0, len(files))
	for _, f := range files {
		unit := quadletServiceUnit(f.name)
		active, failed, state := quadletUnitState(ctx, unit)
		out = append(out, models.PodmanQuadlet{
			Name:        quadletBaseName(f.name),
			UnitFile:    f.path,
			ServiceUnit: unit,
			Active:      active,
			Failed:      failed,
			State:       state,
		})
	}
	return out
}

// scanQuadletFiles returns every .container/.pod file in the given directories.
// Directories that don't exist are skipped silently.
func scanQuadletFiles(dirs []string) []quadletFile {
	var out []quadletFile
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // directory absent or unreadable — skip
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n := e.Name()
			if strings.HasSuffix(n, ".container") || strings.HasSuffix(n, ".pod") {
				out = append(out, quadletFile{name: n, path: filepath.Join(dir, n)})
			}
		}
	}
	return out
}

// quadletBaseName strips the .container/.pod extension from a quadlet filename.
// "test-nginx.container" → "test-nginx"; "myapp.pod" → "myapp".
func quadletBaseName(filename string) string {
	base := filepath.Base(filename)
	base = strings.TrimSuffix(base, ".container")
	base = strings.TrimSuffix(base, ".pod")
	return base
}

// quadletServiceUnit derives the generated systemd service unit name from a
// quadlet filename. Strip the extension only, then append .service.
// "test-nginx.container" → "test-nginx.service"; "myapp.pod" → "myapp.service".
func quadletServiceUnit(filename string) string {
	return quadletBaseName(filename) + ".service"
}

// quadletUnitState queries systemd for a unit's state via systemctl show.
// Returns (false, false, "") when systemctl is unavailable or errors.
func quadletUnitState(ctx context.Context, unit string) (active, failed bool, state string) {
	sCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := runCmd(sCtx, "systemctl", "show", unit,
		"--property=ActiveState,SubState,LoadState")
	if err != nil {
		return false, false, ""
	}
	return parseQuadletState(out)
}

// parseQuadletState parses `systemctl show --property=ActiveState,...` output.
// Only ActiveState drives active/failed; the raw value is returned as state.
func parseQuadletState(output string) (active, failed bool, state string) {
	for _, line := range strings.Split(output, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ActiveState="); ok {
			state = strings.TrimSpace(v)
		}
	}
	return state == "active", state == "failed", state
}

// collectNetworkHealth detects the container network backend and checks for
// MTU mismatches between container networks and the host interface.
//
// Netavark (nftables-based, default in Podman 4+, RHEL 9+) vs CNI (iptables).
// MTU mismatch (container=1500, host=9000 for jumbo frames) causes silent
// packet fragmentation and connection issues that are very hard to diagnose.
func collectNetworkHealth(ctx context.Context, client *http.Client, info *models.DockerInfo) {
	// Detect backend: check for netavark nft table (podman) or iptables chains (docker)
	info.NetworkBackend = detectNetworkBackend(info.Runtime)

	// Get container network MTU via API
	containerMTU := getContainerNetworkMTU(ctx, client)
	if containerMTU == 0 {
		return
	}
	info.ContainerMTU = containerMTU

	// Get host interface MTU (first non-loopback, non-virtual interface)
	hostMTU := getHostMTU()
	if hostMTU == 0 {
		return
	}
	info.HostMTU = hostMTU

	// Mismatch: container MTU > host MTU causes fragmentation
	// Mismatch: container MTU < host MTU is wasteful but not harmful
	if containerMTU > hostMTU {
		info.MTUMismatch = true
	}
	// IP forwarding — required for container outbound traffic
	collectIPForwarding(info)

	// firewalld nftables backend — breaks Docker iptables rules silently
	collectFirewalldCheck(ctx, info)
}

// collectIPForwarding checks /proc/sys/net/ipv4/ip_forward.
func collectIPForwarding(info *models.DockerInfo) {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward") // #nosec G304
	if err != nil {
		return // not Linux or not readable
	}
	info.IPForwardEnabled = strings.TrimSpace(string(data)) == "1"
}

// collectFirewalldCheck checks firewalld backend and docker zone trust.
// Only runs when firewalld is active.
func collectFirewalldCheck(ctx context.Context, info *models.DockerInfo) {
	out, err := runCmd(ctx, "systemctl", "is-active", "firewalld")
	if err != nil || strings.TrimSpace(out) != "active" {
		return // firewalld not running — skip
	}
	info.FirewalldActive = true

	// Read backend from /etc/firewalld/firewalld.conf
	data, err := os.ReadFile("/etc/firewalld/firewalld.conf") // #nosec G304
	if err == nil {
		info.FirewalldBackend = "nftables" // default on modern systems
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "FirewallBackend=") {
				info.FirewalldBackend = strings.TrimPrefix(line, "FirewallBackend=")
				info.FirewalldBackend = strings.TrimSpace(info.FirewalldBackend)
				break
			}
		}
	}

	// Check if docker0 is in any firewalld zone
	zonesOut, _ := runCmd(ctx, "firewall-cmd", "--get-active-zones")
	info.DockerZoneTrusted = strings.Contains(zonesOut, "docker0") ||
		strings.Contains(zonesOut, "docker")
}

func detectNetworkBackend(runtime string) string {
	// Netavark creates an 'inet netavark' nftables table
	if data, err := os.ReadFile("/proc/net/nf_conntrack_stat"); err == nil {
		_ = data // nftables is loaded
	}
	// Check for netavark nft table via /run/netavark or nft list tables
	if _, err := os.Stat("/usr/libexec/podman/netavark"); err == nil {
		return "netavark"
	}
	if _, err := os.Stat("/usr/bin/netavark"); err == nil {
		return "netavark"
	}
	if runtime == "podman" {
		// Podman 4+ defaults to netavark; older uses CNI
		if _, err := os.Stat("/etc/cni/net.d"); err == nil {
			return "cni"
		}
		return "netavark"
	}
	// Docker always uses iptables/nftables via dockerd
	return "iptables"
}

// getContainerNetworkMTU reads the MTU of the default container network
// from the Docker/Podman API (/networks/bridge or /networks/podman).
func getContainerNetworkMTU(ctx context.Context, client *http.Client) int {
	data, err := apiGet(ctx, client, "/networks")
	if err != nil {
		return 0
	}
	var networks []struct {
		Name    string `json:"Name"`
		Options struct {
			MTU string `json:"com.docker.network.driver.mtu"`
		} `json:"Options"`
		IPAM struct {
			Config []struct{} `json:"Config"`
		} `json:"IPAM"`
	}
	if err := json.Unmarshal(data, &networks); err != nil {
		return 0
	}
	for _, n := range networks {
		if n.Name == "bridge" || n.Name == "podman" {
			if n.Options.MTU != "" {
				mtu := 0
				if _, err := fmt.Sscanf(n.Options.MTU, "%d", &mtu); err == nil {
					return mtu
				}
			}
			// Default MTU when not explicitly set
			return 1500
		}
	}
	return 0
}

// getHostMTU returns the MTU of the first physical network interface.
// Reads /sys/class/net/*/mtu — skips lo, virtual, container interfaces.
func getHostMTU() int {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return 0
	}
	skipPrefixes := []string{"lo", "docker", "podman", "cni", "veth", "virbr", "br-", "tunl", "tun", "tap"}
	for _, e := range entries {
		name := e.Name()
		skip := false
		for _, pfx := range skipPrefixes {
			if strings.HasPrefix(name, pfx) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		mtuData, err := os.ReadFile("/sys/class/net/" + name + "/mtu") // #nosec G304
		if err != nil {
			continue
		}
		mtu := 0
		if _, err := fmt.Sscanf(strings.TrimSpace(string(mtuData)), "%d", &mtu); err == nil && mtu > 0 {
			return mtu
		}
	}
	return 0
}
