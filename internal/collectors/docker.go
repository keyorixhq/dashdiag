//go:build linux || darwin

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const crashLoopRestartThreshold = 5

// DockerCollector reads container health from the Docker or Podman socket.
// Uses direct Unix socket HTTP — no Docker SDK dependency.
type DockerCollector struct{}

func NewDockerCollector() *DockerCollector { return &DockerCollector{} }

func (c *DockerCollector) Name() string           { return "Docker" }
func (c *DockerCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *DockerCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.DockerInfo{}

	// Try Docker socket first, then Podman
	socket, runtime := detectContainerSocket()
	if socket == "" {
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
	info.Available = true
	info.Runtime = runtime

	client := socketClient(socket)

	// Containers list
	if err := collectContainers(ctx, client, info); err != nil {
		info.Status = "error"
		info.StatusReason = fmt.Sprintf("failed to list containers: %v", err)
		return info, nil
	}

	// System disk usage
	collectDiskUsage(ctx, client, info)

	// Images
	collectImages(ctx, client, info)

	// Volumes
	collectVolumes(ctx, client, info)

	// On RHEL/Rocky 10+ with zero images and containers, daemon likely failed
	// to start due to missing iptables-legacy — add actionable hint.
	if info.TotalContainers == 0 && info.ImagesCount == 0 && isRHEL10Plus() {
		info.StatusReason = "Docker daemon may have failed to start — on RHEL/Rocky 10+ add '{\"iptables\": false}' to /etc/docker/daemon.json (iptables-legacy removed in RHEL 10)"
	}

	return info, nil
}

// detectContainerSocket returns the first available socket and its runtime name.
func detectContainerSocket() (string, string) {
	candidates := []struct{ path, runtime string }{
		{"/var/run/docker.sock", "docker"},
		{"/run/docker.sock", "docker"},
		{"/run/podman/podman.sock", "podman"},
		{"/var/run/podman/podman.sock", "podman"},
	}
	for _, c := range candidates {
		conn, err := net.DialTimeout("unix", c.path, 500*time.Millisecond)
		if err == nil {
			conn.Close() //nolint:errcheck
			return c.path, c.runtime
		}
	}
	return "", ""
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
		"http://localhost/v1.41"+path, nil)
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

		// Fetch detailed inspect for health status and restart count
		health, restarts := containerDetail(ctx, client, c.ID[:12])
		if health == "unhealthy" {
			info.UnhealthyCount++
			info.Unhealthy = append(info.Unhealthy, name)
		}
		if restarts >= crashLoopRestartThreshold {
			info.CrashLoopCount++
			info.CrashLooping = append(info.CrashLooping, name)
		}

		info.Containers = append(info.Containers, models.ContainerInfo{
			ID:      c.ID[:12],
			Name:    name,
			Image:   c.Image,
			State:   state,
			Health:  health,
			Restart: restarts,
		})
	}
	return nil
}

func containerDetail(ctx context.Context, client *http.Client, id string) (health string, restarts int) {
	data, err := apiGet(ctx, client, "/containers/"+id+"/json")
	if err != nil {
		return "none", 0
	}
	var detail struct {
		State struct {
			Health struct {
				Status string `json:"Status"`
			} `json:"Health"`
			RestartCount int `json:"RestartCount"`
		} `json:"State"`
	}
	if err := json.Unmarshal(data, &detail); err != nil {
		return "none", 0
	}
	h := detail.State.Health.Status
	if h == "" {
		h = "none"
	}
	return h, detail.State.RestartCount
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
