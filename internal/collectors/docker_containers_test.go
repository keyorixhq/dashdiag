//go:build linux

package collectors

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// fakeDockerAPISource wraps a Bundle-backed Replay (so readFile still works
// for collectDNSTrap/isRHEL10Plus) but overrides Cached to serve canned JSON
// per Docker API path, bypassing the real unix-socket dial entirely — apiGet
// routes every call through activeSource.Cached("docker-api/"+path, ...).
type fakeDockerAPISource struct {
	*source.Replay
	responses map[string][]byte
}

func (f fakeDockerAPISource) Cached(key string, _ func() ([]byte, error)) ([]byte, error) {
	path := strings.TrimPrefix(key, "docker-api/")
	if data, ok := f.responses[path]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("no fixture for docker-api path %q", path)
}

func withDockerAPIFixture(t *testing.T, responses map[string][]byte, seed func(b *source.Bundle)) *http.Client {
	t.Helper()
	b := source.NewBundle()
	if seed != nil {
		seed(b)
	}
	prev := SetSource(fakeDockerAPISource{Replay: source.NewReplay(b), responses: responses})
	t.Cleanup(func() { SetSource(prev) })
	return &http.Client{}
}

const containerListJSON = `[
	{"Id":"aaaaaaaaaaaa1111","Names":["/web"],"Image":"nginx:latest","State":"running","Status":"Up 2 hours"},
	{"Id":"bbbbbbbbbbbb2222","Names":["/worker"],"Image":"worker:latest","State":"exited","Status":"Exited (137) 5 minutes ago"}
]`

func healthyDetailJSON() string {
	return `{
		"RestartCount": 0,
		"State": {"Running": true, "StartedAt": "` + time.Now().Add(-2*time.Hour).Format(time.RFC3339Nano) + `", "ExitCode": 0, "Health": {"Status": "healthy"}},
		"Config": {"Env": ["PATH=/usr/bin"], "User": ""},
		"HostConfig": {"Binds": [], "LogConfig": {"Type": "json-file", "Config": {}}}
	}`
}

func crashLoopingDetailJSON() string {
	return `{
		"RestartCount": 12,
		"State": {"Running": false, "StartedAt": "` + time.Now().Add(-1*time.Minute).Format(time.RFC3339Nano) + `", "ExitCode": 137},
		"Config": {"Env": ["DB_PASSWORD=hunter2"], "User": "root"},
		"HostConfig": {"Binds": ["/var/run/docker.sock:/var/run/docker.sock"], "LogConfig": {"Type": "json-file", "Config": {}}}
	}`
}

func unhealthyDetailJSON() string {
	return `{
		"RestartCount": 0,
		"State": {"Running": true, "StartedAt": "` + time.Now().Add(-2*time.Hour).Format(time.RFC3339Nano) + `", "ExitCode": 0, "Health": {"Status": "unhealthy"}},
		"Config": {"Env": ["PATH=/usr/bin"], "User": ""},
		"HostConfig": {"Binds": [], "LogConfig": {"Type": "json-file", "Config": {}}}
	}`
}

func TestCollectContainers_HappyPath(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/containers/json?all=true&size=false": []byte(containerListJSON),
		"/containers/aaaaaaaaaaaa/json":        []byte(healthyDetailJSON()),
		"/containers/bbbbbbbbbbbb/json":        []byte(crashLoopingDetailJSON()),
	}, nil)

	info := &models.DockerInfo{}
	if err := collectContainers(context.Background(), client, info); err != nil {
		t.Fatalf("collectContainers: %v", err)
	}

	if info.TotalContainers != 2 || info.RunningCount != 1 || info.StoppedCount != 1 {
		t.Errorf("expected 2 total / 1 running / 1 stopped, got %+v", info)
	}
	if info.CrashLoopCount != 1 || len(info.CrashLooping) != 1 || info.CrashLooping[0] != "worker" {
		t.Errorf("expected worker flagged as crash-looping (12 restarts, started 1m ago), got %+v", info)
	}
	if info.ContainersWithSecrets != 1 {
		t.Errorf("expected 1 container with a plaintext secret (DB_PASSWORD), got %d", info.ContainersWithSecrets)
	}
	if info.SocketMountedCount != 1 {
		t.Errorf("expected 1 container with the docker socket mounted, got %d", info.SocketMountedCount)
	}
	if info.RunningAsRootCount != 1 {
		// web is running with no explicit Config.User — an empty User field
		// defaults to root (no USER directive in the image), and web is the
		// only container in the "running" state; worker also runs as root but
		// is exited, so it must not count.
		t.Errorf("expected 1 currently-running root container (web, empty User defaults to root), got %d", info.RunningAsRootCount)
	}
	if len(info.Containers) != 2 || info.Containers[1].ExitCode != 137 || info.Containers[1].ExitLabel != "OOM kill (SIGKILL)" {
		t.Errorf("expected worker's exit code/label to be populated, got %+v", info.Containers)
	}
}

// TestCollectContainers_UnhealthyContainer guards the health-status branch:
// a container reporting Health.Status=="unhealthy" (a Docker HEALTHCHECK
// failure) must increment UnhealthyCount and be listed in Unhealthy.
func TestCollectContainers_UnhealthyContainer(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/containers/json?all=true&size=false": []byte(containerListJSON),
		"/containers/aaaaaaaaaaaa/json":        []byte(unhealthyDetailJSON()),
		"/containers/bbbbbbbbbbbb/json":        []byte(crashLoopingDetailJSON()),
	}, nil)

	info := &models.DockerInfo{}
	if err := collectContainers(context.Background(), client, info); err != nil {
		t.Fatalf("collectContainers: %v", err)
	}
	if info.UnhealthyCount != 1 || len(info.Unhealthy) != 1 || info.Unhealthy[0] != "web" {
		t.Errorf("expected web flagged unhealthy, got UnhealthyCount=%d Unhealthy=%v", info.UnhealthyCount, info.Unhealthy)
	}
}

// TestCollectContainers_DetailAPIFails guards DetailUnavailable: when the
// per-container inspect call fails, the container must still be listed (not
// dropped) with DetailUnavailable=true, not silently defaulted to healthy/OK.
func TestCollectContainers_DetailAPIFails(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/containers/json?all=true&size=false": []byte(containerListJSON),
		// No fixture for either /containers/<id>/json path -> apiGet fails for both.
	}, nil)

	info := &models.DockerInfo{}
	if err := collectContainers(context.Background(), client, info); err != nil {
		t.Fatalf("collectContainers: %v", err)
	}
	if len(info.Containers) != 2 {
		t.Fatalf("expected both containers still listed despite detail failures, got %d", len(info.Containers))
	}
	for _, c := range info.Containers {
		if !c.DetailUnavailable {
			t.Errorf("expected DetailUnavailable=true for %q when inspect fails, got false", c.Name)
		}
	}
}

// TestCollectContainers_MalformedJSON guards the json.Unmarshal error branch:
// the containers list endpoint returning something that isn't a JSON array
// (a real symptom of a proxy/auth layer intercepting the socket) must
// surface as an error, not panic or silently report zero containers.
func TestCollectContainers_MalformedJSON(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/containers/json?all=true&size=false": []byte("not json"),
	}, nil)
	info := &models.DockerInfo{}
	if err := collectContainers(context.Background(), client, info); err == nil {
		t.Error("expected an error for malformed JSON from the containers list endpoint")
	}
}

func TestCollectContainers_ListAPIFails(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{}, nil)
	info := &models.DockerInfo{}
	if err := collectContainers(context.Background(), client, info); err == nil {
		t.Error("expected an error when the container list API itself fails")
	}
}

// TestCollectContainers_ShortContainerID guards against a panic when the
// Docker API returns an "Id" shorter than the 12-character prefix dsd
// conventionally displays. A malicious or compromised daemon (or a proxy in
// front of the socket) fully controls this field, so a naive id[:12] slice
// is a crash-the-whole-process bug on any Id under 12 bytes.
func TestCollectContainers_ShortContainerID(t *testing.T) {
	const shortListJSON = `[
		{"Id":"ab","Names":["/tiny"],"Image":"scratch:latest","State":"running","Status":"Up 1 second"}
	]`
	client := withDockerAPIFixture(t, map[string][]byte{
		"/containers/json?all=true&size=false": []byte(shortListJSON),
		// No fixture for /containers/ab/json — detail call fails, which is fine;
		// the point is that collectContainers itself must not panic on c.ID[:12].
	}, nil)

	info := &models.DockerInfo{}
	if err := collectContainers(context.Background(), client, info); err != nil {
		t.Fatalf("collectContainers: %v", err)
	}
	if len(info.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(info.Containers))
	}
	if info.Containers[0].ID != "ab" {
		t.Errorf("expected short ID %q to pass through unchanged, got %q", "ab", info.Containers[0].ID)
	}
}

func TestContainerDetail_ParsesAllFields(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/containers/deadbeef0000/json": []byte(`{
			"RestartCount": 3,
			"State": {"Running": true, "StartedAt": "` + time.Now().Format(time.RFC3339Nano) + `", "ExitCode": 0, "Health": {"Status": "unhealthy"}},
			"Config": {"Env": ["API_TOKEN=xyz"], "User": "0"},
			"HostConfig": {"Binds": ["/var/run/docker.sock:/var/run/docker.sock:ro"], "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m"}}}
		}`),
	}, nil)

	det := containerDetail(context.Background(), client, "deadbeef0000")
	if det.detailFailed {
		t.Fatal("expected detailFailed=false for a well-formed response")
	}
	if det.health != "unhealthy" || det.restarts != 3 {
		t.Errorf("health/restarts = %q/%d, want unhealthy/3", det.health, det.restarts)
	}
	if !det.runsAsRoot {
		t.Error("User=\"0\" must be treated as running as root")
	}
	if !det.socketMounted {
		t.Error("a docker.sock bind must set socketMounted=true")
	}
	if len(det.secrets) != 1 || det.secrets[0] != "API_TOKEN" {
		t.Errorf("expected API_TOKEN flagged as a secret, got %+v", det.secrets)
	}
	if !det.logMaxSizeSet {
		t.Error("expected logMaxSizeSet=true when max-size is configured")
	}
}

func TestContainerDetail_APIFails(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{}, nil)
	det := containerDetail(context.Background(), client, "nosuchid00000")
	if !det.detailFailed || det.health != "none" {
		t.Errorf("expected detailFailed=true health=none on API failure, got %+v", det)
	}
}

func TestContainerDetail_MalformedJSON(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/containers/badjson0000/json": []byte("{not valid json"),
	}, nil)
	det := containerDetail(context.Background(), client, "badjson0000")
	if !det.detailFailed || det.health != "none" {
		t.Errorf("expected detailFailed=true health=none on malformed JSON, got %+v", det)
	}
}

func TestCollectDNSTrap_LoopbackNameserver(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/info": []byte(`{"DNS":["8.8.8.8"]}`),
	}, func(b *source.Bundle) {
		b.PutFile("/etc/resolv.conf", []byte("nameserver 127.0.0.53\noptions edns0\n"))
	})

	info := &models.DockerInfo{}
	collectDNSTrap(context.Background(), client, info)
	if !info.DNSTrap {
		t.Fatal("expected DNSTrap=true for a loopback nameserver (systemd-resolved stub)")
	}
	if info.DNSTrapServer != "127.0.0.53" {
		t.Errorf("expected DNSTrapServer=127.0.0.53, got %q", info.DNSTrapServer)
	}
	if len(info.DaemonDNSServers) != 1 || info.DaemonDNSServers[0] != "8.8.8.8" {
		t.Errorf("expected daemon DNS servers populated from /info, got %+v", info.DaemonDNSServers)
	}
}

func TestCollectDNSTrap_RealNameserverNoTrap(t *testing.T) {
	client := withDockerAPIFixture(t, nil, func(b *source.Bundle) {
		b.PutFile("/etc/resolv.conf", []byte("nameserver 8.8.8.8\n"))
	})
	info := &models.DockerInfo{}
	collectDNSTrap(context.Background(), client, info)
	if info.DNSTrap {
		t.Error("a real upstream nameserver must not be flagged as a DNS trap")
	}
}

func TestCollectDNSTrap_ResolvConfUnreadable(t *testing.T) {
	client := withDockerAPIFixture(t, nil, nil)
	info := &models.DockerInfo{}
	collectDNSTrap(context.Background(), client, info) // must not panic
	if info.DNSTrap {
		t.Error("expected DNSTrap=false when resolv.conf is unreadable")
	}
}

func TestIsRHEL10Plus(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\nVERSION_ID=\"10.2\"\n"))
	})
	if !isRHEL10Plus() {
		t.Error("expected RHEL 10.2 to report true")
	}
}

func TestIsRHEL10Plus_OlderVersion(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rocky\nVERSION_ID=\"9.4\"\n"))
	})
	if isRHEL10Plus() {
		t.Error("expected Rocky 9.4 to report false")
	}
}

func TestIsRHEL10Plus_NonRHELFamily(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"))
	})
	if isRHEL10Plus() {
		t.Error("expected a non-RHEL-family distro to report false regardless of version number")
	}
}
