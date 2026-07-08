//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestDockerCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewDockerCollector()
	if c.Name() != "Docker" {
		t.Errorf("Name() = %q, want Docker", c.Name())
	}
	if c.Timeout() != 10*time.Second {
		t.Errorf("Timeout() = %v, want 10s", c.Timeout())
	}
	if c.Deep {
		t.Error("NewDockerCollector: expected Deep=false")
	}
	if !NewDockerDeepCollector().Deep {
		t.Error("NewDockerDeepCollector: expected Deep=true")
	}
	pc := NewDockerCollectorWithProfile(platform.Profile{Distro: "rhel", MajorVersion: 10})
	if !pc.isRHEL10Plus() {
		t.Error("expected profile-based isRHEL10Plus=true for rhel/10")
	}
}

func TestDockerCollector_IsRHEL10Plus_ProfileOverridesFileRead(t *testing.T) {
	// A non-zero profile must be trusted over the /etc/os-release fallback —
	// no source needs to be seeded at all.
	pc := NewDockerCollectorWithProfile(platform.Profile{Distro: "debian", MajorVersion: 12})
	if pc.isRHEL10Plus() {
		t.Error("expected false for a debian profile regardless of any os-release content")
	}
}

func TestCollectDaemonHealth_Happy(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/info":    []byte(`{"Driver":"overlay2","Architecture":"x86_64","Swarm":{"LocalNodeState":"active","ControlAvailable":true}}`),
		"/version": []byte(`{"Version":"27.3.1","ApiVersion":"1.47"}`),
	}, func(b *source.Bundle) {
		b.PutCmd("docker", []string{"compose", "version", "--short"}, "v2.29.1\n", 0)
		b.PutCmdNotFound("docker-compose", []string{"version", "--short"})
		b.PutCmd("journalctl", []string{
			"-u", "docker", "-n", "30", "--no-pager", "--since", "10 minutes ago", "--output=short",
		}, "May 19 14:05:46 host dockerd[1]: level=error msg=\"failed to start container\"\n", 0)
	})
	d := collectDaemonHealth(context.Background(), client, "docker")
	if d.StorageDriver != "overlay2" || d.Architecture != "amd64" {
		t.Errorf("StorageDriver/Architecture = %q/%q", d.StorageDriver, d.Architecture)
	}
	if d.SwarmState != "active" || d.SwarmRole != "manager" {
		t.Errorf("SwarmState/SwarmRole = %q/%q, want active/manager", d.SwarmState, d.SwarmRole)
	}
	if d.Version != "27.3.1" || d.APIVersion != "1.47" {
		t.Errorf("Version/APIVersion = %q/%q", d.Version, d.APIVersion)
	}
	if d.ComposePlugin != "2.29.1" {
		t.Errorf("ComposePlugin = %q, want 2.29.1", d.ComposePlugin)
	}
	if d.ComposeStandalone != "" {
		t.Errorf("ComposeStandalone = %q, want empty (not installed)", d.ComposeStandalone)
	}
	if d.RecentErrors != 1 || d.LastDaemonError == "" {
		t.Errorf("RecentErrors/LastDaemonError = %d/%q, want 1/non-empty", d.RecentErrors, d.LastDaemonError)
	}
}

func TestCollectDaemonHealth_APIFailuresAndPodmanSkipsJournal(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{}, func(b *source.Bundle) {
		b.PutCmdNotFound("docker", []string{"compose", "version", "--short"})
		b.PutCmdNotFound("docker-compose", []string{"version", "--short"})
	})
	d := collectDaemonHealth(context.Background(), client, "podman")
	if !d.Responding {
		t.Error("expected Responding=true unconditionally")
	}
	if d.StorageDriver != "" || d.Version != "" || d.ComposePlugin != "" {
		t.Errorf("expected all zero values on API failure, got %+v", d)
	}
	if d.RecentErrors != 0 {
		t.Errorf("RecentErrors = %d, want 0 — journal is only checked for runtime=docker", d.RecentErrors)
	}
}

func TestDetectComposePlugin(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("docker", []string{"compose", "version", "--short"}, "v2.29.1\n", 0)
	})
	if got := detectComposePlugin(context.Background()); got != "2.29.1" {
		t.Errorf("got %q, want 2.29.1", got)
	}
}

func TestDetectComposePlugin_NotInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("docker", []string{"compose", "version", "--short"})
	})
	if got := detectComposePlugin(context.Background()); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestDetectComposeStandalone(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("docker-compose", []string{"version", "--short"}, "1.29.2\n", 0)
	})
	if got := detectComposeStandalone(context.Background()); got != "1.29.2" {
		t.Errorf("got %q, want 1.29.2", got)
	}
}

func TestDetectComposeStandalone_NotInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("docker-compose", []string{"version", "--short"})
	})
	if got := detectComposeStandalone(context.Background()); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestCollectDaemonJournalErrors(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("journalctl", []string{
			"-u", "docker", "-n", "30", "--no-pager", "--since", "10 minutes ago", "--output=short",
		},
			"May 19 14:00:00 host dockerd[1]: level=info msg=\"started\"\n"+
				"May 19 14:01:00 host dockerd[1]: level=warning msg=\"low disk space\"\n"+
				"May 19 14:02:00 host dockerd[1]: docker error connecting to registry\n", 0)
	})
	d := &models.DockerDaemon{}
	collectDaemonJournalErrors(context.Background(), d)
	if d.RecentErrors != 2 {
		t.Errorf("RecentErrors = %d, want 2 (warning line + generic docker-error line)", d.RecentErrors)
	}
	if d.LastDaemonError == "" {
		t.Error("expected LastDaemonError to be populated")
	}
}

func TestCollectDaemonJournalErrors_CmdFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("journalctl", []string{
			"-u", "docker", "-n", "30", "--no-pager", "--since", "10 minutes ago", "--output=short",
		})
	})
	d := &models.DockerDaemon{}
	collectDaemonJournalErrors(context.Background(), d)
	if d.RecentErrors != 0 {
		t.Errorf("RecentErrors = %d, want 0", d.RecentErrors)
	}
}

func TestCollectDiskUsage_Happy(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/system/df": []byte(`{"LayersSize":1073741824,"Volumes":[{"UsageData":{"Size":536870912}}]}`),
	}, nil)
	info := &models.DockerInfo{}
	collectDiskUsage(context.Background(), client, info)
	want := 1.5
	if info.DiskUsageGB < want-0.01 || info.DiskUsageGB > want+0.01 {
		t.Errorf("DiskUsageGB = %v, want ~%v", info.DiskUsageGB, want)
	}
}

func TestCollectDiskUsage_APIFails(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{}, nil)
	info := &models.DockerInfo{}
	collectDiskUsage(context.Background(), client, info)
	if info.DiskUsageGB != 0 {
		t.Errorf("DiskUsageGB = %v, want 0", info.DiskUsageGB)
	}
}

func TestCollectImages_Happy(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/images/json?all=false": []byte(`[
			{"RepoTags":["nginx:latest"]},
			{"RepoTags":["<none>:<none>"]},
			{"RepoTags":[]}
		]`),
	}, nil)
	info := &models.DockerInfo{}
	collectImages(context.Background(), client, info)
	if info.ImagesCount != 3 {
		t.Errorf("ImagesCount = %d, want 3", info.ImagesCount)
	}
	if info.DanglingImages != 2 {
		t.Errorf("DanglingImages = %d, want 2 (untagged + <none>:<none>)", info.DanglingImages)
	}
}

func TestCollectImages_APIFails(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{}, nil)
	info := &models.DockerInfo{}
	collectImages(context.Background(), client, info)
	if info.ImagesCount != 0 {
		t.Errorf("ImagesCount = %d, want 0", info.ImagesCount)
	}
}

func TestCollectVolumes_Happy(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/volumes": []byte(`{"Volumes":[{},{}]}`),
	}, nil)
	info := &models.DockerInfo{}
	collectVolumes(context.Background(), client, info)
	if info.VolumesCount != 2 {
		t.Errorf("VolumesCount = %d, want 2", info.VolumesCount)
	}
}

func TestCollectVolumes_APIFails(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{}, nil)
	info := &models.DockerInfo{}
	collectVolumes(context.Background(), client, info)
	if info.VolumesCount != 0 {
		t.Errorf("VolumesCount = %d, want 0", info.VolumesCount)
	}
}

func TestCollectImageArch_Happy(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/images/nginx:latest/json": []byte(`{"Architecture":"aarch64"}`),
	}, nil)
	if got := collectImageArch(context.Background(), client, "nginx:latest"); got != "arm64" {
		t.Errorf("got %q, want arm64", got)
	}
}

func TestCollectImageArch_APIFails(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{}, nil)
	if got := collectImageArch(context.Background(), client, "missing:latest"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestCollectImageArch_Malformed(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/images/bad:latest/json": []byte("not json"),
	}, nil)
	if got := collectImageArch(context.Background(), client, "bad:latest"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestCollectArchMismatch(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/images/nginx:latest/json": []byte(`{"Architecture":"aarch64"}`),
		"/images/other:latest/json": []byte(`{"Architecture":"x86_64"}`),
	}, nil)
	info := &models.DockerInfo{
		HostArch: "amd64",
		Containers: []models.ContainerInfo{
			{Image: "nginx:latest"},
			{Image: "nginx:latest"}, // shares the per-image cache
			{Image: "other:latest"},
			{Image: ""}, // skipped entirely
		},
	}
	collectArchMismatch(context.Background(), client, info)
	if info.ArchMismatchCount != 2 {
		t.Errorf("ArchMismatchCount = %d, want 2", info.ArchMismatchCount)
	}
	if !info.Containers[0].ArchMismatch || info.Containers[0].ImageArch != "arm64" {
		t.Errorf("container[0] = %+v, want ArchMismatch=true ImageArch=arm64", info.Containers[0])
	}
	if !info.Containers[1].ArchMismatch {
		t.Error("container[1] must also be flagged (cached lookup, same image)")
	}
	if info.Containers[2].ArchMismatch {
		t.Error("container[2] (same arch as host) must not be flagged")
	}
}

func TestCollectDockerEvents_Happy(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	orig := timeNow
	timeNow = func() time.Time { return fixed }
	t.Cleanup(func() { timeNow = orig })

	since := fmt.Sprintf("%d", fixed.Add(-1*time.Hour).Unix())
	until := fmt.Sprintf("%d", fixed.Unix())
	path := fmt.Sprintf("/events?since=%s&until=%s&filters=%s",
		since, until, `{"type":["container"],"event":["die","oom","kill"]}`)

	client := withDockerAPIFixture(t, map[string][]byte{
		path: []byte(`{"Action":"oom","Actor":{"Attributes":{"name":"victim"}},"time":1000}`),
	}, nil)
	info := &models.DockerInfo{}
	collectDockerEvents(context.Background(), client, info)
	if len(info.RecentEvents) != 1 || info.OOMEvents != 1 {
		t.Errorf("RecentEvents=%+v OOMEvents=%d, want 1 event/1 oom", info.RecentEvents, info.OOMEvents)
	}
}

func TestCollectDockerEvents_APIFails(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{}, nil)
	info := &models.DockerInfo{}
	collectDockerEvents(context.Background(), client, info)
	if len(info.RecentEvents) != 0 || info.OOMEvents != 0 {
		t.Errorf("expected no events on API failure, got %+v", info)
	}
}

func TestDockerInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("docker", []string{"--version"}, "Docker version 27.3.1, build ...\n", 0)
	})
	if !dockerInstalled() {
		t.Error("expected true")
	}
}

func TestDockerInstalled_NotFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("docker", []string{"--version"})
	})
	if dockerInstalled() {
		t.Error("expected false")
	}
}

func TestCollectSocketPermReason_StatFails(t *testing.T) {
	got := collectSocketPermReason("/no/such/socket", "docker")
	want := "docker socket found at /no/such/socket but permission denied"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCollectSocketPermReason_RealSocketFile(t *testing.T) {
	// collectSocketPermReason reads the live GID/groups (documented as inherently
	// live, not source-routed) — just confirm it returns a sensible, non-crashing
	// message referencing the real path without pinning the in-group branch,
	// which depends on the test runner's process groups.
	path := filepath.Join(t.TempDir(), "docker.sock")
	if err := os.WriteFile(path, nil, 0o660); err != nil {
		t.Fatal(err)
	}
	got := collectSocketPermReason(path, "docker")
	if got == "" {
		t.Fatal("expected a non-empty message")
	}
}

func TestCollectPodmanQuadlets_Happy(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/etc/containers/systemd", []string{"web.container"})
		b.PutDir("/root/.config/containers/systemd", nil)
		b.PutCmd("systemctl", []string{"show", "web.service", "--property=ActiveState,SubState,LoadState"},
			"ActiveState=active\nSubState=running\nLoadState=loaded\n", 0)
	})
	quads := collectPodmanQuadlets(context.Background())
	if len(quads) != 1 {
		t.Fatalf("got %d quadlets, want 1", len(quads))
	}
	q := quads[0]
	if q.Name != "web" || q.ServiceUnit != "web.service" || !q.Active || q.Failed {
		t.Errorf("quadlet = %+v", q)
	}
}

func TestCollectPodmanQuadlets_NoneFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/etc/containers/systemd", nil)
		b.PutDir("/root/.config/containers/systemd", nil)
	})
	if quads := collectPodmanQuadlets(context.Background()); quads != nil {
		t.Errorf("expected nil, got %+v", quads)
	}
}

func TestQuadletUnitState_Active(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"show", "web.service", "--property=ActiveState,SubState,LoadState"},
			"ActiveState=active\n", 0)
	})
	active, failed, state := quadletUnitState(context.Background(), "web.service")
	if !active || failed || state != "active" {
		t.Errorf("active/failed/state = %v/%v/%q, want true/false/active", active, failed, state)
	}
}

func TestQuadletUnitState_CmdFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"show", "gone.service", "--property=ActiveState,SubState,LoadState"})
	})
	active, failed, state := quadletUnitState(context.Background(), "gone.service")
	if active || failed || state != "" {
		t.Errorf("active/failed/state = %v/%v/%q, want false/false/empty", active, failed, state)
	}
}

func TestPodmanQuadletsPresent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/etc/containers/systemd", []string{"web.container"})
	})
	if !PodmanQuadletsPresent() {
		t.Error("expected true")
	}
}

func TestPodmanQuadletsPresent_None(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/etc/containers/systemd", nil)
	})
	if PodmanQuadletsPresent() {
		t.Error("expected false")
	}
}

func TestGetHostMTU_Happy(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"lo", "docker0", "eth0"})
		b.PutFile("/sys/class/net/eth0/mtu", []byte("1500\n"))
	})
	if got := getHostMTU(); got != 1500 {
		t.Errorf("got %d, want 1500", got)
	}
}

func TestGetHostMTU_AllSkippedOrUnreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"lo", "veth1234"})
	})
	if got := getHostMTU(); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestGetHostMTU_DirUnreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := getHostMTU(); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestGetContainerNetworkMTU_ExplicitOption(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/networks": []byte(`[{"Name":"bridge","Options":{"com.docker.network.driver.mtu":"9000"}}]`),
	}, nil)
	if got := getContainerNetworkMTU(context.Background(), client); got != 9000 {
		t.Errorf("got %d, want 9000", got)
	}
}

func TestGetContainerNetworkMTU_DefaultWhenUnset(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/networks": []byte(`[{"Name":"podman","Options":{}}]`),
	}, nil)
	if got := getContainerNetworkMTU(context.Background(), client); got != 1500 {
		t.Errorf("got %d, want 1500 (default)", got)
	}
}

func TestGetContainerNetworkMTU_NoMatchingNetwork(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/networks": []byte(`[{"Name":"custom-net","Options":{}}]`),
	}, nil)
	if got := getContainerNetworkMTU(context.Background(), client); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestGetContainerNetworkMTU_APIFails(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{}, nil)
	if got := getContainerNetworkMTU(context.Background(), client); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestDetectNetworkBackend_NetavarkBinary(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/libexec/podman/netavark", source.FileMeta{})
	})
	if got := detectNetworkBackend("podman"); got != "netavark" {
		t.Errorf("got %q, want netavark", got)
	}
}

func TestDetectNetworkBackend_PodmanCNIFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/etc/cni/net.d", source.FileMeta{})
	})
	if got := detectNetworkBackend("podman"); got != "cni" {
		t.Errorf("got %q, want cni", got)
	}
}

func TestDetectNetworkBackend_PodmanDefaultNetavark(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := detectNetworkBackend("podman"); got != "netavark" {
		t.Errorf("got %q, want netavark (podman 4+ default)", got)
	}
}

func TestDetectNetworkBackend_Docker(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := detectNetworkBackend("docker"); got != "iptables" {
		t.Errorf("got %q, want iptables", got)
	}
}

func TestCollectFirewalldCheck_ActiveWithDockerZone(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "firewalld"}, "active\n", 0)
		b.PutFile("/etc/firewalld/firewalld.conf", []byte("FirewallBackend=nftables\n"))
		b.PutCmd("firewall-cmd", []string{"--get-active-zones"}, "docker\n  interfaces: docker0\n", 0)
	})
	info := &models.DockerInfo{}
	collectFirewalldCheck(context.Background(), info)
	if !info.FirewalldActive || info.FirewalldBackend != "nftables" || !info.DockerZoneTrusted {
		t.Errorf("info = %+v, want active/nftables/trusted", info)
	}
}

func TestCollectFirewalldCheck_Inactive(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "firewalld"}, "inactive\n", 3)
	})
	info := &models.DockerInfo{}
	collectFirewalldCheck(context.Background(), info)
	if info.FirewalldActive {
		t.Error("expected FirewalldActive=false")
	}
}
