//go:build linux

package collectors

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

func TestCollectVolumes_UnparseableJSON(t *testing.T) {
	client := withDockerAPIFixture(t, map[string][]byte{
		"/volumes": []byte(`not json`),
	}, nil)
	info := &models.DockerInfo{}
	collectVolumes(context.Background(), client, info)
	if info.VolumesCount != 0 {
		t.Errorf("VolumesCount = %d, want 0 on unparseable body", info.VolumesCount)
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

// TestCollectSocketPermReason_GroupMembershipPresent guards the fix for a
// dead-code regression: fi.Sys() on Linux is *syscall.Stat_t, which exposes
// Gid as a struct field, not a Gid() method — the prior `fi.Sys().(interface{
// Gid() uint32 })` assertion could never succeed, so the "group membership
// present but session not refreshed" message never fired even when the
// caller's process genuinely belonged to the socket's group.
func TestCollectSocketPermReason_GroupMembershipPresent(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil || len(groups) == 0 {
		t.Skip("no supplementary groups available to test against")
	}
	path := filepath.Join(t.TempDir(), "docker.sock")
	if err := os.WriteFile(path, nil, 0o660); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, -1, groups[0]); err != nil {
		t.Skipf("cannot chown test socket to gid %d: %v", groups[0], err)
	}
	got := collectSocketPermReason(path, "docker")
	if !strings.Contains(got, "group membership present but session not refreshed") {
		t.Errorf("got %q, want the group-membership-present message", got)
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

// TestDetectNetworkBackend_NetavarkBinAlt covers the /usr/bin/netavark
// fallback path — the libexec location from TestDetectNetworkBackend_NetavarkBinary
// is absent, but the plain /usr/bin location is present.
func TestDetectNetworkBackend_NetavarkBinAlt(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/netavark", source.FileMeta{})
	})
	if got := detectNetworkBackend("podman"); got != "netavark" {
		t.Errorf("got %q, want netavark", got)
	}
}

// TestDetectNetworkBackend_ConntrackStatReadable covers the (currently
// discarded) nf_conntrack_stat read succeeding — a no-op branch, but real
// coverage of the file-present case rather than only the absent case every
// other test here exercises implicitly.
func TestDetectNetworkBackend_ConntrackStatReadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/nf_conntrack_stat", []byte("entries  searched found new invalid\n"))
	})
	if got := detectNetworkBackend("docker"); got != "iptables" {
		t.Errorf("got %q, want iptables", got)
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

// --- Collect / DetectContainerSocket / detectContainerSocket / socketClient ---

// TestDockerCollect_NoSocketNoBinaries guards the simplest "nothing here" path:
// no socket files exist, docker isn't installed, and podman isn't installed —
// Collect must resolve to a benign unavailable state with no StatusReason (per
// the doc comment on docker.go's Collect: idle Podman is not a fault).
func TestDockerCollect_NoSocketNoBinaries(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("docker", []string{"--version"})
	})
	c := NewDockerCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not error, got %v", err)
	}
	info, ok := res.(*models.DockerInfo)
	if !ok {
		t.Fatalf("expected *models.DockerInfo, got %T", res)
	}
	if info.Available {
		t.Error("Available must be false with no socket")
	}
	if info.Status != "unavailable" {
		t.Errorf("Status = %q, want unavailable", info.Status)
	}
	if info.StatusReason != "" {
		t.Errorf("StatusReason = %q, want empty (idle Podman/no-runtime is benign, not a fault)", info.StatusReason)
	}
}

// TestDockerCollect_NoSocketButDockerInstalled guards the "installed but not
// running" fault path — dockerd is on PATH but no socket answers, which the
// doc comment calls out as a genuine fault (unlike idle Podman).
func TestDockerCollect_NoSocketButDockerInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("docker", []string{"--version"}, "Docker version 27.3.1, build abc\n", 0)
	})
	c := NewDockerCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not error, got %v", err)
	}
	info := res.(*models.DockerInfo) //nolint:errcheck // asserted by identity test elsewhere
	if info.StatusReason != "Docker installed but daemon not running" {
		t.Errorf("StatusReason = %q, want the daemon-not-running reason", info.StatusReason)
	}
}

// TestDockerCollect_NoSocketButDockerInstalled_RHEL10Hint guards the
// RHEL/Rocky 10+ iptables-legacy hint appended to the same fault path.
func TestDockerCollect_NoSocketButDockerInstalled_RHEL10Hint(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("docker", []string{"--version"}, "Docker version 27.3.1, build abc\n", 0)
	})
	c := NewDockerCollectorWithProfile(platform.Profile{Distro: "rhel", MajorVersion: 10})
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not error, got %v", err)
	}
	info := res.(*models.DockerInfo) //nolint:errcheck
	if !strings.Contains(info.StatusReason, "iptables-legacy removed in RHEL 10") {
		t.Errorf("StatusReason = %q, want the RHEL10+ iptables-legacy hint", info.StatusReason)
	}
}

// TestDockerCollect_PodmanQuadletsWithoutSocket guards the daemonless-Podman
// path: no socket answers and no dockerd is installed, but Podman is on PATH
// and manages containers purely via systemd quadlets (invisible to the API
// socket) — Collect must surface those quadlets rather than reporting
// unavailable.
func TestDockerCollect_PodmanQuadletsWithoutSocket(t *testing.T) {
	withCombinedFixture(t,
		map[string][]byte{"lookpath/podman": []byte("/usr/bin/podman")},
		nil,
		func(b *source.Bundle) {
			b.PutCmdNotFound("docker", []string{"--version"})
			b.PutDir("/etc/containers/systemd", []string{"web.container"})
			b.PutDir("/root/.config/containers/systemd", nil)
			b.PutCmd("systemctl", []string{"show", "web.service", "--property=ActiveState,SubState,LoadState"},
				"ActiveState=active\nSubState=running\nLoadState=loaded\n", 0)
		})
	c := NewDockerCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not error, got %v", err)
	}
	info := res.(*models.DockerInfo) //nolint:errcheck
	if !info.Available {
		t.Error("Available must be true when Podman quadlets are found")
	}
	if info.Runtime != "podman" {
		t.Errorf("Runtime = %q, want podman", info.Runtime)
	}
	if len(info.PodmanQuadlets) != 1 || info.PodmanQuadlets[0].Name != "web" {
		t.Errorf("PodmanQuadlets = %+v, want a single 'web' entry", info.PodmanQuadlets)
	}
}

// TestDockerCollect_SocketPermissionDenied guards the 7h permission-denied
// path — a socket file exists but the dial reports permission-denied.
func TestDockerCollect_SocketPermissionDenied(t *testing.T) {
	withCombinedFixture(t,
		map[string][]byte{"dial/unix//var/run/docker.sock": {'p'}},
		nil,
		func(b *source.Bundle) {
			b.PutStat("/var/run/docker.sock", source.FileMeta{})
		})
	c := NewDockerCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not error, got %v", err)
	}
	info := res.(*models.DockerInfo) //nolint:errcheck
	if !info.SocketPermDenied {
		t.Error("SocketPermDenied must be true")
	}
	if info.Status != "unavailable" {
		t.Errorf("Status = %q, want unavailable", info.Status)
	}
	if info.StatusReason == "" {
		t.Error("expected a non-empty StatusReason describing the permission fault")
	}
}

// TestDockerCollect_HappyPathMinimal guards the full Collect body when a
// socket IS reachable: detectContainerSocket finds it, socketClient's client
// is handed to every collect* helper, and apiGet's docker-api/<path> cache
// keys serve every API call. Container list is empty so the per-container
// inspect fan-out (containerDetail) never needs its own fixtures — this
// isolates Collect's own wiring (socket detection -> daemon health -> disk ->
// images -> volumes -> network -> DNS trap -> events) from the
// already-covered per-container parsing logic in docker_containers_test.go.
func TestDockerCollect_HappyPathMinimal(t *testing.T) {
	cached := map[string][]byte{
		"dial/unix//var/run/docker.sock":                  {'1'},
		"docker-api//info":                                []byte(`{"Driver":"overlay2","Architecture":"x86_64"}`),
		"docker-api//version":                             []byte(`{"Version":"27.3.1","ApiVersion":"1.47"}`),
		"docker-api//containers/json?all=true&size=false": []byte(`[]`),
		"docker-api//system/df":                           []byte(`{}`),
		"docker-api//images/json?all=false":               []byte(`[]`),
		"docker-api//volumes":                             []byte(`{"Volumes":[]}`),
		"docker-api//networks":                            []byte(`[]`),
	}
	withCombinedFixture(t, cached, nil, func(b *source.Bundle) {
		b.PutStat("/var/run/docker.sock", source.FileMeta{})
		b.PutCmdNotFound("docker-compose", []string{"version", "--short"})
		b.PutCmdNotFound("podman", []string{"--version"})
		b.PutCmd("systemctl", []string{"is-active", "firewalld"}, "inactive\n", 3)
	})
	c := NewDockerCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not error, got %v", err)
	}
	info := res.(*models.DockerInfo) //nolint:errcheck
	if !info.Available {
		t.Fatal("Available must be true once the socket dials OK")
	}
	if info.Runtime != "docker" {
		t.Errorf("Runtime = %q, want docker", info.Runtime)
	}
	if info.Status == "error" {
		t.Errorf("Status must not be error, got StatusReason=%q", info.StatusReason)
	}
	if info.Daemon == nil || info.Daemon.StorageDriver != "overlay2" {
		t.Errorf("Daemon = %+v, want StorageDriver=overlay2", info.Daemon)
	}
	if info.TotalContainers != 0 {
		t.Errorf("TotalContainers = %d, want 0 (empty container list fixture)", info.TotalContainers)
	}
	if info.HostArch != "amd64" {
		t.Errorf("HostArch = %q, want amd64 (normalized from x86_64)", info.HostArch)
	}
}

// TestDockerCollect_DeepModeInvokesLogDriverHealth guards the c.Deep &&
// Runtime=="docker" branch that wires collectLogDriverHealth into Collect —
// the deep-mode-only field must be populated when Deep=true, and left nil
// for a plain (non-deep) collector on an otherwise identical fixture.
func TestDockerCollect_DeepModeInvokesLogDriverHealth(t *testing.T) {
	cached := map[string][]byte{
		"dial/unix//var/run/docker.sock":                  {'1'},
		"docker-api//info":                                []byte(`{"Driver":"overlay2","Architecture":"x86_64"}`),
		"docker-api//version":                             []byte(`{"Version":"27.3.1","ApiVersion":"1.47"}`),
		"docker-api//containers/json?all=true&size=false": []byte(`[]`),
		"docker-api//system/df":                           []byte(`{}`),
		"docker-api//images/json?all=false":               []byte(`[]`),
		"docker-api//volumes":                             []byte(`{"Volumes":[]}`),
		"docker-api//networks":                            []byte(`[]`),
	}
	withCombinedFixture(t, cached, nil, func(b *source.Bundle) {
		b.PutStat("/var/run/docker.sock", source.FileMeta{})
		b.PutCmdNotFound("docker-compose", []string{"version", "--short"})
		b.PutCmdNotFound("podman", []string{"--version"})
		b.PutCmd("systemctl", []string{"is-active", "firewalld"}, "inactive\n", 3)
	})
	c := NewDockerDeepCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not error, got %v", err)
	}
	info := res.(*models.DockerInfo) //nolint:errcheck
	if info.LogDriver == nil {
		t.Error("LogDriver must be populated in Deep mode for the docker runtime")
	}
}

// TestDockerCollect_ContainerListError guards the "error" status branch: a
// reachable socket but a failing /containers/json call must set
// Status=error with a StatusReason, and must not proceed to any of the
// later collect* calls.
func TestDockerCollect_ContainerListError(t *testing.T) {
	cached := map[string][]byte{
		"dial/unix//var/run/docker.sock": {'1'},
		"docker-api//info":               []byte(`{"Driver":"overlay2"}`),
		"docker-api//version":            []byte(`{"Version":"27.3.1"}`),
		// /containers/json deliberately NOT seeded -> apiGet errors.
	}
	withCombinedFixture(t, cached, nil, func(b *source.Bundle) {
		b.PutStat("/var/run/docker.sock", source.FileMeta{})
		b.PutCmdNotFound("docker-compose", []string{"version", "--short"})
		b.PutCmdNotFound("podman", []string{"--version"})
	})
	c := NewDockerCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not error, got %v", err)
	}
	info := res.(*models.DockerInfo) //nolint:errcheck
	if info.Status != "error" {
		t.Errorf("Status = %q, want error", info.Status)
	}
	if !strings.Contains(info.StatusReason, "failed to list containers") {
		t.Errorf("StatusReason = %q, want it to mention failed to list containers", info.StatusReason)
	}
}

// TestDetectContainerSocket_ExportedWrapper guards the thin exported wrapper:
// it must return the same (path, runtime) pair as the internal function and
// discard the permDenied bool.
func TestDetectContainerSocket_ExportedWrapper(t *testing.T) {
	withCombinedFixture(t,
		map[string][]byte{"dial/unix//var/run/docker.sock": {'1'}},
		nil,
		func(b *source.Bundle) {
			b.PutStat("/var/run/docker.sock", source.FileMeta{})
		})
	path, runtime := DetectContainerSocket()
	if path != "/var/run/docker.sock" || runtime != "docker" {
		t.Errorf("DetectContainerSocket() = (%q, %q), want (/var/run/docker.sock, docker)", path, runtime)
	}
}

// TestDetectContainerSocket_CandidateOrder guards the candidate list ordering
// and skip-on-absent behavior: /var/run/docker.sock is checked first but
// doesn't exist, so detection must fall through to the next existing
// candidate (/run/podman/podman.sock) rather than stopping at the first
// entry in the list.
func TestDetectContainerSocket_CandidateOrder(t *testing.T) {
	withCombinedFixture(t,
		map[string][]byte{"dial/unix//run/podman/podman.sock": {'1'}},
		nil,
		func(b *source.Bundle) {
			b.PutStat("/run/podman/podman.sock", source.FileMeta{})
			// /var/run/docker.sock, /run/docker.sock intentionally not stat'd -> fileExists false.
		})
	path, runtime, permDenied := detectContainerSocket()
	if path != "/run/podman/podman.sock" || runtime != "podman" || permDenied {
		t.Errorf("detectContainerSocket() = (%q, %q, %v), want (/run/podman/podman.sock, podman, false)", path, runtime, permDenied)
	}
}

// TestDetectContainerSocket_NoneFound guards the exhausted-candidates path:
// no socket file exists at all, so detection must return the zero values
// without error.
func TestDetectContainerSocket_NoneFound(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // nothing seeded -> every fileExists() is false
	path, runtime, permDenied := detectContainerSocket()
	if path != "" || runtime != "" || permDenied {
		t.Errorf("detectContainerSocket() = (%q, %q, %v), want all zero values", path, runtime, permDenied)
	}
}

// TestDetectContainerSocket_PermissionDenied guards the permDenied=true
// return: a socket file exists but the dial reports permission-denied.
func TestDetectContainerSocket_PermissionDenied(t *testing.T) {
	withCombinedFixture(t,
		map[string][]byte{"dial/unix//var/run/docker.sock": {'p'}},
		nil,
		func(b *source.Bundle) {
			b.PutStat("/var/run/docker.sock", source.FileMeta{})
		})
	path, runtime, permDenied := detectContainerSocket()
	if path != "/var/run/docker.sock" || runtime != "docker" || !permDenied {
		t.Errorf("detectContainerSocket() = (%q, %q, %v), want (/var/run/docker.sock, docker, true)", path, runtime, permDenied)
	}
}

// TestSocketClient guards socketClient's structural contract (timeout, and a
// DialContext func is wired up). The DialContext closure itself dials a real
// Unix socket via net.Dialer — it is NOT routed through the source/replay
// mechanism (apiGet bypasses socketClient entirely in tests by caching at the
// docker-api/<path> level, per apiGet's doc comment), so exercising the
// closure body would require a genuine live socket. That part is intentionally
// left untested here; only the client's own construction is verified.
func TestSocketClient(t *testing.T) {
	t.Parallel()
	client := socketClient("/var/run/docker.sock")
	if client == nil {
		t.Fatal("socketClient returned nil")
	}
	if client.Timeout != 8*time.Second {
		t.Errorf("Timeout = %v, want 8s", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", client.Transport)
	}
	if transport.DialContext == nil {
		t.Error("expected a non-nil DialContext")
	}
}

// TestSocketClient_DialContext_Live exercises the DialContext closure body
// (previously untested — see the doc comment above) against a genuine local
// Unix socket: a bare net.Listener in t.TempDir() serving a canned HTTP
// response, never the real Docker daemon. This also drives apiGetLive's full
// success path (client.Do succeeds, then the chunked resp.Body.Read loop),
// which no other test reaches — every other apiGet test intercepts Cached
// directly and never dials a real socket.
func TestSocketClient_DialContext_Live(t *testing.T) {
	t.Parallel()
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}),
		ReadHeaderTimeout: 2 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close() //nolint:errcheck

	client := socketClient(sockPath)
	got, err := apiGetLive(context.Background(), client, "/info")
	if err != nil {
		t.Fatalf("apiGetLive() error: %v", err)
	}
	if string(got) != `{"ok":true}` {
		t.Errorf("apiGetLive() = %q, want {\"ok\":true}", got)
	}
}

// TestApiGetLive_DialError guards apiGetLive's client.Do error branch against
// a socket path that genuinely does not exist — a fast, deterministic local
// dial failure (no real network involved), unlike a hardcoded remote IMDS URL.
func TestApiGetLive_DialError(t *testing.T) {
	t.Parallel()
	client := socketClient(filepath.Join(t.TempDir(), "does-not-exist.sock"))
	got, err := apiGetLive(context.Background(), client, "/info")
	if err == nil {
		t.Fatal("expected an error dialing a nonexistent socket")
	}
	if got != nil {
		t.Errorf("got = %v, want nil on error", got)
	}
}
