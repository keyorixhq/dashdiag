//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestCollectDaemonHealth_SwarmWorkerBranch guards line docker.go:732 —
// when the swarm state is "active" but ControlAvailable is false, SwarmRole
// must be set to "worker", not "manager".
func TestCollectDaemonHealth_SwarmWorkerBranch(t *testing.T) {
	// t.Parallel() omitted: withDockerAPIFixture mutates the shared activeSource package global.
	client := withDockerAPIFixture(t, map[string][]byte{
		"/info": []byte(`{"Driver":"overlay2","Architecture":"x86_64","Swarm":{"LocalNodeState":"active","ControlAvailable":false}}`),
	}, func(b *source.Bundle) {
		b.PutCmdNotFound("docker", []string{"compose", "version", "--short"})
		b.PutCmdNotFound("docker-compose", []string{"version", "--short"})
		b.PutCmdNotFound("journalctl", []string{
			"-u", "docker", "-n", "30", "--no-pager", "--since", "10 minutes ago", "--output=short",
		})
	})
	d := collectDaemonHealth(context.Background(), client, "docker")
	if d.SwarmRole != "worker" {
		t.Errorf("SwarmRole = %q, want worker when ControlAvailable=false", d.SwarmRole)
	}
	if d.SwarmState != "active" {
		t.Errorf("SwarmState = %q, want active", d.SwarmState)
	}
}

// TestDetectComposePlugin_EmptyOutputAfterTrim guards line docker.go:777 —
// when `docker compose version --short` succeeds but the output is all
// whitespace (or v-prefix only), the result must be "" not " " / "v".
func TestDetectComposePlugin_EmptyOutputAfterTrim(t *testing.T) {
	// t.Parallel() omitted: withFixtureSource mutates the shared activeSource package global.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("docker", []string{"compose", "version", "--short"}, "   \n", 0)
	})
	if got := detectComposePlugin(context.Background()); got != "" {
		t.Errorf("detectComposePlugin() = %q, want empty string when output is all whitespace", got)
	}
}

// TestCollectDiskUsage_BadJSON guards line docker.go:843 — when /system/df
// returns something that isn't valid JSON, DiskUsageGB must remain 0.
func TestCollectDiskUsage_BadJSON(t *testing.T) {
	// t.Parallel() omitted: withDockerAPIFixture mutates the shared activeSource package global.
	client := withDockerAPIFixture(t, map[string][]byte{
		"/system/df": []byte("not valid json at all"),
	}, nil)
	info := &models.DockerInfo{}
	collectDiskUsage(context.Background(), client, info)
	if info.DiskUsageGB != 0 {
		t.Errorf("DiskUsageGB = %v, want 0 on unparseable /system/df body", info.DiskUsageGB)
	}
}

// TestCollectImages_BadJSON guards line docker.go:863 — when
// /images/json?all=false returns something that isn't a JSON array,
// ImagesCount must remain 0.
func TestCollectImages_BadJSON(t *testing.T) {
	// t.Parallel() omitted: withDockerAPIFixture mutates the shared activeSource package global.
	client := withDockerAPIFixture(t, map[string][]byte{
		"/images/json?all=false": []byte("not valid json"),
	}, nil)
	info := &models.DockerInfo{}
	collectImages(context.Background(), client, info)
	if info.ImagesCount != 0 {
		t.Errorf("ImagesCount = %d, want 0 on unparseable /images/json body", info.ImagesCount)
	}
}

// TestQuadletFilesPresent_DirectoryEntrySkipped guards line docker.go:918 —
// a sub-directory inside the quadlet dir must be skipped (directories are
// not .container / .pod files), so quadletFilesPresent must return false for
// a dir that contains only a subdirectory.
//
// probeIsDir calls ReadDir on each entry name to determine IsDir. We PutDir
// the nested path too so that probeIsDir("/etc/containers/systemd/subdir")
// returns true (ReadDir succeeds → IsDir=true).
func TestQuadletFilesPresent_DirectoryEntrySkipped(t *testing.T) {
	// t.Parallel() omitted: withFixtureSource mutates the shared activeSource package global.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/etc/containers/systemd", []string{"subdir"})
		// PutDir the sub-entry so probeIsDir returns true for it.
		b.PutDir("/etc/containers/systemd/subdir", nil)
	})
	if quadletFilesPresent("/etc/containers/systemd") {
		t.Error("expected false: a directory entry must not be treated as a quadlet file")
	}
}

// TestIsRHEL10Plus_RHELFamilyButNoVersionID guards line docker.go:969 —
// the function returns false when the distro IS rhel-family but there is
// no VERSION_ID line in os-release (falls through the for loop to the
// final return false).
func TestIsRHEL10Plus_RHELFamilyButNoVersionID(t *testing.T) {
	// t.Parallel() omitted: withFixtureSource mutates the shared activeSource package global.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/os-release", []byte("ID=rhel\nNAME=\"Red Hat Enterprise Linux\"\n"))
	})
	if isRHEL10Plus() {
		t.Error("isRHEL10Plus() = true, want false when there is no VERSION_ID line")
	}
}

// TestGetContainerNetworkMTU_BadJSON guards line docker.go:1250 — when
// /networks returns unparseable JSON, the function must return 0.
func TestGetContainerNetworkMTU_BadJSON(t *testing.T) {
	// t.Parallel() omitted: withDockerAPIFixture mutates the shared activeSource package global.
	client := withDockerAPIFixture(t, map[string][]byte{
		"/networks": []byte("not valid json"),
	}, nil)
	if got := getContainerNetworkMTU(context.Background(), client); got != 0 {
		t.Errorf("getContainerNetworkMTU() = %d, want 0 on bad JSON", got)
	}
}

// TestGetHostMTU_DirectoryEntrySkipped guards line docker.go:1289 — a
// directory entry under /sys/class/net must be skipped (IsDir=true).
// A dir that has only one real network interface, a loopback and a directory
// sub-entry, must still return the physical interface's MTU without crashing.
//
// probeIsDir checks ReadDir on each entry name; we PutDir the sub-entry path
// to make it appear as a directory (IsDir=true → skip).
func TestGetHostMTU_DirectoryEntrySkipped(t *testing.T) {
	// t.Parallel() omitted: withFixtureSource mutates the shared activeSource package global.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"lo", "netsubdir", "eth0"})
		// Make "netsubdir" appear as a directory so IsDir=true → skipped.
		b.PutDir("/sys/class/net/netsubdir", nil)
		b.PutFile("/sys/class/net/eth0/mtu", []byte("9000\n"))
	})
	if got := getHostMTU(); got != 9000 {
		t.Errorf("getHostMTU() = %d, want 9000 (directory entry must be skipped)", got)
	}
}

// TestCollectDNSTrap_DNSTrapButAPIFails guards line docker.go:569 — when
// /etc/resolv.conf has a loopback nameserver (DNSTrap=true) but the /info
// API call fails, the function must return without setting DaemonDNSServers.
func TestCollectDNSTrap_DNSTrapButAPIFails(t *testing.T) {
	// t.Parallel() omitted: withDockerAPIFixture mutates the shared activeSource package global.
	// fakeDockerAPISource returns an error for any path not in the map.
	// We seed resolv.conf with a loopback NS but provide no /info fixture.
	client := withDockerAPIFixture(t, map[string][]byte{
		// no /info entry → apiGet will fail
	}, func(b *source.Bundle) {
		b.PutFile("/etc/resolv.conf", []byte("nameserver 127.0.0.53\n"))
	})
	info := &models.DockerInfo{}
	collectDNSTrap(context.Background(), client, info)
	if !info.DNSTrap {
		t.Error("DNSTrap = false, want true — loopback nameserver must be detected")
	}
	if info.DNSTrapServer != "127.0.0.53" {
		t.Errorf("DNSTrapServer = %q, want 127.0.0.53", info.DNSTrapServer)
	}
	if info.DaemonDNSConfigured {
		t.Error("DaemonDNSConfigured = true, want false when /info API fails")
	}
}
