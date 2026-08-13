//go:build linux || darwin

package collectors

import (
	"errors"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// noDaemonJSONSource fakes an absent /etc/docker/daemon.json (the common case:
// no daemon-wide override, everything at Docker's own defaults).
type noDaemonJSONSource struct{ source.Source }

func (noDaemonJSONSource) ReadFile(string) ([]byte, error) {
	return nil, errors.New("no such file or directory")
}

func (noDaemonJSONSource) Stat(string) (source.FileMeta, error) {
	return source.FileMeta{}, errors.New("no such file or directory")
}

func (noDaemonJSONSource) ReadDir(string) ([]string, error) {
	return nil, errors.New("no such file or directory")
}

// TestCollectLogDriverHealth_PerContainerOverride is the false-WARN regression
// guard: a per-container --log-opt max-size (Compose's `logging:` stanza is the
// common real-world case) must exclude that container from UnboundedContainers,
// even though the daemon-wide default has no max-size set.
func TestCollectLogDriverHealth_PerContainerOverride(t *testing.T) {
	defer SetSource(SetSource(noDaemonJSONSource{}))

	info := &models.DockerInfo{
		Containers: []models.ContainerInfo{
			{Name: "bounded", LogDriver: "json-file", LogMaxSizeSet: true},
			{Name: "unbounded", LogDriver: "json-file", LogMaxSizeSet: false},
			{Name: "journald", LogDriver: "journald", LogMaxSizeSet: false}, // not sized this way — must not count
		},
	}

	ld := collectLogDriverHealth(info)

	if len(ld.UnboundedContainers) != 1 || ld.UnboundedContainers[0] != "unbounded" {
		t.Errorf("UnboundedContainers = %v, want exactly [\"unbounded\"] (bounded + non-json-file containers excluded)", ld.UnboundedContainers)
	}
}

// TestCollectLogDriverHealth_AllBoundedIsClean confirms that when every
// container has its own max-size set, the daemon-wide default (no max-size)
// produces zero UnboundedContainers — the exact false-WARN this fix closes.
func TestCollectLogDriverHealth_AllBoundedIsClean(t *testing.T) {
	defer SetSource(SetSource(noDaemonJSONSource{}))

	info := &models.DockerInfo{
		Containers: []models.ContainerInfo{
			{Name: "web", LogDriver: "json-file", LogMaxSizeSet: true},
			{Name: "db", LogDriver: "json-file", LogMaxSizeSet: true},
		},
	}

	ld := collectLogDriverHealth(info)

	if len(ld.UnboundedContainers) != 0 {
		t.Errorf("UnboundedContainers = %v, want empty — every container bounds its own logs", ld.UnboundedContainers)
	}
}

// TestCollectLogDriverHealth_DetailFailureIsUnverifiedNotSilent is the false-OK
// regression guard: a container whose `/containers/<id>/json` inspect failed or
// was unparseable has LogDriver/LogMaxSizeSet at their zero values — indistinguishable
// from a real "" driver — and was previously silently excluded from both lists as
// if its logging were confirmed clean. It must instead land in UnverifiedContainers.
func TestCollectLogDriverHealth_DetailFailureIsUnverifiedNotSilent(t *testing.T) {
	defer SetSource(SetSource(noDaemonJSONSource{}))

	info := &models.DockerInfo{
		Containers: []models.ContainerInfo{
			{Name: "bounded", LogDriver: "json-file", LogMaxSizeSet: true},
			{Name: "flaky", DetailUnavailable: true}, // inspect failed — LogDriver/LogMaxSizeSet unset
		},
	}

	ld := collectLogDriverHealth(info)

	if len(ld.UnboundedContainers) != 0 {
		t.Errorf("UnboundedContainers = %v, want empty — the unverified container must not appear here", ld.UnboundedContainers)
	}
	if len(ld.UnverifiedContainers) != 1 || ld.UnverifiedContainers[0] != "flaky" {
		t.Errorf("UnverifiedContainers = %v, want exactly [\"flaky\"]", ld.UnverifiedContainers)
	}
}

// TestCollectLogDriverHealth_DaemonJSONPresent drives the daemon.json-found
// branch: a custom log driver with max-size/max-file set must be reflected in
// the returned DockerLogDriverInfo, and DaemonJSONExists must be true.
func TestCollectLogDriverHealth_DaemonJSONPresent(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/etc/docker/daemon.json", []byte(`{"log-driver":"local","log-opts":{"max-size":"10m","max-file":"3"}}`))
	defer SetSource(SetSource(source.NewReplay(b)))

	ld := collectLogDriverHealth(&models.DockerInfo{})
	if !ld.DaemonJSONExists {
		t.Error("expected DaemonJSONExists=true")
	}
	if ld.Driver != "local" {
		t.Errorf("Driver = %q, want local", ld.Driver)
	}
	if !ld.MaxSizeSet || !ld.MaxFileSet {
		t.Errorf("MaxSizeSet=%v MaxFileSet=%v, want both true", ld.MaxSizeSet, ld.MaxFileSet)
	}
}

// TestCollectLogDriverHealth_DaemonJSONNoDriverDefaultsToJSONFile confirms an
// explicit daemon.json with no log-driver key falls back to the "json-file"
// default, mirroring dockerd's own behaviour.
func TestCollectLogDriverHealth_DaemonJSONNoDriverDefaultsToJSONFile(t *testing.T) {
	b := source.NewBundle()
	b.PutFile("/etc/docker/daemon.json", []byte(`{}`))
	defer SetSource(SetSource(source.NewReplay(b)))

	ld := collectLogDriverHealth(&models.DockerInfo{})
	if ld.Driver != "json-file" {
		t.Errorf("Driver = %q, want json-file (default)", ld.Driver)
	}
}

// TestCollectLogDriverHealth_LargeLogCounted drives the >=500MB LargeLogCount
// branch — only reachable once collectContainerLogSizes actually returns
// entries (needs a readable /var/lib/docker/containers scan).
func TestCollectLogDriverHealth_LargeLogCounted(t *testing.T) {
	const longID = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeff"
	b := source.NewBundle()
	b.PutDir("/var/lib/docker/containers", []string{longID})
	b.PutDir("/var/lib/docker/containers/"+longID, []string{longID + "-json.log"})
	b.PutStat("/var/lib/docker/containers/"+longID+"/"+longID+"-json.log",
		source.FileMeta{Size: 600 * 1024 * 1024})
	defer SetSource(SetSource(source.NewReplay(b)))

	info := &models.DockerInfo{Containers: []models.ContainerInfo{{ID: longID[:12], Name: "biglogger"}}}
	ld := collectLogDriverHealth(info)
	if ld.LargeLogCount != 1 {
		t.Errorf("LargeLogCount = %d, want 1 (a 600MB log exceeds the 500MB threshold)", ld.LargeLogCount)
	}
}

// TestCollectContainerLogSizes_Found drives the full scan path: a container
// directory under /var/lib/docker/containers with a matching -json.log file,
// mapped back to its container name via the id->name lookup.
func TestCollectContainerLogSizes_Found(t *testing.T) {
	const longID = "abc123456789def0123456789abcdef0123456789abcdef0123456789abcdef"
	b := source.NewBundle()
	b.PutDir("/var/lib/docker/containers", []string{longID})
	b.PutDir("/var/lib/docker/containers/"+longID, []string{longID + "-json.log"})
	b.PutStat("/var/lib/docker/containers/"+longID+"/"+longID+"-json.log",
		source.FileMeta{Size: 5 * 1024 * 1024})
	defer SetSource(SetSource(source.NewReplay(b)))

	info := &models.DockerInfo{
		Containers: []models.ContainerInfo{{ID: longID[:12], Name: "web"}},
	}
	logs := collectContainerLogSizes(info)
	if len(logs) != 1 || logs[0].Name != "web" || logs[0].SizeMB != 5 {
		t.Errorf("logs = %+v, want [{web 5}]", logs)
	}
}

// TestCollectContainerLogSizes_UnknownContainerFallsBackToIDPrefix confirms a
// log file with no matching container in info.Containers still reports using
// the 12-char ID prefix as its name, rather than being silently dropped.
func TestCollectContainerLogSizes_UnknownContainerFallsBackToIDPrefix(t *testing.T) {
	const longID = "fedcba987654321000fedcba987654321000fedcba987654321000fedcba98"
	b := source.NewBundle()
	b.PutDir("/var/lib/docker/containers", []string{longID})
	b.PutDir("/var/lib/docker/containers/"+longID, []string{longID + "-json.log"})
	b.PutStat("/var/lib/docker/containers/"+longID+"/"+longID+"-json.log",
		source.FileMeta{Size: 1024 * 1024})
	defer SetSource(SetSource(source.NewReplay(b)))

	info := &models.DockerInfo{}
	logs := collectContainerLogSizes(info)
	if len(logs) != 1 || logs[0].Name != longID[:12] {
		t.Errorf("logs = %+v, want name=%q", logs, longID[:12])
	}
}

// TestCollectContainerLogSizes_SkipsNonDirEntries covers the !e.IsDir() branch:
// a stray non-directory file under /var/lib/docker/containers (e.g. a lock
// or metadata file dockerd left behind) must be skipped, not treated as a
// container ID.
func TestCollectContainerLogSizes_SkipsNonDirEntries(t *testing.T) {
	const longID = "1234567890ab1234567890ab1234567890ab1234567890ab1234567890abcd"
	b := source.NewBundle()
	// "somefile" is listed but never seeded as its own directory, so
	// probeIsDir("/var/lib/docker/containers/somefile") reports false.
	b.PutDir("/var/lib/docker/containers", []string{"somefile", longID})
	b.PutDir("/var/lib/docker/containers/"+longID, []string{longID + "-json.log"})
	b.PutStat("/var/lib/docker/containers/"+longID+"/"+longID+"-json.log",
		source.FileMeta{Size: 1024 * 1024})
	defer SetSource(SetSource(source.NewReplay(b)))

	info := &models.DockerInfo{Containers: []models.ContainerInfo{{ID: longID[:12], Name: "web"}}}
	logs := collectContainerLogSizes(info)
	if len(logs) != 1 || logs[0].Name != "web" {
		t.Errorf("logs = %+v, want exactly [{web ...}] (non-dir entry must be skipped)", logs)
	}
}

// TestCollectContainerLogSizes_ShortDirName guards against a panic when a
// directory under /var/lib/docker/containers is shorter than the 12-char ID
// prefix dsd displays. Directory names here come straight off the
// filesystem — a stray/crafted entry (or an attacker with write access to
// the containers dir) fully controls the name, so a naive name[:12] slice
// is a crash-the-whole-process bug on any entry under 12 bytes.
func TestCollectContainerLogSizes_ShortDirName(t *testing.T) {
	const shortID = "ab"
	b := source.NewBundle()
	b.PutDir("/var/lib/docker/containers", []string{shortID})
	b.PutDir("/var/lib/docker/containers/"+shortID, []string{shortID + "-json.log"})
	b.PutStat("/var/lib/docker/containers/"+shortID+"/"+shortID+"-json.log",
		source.FileMeta{Size: 1024 * 1024})
	defer SetSource(SetSource(source.NewReplay(b)))

	info := &models.DockerInfo{}
	logs := collectContainerLogSizes(info) // must not panic
	if len(logs) != 1 || logs[0].Name != shortID {
		t.Errorf("logs = %+v, want name=%q (short ID passed through unchanged)", logs, shortID)
	}
}

// TestCollectContainerLogSizes_MissingLogFile covers the statFile error
// branch: a container directory whose -json.log file doesn't exist (log
// rotated away, or the driver isn't json-file) must be silently skipped
// rather than erroring the whole scan.
func TestCollectContainerLogSizes_MissingLogFile(t *testing.T) {
	const longID = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678"
	b := source.NewBundle()
	b.PutDir("/var/lib/docker/containers", []string{longID})
	b.PutDir("/var/lib/docker/containers/"+longID, []string{}) // no -json.log seeded
	defer SetSource(SetSource(source.NewReplay(b)))

	info := &models.DockerInfo{Containers: []models.ContainerInfo{{ID: longID[:12], Name: "web"}}}
	if logs := collectContainerLogSizes(info); logs != nil {
		t.Errorf("logs = %+v, want nil when the log file doesn't exist", logs)
	}
}

// TestCollectContainerLogSizes_NoContainersDir confirms a missing/unreadable
// containers directory yields nil, not an error or panic.
func TestCollectContainerLogSizes_NoContainersDir(t *testing.T) {
	defer SetSource(SetSource(noDaemonJSONSource{}))
	if logs := collectContainerLogSizes(&models.DockerInfo{}); logs != nil {
		t.Errorf("logs = %v, want nil", logs)
	}
}
