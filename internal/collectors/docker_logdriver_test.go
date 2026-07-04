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
