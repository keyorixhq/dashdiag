package collectors

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// statfsFailSource fails Statfs for the listed mount points, as a stale NFS
// mount would, and answers the rest with fixed numbers.
type statfsFailSource struct {
	source.Source
	fail map[string]bool
}

func (s statfsFailSource) Statfs(path string) (source.StatfsInfo, error) {
	if s.fail[path] {
		return source.StatfsInfo{}, fmt.Errorf("statfs %s: stale file handle", path)
	}
	return source.StatfsInfo{Bsize: 4096, Blocks: 1000, Bfree: 500, Bavail: 500, Files: 100, Ffree: 90}, nil
}

// DD-COLLECTOR-GAPS-1 High #1: a mount whose statfs fails must be reported as
// unreachable, not silently absent from the result.
func TestCollectMountTable_UnreachableMountIsReportedNotDropped(t *testing.T) {
	prev := SetSource(statfsFailSource{Source: source.Live{}, fail: map[string]bool{"/mnt/nfs": true}})
	t.Cleanup(func() { SetSource(prev) })

	res, err := collectMountTable(context.Background(), []mountEntry{
		{device: "/dev/sda1", mountPoint: "/", fsType: "ext4"},
		{device: "nas:/export", mountPoint: "/mnt/nfs", fsType: "nfs4"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Filesystems) != 1 || res.Filesystems[0].Mount != "/" {
		t.Fatalf("Filesystems = %+v, want only /", res.Filesystems)
	}
	if len(res.UnreachableMounts) != 1 {
		t.Fatalf("UnreachableMounts = %+v, want the stale NFS mount", res.UnreachableMounts)
	}
	m := res.UnreachableMounts[0]
	if m.Mount != "/mnt/nfs" || m.FSType != "nfs4" || !strings.Contains(m.Error, "stale") {
		t.Errorf("unreachable mount = %+v", m)
	}
}

// Positive control: healthy mounts produce no unreachable entries.
func TestCollectMountTable_AllReachableIsClean(t *testing.T) {
	prev := SetSource(statfsFailSource{Source: source.Live{}})
	t.Cleanup(func() { SetSource(prev) })

	res, err := collectMountTable(context.Background(), []mountEntry{{device: "/dev/sda1", mountPoint: "/", fsType: "ext4"}})
	if err != nil || len(res.UnreachableMounts) != 0 || len(res.Filesystems) != 1 {
		t.Fatalf("res=%+v err=%v, want 1 fs and no unreachable", res, err)
	}
}
