//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func permDenied(dir string) error { return fmt.Errorf("open %s: %w", dir, os.ErrPermission) }

// DD-COLLECTOR-GAPS-1 High #5: a Logs sub-path whose read fails must carry its own
// sentinel, never a clean zero.

func TestCollectCrashFiles_UnreadableDirSetsSentinel(t *testing.T) {
	prev := SetSource(readDirErrSource{
		Source: source.NewReplay(source.NewBundle()),
		errs:   map[string]error{"/var/crash": permDenied("/var/crash")},
	})
	t.Cleanup(func() { SetSource(prev) })
	info := &models.LogsInfo{}
	collectCrashFiles(info)
	if !info.CrashFilesUnreadable {
		t.Fatal("CrashFilesUnreadable = false for a permission-denied /var/crash")
	}
}

func TestCollectCrashFiles_AbsentDirsAreClean(t *testing.T) {
	prev := SetSource(readDirErrSource{
		Source: source.NewReplay(source.NewBundle()),
		errs:   map[string]error{"/var/crash": fmt.Errorf("open: %w", os.ErrNotExist)},
	})
	t.Cleanup(func() { SetSource(prev) })
	info := &models.LogsInfo{}
	collectCrashFiles(info)
	if info.CrashFilesUnreadable {
		t.Fatal("CrashFilesUnreadable = true for a directory that simply does not exist")
	}
}

func TestJournalDiskUsage_UnreadableDirSetsSentinel(t *testing.T) {
	prev := SetSource(readDirErrSource{
		Source: source.NewReplay(source.NewBundle()),
		errs:   map[string]error{journalVarPath: permDenied(journalVarPath)},
	})
	t.Cleanup(func() { SetSource(prev) })
	gb, unreadable := journalDiskUsage()
	if !unreadable || gb != 0 {
		t.Fatalf("gb=%v unreadable=%v, want 0 GB flagged unreadable", gb, unreadable)
	}
}

func TestHasCorruptArchived_UnlistableDirIsUnverified(t *testing.T) {
	prev := SetSource(readDirErrSource{
		Source: source.NewReplay(source.NewBundle()),
		errs:   map[string]error{"/var/log/journal": permDenied("/var/log/journal")},
	})
	t.Cleanup(func() { SetSource(prev) })
	corrupt, unverified := hasCorruptArchived("/var/log/journal")
	if corrupt || !unverified {
		t.Fatalf("corrupt=%v unverified=%v, want false/true", corrupt, unverified)
	}
}

func TestDetectCrashLoops_UnitShowFailureIsUnverified(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "--state=failed", "--no-legend", "--no-pager", "--plain"},
			"myapp.service    loaded failed failed My App\n", 0)
		b.PutCmd("systemctl", []string{"show", "myapp.service", "--property=NRestarts", "--property=InactiveEnterTimestamp"}, "", 1)
	})
	loops, unverified := detectCrashLoops(context.Background())
	if len(loops) != 0 || !unverified {
		t.Fatalf("loops=%v unverified=%v, want none flagged unverified", loops, unverified)
	}
}
