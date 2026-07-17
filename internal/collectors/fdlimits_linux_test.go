//go:build linux

package collectors

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestFDLimitsCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewFDLimitsCollector()
	if c.Name() != "FDLimits" {
		t.Errorf("Name() = %q, want FDLimits", c.Name())
	}
	if c.Timeout() != 1*time.Second {
		t.Errorf("Timeout() = %v, want 1s", c.Timeout())
	}
	if c.fileNrPath != "/proc/sys/fs/file-nr" {
		t.Errorf("fileNrPath = %q, want /proc/sys/fs/file-nr", c.fileNrPath)
	}
}

// TestFDLimitsCollector_Collect_LinuxDispatch guards that the top-level
// Collect() dispatches to collectLinux on this platform (runtime.GOOS ==
// "linux" in this build) and returns the system-wide FD usage read via the
// default fileNrPath.
func TestFDLimitsCollector_Collect_LinuxDispatch(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/fs/file-nr", []byte("500\t0\t100000\n"))
		b.PutGlob("/proc/[0-9]*", nil)
	})
	c := NewFDLimitsCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.FDInfo)
	if info.OpenCount != 500 || info.MaxCount != 100000 {
		t.Errorf("OpenCount/MaxCount = %d/%d, want 500/100000", info.OpenCount, info.MaxCount)
	}
}

// TestFDLimitsCollector_CollectLinux_OpenFileError guards the "file-nr can't
// be opened" error path.
func TestFDLimitsCollector_CollectLinux_OpenFileError(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // file-nr unseeded
	c := NewFDLimitsCollector()
	if _, err := c.collectLinux(context.Background()); err == nil {
		t.Error("expected an error when file-nr can't be opened")
	}
}

// TestFDLimitsCollector_CollectLinux_ParseError covers the "parsing file-nr"
// error path: file-nr exists but contains too few fields, causing parseFileNr
// to return an error.
func TestFDLimitsCollector_CollectLinux_ParseError(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/fs/file-nr", []byte("baddata\n")) // 1 field, not 3
	})
	c := NewFDLimitsCollector()
	_, err := c.collectLinux(context.Background())
	if err == nil {
		t.Fatal("expected an error when file-nr has too few fields")
	}
	if !strings.Contains(err.Error(), "parsing file-nr") {
		t.Errorf("error = %q, want 'parsing file-nr' context", err)
	}
}

// TestHotProcInfo guards the soft-limit threshold logic: below-70%-usage is
// skipped, above-70% is reported, and the small-transient-helper exclusion
// (softLimit<=16 && fdCount<=32) suppresses noise from socket-activated units.
func TestHotProcInfo(t *testing.T) {
	t.Run("below threshold not reported", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/123/limits", []byte(
				"Limit                     Soft Limit           Hard Limit           Units\n"+
					"Max open files            1000                 4096                 files\n"))
		})
		_, ok := hotProcInfo("123", 100) // 10% used
		if ok {
			t.Error("expected ok=false when usage is below the 70% threshold")
		}
	})

	t.Run("above threshold reported", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/456/limits", []byte(
				"Limit                     Soft Limit           Hard Limit           Units\n"+
					"Max open files            1000                 4096                 files\n"))
			b.PutFile("/proc/456/comm", []byte("leaky-daemon\n"))
		})
		p, ok := hotProcInfo("456", 900) // 90% used
		if !ok {
			t.Fatal("expected ok=true when usage exceeds 70%")
		}
		if p.PID != 456 || p.Name != "leaky-daemon" || p.SoftLimit != 1000 || p.OpenFDs != 900 {
			t.Errorf("got %+v, want PID=456 Name=leaky-daemon SoftLimit=1000 OpenFDs=900", p)
		}
	})

	t.Run("small transient helper excluded", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/789/limits", []byte(
				"Limit                     Soft Limit           Hard Limit           Units\n"+
					"Max open files            16                   16                   files\n"))
		})
		_, ok := hotProcInfo("789", 15) // 93.75% of 16, but softLimit<=16 && fdCount<=32
		if ok {
			t.Error("expected ok=false for a small-limit transient helper")
		}
	})

	t.Run("limits file unreadable", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		_, ok := hotProcInfo("999", 900)
		if ok {
			t.Error("expected ok=false when /proc/<pid>/limits can't be opened")
		}
	})

	t.Run("no soft limit found", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/111/limits", []byte("Limit                     Soft Limit           Hard Limit           Units\n"))
		})
		_, ok := hotProcInfo("111", 900)
		if ok {
			t.Error("expected ok=false when no 'Max open files' line is present (softLimit<=0)")
		}
	})
}

// TestDeletedFilesFromEntries guards the open-but-deleted-file detection: a
// deleted target counts and sums size, a non-deleted target is skipped, and a
// readlink failure is skipped without incrementing the count.
func TestDeletedFilesFromEntries(t *testing.T) {
	withCombinedFixture(t, nil, map[string]string{
		"/proc/42/fd/3": "/var/log/app.log (deleted)",
		"/proc/42/fd/4": "/var/log/other.log", // not deleted
	}, func(b *source.Bundle) {
		b.PutStat("/proc/42/fd/3", source.FileMeta{Size: 2_000_000_000}) // 2GB
	})
	count, sizeGB := deletedFilesFromEntries("42", []string{"3", "4"})
	if count != 1 {
		t.Errorf("count = %d, want 1 (only fd 3 is deleted)", count)
	}
	if sizeGB < 1.9 || sizeGB > 2.1 {
		t.Errorf("sizeGB = %v, want ~2.0", sizeGB)
	}
}

// TestDeletedFilesFromEntries_StatFails guards that a deleted file whose Stat
// fails still counts (count++) but contributes no size — the count must not
// be silently dropped just because the size couldn't be read.
func TestDeletedFilesFromEntries_StatFails(t *testing.T) {
	withCombinedFixture(t, nil, map[string]string{
		"/proc/42/fd/5": "/var/log/gone.log (deleted)",
	}, func(_ *source.Bundle) {
		// /proc/42/fd/5 Stat intentionally unseeded -> fails
	})
	count, sizeGB := deletedFilesFromEntries("42", []string{"5"})
	if count != 1 {
		t.Errorf("count = %d, want 1 (counted even though Stat failed)", count)
	}
	if sizeGB != 0 {
		t.Errorf("sizeGB = %v, want 0 when Stat failed", sizeGB)
	}
}

// TestScanProcesses exercises the /proc walk end to end: a hot process is
// surfaced and sorted, deleted-file totals accumulate, and a process whose fd
// dir can't be read is skipped without aborting the scan.
func TestScanProcesses(t *testing.T) {
	fds50 := make([]string, 18) // 18/20 = 90% usage, softLimit=20 > 16 avoids the small-helper exclusion
	for i := range fds50 {
		fds50[i] = strconv.Itoa(i)
	}
	withCombinedFixture(t, nil, map[string]string{
		"/proc/50/fd/3": "/tmp/deleted.log (deleted)",
	}, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", []string{"/proc/50", "/proc/60"})
		b.PutDir("/proc/50/fd", fds50)
		b.PutStat("/proc/50/fd/3", source.FileMeta{Size: 1_000_000_000})
		b.PutFile("/proc/50/limits", []byte(
			"Limit                     Soft Limit           Hard Limit           Units\n"+
				"Max open files            20                   100                  files\n"))
		b.PutFile("/proc/50/comm", []byte("hotproc\n"))
		// /proc/60/fd intentionally unseeded -> readDirNames fails -> skipped.
	})
	c := NewFDLimitsCollector()
	scan := c.scanProcesses(context.Background())
	if scan.DeletedOpenFiles != 1 {
		t.Errorf("DeletedOpenFiles = %d, want 1", scan.DeletedOpenFiles)
	}
	if scan.DeletedOpenSizeGB < 0.9 || scan.DeletedOpenSizeGB > 1.1 {
		t.Errorf("DeletedOpenSizeGB = %v, want ~1.0", scan.DeletedOpenSizeGB)
	}
	if len(scan.Hot) != 1 || scan.Hot[0].PID != 50 {
		t.Fatalf("Hot = %+v, want exactly one entry for PID 50", scan.Hot)
	}
}

// TestScanProcesses_CapsAtFive guards the top-5 cut and the FD-pressure-desc,
// PID-asc tiebreak ordering. Each process opens 90 of a 100 soft limit (90%,
// comfortably above both the 70% threshold and the small-transient-helper
// exclusion, which only applies when softLimit<=16 && fdCount<=32).
func TestScanProcesses_CapsAtFive(t *testing.T) {
	dirs := make([]string, 0, 6)
	withFixtureSource(t, func(b *source.Bundle) {
		fds := make([]string, 90)
		for i := range fds {
			fds[i] = strconv.Itoa(i)
		}
		for i := 1; i <= 6; i++ {
			pidDir := "/proc/" + strconv.Itoa(i)
			dirs = append(dirs, pidDir)
			b.PutDir(pidDir+"/fd", fds)
			b.PutFile(pidDir+"/limits", []byte(
				"Limit                     Soft Limit           Hard Limit           Units\n"+
					"Max open files            100                  1000                 files\n"))
			b.PutFile(pidDir+"/comm", []byte("proc\n"))
		}
		b.PutGlob("/proc/[0-9]*", dirs)
	})
	c := NewFDLimitsCollector()
	scan := c.scanProcesses(context.Background())
	if len(scan.Hot) != 5 {
		t.Errorf("len(Hot) = %d, want exactly 5 (capped from 6)", len(scan.Hot))
	}
}
