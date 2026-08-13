//go:build linux

package collectors

import (
	"context"
	"reflect"
	"strconv"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestParseFuserPIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		out  string
		want []int
	}{
		{
			name: "empty output — no processes found",
			out:  "",
			want: nil,
		},
		{
			// Real `fuser -m` output captured on a Debian 13 (psmisc) host,
			// 2026-07-07: no access-mode suffix at all in this (non -v) mode.
			name: "bare pid list, no access suffix",
			out:  "/mnt/busytest:       738518\n",
			want: []int{738518},
		},
		{
			name: "pids with access-mode suffix letters are still parsed",
			out:  "/var:                1234c  5678F  9012m\n",
			want: []int{1234, 5678, 9012},
		},
		{
			name: "duplicate pid across lines collapses to one entry",
			out:  "/data:               100c\n                     100F\n",
			want: []int{100},
		},
		{
			name: "no colon prefix still parses tokens",
			out:  "1234 5678F\n",
			want: []int{1234, 5678},
		},
		{
			// A token with no leading digits (e.g. a stray access-mode letter
			// with no PID, or unexpected fuser output) must be skipped rather
			// than crash strconv.Atoi on an empty slice.
			name: "non-numeric token is skipped",
			out:  "/mnt:                m 1234c\n",
			want: []int{1234},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseFuserPIDs(tt.out)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseFuserPIDs(%q) = %+v, want %+v", tt.out, got, tt.want)
			}
		})
	}
}

func TestNeedsBusyCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fs   models.FilesystemInfo
		want bool
	}{
		{"below gate, writable, rw", models.FilesystemInfo{FSType: "ext4", UsedPct: 50}, false},
		{"at gate exactly", models.FilesystemInfo{FSType: "ext4", UsedPct: 80}, true},
		{"above gate", models.FilesystemInfo{FSType: "xfs", UsedPct: 95}, true},
		{"read-only below gate", models.FilesystemInfo{FSType: "ext4", UsedPct: 10, ReadOnly: true}, true},
		{"inherently read-only image at 100%", models.FilesystemInfo{FSType: "squashfs", UsedPct: 100, ReadOnly: true}, false},
		{"inherently read-only iso9660", models.FilesystemInfo{FSType: "iso9660", UsedPct: 100, ReadOnly: true}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := needsBusyCheck(tt.fs); got != tt.want {
				t.Errorf("needsBusyCheck(%+v) = %v, want %v", tt.fs, got, tt.want)
			}
		})
	}
}

func TestParseFdFlagsWrite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
		want bool
	}{
		{"read-only fd (O_RDONLY=0)", "pos:\t0\nflags:\t0100000\nmnt_id:\t25\n", false},
		{"write-only fd (O_WRONLY=1)", "pos:\t0\nflags:\t0100001\nmnt_id:\t25\n", true},
		{"read-write fd (O_RDWR=2)", "pos:\t0\nflags:\t0100002\nmnt_id:\t25\n", true},
		{"no flags line", "pos:\t0\nmnt_id:\t25\n", false},
		{"flags line with no value field", "pos:\t0\nflags:\nmnt_id:\t25\n", false},
		{"flags line with non-numeric garbage", "pos:\t0\nflags:\tnotoctal\nmnt_id:\t25\n", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := parseFdFlagsWrite(tt.data); got != tt.want {
				t.Errorf("parseFdFlagsWrite(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestFsBusyInherentlyReadOnly(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fsType string
		want   bool
	}{
		{"iso9660", true},
		{"squashfs", true},
		{"erofs", true},
		{"cramfs", true},
		{"ext4", false},
		{"xfs", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := fsBusyInherentlyReadOnly(tt.fsType); got != tt.want {
			t.Errorf("fsBusyInherentlyReadOnly(%q) = %v, want %v", tt.fsType, got, tt.want)
		}
	}
}

// ── fixture-driven: procComm / fdOpenForWrite / fdMatchesMount ──────────────

func TestProcComm(t *testing.T) {
	t.Run("reads and trims comm", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/1234/comm", []byte("nginx\n"))
		})
		if got := procComm("/proc/1234"); got != "nginx" {
			t.Errorf("procComm() = %q, want nginx", got)
		}
	})

	t.Run("unreadable returns empty", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if got := procComm("/proc/9999"); got != "" {
			t.Errorf("procComm() = %q, want empty for unreadable comm", got)
		}
	})
}

func TestFdOpenForWrite(t *testing.T) {
	t.Run("write-only fd", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/100/fdinfo/5", []byte("pos:\t0\nflags:\t0100001\nmnt_id:\t25\n"))
		})
		if !fdOpenForWrite("/proc/100", "5") {
			t.Error("expected true for O_WRONLY fd")
		}
	})

	t.Run("read-only fd", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/100/fdinfo/5", []byte("pos:\t0\nflags:\t0100000\nmnt_id:\t25\n"))
		})
		if fdOpenForWrite("/proc/100", "5") {
			t.Error("expected false for O_RDONLY fd")
		}
	})

	t.Run("unreadable fdinfo returns false", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if fdOpenForWrite("/proc/100", "5") {
			t.Error("expected false when fdinfo unreadable")
		}
	})
}

func TestFdMatchesMount(t *testing.T) {
	t.Run("fd inside mount, read-only", func(t *testing.T) {
		withCombinedFixture(t, nil,
			map[string]string{"/proc/100/fd/3": "/data/file.txt"},
			func(b *source.Bundle) {
				b.PutDir("/proc/100/fd", []string{"3"})
				b.PutFile("/proc/100/fdinfo/3", []byte("pos:\t0\nflags:\t0100000\nmnt_id:\t25\n"))
			})
		write, matched := fdMatchesMount("/proc/100", "/data", "/data/")
		if !matched {
			t.Error("expected matched=true: fd target is inside /data")
		}
		if write {
			t.Error("expected write=false: fd is O_RDONLY")
		}
	})

	t.Run("fd equals mountpoint exactly (write)", func(t *testing.T) {
		withCombinedFixture(t, nil,
			map[string]string{"/proc/100/fd/4": "/data"},
			func(b *source.Bundle) {
				b.PutDir("/proc/100/fd", []string{"4"})
				b.PutFile("/proc/100/fdinfo/4", []byte("pos:\t0\nflags:\t0100002\nmnt_id:\t25\n"))
			})
		write, matched := fdMatchesMount("/proc/100", "/data", "/data/")
		if !matched || !write {
			t.Errorf("expected matched=true write=true for O_RDWR fd equal to the mountpoint itself, got matched=%v write=%v", matched, write)
		}
	})

	t.Run("fd outside mount does not match", func(t *testing.T) {
		withCombinedFixture(t, nil,
			map[string]string{"/proc/100/fd/3": "/other/file.txt"},
			func(b *source.Bundle) {
				b.PutDir("/proc/100/fd", []string{"3"})
			})
		_, matched := fdMatchesMount("/proc/100", "/data", "/data/")
		if matched {
			t.Error("expected matched=false: fd target is outside /data")
		}
	})

	t.Run("different UID or exited process — fd dir unreadable", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		write, matched := fdMatchesMount("/proc/100", "/data", "/data/")
		if write || matched {
			t.Error("expected write=false matched=false when /proc/<pid>/fd is unreadable")
		}
	})

	t.Run("readlink error on one fd is skipped, others still checked", func(t *testing.T) {
		withCombinedFixture(t, nil,
			map[string]string{"/proc/100/fd/4": "/data/other.txt"},
			func(b *source.Bundle) {
				// fd 3 has no readlink recorded -> Replay.Readlink errors -> skipped.
				b.PutDir("/proc/100/fd", []string{"3", "4"})
				b.PutFile("/proc/100/fdinfo/4", []byte("pos:\t0\nflags:\t0100000\nmnt_id:\t25\n"))
			})
		_, matched := fdMatchesMount("/proc/100", "/data", "/data/")
		if !matched {
			t.Error("expected matched=true via fd 4 despite fd 3's readlink error")
		}
	})
}

// ── collectBusyProcesses / fuserBusyProcesses / procFDBusyProcesses ─────────

func TestCollectBusyProcesses(t *testing.T) {
	t.Run("prefers fuser when installed", func(t *testing.T) {
		withCombinedFixture(t,
			map[string][]byte{"lookpath/fuser": []byte("/usr/bin/fuser")},
			map[string]string{"/proc/738518/fd/3": "/mnt/busytest/file"},
			func(b *source.Bundle) {
				b.PutCmd("fuser", []string{"-m", "/mnt/busytest"}, "/mnt/busytest:       738518\n", 1)
				b.PutDir("/proc/738518/fd", []string{"3"})
				b.PutFile("/proc/738518/fdinfo/3", []byte("pos:\t0\nflags:\t0100000\nmnt_id:\t25\n"))
				b.PutFile("/proc/738518/comm", []byte("myapp\n"))
				b.PutFile("/proc/738518/status", []byte("Uid:\t1000\t1000\t1000\t1000\n"))
				b.PutFile("/etc/passwd", []byte("appuser:x:1000:1000::/home/appuser:/bin/bash\n"))
			})
		procs := collectBusyProcesses(context.Background(), "/mnt/busytest")
		if len(procs) != 1 || procs[0].PID != 738518 {
			t.Fatalf("procs = %+v, want 1 entry for PID 738518", procs)
		}
		if procs[0].Command != "myapp" {
			t.Errorf("Command = %q, want myapp", procs[0].Command)
		}
	})

	t.Run("falls back to /proc/*/fd scan when fuser absent", func(t *testing.T) {
		withCombinedFixture(t, nil,
			map[string]string{"/proc/200/fd/3": "/mnt/data/log.txt"},
			func(b *source.Bundle) {
				b.PutDir("/proc", []string{"200"})
				b.PutDir("/proc/200/fd", []string{"3"})
				b.PutFile("/proc/200/fdinfo/3", []byte("pos:\t0\nflags:\t0100001\nmnt_id:\t25\n"))
				b.PutFile("/proc/200/comm", []byte("writer\n"))
			})
		procs := collectBusyProcesses(context.Background(), "/mnt/data")
		if len(procs) != 1 || procs[0].PID != 200 || !procs[0].Write {
			t.Fatalf("procs = %+v, want 1 write-open entry for PID 200", procs)
		}
	})
}

func TestFuserBusyProcesses(t *testing.T) {
	t.Run("caps at fsBusyMaxProcs", func(t *testing.T) {
		var out string
		links := map[string]string{}
		cached := map[string][]byte{}
		for i := range fsBusyMaxProcs + 5 {
			out += " " + strconv.Itoa(1000+i)
		}
		withCombinedFixture(t, cached, links, func(b *source.Bundle) {
			b.PutCmd("fuser", []string{"-m", "/mnt/many"}, "/mnt/many:"+out+"\n", 1)
			// No per-pid fixtures needed: readDirNames("/proc/<pid>/fd") errors
			// (unrecorded) so fdMatchesMount degrades to write=false — fine, this
			// test only checks the cap.
		})
		procs := fuserBusyProcesses(context.Background(), "/mnt/many")
		if len(procs) != fsBusyMaxProcs {
			t.Errorf("len(procs) = %d, want capped at %d", len(procs), fsBusyMaxProcs)
		}
	})

	t.Run("empty fuser output yields no processes", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("fuser", []string{"-m", "/mnt/idle"}, "", 1)
		})
		procs := fuserBusyProcesses(context.Background(), "/mnt/idle")
		if len(procs) != 0 {
			t.Errorf("expected no processes for empty fuser output, got %+v", procs)
		}
	})
}

func TestProcFDBusyProcesses(t *testing.T) {
	t.Run("scans /proc for matching fds", func(t *testing.T) {
		withCombinedFixture(t, nil,
			map[string]string{
				"/proc/10/fd/3": "/data/a.txt",
				"/proc/20/fd/4": "/other/b.txt",
			},
			func(b *source.Bundle) {
				b.PutDir("/proc", []string{"10", "20", "notapid"})
				b.PutDir("/proc/10/fd", []string{"3"})
				b.PutFile("/proc/10/fdinfo/3", []byte("pos:\t0\nflags:\t0100000\nmnt_id:\t25\n"))
				b.PutFile("/proc/10/comm", []byte("reader\n"))
				b.PutDir("/proc/20/fd", []string{"4"})
			})
		procs := procFDBusyProcesses("/data")
		if len(procs) != 1 || procs[0].PID != 10 {
			t.Fatalf("procs = %+v, want exactly PID 10 (PID 20's fd targets /other, not /data)", procs)
		}
	})

	t.Run("unreadable /proc returns nil", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		procs := procFDBusyProcesses("/data")
		if procs != nil {
			t.Errorf("expected nil when /proc unreadable, got %+v", procs)
		}
	})

	t.Run("non-numeric proc entries are skipped", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/proc", []string{"self", "cpuinfo", "meminfo"})
		})
		procs := procFDBusyProcesses("/data")
		if len(procs) != 0 {
			t.Errorf("expected no processes when only non-pid entries present, got %+v", procs)
		}
	})

	t.Run("caps at fsBusyMaxProcs", func(t *testing.T) {
		pids := make([]string, 0, fsBusyMaxProcs+5)
		links := map[string]string{}
		for i := range fsBusyMaxProcs + 5 {
			pid := strconv.Itoa(2000 + i)
			pids = append(pids, pid)
			links["/proc/"+pid+"/fd/3"] = "/data/f.txt"
		}
		withCombinedFixture(t, nil, links, func(b *source.Bundle) {
			b.PutDir("/proc", pids)
			for _, pid := range pids {
				b.PutDir("/proc/"+pid+"/fd", []string{"3"})
			}
		})
		procs := procFDBusyProcesses("/data")
		if len(procs) != fsBusyMaxProcs {
			t.Errorf("len(procs) = %d, want capped at %d", len(procs), fsBusyMaxProcs)
		}
	})
}

// ── collectBusyFilesystems ───────────────────────────────────────────────────

func TestCollectBusyFilesystems(t *testing.T) {
	t.Run("skips filesystems that do not need a busy check", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		fsList := []models.FilesystemInfo{{Mount: "/", FSType: "ext4", UsedPct: 10}}
		collectBusyFilesystems(context.Background(), fsList)
		if len(fsList[0].BusyProcesses) != 0 {
			t.Errorf("expected no busy-process scan for a healthy filesystem, got %+v", fsList[0])
		}
	})

	t.Run("scans a near-full filesystem via the fuser-absent fallback", func(t *testing.T) {
		withCombinedFixture(t, nil,
			map[string]string{"/proc/50/fd/1": "/data/x"},
			func(b *source.Bundle) {
				b.PutDir("/proc", []string{"50"})
				b.PutDir("/proc/50/fd", []string{"1"})
				b.PutFile("/proc/50/fdinfo/1", []byte("pos:\t0\nflags:\t0100000\nmnt_id:\t25\n"))
				b.PutFile("/proc/50/comm", []byte("hog\n"))
			})
		fsList := []models.FilesystemInfo{{Mount: "/data", FSType: "ext4", UsedPct: 95}}
		collectBusyFilesystems(context.Background(), fsList)
		if len(fsList[0].BusyProcesses) != 1 || fsList[0].BusyProcesses[0].PID != 50 {
			t.Errorf("expected 1 busy process (PID 50) on the near-full filesystem, got %+v", fsList[0])
		}
	})

	t.Run("inherently read-only image fs is skipped even at 100%", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		fsList := []models.FilesystemInfo{{Mount: "/rofs", FSType: "squashfs", UsedPct: 100, ReadOnly: true}}
		collectBusyFilesystems(context.Background(), fsList)
		if len(fsList[0].BusyProcesses) != 0 {
			t.Errorf("expected no scan for an inherently read-only image fs, got %+v", fsList[0])
		}
	})
}

// countingLookupSource wraps a Replay and counts "lookpath/fuser" lookups —
// collectBusyProcesses always looks up fuser first (found or not), so the
// count of lookups is exactly the count of busy-process scans actually
// attempted, regardless of whether the test process itself runs as root
// (which would otherwise make BusyCheckNeedsRoot indistinguishable between a
// scanned and an unscanned entry).
type countingLookupSource struct {
	*source.Replay
	fuserLookups int
}

func (c *countingLookupSource) Cached(key string, produce func() ([]byte, error)) ([]byte, error) {
	if key == "lookpath/fuser" {
		c.fuserLookups++
	}
	return c.Replay.Cached(key, produce)
}

// TestCollectBusyFilesystems_CapsNumberOfScans guards internal-collectors-08-05:
// needsBusyCheck flags ANY read-only mount regardless of usage, and with no
// cap, an attacker able to create many read-only mounts (bind/FUSE) could
// force one full /proc sweep per mount. More at-risk filesystems than
// fsBusyMaxScans must still only trigger fsBusyMaxScans actual scans.
func TestCollectBusyFilesystems_CapsNumberOfScans(t *testing.T) {
	b := source.NewBundle()
	fake := &countingLookupSource{Replay: source.NewReplay(b)}
	prev := SetSource(fake)
	t.Cleanup(func() { SetSource(prev) })

	n := fsBusyMaxScans + 5
	fsList := make([]models.FilesystemInfo, n)
	for i := range fsList {
		fsList[i] = models.FilesystemInfo{Mount: "/mnt/ro" + strconv.Itoa(i), FSType: "ext4", ReadOnly: true}
	}
	collectBusyFilesystems(context.Background(), fsList)
	if fake.fuserLookups != fsBusyMaxScans {
		t.Errorf("fuser lookups (scan attempts) = %d, want exactly the scan budget %d out of %d at-risk filesystems",
			fake.fuserLookups, fsBusyMaxScans, n)
	}
}
