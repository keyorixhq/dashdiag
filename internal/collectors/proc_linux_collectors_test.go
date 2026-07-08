//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── ProcCollector identity / Collect ─────────────────────────────────────────

func TestProcCollectorIdentity(t *testing.T) {
	c := NewProcCollector(1234)
	if c.Name() != "Proc" {
		t.Errorf("Name() = %q, want Proc", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
	if c.PID != 1234 {
		t.Errorf("PID = %d, want 1234", c.PID)
	}
}

func TestProcCollector_Collect_TopListMode(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/proc/[0-9]*", []string{"/proc/100"})
		b.PutFile("/proc/100/status", []byte("Name:\tmyapp\nVmRSS:\t102400 kB\n"))
		b.PutFile("/proc/meminfo", []byte("MemTotal:       16777216 kB\n"))
	})
	c := NewProcCollector(0)
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.ProcInfo)
	if len(info.TopProcs) != 1 || info.TopProcs[0].Name != "myapp" {
		t.Fatalf("expected 1 top process named myapp, got %+v", info.TopProcs)
	}
}

func TestProcCollector_Collect_SinglePID(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/proc/100", source.FileMeta{IsDir: true})
		b.PutFile("/proc/100/status", []byte("Name:\tmyapp\nState:\tS (sleeping)\nPid:\t100\nPPid:\t1\nThreads:\t4\nVmRSS:\t2048 kB\nVmSwap:\t0 kB\n"))
	})
	c := NewProcCollector(100)
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.ProcInfo)
	if info.PID != 100 || info.Name != "myapp" {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestProcCollector_Collect_PIDNotFound(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	c := NewProcCollector(99999)
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("expected an error for a non-existent PID")
	}
}

// ── collectProcPID (full field integration) ──────────────────────────────────

func TestCollectProcPID_FullFields(t *testing.T) {
	base := "/proc/200"
	withReadlinkFixture(t, map[string]string{
		base + "/fd/0": "/dev/null",
		base + "/fd/1": "socket:[12345]",
		base + "/fd/2": "pipe:[999]",
	}, func(b *source.Bundle) {
		b.PutStat(base, source.FileMeta{IsDir: true})
		b.PutFile(base+"/status", []byte(
			"Name:\tnginx\nState:\tS (sleeping)\nPid:\t200\nPPid:\t1\nThreads:\t2\n"+
				"VmRSS:\t4096 kB\nVmSwap:\t0 kB\nUid:\t33\t33\t33\t33\n"))
		b.PutFile(base+"/cmdline", []byte("nginx\x00-g\x00daemon off;\x00"))
		b.PutFile(base+"/wchan", []byte("ep_poll"))
		b.PutFile(base+"/stat", []byte(
			"200 (nginx) S 1 200 200 0 -1 4194304 0 0 0 0 10 5 0 0 20 0 1 0 500 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"))
		b.PutFile("/proc/uptime", []byte("1000.00 900.00\n"))
		b.PutDir(base+"/fd", []string{"0", "1", "2"})
		b.PutFile(base+"/limits", []byte("Max open files            1024                 4096                 files\n"))
		b.PutFile(base+"/smaps_rollup", []byte("Rss:            4096 kB\nPss_Dirty:      2048 kB\n"))
		b.PutFile("/etc/passwd", []byte("www-data:x:33:33::/nonexistent:/usr/sbin/nologin\n"))
		b.PutFile("/proc/1/comm", []byte("systemd\n"))
		b.PutFile(base+"/cgroup", []byte("0::/system.slice/nginx.service\n"))
	})

	info, err := collectProcPID(200)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != "nginx" || info.PPID != 1 || info.Threads != 2 {
		t.Errorf("status fields wrong: %+v", info)
	}
	if info.Cmdline != "nginx -g daemon off;" {
		t.Errorf("Cmdline = %q", info.Cmdline)
	}
	if info.WChan != "ep_poll" {
		t.Errorf("WChan = %q", info.WChan)
	}
	if info.User != "www-data" {
		t.Errorf("User = %q, want www-data", info.User)
	}
	if info.ParentName != "systemd" {
		t.Errorf("ParentName = %q, want systemd", info.ParentName)
	}
	if info.CgroupName != "nginx.service" {
		t.Errorf("CgroupName = %q, want nginx.service", info.CgroupName)
	}
	if info.FDCount != 3 || !info.FDReadable || info.FDLimit != 1024 {
		t.Errorf("FD fields wrong: count=%d readable=%v limit=%d", info.FDCount, info.FDReadable, info.FDLimit)
	}
	if info.MemMap == nil || info.MemMap.RSSKb != 4096 {
		t.Errorf("MemMap wrong: %+v", info.MemMap)
	}
	if info.SocketCount != 1 || info.PipeCount != 1 || info.FileCount != 1 {
		t.Errorf("open-file counts wrong: sockets=%d pipes=%d files=%d", info.SocketCount, info.PipeCount, info.FileCount)
	}
}

// ── procUptimeSec ─────────────────────────────────────────────────────────────

func TestProcUptimeSec(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// starttime (field 22 / index 19 post-comm) = 500 jiffies @ HZ=100 -> 5s start.
		b.PutFile("/proc/300/stat", []byte(
			"300 (myapp) S 1 300 300 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"))
		b.PutFile("/proc/uptime", []byte("100.00 90.00\n"))
	})
	if got := procUptimeSec("/proc/300"); got != 95 {
		t.Errorf("procUptimeSec() = %d, want 95 (100 - 500/100)", got)
	}
}

func TestProcUptimeSec_StatMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := procUptimeSec("/proc/999"); got != 0 {
		t.Errorf("procUptimeSec() = %d, want 0", got)
	}
}

func TestProcUptimeSec_UptimeMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/300/stat", []byte(
			"300 (myapp) S 1 300 300 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"))
	})
	if got := procUptimeSec("/proc/300"); got != 0 {
		t.Errorf("procUptimeSec() = %d, want 0 when /proc/uptime is unreadable", got)
	}
}

// ── procCPUSec ────────────────────────────────────────────────────────────────

func TestProcCPUSec(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/300/stat", []byte(
			"300 (myapp) S 1 300 300 0 -1 4194304 0 0 0 0 250 150 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"))
	})
	if got := procCPUSec("/proc/300"); got != 4 {
		t.Errorf("procCPUSec() = %v, want 4 ((250+150)/100)", got)
	}
}

func TestProcCPUSec_StatMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := procCPUSec("/proc/999"); got != 0 {
		t.Errorf("procCPUSec() = %v, want 0", got)
	}
}

// ── procFDInfo ────────────────────────────────────────────────────────────────

func TestProcFDInfo(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc/300/fd", []string{"0", "1", "2", "3"})
		b.PutFile("/proc/300/limits", []byte(
			"Max open files            1024                 4096                 files\n"))
	})
	count, limit, readable := procFDInfo("/proc/300")
	if count != 4 || limit != 1024 || !readable {
		t.Errorf("procFDInfo() = %d/%d/%v, want 4/1024/true (fields[3] is the soft limit)", count, limit, readable)
	}
}

func TestProcFDInfo_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	count, limit, readable := procFDInfo("/proc/999")
	if count != 0 || limit != 0 || readable {
		t.Errorf("procFDInfo() = %d/%d/%v, want 0/0/false", count, limit, readable)
	}
}

// ── procMemMap ────────────────────────────────────────────────────────────────

func TestProcMemMap_SmapsRollup(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/300/smaps_rollup", []byte(
			"Rss:            4096 kB\nPss_Dirty:      2048 kB\nPrivate_Dirty:  1024 kB\n"+
				"Private_Clean:  512 kB\nShared_Clean:   256 kB\nShared_Dirty:   128 kB\nSwap:           0 kB\n"))
	})
	m := procMemMap("/proc/300")
	if m == nil || m.RSSKb != 4096 || m.PssDirtyKb != 2048 || m.PrivateDirtyKb != 1024 {
		t.Fatalf("unexpected mem map: %+v", m)
	}
}

func TestProcMemMap_SmapsFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/300/smaps", []byte("Rss:            8192 kB\n"))
	})
	m := procMemMap("/proc/300")
	if m == nil || m.RSSKb != 8192 {
		t.Fatalf("expected the smaps fallback to be parsed, got %+v", m)
	}
}

func TestProcMemMap_BothUnreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := procMemMap("/proc/999"); got != nil {
		t.Errorf("expected nil when neither smaps_rollup nor smaps is readable, got %+v", got)
	}
}

// ── procUser ──────────────────────────────────────────────────────────────────

func TestProcUser_ResolvedFromPasswd(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/300/status", []byte("Uid:\t33\t33\t33\t33\n"))
		b.PutFile("/etc/passwd", []byte("www-data:x:33:33::/nonexistent:/usr/sbin/nologin\n"))
	})
	if got := procUser("/proc/300"); got != "www-data" {
		t.Errorf("procUser() = %q, want www-data", got)
	}
}

func TestProcUser_UnknownUIDFallsBackToUidPrefix(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/300/status", []byte("Uid:\t7777\t7777\t7777\t7777\n"))
		b.PutFile("/etc/passwd", []byte("root:x:0:0:root:/root:/bin/bash\n"))
	})
	if got := procUser("/proc/300"); got != "uid:7777" {
		t.Errorf("procUser() = %q, want uid:7777", got)
	}
}

func TestProcUser_StatusUnreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := procUser("/proc/999"); got != "" {
		t.Errorf("procUser() = %q, want empty", got)
	}
}

// ── collectOpenFiles ──────────────────────────────────────────────────────────

func TestCollectOpenFiles(t *testing.T) {
	base := "/proc/300"
	withReadlinkFixture(t, map[string]string{
		base + "/fd/0": "/usr/lib/libfoo.so.6",
		base + "/fd/1": "socket:[54321]",
		base + "/fd/2": "pipe:[111]",
		base + "/fd/3": "/opt/app/plugin.so (deleted)",
		base + "/fd/4": "anon_inode:[eventfd]",
	}, func(b *source.Bundle) {
		b.PutDir(base+"/fd", []string{"0", "1", "2", "3", "4"})
	})
	info := &models.ProcInfo{}
	inodes := collectOpenFiles(base, info)
	if len(inodes) != 1 || !inodes["54321"] {
		t.Fatalf("expected socket inode 54321 captured, got %+v", inodes)
	}
	if info.SocketCount != 1 || info.PipeCount != 1 || info.FileCount != 2 {
		t.Errorf("counts wrong: sockets=%d pipes=%d files=%d", info.SocketCount, info.PipeCount, info.FileCount)
	}
	if len(info.DeletedLibs) != 1 || info.DeletedLibs[0] != "plugin.so" {
		t.Errorf("DeletedLibs = %+v, want [plugin.so]", info.DeletedLibs)
	}
	if len(info.OpenFiles) != 5 {
		t.Errorf("OpenFiles = %d entries, want 5", len(info.OpenFiles))
	}
}

func TestCollectOpenFiles_FDDirUnreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	info := &models.ProcInfo{}
	inodes := collectOpenFiles("/proc/999", info)
	if len(inodes) != 0 || len(info.OpenFiles) != 0 {
		t.Errorf("expected no open files when /fd is unreadable, got inodes=%+v files=%+v", inodes, info.OpenFiles)
	}
}

// ── procNetConns ──────────────────────────────────────────────────────────────

func TestProcNetConns_MatchesInode(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/tcp",
			[]byte("  sl  local_address rem_address   st\n"+
				"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"))
		b.PutFile("/proc/net/tcp6", []byte("  sl  local_address rem_address   st\n"))
	})
	conns, err := procNetConns(map[string]bool{"12345": true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("expected 1 matching connection, got %+v", conns)
	}
	if conns[0].Protocol != "tcp" || conns[0].State != "LISTEN" {
		t.Errorf("unexpected connection: %+v", conns[0])
	}
	if conns[0].LocalAddr != "127.0.0.1:8080" {
		t.Errorf("LocalAddr = %q, want 127.0.0.1:8080", conns[0].LocalAddr)
	}
}

func TestProcNetConns_NoInodes(t *testing.T) {
	conns, err := procNetConns(nil)
	if err != nil || conns != nil {
		t.Errorf("expected nil/nil for an empty inode set, got %+v/%v", conns, err)
	}
}

func TestProcNetConns_NoMatch(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/tcp",
			[]byte("  sl  local_address rem_address   st\n"+
				"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0\n"))
		b.PutFile("/proc/net/tcp6", []byte("  sl  local_address rem_address   st\n"))
	})
	conns, err := procNetConns(map[string]bool{"12345": true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(conns) != 0 {
		t.Errorf("expected no matches, got %+v", conns)
	}
}

// ── hexToAddr ─────────────────────────────────────────────────────────────────

func TestHexToAddr_IPv4(t *testing.T) {
	if got := hexToAddr("0100007F:1F90"); got != "127.0.0.1:8080" {
		t.Errorf("hexToAddr() = %q, want 127.0.0.1:8080", got)
	}
}

func TestHexToAddr_IPv6(t *testing.T) {
	got := hexToAddr("00000000000000000000000000000000:0050")
	if got != "[00000000000000000000000000000000]:80" {
		t.Errorf("hexToAddr() = %q", got)
	}
}

func TestHexToAddr_Malformed(t *testing.T) {
	if got := hexToAddr("no-colon-here"); got != "no-colon-here" {
		t.Errorf("hexToAddr() = %q, want the input passed through unchanged", got)
	}
}

// ── tcpState ──────────────────────────────────────────────────────────────────

func TestTCPState_Known(t *testing.T) {
	if got := tcpState("0a"); got != "LISTEN" {
		t.Errorf("tcpState(0a) = %q, want LISTEN (case-insensitive)", got)
	}
	if got := tcpState("01"); got != "ESTABLISHED" {
		t.Errorf("tcpState(01) = %q, want ESTABLISHED", got)
	}
}

func TestTCPState_Unknown(t *testing.T) {
	if got := tcpState("FF"); got != "FF" {
		t.Errorf("tcpState(FF) = %q, want passthrough FF", got)
	}
}
