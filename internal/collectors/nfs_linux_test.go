//go:build linux

package collectors

import (
	"context"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// Characterization tests for the NFS collector's pure parsers. nfsParseSource
// and nfsAuditOptions take strings/structs and return values — no network or
// syscall access. (nfsAuditOptions calls nfsCheckFstab, which reads /etc/fstab;
// the synthetic mount path below never matches a real fstab line, so only the
// option-derived warnings appear.)

func TestNFSParseSource(t *testing.T) {
	tests := []struct {
		source     string
		wantServer string
		wantExport string
	}{
		{"nfs.example.com:/data", "nfs.example.com", "/data"},
		{"10.0.0.5:/srv/share", "10.0.0.5", "/srv/share"},
		{"server:export", "server", "export"},     // no leading slash on export
		{"server", "server", "/"},                 // bare server -> root export
		{"[::1]:/export", "[::1]", "/export"},     // bracketed IPv6
		{"fe80::1:/export", "fe80::1", "/export"}, // bare IPv6 (first ":/" wins)
	}
	for _, tt := range tests {
		server, export := nfsParseSource(tt.source)
		if server != tt.wantServer || export != tt.wantExport {
			t.Errorf("nfsParseSource(%q) = (%q, %q), want (%q, %q)",
				tt.source, server, export, tt.wantServer, tt.wantExport)
		}
	}
}

func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func TestNFSAuditOptions(t *testing.T) {
	const mount = "/mnt/nfs-unit-test" // never present in a real /etc/fstab

	tests := []struct {
		name        string
		options     string
		wantWarn    string // substring that must be present ("" = none required)
		wantNotWarn string // substring that must be absent ("" = no check)
	}{
		{"soft without timeo warns", "soft,rsize=8192", "soft mount without timeo", ""},
		{"soft with timeo is fine", "soft,timeo=600,rsize=8192", "", "soft mount without timeo"},
		{"nolock warns", "rw,nolock", "nolock", ""},
		{"vers=3 warns", "vers=3,rw", "NFSv3", ""},
		{"vers=4.2 is fine", "vers=4.2,rw", "", "consider upgrading"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &models.NFSMount{Mount: mount, Server: "10.255.255.1", Options: tt.options}
			nfsAuditOptions(m)
			if tt.wantWarn != "" && !hasWarning(m.OptionsWarnings, tt.wantWarn) {
				t.Errorf("expected a warning containing %q, got %v", tt.wantWarn, m.OptionsWarnings)
			}
			if tt.wantNotWarn != "" && hasWarning(m.OptionsWarnings, tt.wantNotWarn) {
				t.Errorf("did not expect a warning containing %q, got %v", tt.wantNotWarn, m.OptionsWarnings)
			}
		})
	}
}

// ── Collect() / identity / fixture-driven tests ─────────────────────────────

func TestNFSCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewNFSCollector()
	if c.Name() != "NFS" {
		t.Errorf("Name() = %q, want NFS", c.Name())
	}
	if c.Timeout() != 15*time.Second {
		t.Errorf("Timeout() = %v, want 15s", c.Timeout())
	}
}

// TestNFSCollector_Collect_NoMounts guards the gate-off path: no NFS lines in
// /proc/mounts means Collect returns (nil, nil) — section absent.
func TestNFSCollector_Collect_NoMounts(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/mounts", []byte("/dev/sda1 / ext4 rw,relatime 0 0\n"))
	})
	c := NewNFSCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("expected nil info when no NFS mounts present, got %+v", raw)
	}
}

// TestNFSCollector_Collect_HappyPath exercises the full path: an NFSv4 mount,
// rpcbind active via systemctl, /proc/net/rpc/nfs stats, and mount option/fstab
// audits. The mount's own statfs is never seeded (withCombinedFixture only
// layers Cached/Readlink, not Statfs), so it degrades to Stale via a
// not-recorded Statfs error — that's fine, this test asserts the
// aggregate/parse fields, not mount liveness.
func TestNFSCollector_Collect_HappyPath(t *testing.T) {
	withCombinedFixture(t,
		map[string][]byte{
			"dial/tcp/nfs.example.com:111":  {'1'},
			"dial/tcp/nfs.example.com:2049": {'1'},
		},
		nil,
		func(b *source.Bundle) {
			b.PutFile("/proc/mounts", []byte(
				"nfs.example.com:/export/data /mnt/data nfs4 rw,vers=4.2,addr=10.0.0.5 0 0\n"+
					"/dev/sda1 / ext4 rw,relatime 0 0\n",
			))
			b.PutCmd("systemctl", []string{"is-active", "rpcbind"}, "active\n", 0)
			b.PutFile("/proc/net/rpc/nfs", []byte(
				"net 100 0 0 0\n"+
					"rpc 1000 5 0\n"+
					"proc4 2 10 200 150\n",
			))
			b.PutFile("/etc/fstab", []byte("nfs.example.com:/export/data /mnt/data nfs4 rw,_netdev 0 0\n"))
		})

	c := NewNFSCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.NFSInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.NFSInfo", raw)
	}
	if !info.RpcbindActive {
		t.Error("expected RpcbindActive=true via systemctl is-active")
	}
	if info.RPCCalls != 1000 || info.RetransPerMin != 5 {
		t.Errorf("RPC stats = calls:%v retrans:%v, want 1000/5", info.RPCCalls, info.RetransPerMin)
	}
	if info.ReadOpsPerMin != 10 || info.WriteOpsPerMin != 200 {
		t.Errorf("proc4 ops = read:%v write:%v, want 10/200", info.ReadOpsPerMin, info.WriteOpsPerMin)
	}
	if len(info.Mounts) != 1 {
		t.Fatalf("Mounts = %+v, want exactly 1", info.Mounts)
	}
	m := info.Mounts[0]
	if m.Server != "nfs.example.com" || m.Export != "/export/data" || m.FSType != "nfs4" {
		t.Errorf("mount fields = %+v, want server/export/fstype parsed from source", m)
	}
	if !m.ServerReachable || !m.NFSPortOpen {
		t.Errorf("expected server reachable + port open via dial fixture, got %+v", m)
	}
	// _netdev present -> no fstab warning; vers=4.2 -> no version warning.
	if hasWarning(m.OptionsWarnings, "_netdev") || hasWarning(m.OptionsWarnings, "NFSv") {
		t.Errorf("did not expect _netdev/version warnings, got %v", m.OptionsWarnings)
	}
}

// fakeStatfsErrSource layers per-path Statfs ERROR injection (not just success
// values like fakeStatfsSource in disk_linux_test.go) so nfsCheckMount's
// ESTALE/EIO/generic-error branches can be driven directly.
type fakeStatfsErrSource struct {
	*source.Replay
	errs map[string]error
}

func (f *fakeStatfsErrSource) Statfs(path string) (source.StatfsInfo, error) {
	if e, ok := f.errs[path]; ok {
		return source.StatfsInfo{}, e
	}
	return f.Replay.Statfs(path)
}

func withStatfsErrFixture(t *testing.T, path string, err error) {
	t.Helper()
	b := source.NewBundle()
	prev := SetSource(&fakeStatfsErrSource{Replay: source.NewReplay(b), errs: map[string]error{path: err}})
	t.Cleanup(func() { SetSource(prev) })
}

// TestNfsCheckMount guards the three outcomes: healthy statfs, ESTALE/EIO
// error marking Stale, and a plain error leaving Healthy=false but Stale=false.
func TestNfsCheckMount(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		withStatfsFixture(t, map[string]source.StatfsInfo{
			"/mnt/ok": {Blocks: 1000, Bfree: 500, Bsize: 4096},
		}, nil)
		m := &models.NFSMount{Mount: "/mnt/ok"}
		nfsCheckMount(context.Background(), m)
		if !m.Healthy || m.Stale {
			t.Errorf("expected Healthy=true Stale=false, got %+v", m)
		}
	})

	t.Run("ESTALE marks stale", func(t *testing.T) {
		withStatfsErrFixture(t, "/mnt/stale", syscall.ESTALE)
		m := &models.NFSMount{Mount: "/mnt/stale"}
		nfsCheckMount(context.Background(), m)
		if m.Healthy || !m.Stale {
			t.Errorf("expected Healthy=false Stale=true for ESTALE, got %+v", m)
		}
	})

	t.Run("EIO marks stale", func(t *testing.T) {
		withStatfsErrFixture(t, "/mnt/ioerr", syscall.EIO)
		m := &models.NFSMount{Mount: "/mnt/ioerr"}
		nfsCheckMount(context.Background(), m)
		if m.Healthy || !m.Stale {
			t.Errorf("expected Healthy=false Stale=true for EIO, got %+v", m)
		}
	})

	t.Run("generic error leaves stale false", func(t *testing.T) {
		withStatfsErrFixture(t, "/mnt/othererr", syscall.ENOENT)
		m := &models.NFSMount{Mount: "/mnt/othererr"}
		nfsCheckMount(context.Background(), m)
		if m.Healthy || m.Stale {
			t.Errorf("expected Healthy=false Stale=false for a non-ESTALE/EIO error, got %+v", m)
		}
	})

	t.Run("context canceled marks stale", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		m := &models.NFSMount{Mount: "/mnt/whatever"}
		nfsCheckMount(ctx, m)
		if !m.Stale || m.Healthy {
			t.Errorf("expected Stale=true Healthy=false when ctx already canceled, got %+v", m)
		}
	})

	t.Run("statfs hangs past 2s deadline marks stale", func(t *testing.T) {
		prev := SetSource(&slowStatfsSource{Replay: source.NewReplay(source.NewBundle()), delay: 3 * time.Second})
		t.Cleanup(func() { SetSource(prev) })
		m := &models.NFSMount{Mount: "/mnt/hung"}
		nfsCheckMount(context.Background(), m)
		if !m.Stale || m.Healthy {
			t.Errorf("expected Stale=true Healthy=false when statfs exceeds the 2s deadline, got %+v", m)
		}
	})
}

// slowStatfsSource simulates a hung NFS mount (D-state statfs) by blocking
// longer than nfsCheckMount's 2s deadline, driving the timeout branch that a
// synchronous fake Statfs (immediate return, error or not) can never reach.
type slowStatfsSource struct {
	*source.Replay
	delay time.Duration
}

func (f *slowStatfsSource) Statfs(path string) (source.StatfsInfo, error) {
	time.Sleep(f.delay)
	return f.Replay.Statfs(path)
}

func TestNfsCheckServer(t *testing.T) {
	t.Run("loopback always reachable", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"dial/tcp/127.0.0.1:2049": {'1'},
		}, nil, nil)
		m := &models.NFSMount{Server: "127.0.0.1"}
		nfsCheckServer(m)
		if !m.ServerReachable {
			t.Error("loopback server should always be marked reachable")
		}
	})

	t.Run("localhost always reachable", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"dial/tcp/localhost:2049": {'0'},
		}, nil, nil)
		m := &models.NFSMount{Server: "localhost"}
		nfsCheckServer(m)
		if !m.ServerReachable {
			t.Error("localhost server should always be marked reachable")
		}
	})

	t.Run("remote server dialed via rpcbind/nfs ports", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"dial/tcp/10.1.1.1:111":  {'0'},
			"dial/tcp/10.1.1.1:2049": {'1'},
		}, nil, nil)
		m := &models.NFSMount{Server: "10.1.1.1"}
		nfsCheckServer(m)
		if !m.ServerReachable {
			t.Error("expected reachable via 2049 fallback when 111 is closed")
		}
		if !m.NFSPortOpen {
			t.Error("expected NFSPortOpen=true")
		}
	})

	t.Run("unreachable server", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"dial/tcp/10.9.9.9:111":  {'0'},
			"dial/tcp/10.9.9.9:2049": {'0'},
		}, nil, nil)
		m := &models.NFSMount{Server: "10.9.9.9"}
		nfsCheckServer(m)
		if m.ServerReachable || m.NFSPortOpen {
			t.Errorf("expected unreachable, got %+v", m)
		}
	})
}

func TestNfsCheckFstab(t *testing.T) {
	t.Run("missing _netdev warns", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/etc/fstab", []byte("nfs.example.com:/export /mnt/data nfs4 rw 0 0\n"))
		})
		m := &models.NFSMount{Mount: "/mnt/data", Server: "nfs.example.com"}
		nfsCheckFstab(m)
		if !hasWarning(m.OptionsWarnings, "_netdev missing") {
			t.Errorf("expected _netdev warning, got %v", m.OptionsWarnings)
		}
	})

	t.Run("has _netdev does not warn", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/etc/fstab", []byte("nfs.example.com:/export /mnt/data nfs4 rw,_netdev 0 0\n"))
		})
		m := &models.NFSMount{Mount: "/mnt/data", Server: "nfs.example.com"}
		nfsCheckFstab(m)
		if hasWarning(m.OptionsWarnings, "_netdev missing") {
			t.Errorf("did not expect _netdev warning, got %v", m.OptionsWarnings)
		}
	})

	t.Run("fstab unreadable no-ops", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		m := &models.NFSMount{Mount: "/mnt/data", Server: "nfs.example.com"}
		nfsCheckFstab(m)
		if len(m.OptionsWarnings) != 0 {
			t.Errorf("expected no warnings when fstab unreadable, got %v", m.OptionsWarnings)
		}
	})

	t.Run("comment line skipped", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/etc/fstab", []byte("# nfs.example.com:/export /mnt/data nfs4 rw 0 0\n"))
		})
		m := &models.NFSMount{Mount: "/mnt/data", Server: "nfs.example.com"}
		nfsCheckFstab(m)
		if len(m.OptionsWarnings) != 0 {
			t.Errorf("expected commented line to be skipped, got %v", m.OptionsWarnings)
		}
	})

	t.Run("non-matching line skipped", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/etc/fstab", []byte("/dev/sda1 / ext4 defaults 0 1\n"))
		})
		m := &models.NFSMount{Mount: "/mnt/data", Server: "nfs.example.com"}
		nfsCheckFstab(m)
		if len(m.OptionsWarnings) != 0 {
			t.Errorf("expected no warnings when no fstab line matches the mount, got %v", m.OptionsWarnings)
		}
	})
}

func TestNfsRpcbindActive(t *testing.T) {
	t.Run("systemctl active", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("systemctl", []string{"is-active", "rpcbind"}, "active\n", 0)
		})
		if !nfsRpcbindActive(context.Background()) {
			t.Error("expected true when systemctl reports active")
		}
	})

	t.Run("systemctl inactive falls to process check, none found", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("systemctl", []string{"is-active", "rpcbind"}, "inactive\n", 3)
			b.PutDir("/proc", []string{})
		})
		if nfsRpcbindActive(context.Background()) {
			t.Error("expected false when systemctl inactive and no rpcbind process")
		}
	})

	t.Run("systemctl absent falls back to process check, found", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmdNotFound("systemctl", []string{"is-active", "rpcbind"})
			b.PutDir("/proc", []string{"123"})
			b.PutFile("/proc/123/comm", []byte("rpcbind\n"))
		})
		if !nfsRpcbindActive(context.Background()) {
			t.Error("expected true via anyProcessNamed fallback on non-systemd host")
		}
	})
}

func TestNfsReadStats(t *testing.T) {
	t.Run("parses rpc and proc4 lines", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/net/rpc/nfs", []byte(
				"net 10 0 0 0\n"+
					"rpc 500 3 0\n"+
					"proc4 2 8 42 99\n",
			))
		})
		info := &models.NFSInfo{}
		nfsReadStats(info)
		if info.RPCCalls != 500 || info.RetransPerMin != 3 {
			t.Errorf("rpc stats = %v/%v, want 500/3", info.RPCCalls, info.RetransPerMin)
		}
		if info.ReadOpsPerMin != 8 || info.WriteOpsPerMin != 42 {
			t.Errorf("proc4 ops = %v/%v, want 8/42", info.ReadOpsPerMin, info.WriteOpsPerMin)
		}
	})

	t.Run("unreadable file is a no-op", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		info := &models.NFSInfo{}
		nfsReadStats(info)
		if info.RPCCalls != 0 || info.RetransPerMin != 0 {
			t.Errorf("expected zero-value info when file unreadable, got %+v", info)
		}
	})
}

// TestParseNFSMounts already exists in nfs_linux_source_test.go (happy-path
// parse coverage) — only the unreadable-file degrade case is new here.
func TestParseNFSMounts_Unreadable(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // /proc/mounts never seeded
	mounts := parseNFSMounts()
	if mounts != nil {
		t.Errorf("expected nil when /proc/mounts is unreadable, got %+v", mounts)
	}
}
