//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestDRBDCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewDRBDCollector()
	if c.Name() != "DRBD" {
		t.Errorf("Name() = %q, want DRBD", c.Name())
	}
	if c.Timeout() != 2*time.Second {
		t.Errorf("Timeout() = %v, want 2s", c.Timeout())
	}
}

func TestIsDRBDPresent(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/proc/drbd", source.FileMeta{})
		})
		if !IsDRBDPresent() {
			t.Error("expected true when /proc/drbd exists")
		}
	})

	t.Run("absent", func(t *testing.T) {
		withFixtureSource(t, func(_ *source.Bundle) {})
		if IsDRBDPresent() {
			t.Error("expected false when /proc/drbd does not exist")
		}
	})
}

// TestDRBDCollector_Collect_ModuleNotLoaded guards the gate-off path: no
// /proc/drbd means the module isn't loaded — Collect must return (nil, nil),
// not an empty-but-non-nil DRBDInfo (that would be a phantom row).
func TestDRBDCollector_Collect_ModuleNotLoaded(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {})
	c := NewDRBDCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("Collect() = %v, want nil when /proc/drbd is absent", raw)
	}
}

// TestDRBDCollector_Collect_8xHappyPath exercises the classic 8.x
// single-resource /proc/drbd parse with a sync line.
func TestDRBDCollector_Collect_8xHappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/drbd", []byte(
			"version: 8.4.11 (api:1/proto:86-101)\n"+
				" 0: cs:Connected ro:Primary/Secondary ds:UpToDate/UpToDate C r-----\n"+
				"    ns:0 nr:0 dw:0 dr:0 al:0 bm:0 lo:0 pe:0 ua:0 ap:0 ep:1 wo:f oos:0\n"))
	})
	c := NewDRBDCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.DRBDInfo)
	if info.Version != "8.4.11 (api:1/proto:86-101)" {
		t.Errorf("Version = %q, want 8.4.11 (api:1/proto:86-101)", info.Version)
	}
	if len(info.Resources) != 1 {
		t.Fatalf("Resources = %+v, want 1", info.Resources)
	}
	r := info.Resources[0]
	if r.Minor != 0 || r.ConnState != "Connected" || r.LocalRole != "Primary" || r.LocalDisk != "UpToDate" || r.RemoteDisk != "UpToDate" {
		t.Errorf("Resources[0] = %+v, want minor=0 cs=Connected ro=Primary ds=UpToDate/UpToDate", r)
	}
}

// TestDRBDCollector_Collect_8xNoResources_Empty guards the clean-empty gate:
// module loaded, version 8.x, but no resource lines at all — must gate off
// (nil, nil), not a phantom empty DRBDInfo.
func TestDRBDCollector_Collect_8xNoResources_Empty(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/drbd", []byte("version: 8.4.11 (api:1/proto:86-101)\n"))
	})
	c := NewDRBDCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("Collect() = %v, want nil (no resources, 8.x)", raw)
	}
}

// TestDRBDCollector_Collect_9xFallbackSuccess guards the DRBD 9 netlink
// fallback: /proc/drbd carries only the version header, so parseDRBDProc finds
// nothing, and collectDRBD9 (drbdsetup status --json) supplies the resources.
func TestDRBDCollector_Collect_9xFallbackSuccess(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/drbd", []byte("version: 9.1.4 (api:2/proto:86-121)\n"))
		b.PutCmd("drbdsetup", []string{"status", "--json", "all"},
			`[{"name":"r0","role":"Primary","devices":[{"minor":0,"disk-state":"UpToDate"}],`+
				`"connections":[{"connection-state":"Connected","peer_devices":[{"replication-state":"Established","peer-disk-state":"UpToDate"}]}]}]`,
			0)
	})
	c := NewDRBDCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.DRBDInfo)
	if info.Version != "9.1.4 (api:2/proto:86-121)" {
		t.Errorf("Version = %q, want 9.1.4 (api:2/proto:86-121)", info.Version)
	}
	if len(info.Resources) != 1 {
		t.Fatalf("Resources = %+v, want 1", info.Resources)
	}
	r := info.Resources[0]
	if r.LocalRole != "Primary" || r.LocalDisk != "UpToDate" || r.ConnState != "Connected" || r.RemoteDisk != "UpToDate" {
		t.Errorf("Resources[0] = %+v, want role=Primary disk=UpToDate conn=Connected remote=UpToDate", r)
	}
}

// TestDRBDCollector_Collect_9xDrbdsetupFails is a regression guard for
// internal-collectors-11-01: v9 module loaded, drbdsetup fails to run
// (binary missing, or — commonly, since dsd often runs as root inside a
// container — CAP_NET_ADMIN dropped even though EUID is 0). The old gate
// keyed off os.Geteuid(), so a root-but-capability-dropped run fell straight
// through to "DRBD absent" instead of Unverified, hiding a real
// split-brain/diskless resource with no warning at all. The fix keys off
// whether collectDRBD9 itself succeeded, so this must report Unverified=true
// regardless of the test process's actual privilege level.
func TestDRBDCollector_Collect_9xDrbdsetupFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/drbd", []byte("version: 9.1.4 (api:2/proto:86-121)\n"))
		b.PutCmdNotFound("drbdsetup", []string{"status", "--json", "all"})
	})
	c := NewDRBDCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.DRBDInfo)
	if !ok {
		t.Fatalf("Collect() = %T, want *models.DRBDInfo", raw)
	}
	if !info.Unverified {
		t.Error("Unverified = false, want true (v9, drbdsetup failed) — must not read as DRBD absent")
	}
	if info.Version != "9.1.4 (api:2/proto:86-121)" {
		t.Errorf("Version = %q, want preserved 9.1.4 (api:2/proto:86-121)", info.Version)
	}
}

// TestDRBDCollector_Collect_9xGenuinelyNoResources covers the other side: when
// collectDRBD9 succeeds (drbdsetup ran fine) but genuinely reports zero
// resources, that is trustworthy at any privilege level — gate off as
// absent, not Unverified.
func TestDRBDCollector_Collect_9xGenuinelyNoResources(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/drbd", []byte("version: 9.1.4 (api:2/proto:86-121)\n"))
		b.PutCmd("drbdsetup", []string{"status", "--json", "all"}, "[]", 0)
	})
	c := NewDRBDCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if raw != nil {
		t.Errorf("Collect() = %v, want nil (drbdsetup succeeded with genuinely zero resources)", raw)
	}
}

// TestParseDRBD9JSON_InvalidJSON guards the JSON-decode error branch.
func TestParseDRBD9JSON_InvalidJSON(t *testing.T) {
	t.Parallel()
	got := parseDRBD9JSON([]byte("not json"), "9.1.4")
	if got != nil {
		t.Errorf("parseDRBD9JSON(invalid) = %+v, want nil", got)
	}
}

// TestParseDRBD9JSON_OneMalformedResourceKeepsOthers guards against
// discarding every resource when only ONE fails to decode (e.g. a
// field-type mismatch from a drbdsetup version skew — "minor" arriving as a
// string instead of a number). The first resource is well-formed and must
// still surface (with its real ConnState), not be swallowed into a global
// "Unverified" just because a sibling resource in the same array is broken.
func TestParseDRBD9JSON_OneMalformedResourceKeepsOthers(t *testing.T) {
	t.Parallel()
	const raw = `[
		{"name":"res0","role":"Primary","devices":[{"minor":0,"disk-state":"UpToDate"}],
		 "connections":[{"connection-state":"StandAlone","peer_devices":[]}]},
		{"name":"res1","role":"Secondary","devices":[{"minor":"not-a-number","disk-state":"UpToDate"}]}
	]`
	got := parseDRBD9JSON([]byte(raw), "9.1.4")
	if got == nil {
		t.Fatal("parseDRBD9JSON = nil, want a partial result keeping the well-formed resource")
	}
	if len(got.Resources) != 1 {
		t.Fatalf("Resources = %+v, want exactly 1 (the malformed resource must be skipped, not discard everything)", got.Resources)
	}
	if got.Resources[0].ConnState != "StandAlone" {
		t.Errorf("Resources[0].ConnState = %q, want %q (the down link on the well-formed resource must still surface)",
			got.Resources[0].ConnState, "StandAlone")
	}
}

// TestCollectDRBD9_CommandFails guards the drbdsetup-error and empty-output
// branches of collectDRBD9.
func TestCollectDRBD9_CommandFails(t *testing.T) {
	t.Run("command not found", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmdNotFound("drbdsetup", []string{"status", "--json", "all"})
		})
		if got := collectDRBD9(context.Background(), "9.1.4"); got != nil {
			t.Errorf("collectDRBD9() = %+v, want nil on command error", got)
		}
	})

	t.Run("empty output", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("drbdsetup", []string{"status", "--json", "all"}, "  \n", 0)
		})
		if got := collectDRBD9(context.Background(), "9.1.4"); got != nil {
			t.Errorf("collectDRBD9() = %+v, want nil on empty output", got)
		}
	})
}

// TestApplyDRBD9Connection is a pure-function test covering the connection/
// sync-state folding logic — safe to run in parallel.
func TestApplyDRBD9Connection(t *testing.T) {
	t.Parallel()

	t.Run("connected with established replication defaults ConnState to Connected", func(t *testing.T) {
		t.Parallel()
		res := &models.DRBDResource{}
		applyDRBD9Connection(res, drbd9Resource{
			Connections: []struct {
				ConnectionState string `json:"connection-state"`
				PeerDevices     []struct {
					ReplicationState string  `json:"replication-state"`
					PeerDiskState    string  `json:"peer-disk-state"`
					PercentInSync    float64 `json:"percent-in-sync"`
					OutOfSync        int64   `json:"out-of-sync"`
				} `json:"peer_devices"`
			}{
				{
					ConnectionState: "Connected",
					PeerDevices: []struct {
						ReplicationState string  `json:"replication-state"`
						PeerDiskState    string  `json:"peer-disk-state"`
						PercentInSync    float64 `json:"percent-in-sync"`
						OutOfSync        int64   `json:"out-of-sync"`
					}{{ReplicationState: "Established", PeerDiskState: "UpToDate"}},
				},
			},
		})
		if res.ConnState != "Connected" || res.RemoteDisk != "UpToDate" {
			t.Errorf("res = %+v, want ConnState=Connected RemoteDisk=UpToDate", res)
		}
	})

	t.Run("non-connected link is surfaced and kept", func(t *testing.T) {
		t.Parallel()
		res := &models.DRBDResource{}
		applyDRBD9Connection(res, drbd9Resource{
			Connections: []struct {
				ConnectionState string `json:"connection-state"`
				PeerDevices     []struct {
					ReplicationState string  `json:"replication-state"`
					PeerDiskState    string  `json:"peer-disk-state"`
					PercentInSync    float64 `json:"percent-in-sync"`
					OutOfSync        int64   `json:"out-of-sync"`
				} `json:"peer_devices"`
			}{
				{ConnectionState: "WFConnection"},
			},
		})
		if res.ConnState != "WFConnection" {
			t.Errorf("ConnState = %q, want WFConnection", res.ConnState)
		}
	})

	t.Run("SyncTarget replication overrides ConnState with progress", func(t *testing.T) {
		t.Parallel()
		res := &models.DRBDResource{}
		applyDRBD9Connection(res, drbd9Resource{
			Connections: []struct {
				ConnectionState string `json:"connection-state"`
				PeerDevices     []struct {
					ReplicationState string  `json:"replication-state"`
					PeerDiskState    string  `json:"peer-disk-state"`
					PercentInSync    float64 `json:"percent-in-sync"`
					OutOfSync        int64   `json:"out-of-sync"`
				} `json:"peer_devices"`
			}{
				{
					ConnectionState: "Connected",
					PeerDevices: []struct {
						ReplicationState string  `json:"replication-state"`
						PeerDiskState    string  `json:"peer-disk-state"`
						PercentInSync    float64 `json:"percent-in-sync"`
						OutOfSync        int64   `json:"out-of-sync"`
					}{{ReplicationState: "SyncTarget", PeerDiskState: "Inconsistent", PercentInSync: 42.5, OutOfSync: 1024}},
				},
			},
		})
		if res.ConnState != "SyncTarget" || res.SyncPct != 42.5 || res.SyncKBLeft != 1024 {
			t.Errorf("res = %+v, want ConnState=SyncTarget SyncPct=42.5 SyncKBLeft=1024", res)
		}
	})

	t.Run("first non-connected link wins, later healthy peer does not overwrite", func(t *testing.T) {
		t.Parallel()
		res := &models.DRBDResource{}
		applyDRBD9Connection(res, drbd9Resource{
			Connections: []struct {
				ConnectionState string `json:"connection-state"`
				PeerDevices     []struct {
					ReplicationState string  `json:"replication-state"`
					PeerDiskState    string  `json:"peer-disk-state"`
					PercentInSync    float64 `json:"percent-in-sync"`
					OutOfSync        int64   `json:"out-of-sync"`
				} `json:"peer_devices"`
			}{
				{ConnectionState: "StandAlone"},
				{ConnectionState: "Connected"},
			},
		})
		if res.ConnState != "StandAlone" {
			t.Errorf("ConnState = %q, want StandAlone (first failing link kept)", res.ConnState)
		}
	})
}

// TestParseDRBDProc covers the header/stats/sync-line parsing branches,
// including the regression guard against the stats-line-mistaken-for-header
// bug (trimmed[2]==':' on "ns:0 nr:0 ...").
func TestParseDRBDProc(t *testing.T) {
	t.Parallel()

	t.Run("multi-resource with sync line", func(t *testing.T) {
		t.Parallel()
		content := "version: 8.4.11 (api:1/proto:86-101)\n" +
			" 0: cs:Connected ro:Primary/Secondary ds:UpToDate/UpToDate C r-----\n" +
			"    ns:0 nr:0 dw:0 dr:0 al:0 bm:0 lo:0 pe:0 ua:0 ap:0 ep:1 wo:f oos:0\n" +
			" 1: cs:SyncSource ro:Primary/Secondary ds:UpToDate/Inconsistent C r-----\n" +
			"    [=>..................] sync'ed: 12.5% (98765/102400)K\n"
		info := parseDRBDProc(strings.NewReader(content))
		if len(info.Resources) != 2 {
			t.Fatalf("Resources = %+v, want 2", info.Resources)
		}
		if info.Resources[0].ConnState != "Connected" {
			t.Errorf("Resources[0].ConnState = %q, want Connected (the stats line must not overwrite it)", info.Resources[0].ConnState)
		}
		if info.Resources[1].SyncPct != 12.5 || info.Resources[1].SyncKBLeft != 98765 {
			t.Errorf("Resources[1] = %+v, want SyncPct=12.5 SyncKBLeft=98765", info.Resources[1])
		}
	})

	t.Run("no resources yields empty slice", func(t *testing.T) {
		t.Parallel()
		info := parseDRBDProc(strings.NewReader("version: 8.4.11 (api:1/proto:86-101)\n"))
		if len(info.Resources) != 0 {
			t.Errorf("Resources = %+v, want none", info.Resources)
		}
		if info.Unverified {
			t.Error("Unverified = true, want false on a clean scan")
		}
	})
}

// errorReaderDRBD always returns an error on Read, to exercise the
// scanner.Err() != nil branch of parseDRBDProc: a partial/failed read of
// /proc/drbd must mark Unverified rather than silently reporting a clean
// empty scan.
type errorReaderDRBD struct{}

func (errorReaderDRBD) Read([]byte) (int, error) { return 0, errDRBDBoom }

var errDRBDBoom = &drbdTestErr{"boom"}

type drbdTestErr struct{ s string }

func (e *drbdTestErr) Error() string { return e.s }

func TestParseDRBDProc_ScannerError(t *testing.T) {
	t.Parallel()
	info := parseDRBDProc(errorReaderDRBD{})
	if !info.Unverified {
		t.Error("Unverified = false, want true on a scanner read error")
	}
}

// TestParseDRBDResourceLine is a pure-function test — safe to run in parallel.
func TestParseDRBDResourceLine(t *testing.T) {
	t.Parallel()

	t.Run("full line", func(t *testing.T) {
		t.Parallel()
		r := parseDRBDResourceLine("0: cs:Connected ro:Primary/Secondary ds:UpToDate/UpToDate C r-----")
		if r.Minor != 0 || r.ConnState != "Connected" || r.LocalRole != "Primary" || r.LocalDisk != "UpToDate" || r.RemoteDisk != "UpToDate" {
			t.Errorf("got %+v, want minor=0 cs=Connected ro=Primary ds=UpToDate/UpToDate", r)
		}
	})

	t.Run("two digit minor", func(t *testing.T) {
		t.Parallel()
		r := parseDRBDResourceLine("12: cs:StandAlone ro:Secondary/Unknown ds:Outdated/DUnknown")
		if r.Minor != 12 || r.ConnState != "StandAlone" || r.LocalRole != "Secondary" {
			t.Errorf("got %+v, want minor=12 cs=StandAlone ro=Secondary", r)
		}
	})

	t.Run("no colon leaves minor zero", func(t *testing.T) {
		t.Parallel()
		r := parseDRBDResourceLine("garbage line with no colon at start")
		if r.Minor != 0 {
			t.Errorf("Minor = %d, want 0", r.Minor)
		}
	})
}

// TestParseDRBDSyncLine is a pure-function test — safe to run in parallel.
func TestParseDRBDSyncLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		line       string
		wantPct    float64
		wantKBLeft int64
	}{
		{
			name:       "standard sync line",
			line:       "    [=>..................] sync'ed: 12.5% (98765/102400)K",
			wantPct:    12.5,
			wantKBLeft: 98765,
		},
		{
			name:       "commas in numbers stripped",
			line:       "sync'ed: 5.0% (1,234/999,999)K",
			wantPct:    5.0,
			wantKBLeft: 1234,
		},
		{
			name:       "no sync marker yields zero",
			line:       "no sync info here",
			wantPct:    0,
			wantKBLeft: 0,
		},
		{
			name:       "no parens yields zero KB left but keeps pct",
			line:       "sync'ed: 33.3%",
			wantPct:    33.3,
			wantKBLeft: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pct, kbLeft := parseDRBDSyncLine(tt.line)
			if pct != tt.wantPct || kbLeft != tt.wantKBLeft {
				t.Errorf("parseDRBDSyncLine(%q) = (%v,%v), want (%v,%v)", tt.line, pct, kbLeft, tt.wantPct, tt.wantKBLeft)
			}
		})
	}

	t.Run("garbled negative/NaN values are clamped", func(t *testing.T) {
		t.Parallel()
		pct, kbLeft := parseDRBDSyncLine("sync'ed: -5.0% (-100/200)K")
		if pct != 0 {
			t.Errorf("pct = %v, want 0 (negative clamped)", pct)
		}
		if kbLeft != 0 {
			t.Errorf("kbLeft = %v, want 0 (negative clamped)", kbLeft)
		}
	})
}
