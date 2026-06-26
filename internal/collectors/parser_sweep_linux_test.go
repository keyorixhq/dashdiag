//go:build linux

package collectors

import (
	"strings"
	"testing"
)

// TestDRBDStatsLineNotResourceHeader: the per-resource stats line "ns:0 nr:0 ..."
// must NOT be parsed as a new resource header (the old trimmed[2]==':' check matched
// "ns:", duplicating the resource and stealing the sync line).
func TestDRBDStatsLineNotResourceHeader(t *testing.T) {
	proc := ` 1: cs:SyncSource ro:Primary/Secondary ds:UpToDate/Inconsistent C r-----
    ns:1024 nr:0 dw:0 dr:2048 al:0 bm:0 lo:0 pe:0 ua:0 ap:0 ep:1 wo:f oos:5120
	[==>.................] sync'ed: 17.0% (5120/6144)K
`
	info := parseDRBDProc(strings.NewReader(proc))
	if len(info.Resources) != 1 {
		t.Fatalf("got %d resources, want 1 (stats line must not start a new resource): %+v", len(info.Resources), info.Resources)
	}
	if info.Resources[0].SyncPct == 0 {
		t.Errorf("sync%% should attach to the resource, got 0 (stats line stole it?)")
	}
}

// TestParseDRBD9JSON: DRBD 9.x publishes resource state via `drbdsetup status
// --json` (netlink), NOT /proc/drbd (which holds only a version header on v9). The
// fixture is verbatim real output from drbd9x 9.3.2 (ELRepo on AlmaLinux 10) for a
// resource whose peer is unreachable: connection Connecting, local disk Inconsistent.
// Without the v9 fallback this whole resource was invisible (silent false-OK).
func TestParseDRBD9JSON(t *testing.T) {
	const out = `[
{
  "name": "r0",
  "node-id": 0,
  "role": "Secondary",
  "devices": [
    { "volume": 0, "minor": 0, "disk-state": "Inconsistent", "size": 131032 } ],
  "connections": [
    {
      "peer-node-id": 1,
      "name": "faketwo",
      "connection-state": "Connecting",
      "peer-role": "Unknown",
      "peer_devices": [
        { "volume": 0, "replication-state": "Off", "peer-disk-state": "DUnknown", "out-of-sync": 131032, "percent-in-sync": 0.00 } ]
    } ]
}
]`
	info := parseDRBD9JSON([]byte(out), "9.3.2 (api:2/proto:118-124)")
	if info == nil || len(info.Resources) != 1 {
		t.Fatalf("got %+v, want 1 resource", info)
	}
	r := info.Resources[0]
	if r.ConnState != "Connecting" {
		t.Errorf("ConnState = %q, want Connecting (the down-link signal)", r.ConnState)
	}
	if r.LocalDisk != "Inconsistent" {
		t.Errorf("LocalDisk = %q, want Inconsistent", r.LocalDisk)
	}
	if r.LocalRole != "Secondary" {
		t.Errorf("LocalRole = %q, want Secondary", r.LocalRole)
	}
	if r.RemoteDisk != "DUnknown" {
		t.Errorf("RemoteDisk = %q, want DUnknown", r.RemoteDisk)
	}

	// A healthy, fully-connected resource must map to ConnState "Connected" so the
	// heuristic emits no insight (no false alarm).
	const healthy = `[{"name":"r0","role":"Primary","devices":[{"minor":0,"disk-state":"UpToDate"}],"connections":[{"connection-state":"Connected","peer_devices":[{"replication-state":"Established","peer-disk-state":"UpToDate","percent-in-sync":100.0}]}]}]`
	hi := parseDRBD9JSON([]byte(healthy), "9.3.2")
	if hi == nil || len(hi.Resources) != 1 || hi.Resources[0].ConnState != "Connected" {
		t.Fatalf("healthy resource: got %+v, want ConnState Connected", hi)
	}

	// A resync in progress: connection Connected but replication SyncTarget — the
	// sync state must surface as ConnState so the heuristic shows progress (and does
	// not CRIT the expected-Inconsistent disk).
	const syncing = `[{"name":"r0","role":"Secondary","devices":[{"minor":0,"disk-state":"Inconsistent"}],"connections":[{"connection-state":"Connected","peer_devices":[{"replication-state":"SyncTarget","peer-disk-state":"UpToDate","out-of-sync":4096,"percent-in-sync":42.5}]}]}]`
	si := parseDRBD9JSON([]byte(syncing), "9.3.2")
	if si == nil || len(si.Resources) != 1 {
		t.Fatalf("syncing: got %+v", si)
	}
	if si.Resources[0].ConnState != "SyncTarget" || si.Resources[0].SyncPct != 42.5 {
		t.Errorf("syncing: ConnState/SyncPct = %q/%.1f, want SyncTarget/42.5", si.Resources[0].ConnState, si.Resources[0].SyncPct)
	}
}

// TestIsSnapperSeparator: ASCII separators (older/non-UTF-8 snapper) must be skipped,
// not counted as a phantom config/snapshot row.
func TestIsSnapperSeparator(t *testing.T) {
	for _, sep := range []string{"-------+--------+-------", "──────┼──────┼──────", "----  ----", "│ ─ │"} {
		if !isSnapperSeparator(sep) {
			t.Errorf("isSnapperSeparator(%q) = false, want true", sep)
		}
	}
	for _, row := range []string{"root | single | 5", "0 | pre  | 2026-01-01", "myconfig"} {
		if isSnapperSeparator(row) {
			t.Errorf("isSnapperSeparator(%q) = true, want false (real data row)", row)
		}
	}
}
