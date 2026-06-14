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
