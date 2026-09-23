//go:build linux

package collectors

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Verdict-integrity oracles for the apt and tdnf security-update counters —
// the complement to FuzzCollectDNFVerdict for the other two package managers.
// FuzzAptAccumulateUpdate / FuzzParseTDNFUpdateInfo already prove these never
// panic on hostile `dsd replay` output; these assert they never MISCOUNT, since
// the count is what feeds PackagesInfo.SecurityUpdates and thus the security-
// patch verdict. Each oracle re-derives the count from the same documented rule
// the production parser uses, kept in lockstep so an unreviewed change to how a
// verdict is counted turns the harness red.

// FuzzAptAccumulateUpdateVerdict pins the apt per-line rule: a line contributes
// exactly one security update iff it has >=2 fields; it is Critical iff the
// package (field[1]) equals a critical prefix or starts with "<prefix>-", else
// Important; and it appends exactly one Updates entry.
func FuzzAptAccumulateUpdateVerdict(f *testing.F) {
	f.Add("Inst openssl [3.0.1] (3.0.2 Ubuntu:22.04/jammy-security [amd64])")
	f.Add("Inst linux-image-generic [5.15.0.1] (5.15.0.2 jammy-security [amd64])")
	f.Add("curl/jammy-updates 7.81.0 amd64")
	f.Add("a b")
	f.Add("single")
	f.Add("")
	f.Add("many\t\t\tfields   with\ttabs\t\t")
	crit := map[string]bool{"linux": true, "openssl": true, "openssh": true, "glibc": true, "curl": true}

	f.Fuzz(func(t *testing.T, line string) {
		info := &models.PackagesInfo{Checked: true, PackageManager: "apt"}
		aptAccumulateUpdate(info, crit, line)

		fields := strings.Fields(line)
		want := 0
		if len(fields) >= 2 {
			want = 1
		}
		if info.SecurityUpdates != want {
			t.Fatalf("apt SecurityUpdates=%d want %d for %q", info.SecurityUpdates, want, line)
		}
		if len(info.Updates) != want {
			t.Fatalf("apt Updates len=%d want %d for %q", len(info.Updates), want, line)
		}
		if info.CriticalUpdates+info.ImportantUpdates != want {
			t.Fatalf("apt severity split critical=%d important=%d, total must equal %d for %q", info.CriticalUpdates, info.ImportantUpdates, want, line)
		}
		if want == 1 {
			pkg := fields[1]
			critExpected := false
			for c := range crit {
				if pkg == c || strings.HasPrefix(pkg, c+"-") {
					critExpected = true
					break
				}
			}
			if (info.CriticalUpdates == 1) != critExpected {
				t.Fatalf("apt severity misclassified pkg %q: got critical=%v want %v", pkg, info.CriticalUpdates == 1, critExpected)
			}
		}
	})
}

// FuzzParseTDNFUpdateInfoVerdict pins the tdnf (Photon OS) advisory count that
// feeds SecurityUpdates. Text rule: one entry per line with >=3 fields whose
// first field starts with "patch:". JSON rule: one entry per top-level array
// element (independently counted via []json.RawMessage, which does not depend on
// the entry struct, so the oracle can't drift with it).
func FuzzParseTDNFUpdateInfoVerdict(f *testing.F) {
	f.Add(`[{"UpdateID":"PHSA-2024-0001","Packages":["openssl-1.1.1w.rpm"]}]`)
	f.Add(`[{},{},{}]`)
	f.Add(`[1,2,3]`)
	f.Add("patch:PHSA-2024-0001  security  openssl-1.1.1w\n")
	f.Add("patch:only two\nnotpatch a b c\n\n")
	f.Add("")
	f.Add("not json {[}")

	f.Fuzz(func(t *testing.T, out string) {
		// Text parser oracle.
		textEntries := parseTDNFUpdateInfoText(out)
		wantText := 0
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || !strings.HasPrefix(fields[0], "patch:") {
				continue
			}
			wantText++
		}
		if len(textEntries) != wantText {
			t.Fatalf("tdnf text advisory count=%d want %d for %q", len(textEntries), wantText, out)
		}

		// JSON parser oracle: when it reports parsed, the count must equal the
		// number of top-level array elements in the same bracket-delimited slice.
		jsonEntries, parsed, _ := parseTDNFUpdateInfoJSON(out)
		if parsed {
			start := strings.Index(out, "[")
			end := strings.LastIndex(out, "]")
			var raw []json.RawMessage
			if start >= 0 && end > start && json.Unmarshal([]byte(out[start:end+1]), &raw) == nil {
				if len(jsonEntries) != len(raw) {
					t.Fatalf("tdnf json advisory count=%d want %d for %q", len(jsonEntries), len(raw), out)
				}
			}
		}
	})
}
