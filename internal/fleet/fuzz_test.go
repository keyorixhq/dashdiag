package fleet

import "testing"

// FuzzParseHealth fuzzes the remote-health JSON parser. This is trust boundary B
// (THREAT_MODEL_CLI.md): parseHealth consumes stdout returned by `dsd health
// --json` on a REMOTE host, which may be compromised or hostile. The invariants
// are (1) it never panics on arbitrary bytes, and (2) it never reports an
// unreachable/garbage host as Reachable — the false-OK bug class applied to the
// fleet aggregator (a foreign JSON object must not masquerade as a healthy host).
func FuzzParseHealth(f *testing.F) {
	seeds := []string{
		`{"hostname":"h1","version":"v0.8.1","insights":[]}`,            // clean host
		`{"insights":[{"check":"cpu","level":"CRIT","message":"hot"}]}`, // crit
		`{"insights":[{"check":"x","level":"WARN","message":"w"}]}`,     // warn
		`banner line\n{"hostname":"h","insights":[]}`,                   // banner prefix
		`{}`,                                  // no insights key — must reject
		`{"error":"permission denied"}`,       // foreign object — must reject
		`[]`,                                  // array, not object
		`null`,                                // null
		``,                                    // empty
		`{"insights":null}`,                   // explicit null insights
		`{"insights":[{"level":"CRIT"}]}`,     // missing fields
		`{"hostname":"\u0000","insights":[]}`, // NUL in hostname
		`{"insights":[` + `{"level":"CRIT","message":"x"},` + `]}`, // trailing comma (invalid)
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var res Result
		ok := parseHealth(data, &res)
		// Invariant: if parseHealth claims success, the result must carry a
		// valid verdict — never an empty/garbage Worst that downstream rollup
		// would mis-bucket. A rejected parse (ok==false) makes no claim.
		if ok {
			switch res.Worst {
			case "OK", "WARN", "CRIT":
				// valid
			default:
				t.Fatalf("parseHealth accepted input but produced invalid Worst=%q for input %q", res.Worst, data)
			}
		}
	})
}
