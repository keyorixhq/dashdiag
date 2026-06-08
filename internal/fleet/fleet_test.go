package fleet

import "testing"

func TestParseHealth_CritsAndWarns(t *testing.T) {
	js := `{"hostname":"web1","version":"v0.6.1","insights":[
		{"check":"Disk","level":"CRIT","message":"disk 95% full"},
		{"check":"SSH","level":"WARN","message":"password auth enabled"},
		{"check":"Net","level":"WARN","message":"high retrans"},
		{"check":"Info","level":"INFO","message":"ignored"}
	]}`
	var r Result
	if ok := parseHealth([]byte(js), &r); !ok {
		t.Fatal("expected parse ok")
	}
	if r.Hostname != "web1" || r.Version != "v0.6.1" {
		t.Errorf("meta wrong: %+v", r)
	}
	if r.Crit != 1 || r.Warn != 2 {
		t.Errorf("counts = crit %d warn %d, want 1/2", r.Crit, r.Warn)
	}
	if r.Worst != "CRIT" || r.TopIssue != "disk 95% full" {
		t.Errorf("worst=%q top=%q", r.Worst, r.TopIssue)
	}
}

func TestParseHealth_WarnOnly(t *testing.T) {
	js := `{"hostname":"h","insights":[{"check":"SSH","level":"WARN","message":"w1"}]}`
	var r Result
	parseHealth([]byte(js), &r)
	if r.Worst != "WARN" || r.TopIssue != "w1" {
		t.Errorf("worst=%q top=%q", r.Worst, r.TopIssue)
	}
}

func TestParseHealth_Clean(t *testing.T) {
	var r Result
	parseHealth([]byte(`{"hostname":"h","insights":[]}`), &r)
	if r.Worst != "OK" || r.Crit != 0 || r.Warn != 0 {
		t.Errorf("clean host wrong: %+v", r)
	}
}

func TestParseHealth_BannerPrefix(t *testing.T) {
	// dsd prints a one-line banner to stdout before JSON in some modes.
	js := "⚡ DashDiag (dsd) v0.6.1 — web1\n{\"hostname\":\"web1\",\"insights\":[]}"
	var r Result
	if ok := parseHealth([]byte(js), &r); !ok {
		t.Fatal("should skip banner and parse JSON")
	}
	if r.Hostname != "web1" {
		t.Errorf("hostname = %q", r.Hostname)
	}
}

func TestParseHealth_Garbage(t *testing.T) {
	var r Result
	if ok := parseHealth([]byte("ssh: connect to host: Connection refused"), &r); ok {
		t.Error("garbage should not parse")
	}
}

// Valid JSON that is NOT a dsd health document (no "insights" key) must be
// rejected, not counted as a healthy/reachable host — otherwise a foreign tool's
// output or an error object hides a genuinely failing remote.
func TestParseHealth_NonHealthJSON(t *testing.T) {
	for _, js := range []string{
		`{}`,
		`{"error":"command not found: dsd","level":"CRIT"}`,
		`{"hostname":"h","version":"v9"}`, // looks dsd-ish but no insights key
	} {
		var r Result
		if ok := parseHealth([]byte(js), &r); ok {
			t.Errorf("non-health JSON %q must be rejected (got reachable/OK)", js)
		}
	}
}

func TestWorstExitCode(t *testing.T) {
	cases := []struct {
		name string
		in   []Result
		want int
	}{
		{"all ok", []Result{{Reachable: true, Worst: "OK"}}, 0},
		{"a warn", []Result{{Reachable: true, Worst: "OK"}, {Reachable: true, Worst: "WARN"}}, 1},
		{"a crit", []Result{{Reachable: true, Worst: "WARN"}, {Reachable: true, Worst: "CRIT"}}, 2},
		{"unreachable", []Result{{Reachable: false, Worst: "ERROR"}}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := WorstExitCode(c.in); got != c.want {
				t.Errorf("WorstExitCode = %d, want %d", got, c.want)
			}
		})
	}
}

func TestSortByHost(t *testing.T) {
	in := []Result{{Host: "web2"}, {Host: "db1"}, {Host: "web1"}}
	out := SortByHost(in)
	if out[0].Host != "db1" || out[1].Host != "web1" || out[2].Host != "web2" {
		t.Errorf("sort order wrong: %v", []string{out[0].Host, out[1].Host, out[2].Host})
	}
	// original not mutated
	if in[0].Host != "web2" {
		t.Error("SortByHost mutated input")
	}
}

func TestOptionsDefaults(t *testing.T) {
	o := Options{}.withDefaults()
	if o.RemoteCmd == "" || o.Concurrency == 0 || o.ConnectTimeout == 0 || o.RunTimeout == 0 || o.RemoteBinDir == "" {
		t.Errorf("defaults not filled: %+v", o)
	}
}
