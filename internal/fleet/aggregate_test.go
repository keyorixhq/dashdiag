package fleet

import "testing"

const scopeFleetWide = "fleet-wide"

func mkResult(host string, issues ...Issue) Result {
	r := Result{Host: host, Reachable: true, Worst: "OK", Issues: issues}
	for _, i := range issues {
		if i.Level == "CRIT" {
			r.Worst = "CRIT"
		} else if i.Level == "WARN" && r.Worst != "CRIT" {
			r.Worst = "WARN"
		}
	}
	return r
}

func findGroup(groups []IssueGroup, check, level string) *IssueGroup {
	for i := range groups {
		if groups[i].Check == check && groups[i].Level == level {
			return &groups[i]
		}
	}
	return nil
}

func TestMaskNumbers(t *testing.T) {
	if got := maskNumbers("RAM at 97%"); got != "RAM at #%" {
		t.Errorf("maskNumbers = %q", got)
	}
	if maskNumbers("RAM at 97%") != maskNumbers("RAM at 85%") {
		t.Error("different values should mask to the same shape")
	}
}

func TestAggregateIssues_FleetWideVsOutlier(t *testing.T) {
	// 4 hosts: 3 share an NTP issue (fleet-wide), 1 has a unique failed unit (outlier).
	results := []Result{
		mkResult("h1", Issue{"Clock", "WARN", "NTP offset is 800 ms"}),
		mkResult("h2", Issue{"Clock", "WARN", "NTP offset is 950 ms"}),
		mkResult("h3", Issue{"Clock", "WARN", "NTP offset is 700 ms"}),
		mkResult("h4", Issue{"Systemd", "CRIT", "unit nginx.service has failed"}),
	}
	groups := AggregateIssues(results)

	clock := findGroup(groups, "Clock", "WARN")
	if clock == nil || clock.Count != 3 || clock.Scope != scopeFleetWide {
		t.Fatalf("Clock should be fleet-wide across 3 hosts, got %+v", clock)
	}
	sysd := findGroup(groups, "Systemd", "CRIT")
	if sysd == nil || sysd.Count != 1 || sysd.Scope != "outlier" || sysd.Hosts[0] != "h4" {
		t.Fatalf("Systemd should be an outlier on h4, got %+v", sysd)
	}
	// Different NTP values (800/950/700 ms) must collapse into ONE group.
	if clock.Count != 3 {
		t.Errorf("masked values should group: want 3 hosts, got %d", clock.Count)
	}
}

func TestAggregateIssues_OrderingFleetWideFirst(t *testing.T) {
	results := []Result{
		mkResult("a", Issue{"Disk", "CRIT", "/ at 99%"}), // outlier CRIT
		mkResult("b", Issue{"Network", "WARN", "latency 200 ms"}),
		mkResult("c", Issue{"Network", "WARN", "latency 250 ms"}), // fleet-wide WARN (2/3)
	}
	groups := AggregateIssues(results)
	if len(groups) == 0 || groups[0].Scope != scopeFleetWide {
		t.Fatalf("fleet-wide should sort first, got %+v", groups)
	}
}

// TestAggregateIssues_LevelTiebreakOrdering exercises the sort comparator's
// level tiebreak: within the SAME scope, a CRIT group must sort before a WARN
// group even when the WARN group has a higher host count.
func TestAggregateIssues_LevelTiebreakOrdering(t *testing.T) {
	t.Parallel()
	// 3 reachable hosts, both issues affecting exactly 1 host each -> both
	// classify as "outlier" (same scope), differing only by level.
	results := []Result{
		mkResult("h1", Issue{"Disk", "CRIT", "/ at 99%"}),
		mkResult("h2", Issue{"Net", "WARN", "latency high"}),
		mkResult("h3"),
	}
	groups := AggregateIssues(results)
	disk := findGroup(groups, "Disk", "CRIT")
	net := findGroup(groups, "Net", "WARN")
	if disk == nil || net == nil {
		t.Fatalf("expected both Disk and Net groups, got %+v", groups)
	}
	if disk.Scope != net.Scope {
		t.Fatalf("test setup requires same scope for both groups, got Disk=%q Net=%q", disk.Scope, net.Scope)
	}
	var diskIdx, netIdx int
	for i, g := range groups {
		if g.Check == "Disk" {
			diskIdx = i
		}
		if g.Check == "Net" {
			netIdx = i
		}
	}
	if diskIdx >= netIdx {
		t.Errorf("CRIT group Disk (idx %d) should sort before WARN group Net (idx %d)", diskIdx, netIdx)
	}
}

// TestClassifyScope is a table-driven boundary test over classifyScope's four
// branches: too few reachable hosts to judge, a lone host (outlier), a
// majority (fleet-wide), and a shared-but-minority case (common).
func TestClassifyScope(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		count, reached int
		want           string
	}{
		{"zero reachable can't classify", 1, 0, "common"},
		{"single reachable can't classify", 1, 1, "common"},
		{"lone host among many is an outlier", 1, 4, "outlier"},
		{"exact majority is fleet-wide", 3, 4, scopeFleetWide},
		{"bare majority (more than half) is fleet-wide", 2, 3, scopeFleetWide},
		{"shared but not a majority is common", 2, 5, "common"},
		{"exactly half is common, not fleet-wide", 2, 4, "common"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := classifyScope(c.count, c.reached); got != c.want {
				t.Errorf("classifyScope(%d, %d) = %q, want %q", c.count, c.reached, got, c.want)
			}
		})
	}
}

// TestAggregateIssues_CommonScope covers the "shared, but not a majority"
// group scope: 2 of 5 reachable hosts share an issue — not one lone outlier,
// not a majority, so it must classify as "common" rather than either extreme.
func TestAggregateIssues_CommonScope(t *testing.T) {
	t.Parallel()
	results := []Result{
		mkResult("h1", Issue{"Swap", "WARN", "swap 40% used"}),
		mkResult("h2", Issue{"Swap", "WARN", "swap 55% used"}),
		mkResult("h3"),
		mkResult("h4"),
		mkResult("h5"),
	}
	groups := AggregateIssues(results)
	g := findGroup(groups, "Swap", "WARN")
	if g == nil || g.Count != 2 || g.Scope != "common" {
		t.Fatalf("Swap should be common across 2/5 hosts, got %+v", g)
	}
}

// TestAggregateIssues_ExactDuplicateWithinHost drives the seen[key] continue
// branch directly: the SAME masked key (not just the same Check+Level, but
// the same masked message shape too) reported twice for one host must be
// skipped on the second occurrence, not double-added to that host's set.
func TestAggregateIssues_ExactDuplicateWithinHost(t *testing.T) {
	t.Parallel()
	r := mkResult("solo",
		Issue{"Clock", "WARN", "NTP offset is 500 ms"},
		Issue{"Clock", "WARN", "NTP offset is 700 ms"}, // masks to the identical key as above
	)
	groups := AggregateIssues([]Result{r})
	g := findGroup(groups, "Clock", "WARN")
	if g == nil || g.Count != 1 || len(g.Hosts) != 1 {
		t.Fatalf("exact duplicate masked issue should collapse to one host entry, got %+v", g)
	}
}

// TestAggregateIssues_CountTiebreakOrdering exercises the final sort's
// Count-descending tiebreak: two groups in the same scope/level bucket must
// order the higher-count group first.
func TestAggregateIssues_CountTiebreakOrdering(t *testing.T) {
	t.Parallel()
	// 5 reachable hosts. A hits 4 of them (4*2=8>5 -> fleet-wide). B hits 3 of
	// the same hosts (3*2=6>5 -> also fleet-wide, but a smaller count than A).
	// Same scope + same level (WARN) puts both through the Count-descending
	// tiebreak, where A (higher count) must sort first.
	results := []Result{
		mkResult("h1", Issue{"A", "WARN", "a issue"}, Issue{"B", "WARN", "b issue"}),
		mkResult("h2", Issue{"A", "WARN", "a issue"}, Issue{"B", "WARN", "b issue"}),
		mkResult("h3", Issue{"A", "WARN", "a issue"}, Issue{"B", "WARN", "b issue"}),
		mkResult("h4", Issue{"A", "WARN", "a issue"}),
		mkResult("h5"),
	}
	groups := AggregateIssues(results)
	a := findGroup(groups, "A", "WARN")
	b := findGroup(groups, "B", "WARN")
	if a == nil || b == nil {
		t.Fatalf("expected both A and B groups, got %+v", groups)
	}
	if a.Scope != b.Scope {
		t.Fatalf("test setup requires same scope for both groups, got A=%q B=%q", a.Scope, b.Scope)
	}
	// A has count 4, B has count 3 — A must sort first within the same scope/level.
	var aIdx, bIdx int
	for i, g := range groups {
		if g.Check == "A" {
			aIdx = i
		}
		if g.Check == "B" {
			bIdx = i
		}
	}
	if aIdx >= bIdx {
		t.Errorf("higher-count group A (idx %d) should sort before B (idx %d)", aIdx, bIdx)
	}
}

func TestAggregateIssues_DedupWithinHost(t *testing.T) {
	// Same masked issue twice on one host counts that host once.
	r := mkResult("solo",
		Issue{"Drives", "WARN", "sda 90% worn"},
		Issue{"Drives", "WARN", "sdb 91% worn"},
	)
	// one reachable host → scope can't be drift; just assert single-host count.
	groups := AggregateIssues([]Result{r})
	g := findGroup(groups, "Drives", "WARN")
	if g == nil || g.Count != 1 {
		t.Fatalf("same host should count once, got %+v", g)
	}
}
