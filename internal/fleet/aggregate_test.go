package fleet

import "testing"

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
	if clock == nil || clock.Count != 3 || clock.Scope != "fleet-wide" {
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
	if len(groups) == 0 || groups[0].Scope != "fleet-wide" {
		t.Fatalf("fleet-wide should sort first, got %+v", groups)
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
