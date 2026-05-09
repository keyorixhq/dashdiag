package drilldown

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func TestPopulateAll_OKInsightsUnchanged(t *testing.T) {
	ins := []models.Insight{
		{Level: "OK", Check: "CPU", Message: "all good"},
		{Level: "OK", Check: "Memory", Message: "all good"},
	}
	ctx := context.Background()
	got := PopulateAll(ctx, ins, nil)
	for _, i := range got {
		if i.Details != nil {
			t.Errorf("OK insight %q got unexpected Details", i.Check)
		}
	}
}

func TestPopulateAll_UnknownCheckPassesThrough(t *testing.T) {
	ins := []models.Insight{
		{Level: "WARN", Check: "UnknownCheck", Message: "something weird"},
	}
	ctx := context.Background()
	got := PopulateAll(ctx, ins, nil)
	if got[0].Details != nil {
		t.Errorf("unknown check should have nil Details, got %+v", got[0].Details)
	}
}

func TestPopulateAll_CancelledContextNocrash(t *testing.T) {
	ins := []models.Insight{
		{Level: "CRIT", Check: "Memory", Message: "RAM at 96%"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled
	// Should not panic or hang
	_ = PopulateAll(ctx, ins, nil)
}

func TestPopulateAll_MultipleWARNCRIT(t *testing.T) {
	ins := []models.Insight{
		{Level: "OK", Check: "CPU", Message: "fine"},
		{Level: "WARN", Check: "UnknownA", Message: "warn"},
		{Level: "CRIT", Check: "UnknownB", Message: "crit"},
	}
	ctx := context.Background()
	got := PopulateAll(ctx, ins, nil)
	if got[0].Level != "OK" {
		t.Error("first insight should still be OK")
	}
	// UnknownA and UnknownB should have nil Details (no dispatcher entry)
	if got[1].Details != nil || got[2].Details != nil {
		t.Error("unknown checks should produce nil Details")
	}
}

func TestPopulateAll_ResultsPassedThrough(t *testing.T) {
	results := []runner.Result{
		{Name: "Network", Data: nil},
	}
	ins := []models.Insight{
		{Level: "WARN", Check: "Network", Message: "gateway ping is 250 ms"},
	}
	ctx := context.Background()
	// Should not panic even if the Network drilldown finds no ss/netstat
	_ = PopulateAll(ctx, ins, results)
}

func TestParseMountFromMessage(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"disk usage at 85% on / (/dev/sda1)", "/"},
		{"disk usage at 85% on /var (/dev/sdb1)", "/var"},
		{"disk usage at 90% on /data/logs (/dev/sdc)", "/data/logs"},
		{"inode usage at 90% on /home", "/home"},
		{"something unrelated", "/"},
	}
	for _, c := range cases {
		got := parseMountFromMessage(c.msg)
		if got != c.want {
			t.Errorf("parseMountFromMessage(%q) = %q, want %q", c.msg, got, c.want)
		}
	}
}

func TestParseUnitFromMessage(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"unit foo.service has failed", "foo.service"},
		{"unit nginx.service has failed", "nginx.service"},
		{"unrelated message", ""},
	}
	for _, c := range cases {
		got := parseUnitFromMessage(c.msg)
		if got != c.want {
			t.Errorf("parseUnitFromMessage(%q) = %q, want %q", c.msg, got, c.want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{512, "512B"},
		{1500, "1.5KB"},
		{2 * 1024 * 1024, "2.0MB"},
		{3 * 1024 * 1024 * 1024, "3.0GB"},
	}
	for _, c := range cases {
		got := formatBytes(c.in)
		if got != c.want {
			t.Errorf("formatBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
