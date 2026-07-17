package store

import (
	"testing"
	"time"
)

func TestDiffChecks(t *testing.T) {
	t.Parallel()
	ts := time.Now()

	cases := []struct {
		name    string
		prev    map[string]string
		cur     map[string]string
		want    []CheckChange // sorted by Name
	}{
		{
			name: "no changes",
			prev: map[string]string{"cpu": "OK", "mem": "WARN"},
			cur:  map[string]string{"cpu": "OK", "mem": "WARN"},
			want: nil,
		},
		{
			name: "status changed",
			prev: map[string]string{"cpu": "OK", "mem": "OK"},
			cur:  map[string]string{"cpu": "OK", "mem": "WARN"},
			want: []CheckChange{{Name: "mem", Before: "OK", After: "WARN"}},
		},
		{
			name: "new check appeared",
			prev: map[string]string{"cpu": "OK"},
			cur:  map[string]string{"cpu": "OK", "disk": "CRIT"},
			want: []CheckChange{{Name: "disk", Before: "", After: "CRIT"}},
		},
		{
			name: "check removed",
			prev: map[string]string{"cpu": "OK", "gpu": "WARN"},
			cur:  map[string]string{"cpu": "OK"},
			want: []CheckChange{{Name: "gpu", Before: "WARN", After: ""}},
		},
		{
			name: "multiple changes sorted by name",
			prev: map[string]string{"net": "OK", "cpu": "WARN", "mem": "OK"},
			cur:  map[string]string{"net": "CRIT", "cpu": "OK", "mem": "OK"},
			want: []CheckChange{
				{Name: "cpu", Before: "WARN", After: "OK"},
				{Name: "net", Before: "OK", After: "CRIT"},
			},
		},
		{
			name: "both empty",
			prev: map[string]string{},
			cur:  map[string]string{},
			want: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			prev := Entry{Timestamp: ts, Hostname: "h", Checks: c.prev}
			cur := Entry{Timestamp: ts, Hostname: "h", Checks: c.cur}
			got := DiffChecks(prev, cur)
			if len(got) != len(c.want) {
				t.Fatalf("got %d changes, want %d: %v", len(got), len(c.want), got)
			}
			for i, g := range got {
				w := c.want[i]
				if g.Name != w.Name || g.Before != w.Before || g.After != w.After {
					t.Errorf("[%d] got %+v, want %+v", i, g, w)
				}
			}
		})
	}
}
