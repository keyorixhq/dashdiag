package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/fleet"
	"github.com/keyorixhq/dashdiag/internal/output"
)

func TestFleetStatusLabel(t *testing.T) {
	cases := []struct {
		name string
		r    fleet.Result
		mode output.OutputMode
		want string
	}{
		{"unreachable", fleet.Result{Reachable: false, Worst: "OK"}, output.ModePlain, "UNREACHABLE"},
		{"reachable but ERROR worst", fleet.Result{Reachable: true, Worst: "ERROR"}, output.ModePlain, "UNREACHABLE"},
		{"crit plain", fleet.Result{Reachable: true, Worst: "CRIT"}, output.ModePlain, "CRIT"},
		{"warn plain", fleet.Result{Reachable: true, Worst: "WARN"}, output.ModePlain, "WARN"},
		{"ok plain", fleet.Result{Reachable: true, Worst: "OK"}, output.ModePlain, "OK"},
		{"crit human", fleet.Result{Reachable: true, Worst: "CRIT"}, output.ModeHuman, "❌ CRIT"},
		{"unreachable human", fleet.Result{Reachable: false, Worst: "OK"}, output.ModeHuman, "🔌 UNREACHABLE"},
	}
	for _, c := range cases {
		if got := fleetStatusLabel(c.r, c.mode); got != c.want {
			t.Errorf("%s: fleetStatusLabel(%+v) = %q, want %q", c.name, c.r, got, c.want)
		}
	}
}
