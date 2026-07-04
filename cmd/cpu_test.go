package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/output"
)

func TestCPUIcon(t *testing.T) {
	cases := []struct {
		name            string
		val, warn, crit float64
		want            string
	}{
		{"below warn", 10, 50, 90, "OK"},
		{"at warn", 50, 50, 90, "WARN"},
		{"between warn and crit", 70, 50, 90, "WARN"},
		{"at crit", 90, 50, 90, "CRIT"},
		{"above crit", 99, 50, 90, "CRIT"},
	}
	for _, c := range cases {
		got := strings.TrimSpace(cpuIcon(c.val, c.warn, c.crit, output.ModePlain))
		if got != c.want {
			t.Errorf("%s: cpuIcon(%v, warn=%v, crit=%v) = %q, want %q", c.name, c.val, c.warn, c.crit, got, c.want)
		}
	}
}
