package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

func TestKVMVMIcon(t *testing.T) {
	cases := []struct {
		name string
		vm   models.KVMVM
		want string
	}{
		{"crashed", models.KVMVM{State: models.KVMCrashed}, "CRIT"},
		{"paused", models.KVMVM{State: models.KVMPaused}, "WARN"},
		{"running", models.KVMVM{State: models.KVMRunning}, "OK"},
		// A shut-off VM is normal (OFF) UNLESS it's supposed to autostart —
		// then it staying down is itself a fault worth flagging.
		{"shut off, no autostart", models.KVMVM{State: models.KVMShutOff}, "OFF"},
		{"shut off, autostart expected", models.KVMVM{State: models.KVMShutOff, AutoStart: true}, "WARN"},
		{"shut down, autostart expected", models.KVMVM{State: models.KVMShutDown, AutoStart: true}, "WARN"},
	}
	for _, c := range cases {
		got := strings.TrimSpace(kvmVMIcon(c.vm, output.ModePlain))
		if got != c.want {
			t.Errorf("%s: kvmVMIcon(%+v) = %q, want %q", c.name, c.vm, got, c.want)
		}
	}
}
