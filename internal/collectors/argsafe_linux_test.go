//go:build linux

package collectors

import (
	"context"
	"reflect"
	"testing"
)

// Each table row drives one real call site with an option-shaped host value and
// asserts nothing is executed, then with a normal value and asserts the argv.
func TestLinuxHostArgCallers(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		run  func(v string)
		good string
		want []string // argv for the good value
	}{
		{"isServiceActive", func(v string) { isServiceActive(v) }, "cron.service", []string{"systemctl", "is-active", "--", "cron.service"}},
		{"ociServiceState", func(v string) { ociServiceState(ctx, v) }, "oracle-cloud-agent", []string{"systemctl", "show", "-p", "LoadState,ActiveState", "--value", "--", "oracle-cloud-agent"}},
		{"unitActive", func(v string) { unitActive(ctx, v) }, "jupiter.service", []string{"systemctl", "is-active", "--", "jupiter.service"}},
		{"kvmDomInfo", func(v string) { kvmDomInfo(ctx, v) }, "vm1", []string{"virsh", "dominfo", "vm1"}},
		{"parseBtrfsShow", func(v string) { parseBtrfsShow(ctx, v) }, "/mnt/data", []string{"btrfs", "filesystem", "show", "/mnt/data"}},
		{"fuserBusyProcesses", func(v string) { fuserBusyProcesses(ctx, v) }, "/mnt/data", []string{"fuser", "-m", "/mnt/data"}},
		{"lsZContext", func(v string) { lsZContext(ctx, v) }, "/etc/passwd", []string{"ls", "-dZ", "--", "/etc/passwd"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, bad := range optionShaped {
				spy := &argvSpy{}
				prev := SetSource(spy.source())
				tc.run(bad)
				SetSource(prev)
				if spy.count() != 0 {
					t.Errorf("%q reached exec: %v", bad, spy.calls)
				}
			}
			spy := &argvSpy{}
			defer SetSource(SetSource(spy.source()))
			tc.run(tc.good)
			if len(spy.calls) == 0 || !reflect.DeepEqual(spy.calls[0], tc.want) {
				t.Fatalf("argv = %v, want first call %v", spy.calls, tc.want)
			}
		})
	}
}
