//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// busyboxDmesgSource models an Alpine/OpenRC host: no journalctl, and a busybox
// `dmesg` that rejects util-linux flags (--time-format) but works when invoked
// bare. Regression guard for the OOM-dead-on-Alpine bug (found on an Alpine 3.22
// EC2 box): OOM detection must fall back to plain `dmesg` instead of reporting
// "kernel log unreadable" when dmesg is in fact fully readable as root.
type busyboxDmesgSource struct {
	source.Source
	bareDmesgCalled bool
}

func (b *busyboxDmesgSource) Run(_ context.Context, name string, args ...string) (source.Result, error) {
	switch {
	case name == "journalctl":
		return source.Result{ExitCode: 1}, &cmdError{name: name, code: 1} // no systemd
	case name == "dmesg" && len(args) > 0:
		// busybox dmesg doesn't understand --time-format / --since / etc.
		return source.Result{ExitCode: 1}, &cmdError{name: name, code: 1}
	case name == "dmesg":
		b.bareDmesgCalled = true
		// boot-relative timestamps — exactly what busybox dmesg emits.
		return source.Result{Stdout: []byte(
			"[ 10.5] systemd-free boot\n" +
				"[ 1234.56] Out of memory: Killed process 999 (python3) total-vm:1000kB\n",
		)}, nil
	}
	return source.Result{}, &cmdError{name: name, code: 1}
}

func TestOOMFallsBackToBareDmesgOnBusybox(t *testing.T) {
	src := &busyboxDmesgSource{}
	defer SetSource(SetSource(src))

	res, err := (&OOMCollector{}).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect errored: %v", err)
	}
	info := res.(*models.OOMInfo)

	if !src.bareDmesgCalled {
		t.Error("OOM must retry bare `dmesg` when `dmesg --time-format` fails (busybox)")
	}
	if info.StatusReason != "" {
		t.Errorf("OOM must NOT report unreadable when bare dmesg works, got %q", info.StatusReason)
	}
	if info.EventsLast24h != 1 {
		t.Errorf("expected the OOM kill parsed from bare dmesg, got %d events", info.EventsLast24h)
	}
	if len(info.RecentEvents) == 0 || !strings.Contains(info.RecentEvents[0].Process, "python3") {
		t.Errorf("expected the killed process surfaced, got %+v", info.RecentEvents)
	}
}
