package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// DD-COLLECTOR-GAPS-1 Medium #8: under hidepid=2 / ProtectProc=invisible the
// /proc listing omits other users' PIDs (PID 1 included) with no error, so the
// zombie/hung counts are a valid-looking undercount. The collector must say so.
func TestProcessesCollectLinux_HidepidListingIsFlaggedRestricted(t *testing.T) {
	b := source.NewBundle()
	b.PutGlob("/proc/[0-9]*", []string{"/proc/4242"}) // no /proc/1: other users hidden
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	info, err := NewProcessesCollector().collectLinux(context.Background())
	if err != nil {
		t.Fatalf("collectLinux: %v", err)
	}
	if !info.ListRestricted {
		t.Error("ListRestricted = false for a /proc listing that lacks PID 1")
	}
}

func TestProcessesCollectLinux_FullListingIsNotRestricted(t *testing.T) {
	b := source.NewBundle()
	b.PutGlob("/proc/[0-9]*", []string{"/proc/1", "/proc/4242"})
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	info, err := NewProcessesCollector().collectLinux(context.Background())
	if err != nil {
		t.Fatalf("collectLinux: %v", err)
	}
	if info.ListRestricted {
		t.Error("ListRestricted = true for a listing that includes PID 1")
	}
}

func TestProcessesCollectDarwin_PsFailureIsFlaggedUnreadable(t *testing.T) {
	b := source.NewBundle()
	b.PutCmdNotFound("ps", []string{"axo", "pid,ppid,stat,comm"})
	prev := SetSource(source.NewReplay(b))
	t.Cleanup(func() { SetSource(prev) })

	info, err := NewProcessesCollector().collectDarwin(context.Background())
	if err != nil {
		t.Fatalf("collectDarwin: %v", err)
	}
	if !info.ListUnreadable {
		t.Error("ListUnreadable = false although ps could not run")
	}
}
