//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// DD-COLLECTOR-GAPS-1 Low items: a failed read must set the sentinel, never fold
// into a clean value.

func TestKdumpCollector_NoSystemctlAnswerIsUnverified(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/lib/systemd/system/kdump.service", source.FileMeta{Mode: 0o644})
		b.PutCmdNotFound("systemctl", []string{"is-enabled", "kdump"})
		b.PutCmdNotFound("systemctl", []string{"is-active", "kdump"})
	})
	raw, err := NewKdumpCollector(platform.ContainerContext{}).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if info := raw.(*models.KdumpInfo); !info.StateUnverified {
		t.Errorf("StateUnverified = false although systemctl gave no answer: %+v", info)
	}
}

func TestTunedCollector_ActiveButProfileUnreadableIsUnverified(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/lib/systemd/system/tuned.service", source.FileMeta{Mode: 0o644})
		b.PutCmd("systemctl", []string{"is-active", "tuned"}, "active\n", 0)
		b.PutCmd("tuned-adm", []string{"active"}, "", 1)
		b.PutCmd("tuned-adm", []string{"recommend"}, "virtual-guest\n", 0)
	})
	raw, err := NewTunedCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if info := raw.(*models.TunedInfo); !info.StateUnverified {
		t.Errorf("StateUnverified = false although tuned-adm active failed: %+v", info)
	}
}

func TestThermalCollector_DriverFoundInputUnreadableIsFlagged(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/sys/class/hwmon/hwmon*", []string{"/sys/class/hwmon/hwmon0"})
		b.PutFile("/sys/class/hwmon/hwmon0/name", []byte("coretemp\n"))
		b.PutGlob("/sys/class/hwmon/hwmon0/temp*_input", []string{"/sys/class/hwmon/hwmon0/temp1_input"})
		// temp1_input deliberately not seeded: the read fails.
	})
	raw, err := NewThermalCollector().Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	info, ok := raw.(*models.ThermalInfo)
	if !ok || info == nil || !info.SensorUnreadable {
		t.Fatalf("SensorUnreadable not set: %#v", raw)
	}
}

func TestContainerdNamespacesChecked_ListFailureIsUnreadableNotIdle(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ctr", []string{"namespaces", "list", "-q"}, "", 1)
	})
	ns, _, nsUnreadable, _ := containerdNamespacesChecked(context.Background(), "ctr")
	if ns != nil || !nsUnreadable {
		t.Fatalf("ns=%v nsUnreadable=%v, want nil/true", ns, nsUnreadable)
	}
}

func TestContainerdNamespacesChecked_EmptyAnswerIsGenuinelyIdle(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ctr", []string{"namespaces", "list", "-q"}, "", 0)
	})
	if _, _, nsUnreadable, countsUnreadable := containerdNamespacesChecked(context.Background(), "ctr"); nsUnreadable || countsUnreadable {
		t.Fatal("an empty successful answer must not be flagged unreadable")
	}
}

func TestContainerdNamespacesChecked_CountFailureIsFlagged(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ctr", []string{"namespaces", "list", "-q"}, "default\n", 0)
		b.PutCmd("ctr", []string{"-n", "default", "containers", "list", "-q"}, "", 1)
	})
	_, _, nsUnreadable, countsUnreadable := containerdNamespacesChecked(context.Background(), "ctr")
	if nsUnreadable || !countsUnreadable {
		t.Fatalf("nsUnreadable=%v countsUnreadable=%v, want false/true", nsUnreadable, countsUnreadable)
	}
}
