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
