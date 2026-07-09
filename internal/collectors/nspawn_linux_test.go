//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestNspawnCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewNspawnCollector()
	if c.Name() != "Nspawn" {
		t.Errorf("Name() = %q, want Nspawn", c.Name())
	}
	if c.Timeout() != 4*time.Second {
		t.Errorf("Timeout() = %v, want 4s", c.Timeout())
	}
}

func TestIsNspawnPresent(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withCombinedFixture(t,
			map[string][]byte{"lookpath/machinectl": []byte("/usr/bin/machinectl")},
			nil,
			func(_ *source.Bundle) {},
		)
		if !IsNspawnPresent() {
			t.Error("expected true when machinectl resolves on $PATH")
		}
	})

	t.Run("absent", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		if IsNspawnPresent() {
			t.Error("expected false when machinectl is not on $PATH")
		}
	})
}

// TestNspawnCollector_Collect_MachinectlAbsent guards the gate-off path: when
// machinectl isn't on $PATH, Collect must return an empty NspawnInfo{} without
// attempting the "machinectl list" or systemctl calls.
func TestNspawnCollector_Collect_MachinectlAbsent(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{}, nil, func(_ *source.Bundle) {})
	c := NewNspawnCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NspawnInfo)
	if info.Available {
		t.Errorf("expected Available=false when machinectl absent, got %+v", info)
	}
}

// TestNspawnCollector_Collect_EmptyList guards the "machinectl installed but no
// containers" path: empty/whitespace-only output must leave Available false and
// not attempt to parse containers.
func TestNspawnCollector_Collect_EmptyList(t *testing.T) {
	withCombinedFixture(t,
		map[string][]byte{"lookpath/machinectl": []byte("/usr/bin/machinectl")},
		nil,
		func(b *source.Bundle) {
			b.PutCmd("machinectl", []string{"list", "--no-legend", "--no-pager"}, "   \n", 0)
		},
	)
	c := NewNspawnCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NspawnInfo)
	if info.Available {
		t.Errorf("expected Available=false for blank machinectl output, got %+v", info)
	}
}

// TestNspawnCollector_Collect_HappyPath exercises the full path: machinectl
// lists two containers and systemctl reports one failed nspawn unit.
func TestNspawnCollector_Collect_HappyPath(t *testing.T) {
	withCombinedFixture(t,
		map[string][]byte{"lookpath/machinectl": []byte("/usr/bin/machinectl")},
		nil,
		func(b *source.Bundle) {
			b.PutCmd("machinectl", []string{"list", "--no-legend", "--no-pager"},
				"web1     container nspawn debian   12   -\nweb2     container nspawn ubuntu   22.04 -\n", 0)
			b.PutCmd("systemctl", []string{"list-units", "systemd-nspawn@*.service",
				"--state=failed", "--no-legend", "--no-pager", "--plain"},
				"systemd-nspawn@web3.service loaded failed failed systemd-nspawn@web3.service\n", 0)
		},
	)
	c := NewNspawnCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NspawnInfo)
	if !info.Available {
		t.Fatal("expected Available=true")
	}
	if len(info.Containers) != 2 {
		t.Fatalf("Containers = %+v, want 2", info.Containers)
	}
	if info.Containers[0].Name != "web1" || info.Containers[0].State != "running" {
		t.Errorf("Containers[0] = %+v, want name=web1 state=running", info.Containers[0])
	}
	if info.FailedCount != 1 {
		t.Errorf("FailedCount = %d, want 1", info.FailedCount)
	}
}

// TestCountFailedNspawnUnits_SystemctlFails guards the error branch: a
// systemctl failure must return 0, not propagate an error.
func TestCountFailedNspawnUnits_SystemctlFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "systemd-nspawn@*.service",
			"--state=failed", "--no-legend", "--no-pager", "--plain"}, "", 1)
	})
	if got := countFailedNspawnUnits(context.Background()); got != 0 {
		t.Errorf("countFailedNspawnUnits() = %d, want 0 on systemctl error", got)
	}
}

// TestCountFailedNspawnUnits_NoMatches guards a clean systemctl result with no
// nspawn-prefixed lines (e.g. blank or unrelated unit noise) counting zero.
func TestCountFailedNspawnUnits_NoMatches(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"list-units", "systemd-nspawn@*.service",
			"--state=failed", "--no-legend", "--no-pager", "--plain"}, "\n", 0)
	})
	if got := countFailedNspawnUnits(context.Background()); got != 0 {
		t.Errorf("countFailedNspawnUnits() = %d, want 0", got)
	}
}

// TestParseMachinectlList_Additional is a pure-function test (no fixture
// dependency) covering blank-line and empty-input edge cases not exercised by
// TestParseMachinectlList in medium_low_linux_test.go — safe to run in parallel.
func TestParseMachinectlList_Additional(t *testing.T) {
	t.Parallel()
	t.Run("blank lines skipped", func(t *testing.T) {
		t.Parallel()
		got := parseMachinectlList("\n  \nweb1 container nspawn debian 12 -\n")
		if len(got) != 1 || got[0].Name != "web1" {
			t.Fatalf("got %+v, want 1 container named web1", got)
		}
	})

	t.Run("empty input yields nil", func(t *testing.T) {
		t.Parallel()
		got := parseMachinectlList("")
		if len(got) != 0 {
			t.Fatalf("got %+v, want none", got)
		}
	})
}
