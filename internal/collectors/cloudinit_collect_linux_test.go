//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestCloudInitCollectorIdentity guards the Collector interface wiring — no
// fixture dependency, safe to parallelize.
func TestCloudInitCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewCloudInitCollector()
	if c.Name() != "CloudInit" {
		t.Errorf("Name() = %q, want CloudInit", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

func TestCloudInitAvailable(t *testing.T) {
	t.Run("cli on PATH", func(t *testing.T) {
		withLookPathFixture(t, map[string]bool{"cloud-init": true}, func(b *source.Bundle) {})
		if !CloudInitAvailable() {
			t.Error("expected true when cloud-init is on $PATH")
		}
	})

	t.Run("status.json present, cli absent", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutStat("/run/cloud-init/status.json", source.FileMeta{Mode: 0o644})
		})
		if !CloudInitAvailable() {
			t.Error("expected true when the runtime status file exists")
		}
	})

	t.Run("neither present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		if CloudInitAvailable() {
			t.Error("expected false when neither the CLI nor the status file is present")
		}
	})
}

// TestCloudInitCollector_Collect_JSONHappyPath exercises the primary JSON path:
// `cloud-init status --format=json` succeeds and parses.
func TestCloudInitCollector_Collect_JSONHappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("cloud-init", []string{"status", "--format=json"}, `{
			"status": "done",
			"extended_status": "done",
			"datasource": "nocloud",
			"errors": [],
			"recoverable_errors": {}
		}`, 0)
	})

	c := NewCloudInitCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CloudInitInfo)
	if !info.Available {
		t.Error("expected Available=true")
	}
	if info.Status != "done" {
		t.Errorf("Status = %q, want done", info.Status)
	}
	if info.StatusUnverified {
		t.Error("expected StatusUnverified=false when JSON parsed successfully")
	}
}

// TestCloudInitCollector_Collect_NonZeroExitDiscardsJSON pins CURRENT (buggy)
// behavior, not the intended one — see PRODUCTION BUG note below.
//
// The doc comment on Collect() explicitly says `cloud-init status` exits
// non-zero to *report* state (1=error, 2=degraded) while still printing the
// status JSON to stdout, and that the code parses "regardless of exit code"
// by ignoring the error return (`out, _ := runCmd(...)`). But runCmd (as
// opposed to runCmdOutput) discards stdout entirely on a non-zero exit and
// returns "" — see runCmd in collector.go:115-124, contrasted with
// runCmdOutput at collector.go:131-140 ("KEEPS stdout even when the command
// exits non-zero... Use this when a tool reports problems through its exit
// code"). So ignoring the error here does NOT recover the JSON; `out` is
// already "" by the time Collect() sees it, and the non-zero-exit status
// (status:"error"/"degraded" — precisely the case the doc comment says is
// "the case we most need to flag") silently falls through to
// StatusUnverified instead of being parsed. Likely fix: call runCmdOutput
// instead of runCmd for both cloud-init invocations in Collect()
// (cloudinit_linux.go:51 and :58). Left unfixed per task instructions —
// this test pins the observed behavior as a regression guard, not the
// intended one.
func TestCloudInitCollector_Collect_NonZeroExitDiscardsJSON(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("cloud-init", []string{"status", "--format=json"}, `{
			"status": "error",
			"datasource": "ec2",
			"errors": ["module foo failed"],
			"recoverable_errors": {}
		}`, 1)
		b.PutCmd("cloud-init", []string{"status"}, "", 1)
	})

	c := NewCloudInitCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CloudInitInfo)
	// BUG: this SHOULD be "error" (see doc comment above Collect()), but
	// runCmd discards stdout on non-zero exit, so the JSON never reaches the
	// parser and Status stays empty / StatusUnverified is set instead.
	if info.Status != "" {
		t.Errorf("Status = %q, want empty (current buggy behavior — stdout is discarded on non-zero exit)", info.Status)
	}
	if !info.StatusUnverified {
		t.Error("expected StatusUnverified=true (current buggy behavior masks the real 'error' status as unverified)")
	}
}

// TestCloudInitCollector_Collect_TextFallback exercises the old-CLI fallback:
// --format=json produces no usable output, plain `cloud-init status` succeeds.
func TestCloudInitCollector_Collect_TextFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("cloud-init", []string{"status", "--format=json"}, "", 1)
		b.PutCmd("cloud-init", []string{"status"}, "status: running\n", 0)
	})

	c := NewCloudInitCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CloudInitInfo)
	if info.Status != "running" {
		t.Errorf("Status = %q, want running (text fallback)", info.Status)
	}
	if info.StatusUnverified {
		t.Error("expected StatusUnverified=false when the text fallback parsed a status")
	}
}

// TestCloudInitCollector_Collect_StatusUnverified guards the "status not read"
// terminal branch: neither the JSON nor the text form produced a parseable
// status, so the verdict must say "not verified" rather than stay silent.
func TestCloudInitCollector_Collect_StatusUnverified(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("cloud-init", []string{"status", "--format=json"}, "", 1)
		b.PutCmd("cloud-init", []string{"status"}, "", 1)
	})

	c := NewCloudInitCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CloudInitInfo)
	if !info.StatusUnverified {
		t.Errorf("expected StatusUnverified=true when neither CLI form produced output, got %+v", info)
	}
	if info.Status != "" {
		t.Errorf("expected empty Status, got %q", info.Status)
	}
}

// TestCloudInitCollector_Collect_CmdAbsent guards the not-found path: the
// cloud-init binary is entirely absent (e.g. gate passed via status.json only,
// but the CLI itself got pruned mid-image) — Collect must not panic and must
// fall through to StatusUnverified.
func TestCloudInitCollector_Collect_CmdAbsent(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("cloud-init", []string{"status", "--format=json"})
		b.PutCmdNotFound("cloud-init", []string{"status"})
	})

	c := NewCloudInitCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CloudInitInfo)
	if !info.StatusUnverified {
		t.Errorf("expected StatusUnverified=true when cloud-init binary is absent, got %+v", info)
	}
}
