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

// TestCloudInitCollector_Collect_NonZeroExitStillParsesJSON verifies that a
// non-zero exit from `cloud-init status` (1=error, 2=degraded) does not
// discard the status JSON it still prints to stdout. Regression test for a
// bug where Collect() used runCmd (which discards stdout on non-zero exit)
// instead of runCmdOutput (which preserves it) — see runCmdOutput's doc
// comment in collector.go for the general pattern. Before the fix, this case
// (the exact "instance failed to configure" scenario the doc comment on
// Collect() says is "the case we most need to flag") silently fell through
// to StatusUnverified instead of surfacing status:"error".
func TestCloudInitCollector_Collect_NonZeroExitStillParsesJSON(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("cloud-init", []string{"status", "--format=json"}, `{
			"status": "error",
			"datasource": "ec2",
			"errors": ["module foo failed"],
			"recoverable_errors": {}
		}`, 1)
	})

	c := NewCloudInitCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.CloudInitInfo)
	if info.Status != "error" {
		t.Errorf("Status = %q, want error", info.Status)
	}
	if info.StatusUnverified {
		t.Error("expected StatusUnverified=false when the non-zero-exit JSON parsed successfully")
	}
	if len(info.Errors) != 1 || info.Errors[0] != "module foo failed" {
		t.Errorf("Errors = %v, want [module foo failed]", info.Errors)
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
