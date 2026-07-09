//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestRancherCollectorIdentity guards the Collector interface wiring — no
// fixture dependency, safe to parallelize.
func TestRancherCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewRancherCollector()
	if c.Name() != "Rancher" {
		t.Errorf("Name() = %q, want Rancher", c.Name())
	}
	if c.Timeout() != 12*time.Second {
		t.Errorf("Timeout() = %v, want 12s", c.Timeout())
	}
}

// TestRancherAvailable pins RancherAvailable == K8sAvailable (kubectl gate).
func TestRancherAvailable(t *testing.T) {
	t.Run("kubectl present", func(t *testing.T) {
		withLookPathFixture(t, map[string]bool{"kubectl": true}, func(b *source.Bundle) {})
		if !RancherAvailable() {
			t.Error("expected true when kubectl is present")
		}
	})

	t.Run("no k8s binaries anywhere", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		if RancherAvailable() {
			t.Error("expected false when no k8s binary is found")
		}
	})
}

// TestRancherCollector_Collect_NoKubectl guards the early-return gate: no
// usable kubectl binary means Collect returns an empty RancherInfo without
// attempting any cluster query.
func TestRancherCollector_Collect_NoKubectl(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})

	c := NewRancherCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.RancherInfo)
	if info.Available {
		t.Errorf("expected Available=false with no kubectl, got %+v", info)
	}
}

// TestRancherCollector_Collect_NamespaceAbsent guards the "cattle-system not
// found" silent path: kubectl works but Rancher is not installed on this
// cluster — Available must stay false, not error.
func TestRancherCollector_Collect_NamespaceAbsent(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{"lookpath/kubectl": []byte("/usr/bin/kubectl")}, nil, func(b *source.Bundle) {
		b.PutCmd("kubectl", []string{"get", "namespace", "cattle-system", "-o", "name"}, "", 1)
	})

	c := NewRancherCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.RancherInfo)
	if info.Available {
		t.Errorf("expected Available=false when cattle-system namespace is absent, got %+v", info)
	}
}

// TestRancherCollector_Collect_HappyPath exercises the full path: cattle-system
// present, both deployments queried and parsed.
func TestRancherCollector_Collect_HappyPath(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{"lookpath/kubectl": []byte("/usr/bin/kubectl")}, nil, func(b *source.Bundle) {
		b.PutCmd("kubectl", []string{"get", "namespace", "cattle-system", "-o", "name"},
			"namespace/cattle-system\n", 0)
		b.PutCmd("kubectl", []string{"get", "deploy", "rancher", "-n", "cattle-system", "--no-headers"},
			"rancher   3/3     3            3           10d\n", 0)
		b.PutCmd("kubectl", []string{"get", "deploy", "rancher-webhook", "-n", "cattle-system", "--no-headers"},
			"rancher-webhook   1/1     1            1           10d\n", 0)
	})

	c := NewRancherCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.RancherInfo)
	if !info.Available {
		t.Fatalf("expected Available=true, got %+v", info)
	}
	if info.ServerReady != 3 || info.ServerDesired != 3 {
		t.Errorf("ServerReady/Desired = %d/%d, want 3/3", info.ServerReady, info.ServerDesired)
	}
	if info.WebhookReady != 1 || info.WebhookDesired != 1 {
		t.Errorf("WebhookReady/Desired = %d/%d, want 1/1", info.WebhookReady, info.WebhookDesired)
	}
}

// TestRancherCollector_Collect_DeploysUnreadable guards the deployment-query
// failure path (server present, webhook query fails): must degrade to 0/0, not
// error out or leave the collector call chain incomplete.
func TestRancherCollector_Collect_DeploysUnreadable(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{"lookpath/kubectl": []byte("/usr/bin/kubectl")}, nil, func(b *source.Bundle) {
		b.PutCmd("kubectl", []string{"get", "namespace", "cattle-system", "-o", "name"},
			"namespace/cattle-system\n", 0)
		b.PutCmd("kubectl", []string{"get", "deploy", "rancher", "-n", "cattle-system", "--no-headers"},
			"", 1)
		b.PutCmd("kubectl", []string{"get", "deploy", "rancher-webhook", "-n", "cattle-system", "--no-headers"},
			"", 1)
	})

	c := NewRancherCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.RancherInfo)
	if !info.Available {
		t.Fatal("expected Available=true (namespace is present)")
	}
	if info.ServerReady != 0 || info.ServerDesired != 0 || info.WebhookReady != 0 || info.WebhookDesired != 0 {
		t.Errorf("expected all-zero ready/desired on query failure, got %+v", info)
	}
}
