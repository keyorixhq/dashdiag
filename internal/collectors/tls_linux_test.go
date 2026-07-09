//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestTLSCollectorIdentity guards the static Name/Timeout contract — pure, no
// fixture dependency, safe to run in parallel.
func TestTLSCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewTLSCollector()
	if c.Name() != "TLS" {
		t.Errorf("Name() = %q, want TLS", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

// TestTLSCollector_Collect_NoCertPathsPresent guards the all-absent case: none
// of the hardcoded cert directories are seeded, so readDirEntries fails for
// every path and Collect must return a clean, empty TLSInfo rather than error.
func TestTLSCollector_Collect_NoCertPathsPresent(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {})
	c := NewTLSCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.TLSInfo)
	if len(info.Certs) != 0 || len(info.Uncheckable) != 0 || info.Expired != 0 || info.Expiring != 0 {
		t.Errorf("expected an empty TLSInfo when no cert paths exist, got %+v", info)
	}
}

// TestTLSCollector_Collect_HappyPath exercises the full walk-and-classify
// path: a valid long-lived cert in one of the hardcoded dirs is found, an
// expiring cert (<=30 days) increments Expiring, an already-expired cert
// increments Expired, a non-cert extension is skipped, and a garbled cert
// file lands in Uncheckable rather than being silently dropped.
func TestTLSCollector_Collect_HappyPath(t *testing.T) {
	now := time.Now()
	validPEM := makeTestCertPEM(t, now.Add(-24*time.Hour), now.Add(100*24*time.Hour))
	expiringPEM := makeTestCertPEM(t, now.Add(-24*time.Hour), now.Add(10*24*time.Hour))
	expiredPEM := makeTestCertPEM(t, now.Add(-100*24*time.Hour), now.Add(-1*time.Hour))

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/etc/ssl/private", []string{"valid.crt", "notes.key", "garbled.pem"})
		b.PutFile("/etc/ssl/private/valid.crt", validPEM)
		b.PutFile("/etc/ssl/private/notes.key", []byte("not a cert, must be skipped by extension filter"))
		b.PutFile("/etc/ssl/private/garbled.pem", []byte("-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n"))

		b.PutDir("/etc/letsencrypt/live", []string{"expiring.pem"})
		b.PutFile("/etc/letsencrypt/live/expiring.pem", expiringPEM)

		b.PutDir("/etc/nginx/ssl", []string{"expired.crt"})
		b.PutFile("/etc/nginx/ssl/expired.crt", expiredPEM)

		// Remaining hardcoded paths left unseeded — must be skipped cleanly.
	})

	c := NewTLSCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.TLSInfo)

	if len(info.Certs) != 3 {
		t.Fatalf("expected 3 parsed certs (valid, expiring, expired), got %d: %+v", len(info.Certs), info.Certs)
	}
	if len(info.Uncheckable) != 1 || info.Uncheckable[0].Path != "/etc/ssl/private/garbled.pem" {
		t.Errorf("expected the garbled cert to be Uncheckable, got %+v", info.Uncheckable)
	}
	if info.Expiring != 1 {
		t.Errorf("expected Expiring=1, got %d", info.Expiring)
	}
	if info.Expired != 1 {
		t.Errorf("expected Expired=1, got %d", info.Expired)
	}
}

// TestTLSCollector_Collect_RecursesNestedDirs guards that Collect's walk
// (via walkCertDir) actually recurses into subdirectories of a hardcoded cert
// path, not just the top level.
func TestTLSCollector_Collect_RecursesNestedDirs(t *testing.T) {
	now := time.Now()
	pemBytes := makeTestCertPEM(t, now.Add(-24*time.Hour), now.Add(100*24*time.Hour))

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/etc/haproxy", []string{"nested"})
		b.PutDir("/etc/haproxy/nested", []string{"leaf.crt"})
		b.PutFile("/etc/haproxy/nested/leaf.crt", pemBytes)
	})

	c := NewTLSCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.TLSInfo)
	if len(info.Certs) != 1 || info.Certs[0].Path != "/etc/haproxy/nested/leaf.crt" {
		t.Fatalf("expected the nested cert to be found via recursion, got %+v", info.Certs)
	}
}

// TestTLSCollector_Collect_ContextCancelled guards the ctx.Done() early-exit
// inside the per-path scan loop: a cancelled context must return the
// (possibly partial) info without error, never propagate ctx.Err().
func TestTLSCollector_Collect_ContextCancelled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/etc/ssl/private", []string{"valid.crt"})
		b.PutFile("/etc/ssl/private/valid.crt", makeTestCertPEM(t, time.Now().Add(-time.Hour), time.Now().Add(100*24*time.Hour)))
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewTLSCollector()
	raw, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.TLSInfo)
	if info == nil {
		t.Fatal("expected a non-nil TLSInfo even when ctx is already cancelled")
	}
}
