//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestEntropyCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewEntropyCollector()
	if c.Name() != "Entropy" {
		t.Errorf("Name() = %q, want Entropy", c.Name())
	}
	if c.Timeout() != 1e9 { // 1 * time.Second, avoid importing time just for this
		t.Errorf("Timeout() = %v, want 1s", c.Timeout())
	}
}

// TestEntropyCollector_Collect_Success guards the happy path: entropy_avail
// and poolsize are both read and parsed into the model.
func TestEntropyCollector_Collect_Success(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/kernel/random/entropy_avail", []byte("3821\n"))
		b.PutFile("/proc/sys/kernel/random/poolsize", []byte("4096\n"))
	})
	c := NewEntropyCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := res.(*models.EntropyInfo)
	if !ok || info == nil {
		t.Fatalf("expected *models.EntropyInfo, got %T", res)
	}
	if !info.Available {
		t.Error("Available should be true")
	}
	if info.EntropyBits != 3821 {
		t.Errorf("EntropyBits = %d, want 3821", info.EntropyBits)
	}
	if info.PoolSize != 4096 {
		t.Errorf("PoolSize = %d, want 4096", info.PoolSize)
	}
}

// TestEntropyCollector_Collect_EntropyAvailMissing guards the error path: when
// entropy_avail can't be read at all, Collect must return an error (not a
// zero-value model masquerading as a real reading).
func TestEntropyCollector_Collect_EntropyAvailMissing(t *testing.T) {
	withFixtureSource(t, func(_ *source.Bundle) {}) // nothing seeded
	c := NewEntropyCollector()
	res, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("expected an error when entropy_avail is unreadable")
	}
	if res != nil {
		t.Errorf("expected nil result on error, got %v", res)
	}
}

// TestEntropyCollector_Collect_PoolSizeMissing guards the partial-failure
// path: entropy_avail readable but poolsize missing must still succeed, with
// PoolSize left at zero (readProcInt error is deliberately ignored for
// poolsize per the production code).
func TestEntropyCollector_Collect_PoolSizeMissing(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/kernel/random/entropy_avail", []byte("100\n"))
	})
	c := NewEntropyCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.EntropyInfo)
	if info.EntropyBits != 100 {
		t.Errorf("EntropyBits = %d, want 100", info.EntropyBits)
	}
	if info.PoolSize != 0 {
		t.Errorf("PoolSize = %d, want 0 (unreadable, ignored)", info.PoolSize)
	}
}

// TestReadProcInt guards the parser directly: valid int, whitespace trimming,
// and a non-numeric value producing an error.
func TestReadProcInt(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/kernel/random/entropy_avail", []byte("  256  \n"))
		b.PutFile("/proc/sys/vm/bogus", []byte("not-a-number\n"))
	})
	v, err := readProcInt("/proc/sys/kernel/random/entropy_avail")
	if err != nil || v != 256 {
		t.Errorf("readProcInt = (%d,%v), want (256,nil)", v, err)
	}
	if _, err := readProcInt("/proc/sys/vm/bogus"); err == nil {
		t.Error("expected a parse error for a non-numeric value")
	}
	if _, err := readProcInt("/proc/sys/vm/does-not-exist"); err == nil {
		t.Error("expected an error for a missing file")
	}
}
