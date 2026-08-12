//go:build linux

package collectors

import (
	"context"
	"io/fs"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// fakeDirPermissionDeniedSource denies ReadDir on one specific path — the
// Bundle API has no public seam for a ReadDir permission error, distinct from
// "not recorded" (which Replay.ReadDir already surfaces as its own error).
type fakeDirPermissionDeniedSource struct {
	*source.Replay
	deniedDir string
}

func (f fakeDirPermissionDeniedSource) ReadDir(dir string) ([]string, error) {
	if dir == f.deniedDir {
		return nil, &fs.PathError{Op: "open", Path: dir, Err: fs.ErrPermission}
	}
	return f.Replay.ReadDir(dir)
}

func TestInfiniBandCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewInfiniBandCollector()
	if c.Name() != "InfiniBand" {
		t.Errorf("Name() = %q, want InfiniBand", c.Name())
	}
	if c.Timeout() <= 0 {
		t.Errorf("Timeout() = %v, want > 0", c.Timeout())
	}
}

// TestInfiniBandCollector_Collect_NoDevices guards the no-hardware case: an
// empty directory listing leaves info.Ports nil, but Collect still returns a
// non-nil *models.InfiniBandInfo (unlike e.g. NVMe, InfiniBand doesn't gate
// off to nil — verified against the source), and ReadFailed stays false since
// the directory genuinely exists and was read successfully.
func TestInfiniBandCollector_Collect_NoDevices(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/infiniband", nil)
	})
	c := NewInfiniBandCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info, ok := raw.(*models.InfiniBandInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.InfiniBandInfo", raw)
	}
	if len(info.Ports) != 0 {
		t.Errorf("Ports = %+v, want empty", info.Ports)
	}
	if info.ReadFailed {
		t.Error("ReadFailed = true, want false (directory genuinely empty, not unreadable)")
	}
}

// TestInfiniBandCollector_Collect_DirUnreadable covers the false-OK this
// collector previously had no way to detect: /sys/class/infiniband exists but
// can't be read (a restricted/namespaced /sys view), as opposed to genuinely
// not existing. Must set ReadFailed, never silently read as "no IB hardware".
func TestInfiniBandCollector_Collect_DirUnreadable(t *testing.T) {
	b := source.NewBundle()
	prev := SetSource(fakeDirPermissionDeniedSource{
		Replay:    source.NewReplay(b),
		deniedDir: "/sys/class/infiniband",
	})
	t.Cleanup(func() { SetSource(prev) })

	c := NewInfiniBandCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.InfiniBandInfo)
	if !info.ReadFailed {
		t.Error("ReadFailed = false, want true when the directory read is denied")
	}
	if len(info.Ports) != 0 {
		t.Errorf("Ports = %+v, want empty", info.Ports)
	}
}

// TestInfiniBandCollector_Collect_OneDeviceOnePort exercises the full glob ->
// per-device port glob -> readIBPort path end to end.
func TestInfiniBandCollector_Collect_OneDeviceOnePort(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/infiniband", []string{"mlx5_0"})
		b.PutGlob("/sys/class/infiniband/mlx5_0/ports/*", []string{"/sys/class/infiniband/mlx5_0/ports/1"})
		b.PutFile("/sys/class/infiniband/mlx5_0/ports/1/state", []byte("4: ACTIVE\n"))
		b.PutFile("/sys/class/infiniband/mlx5_0/ports/1/rate", []byte("100 Gb/sec (4X EDR)\n"))
	})
	c := NewInfiniBandCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.InfiniBandInfo)
	if len(info.Ports) != 1 {
		t.Fatalf("Ports = %+v, want exactly 1", info.Ports)
	}
	p := info.Ports[0]
	if p.Device != "mlx5_0" || p.Port != 1 {
		t.Errorf("Device/Port = %q/%d, want mlx5_0/1", p.Device, p.Port)
	}
	if p.State != "ACTIVE" {
		t.Errorf("State = %q, want ACTIVE", p.State)
	}
	if p.Width != "4X" || p.Speed != "EDR" {
		t.Errorf("Width/Speed = %q/%q, want 4X/EDR", p.Width, p.Speed)
	}
}

// TestInfiniBandCollector_Collect_MultiplePortsAndDevices guards that ports
// from multiple HCA devices are all flattened into info.Ports.
func TestInfiniBandCollector_Collect_MultiplePortsAndDevices(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/infiniband", []string{"mlx5_0", "rxe0"})
		b.PutGlob("/sys/class/infiniband/mlx5_0/ports/*", []string{
			"/sys/class/infiniband/mlx5_0/ports/1",
			"/sys/class/infiniband/mlx5_0/ports/2",
		})
		b.PutFile("/sys/class/infiniband/mlx5_0/ports/1/state", []byte("4: ACTIVE\n"))
		b.PutFile("/sys/class/infiniband/mlx5_0/ports/1/rate", []byte("100 Gb/sec (4X EDR)\n"))
		b.PutFile("/sys/class/infiniband/mlx5_0/ports/2/state", []byte("1: DOWN\n"))
		b.PutFile("/sys/class/infiniband/mlx5_0/ports/2/rate", []byte("40 Gb/sec (4X QDR)\n"))
		b.PutGlob("/sys/class/infiniband/rxe0/ports/*", []string{"/sys/class/infiniband/rxe0/ports/1"})
		b.PutFile("/sys/class/infiniband/rxe0/ports/1/state", []byte("4: ACTIVE\n"))
		b.PutFile("/sys/class/infiniband/rxe0/ports/1/rate", []byte("10 Gb/sec\n"))
	})
	c := NewInfiniBandCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.InfiniBandInfo)
	if len(info.Ports) != 3 {
		t.Fatalf("Ports = %+v, want exactly 3", info.Ports)
	}
	// rxe0's rate has no parenthesized width/speed — must be left as the raw string.
	var rxePort *models.IBPort
	for i := range info.Ports {
		if info.Ports[i].Device == "rxe0" {
			rxePort = &info.Ports[i]
		}
	}
	if rxePort == nil {
		t.Fatal("expected an rxe0 port in the results")
	}
	if rxePort.Speed != "10 Gb/sec" || rxePort.Width != "" {
		t.Errorf("rxe0 port Speed/Width = %q/%q, want raw rate string / empty width", rxePort.Speed, rxePort.Width)
	}
}

func TestIsInfiniBandPresent(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/sys/class/infiniband", []string{"mlx5_0"})
		})
		if !IsInfiniBandPresent() {
			t.Error("IsInfiniBandPresent() = false, want true")
		}
	})
	t.Run("absent", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/sys/class/infiniband", nil)
		})
		if IsInfiniBandPresent() {
			t.Error("IsInfiniBandPresent() = true, want false")
		}
	})
	// A directory that exists but can't be read (restricted /sys view) must
	// keep the collector in the run rather than silently reading as absent —
	// see TestInfiniBandCollector_Collect_DirUnreadable for the Collect() side.
	t.Run("unreadable", func(t *testing.T) {
		b := source.NewBundle()
		prev := SetSource(fakeDirPermissionDeniedSource{
			Replay:    source.NewReplay(b),
			deniedDir: "/sys/class/infiniband",
		})
		t.Cleanup(func() { SetSource(prev) })
		if !IsInfiniBandPresent() {
			t.Error("IsInfiniBandPresent() = false, want true when the directory read is denied (ambiguous, not confirmed absent)")
		}
	})
}

// TestReadIBPort_StateWithoutColon guards the fallback: a state string with
// no ": " separator is left as-is (only the recognized "N: STATE" form is
// stripped down to STATE).
func TestReadIBPort_StateWithoutColon(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/infiniband/mlx5_0/ports/1/state", []byte("ACTIVE\n"))
		b.PutFile("/sys/class/infiniband/mlx5_0/ports/1/rate", []byte("\n"))
	})
	port := readIBPort("mlx5_0", "/sys/class/infiniband/mlx5_0/ports/1")
	if port.State != "ACTIVE" {
		t.Errorf("State = %q, want ACTIVE (no colon form left as-is)", port.State)
	}
	if port.Speed != "" {
		t.Errorf("Speed = %q, want empty", port.Speed)
	}
}

// TestReadIBPort_RateSingleFieldInParens guards the width/speed extraction
// bailing out gracefully when the parenthesized content has fewer than two
// fields (the "len(parts) >= 2" guard in readIBPort).
func TestReadIBPort_RateSingleFieldInParens(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/infiniband/mlx5_0/ports/1/state", []byte("4: ACTIVE\n"))
		b.PutFile("/sys/class/infiniband/mlx5_0/ports/1/rate", []byte("100 Gb/sec (EDR)\n"))
	})
	port := readIBPort("mlx5_0", "/sys/class/infiniband/mlx5_0/ports/1")
	// Only one field inside the parens -> Width/Speed left at their pre-parse
	// values (Speed keeps the full raw "100 Gb/sec (EDR)" string).
	if port.Width != "" {
		t.Errorf("Width = %q, want empty (single-field parens must not populate it)", port.Width)
	}
	if port.Speed != "100 Gb/sec (EDR)" {
		t.Errorf("Speed = %q, want raw unparsed rate string", port.Speed)
	}
}
