//go:build linux

package collectors

import (
	"testing"
)

// Captured from /proc/pressure/memory on a loaded system
const psiMemoryLoaded = `some avg10=5.21 avg60=3.14 avg300=1.02 total=12345678
full avg10=2.10 avg60=1.05 avg300=0.34 total=5678901
`

const psiMemoryCritical = `some avg10=45.00 avg60=32.00 avg300=15.00 total=99999999
full avg10=22.00 avg60=18.00 avg300=8.00 total=44444444
`

const psiMemoryIdle = `some avg10=0.00 avg60=0.00 avg300=0.00 total=0
full avg10=0.00 avg60=0.00 avg300=0.00 total=0
`

func TestReadPSIFile(t *testing.T) {
	t.Run("loaded system parses correctly", func(t *testing.T) {
		lines, err := readPSIString(psiMemoryLoaded)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(lines) != 2 {
			t.Fatalf("lines = %d, want 2", len(lines))
		}
		if lines[0].Avg10 != 5.21 {
			t.Errorf("some.avg10 = %f, want 5.21", lines[0].Avg10)
		}
		if lines[0].Avg60 != 3.14 {
			t.Errorf("some.avg60 = %f, want 3.14", lines[0].Avg60)
		}
		if lines[1].Avg10 != 2.10 {
			t.Errorf("full.avg10 = %f, want 2.10", lines[1].Avg10)
		}
	})

	t.Run("idle system returns zeros", func(t *testing.T) {
		lines, err := readPSIString(psiMemoryIdle)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, l := range lines {
			if l.Avg10 != 0 || l.Avg60 != 0 || l.Avg300 != 0 {
				t.Errorf("expected all zeros, got %+v", l)
			}
		}
	})

	t.Run("critical memory pressure detected", func(t *testing.T) {
		lines, err := readPSIString(psiMemoryCritical)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if lines[1].Avg60 < 10 {
			t.Errorf("full.avg60 = %f, want >= 10 (critical threshold)", lines[1].Avg60)
		}
	})
}
