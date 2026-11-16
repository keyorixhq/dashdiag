package resource

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBudgetMath(t *testing.T) {
	if got, want := Budget(100, 64), uint64(64*100+AllocFloor); got != want {
		t.Fatalf("Budget(100,64) = %d, want %d", got, want)
	}
	if got, want := Budget(0, 64), uint64(AllocFloor); got != want {
		t.Fatalf("Budget(0,64) = %d, want %d (floor)", got, want)
	}
}

func TestMeasureSeesAllocation(t *testing.T) {
	// A 2 MiB allocation must show up in AllocBytes (well above the ~KB of
	// measurement noise), and InputLen/amplification must be populated.
	r := Measure(1<<10, func() {
		b := make([]byte, 2<<20)
		for i := range b {
			b[i] = byte(i) // touch it so the compiler can't elide the alloc
		}
		sink = b
	})
	if r.AllocBytes < 2<<20 {
		t.Fatalf("Measure missed a 2 MiB allocation: got %d B", r.AllocBytes)
	}
	if r.InputLen != 1<<10 || r.Amplification < 2000 {
		t.Fatalf("Measure populated wrong fields: %s", r)
	}
}

var sink []byte

func TestCheckPassesUnderBudget(t *testing.T) {
	// A call that allocates well under the floor must not fail.
	r := Check(t, 10, 64, func() { sink = make([]byte, 1024) })
	if r.AllocBytes == 0 {
		t.Fatalf("Check returned a zero-alloc report for a 1 KiB allocation")
	}
}

func TestFingerprintDetectsEveryChange(t *testing.T) {
	dir := t.TempDir()
	base := Fingerprint(t, dir)

	// Unchanged tree → identical fingerprint.
	if again := Fingerprint(t, dir); again != base {
		t.Fatalf("Fingerprint not stable on an unchanged tree:\n %s\n %s", base, again)
	}

	// Adding a file changes it.
	f := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(f, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	withFile := Fingerprint(t, dir)
	if withFile == base {
		t.Fatal("Fingerprint did not change when a file was added")
	}

	// Rewriting the content (same size) changes it (content is hashed).
	if err := os.WriteFile(f, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rewritten := Fingerprint(t, dir); rewritten == withFile {
		t.Fatal("Fingerprint did not change on a same-size content rewrite")
	}

	// AssertUnchanged must fail-path cleanly: it passes when nothing changed.
	stable := Fingerprint(t, dir)
	AssertUnchanged(t, dir, stable) // no change since `stable` → must not fail
}
