package source

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzFromSnapshot fuzzes FromSnapshot(path) — the hw-snapshot.sh tarball ingest
// that `dsd replay` falls back to when LoadTarball rejects a file as not a
// native raw-v1 bundle (cmd/replay.go's loadBundle). It is bounded
// (maxSnapshotIngestBytes 256MiB in memory, entry-count and per-entry caps) but,
// unlike the LoadTarball path it backstops, was not fuzzed. Property: never
// panics and always terminates within its caps on an attacker-controlled
// tarball. Reuses tarballOf/gzipBytes/tarEntry from fuzz_untrusted_test.go
// (same package).
func FuzzFromSnapshot(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not gzip"))
	f.Add(gzipBytes([]byte("gzip but not a tar archive")))
	f.Add(tarballOf(tarEntry{name: "os-release.txt", body: "ID=fuzz\n"}))
	f.Add(tarballOf(tarEntry{name: "dump.txt", body: "===== /proc/cmdline =====\nquiet splash\n"}))
	f.Add(tarballOf(tarEntry{name: "plain.txt", body: "no section header, just text"}))
	f.Add(tarballOf(tarEntry{name: "cmd.err", body: "non-txt entry is skipped"}))
	f.Add(tarballOf(tarEntry{name: "proc-cpuinfo.txt", body: "processor\t: 0\n"}))
	{
		many := make([]tarEntry, 0, 300)
		for i := range 300 {
			many = append(many, tarEntry{name: filepath.Join("many", string(rune('a'+i%26))+".txt"), body: "x"})
		}
		f.Add(tarballOf(many...))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		src := filepath.Join(t.TempDir(), "snap.tar.gz")
		if err := os.WriteFile(src, data, 0o600); err != nil {
			t.Fatalf("writing snapshot tarball: %v", err)
		}
		_, _ = FromSnapshot(src) // success or error both fine; must not panic or exceed caps
	})
}
