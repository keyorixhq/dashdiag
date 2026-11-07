//go:build taintoverlay

package source

// Input-to-sink taint harness for bundle loading (see internal/fuzzutil/taint).
// `dsd replay <bundle.tar.gz>` extracts an untrusted archive into a temp dir and
// loads its manifest/index. Every name the archive controls carries the marker
// (tar entry names, index paths, blob names), including "../" and absolute
// forms. Contract: all IO stays inside the extraction directory (a temp dir
// under the harness-owned TMPDIR); anything else, and any command/host/query
// flow, is unexpected.
//
// Run: go test -tags taintoverlay -overlay <taintoverlay dir>/overlay.json \
//        -vet=off -run '^$' -fuzz FuzzTaintLoadTarball ./internal/source

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/fuzzutil/taint"
)

func FuzzTaintLoadTarball(f *testing.F) {
	f.Add("a", "b", "c", uint8(0))
	f.Fuzz(func(t *testing.T, entry, idxPath, blob string, mode uint8) {
		taint.RequireOverlay(t.Fatalf)
		taint.Reset()
		taint.ResetRules()
		tmp := t.TempDir()
		t.Setenv("TMPDIR", tmp)
		taint.Allow(taint.Rule{Class: taint.Path, Root: filepath.Join(tmp, "dsd-raw-*"), Why: "extraction dir"})
		defer taint.Check(t.Fatalf)

		mk := taint.PathStr
		if mode%2 == 1 {
			mk = taint.Str
		}
		idx, _ := json.Marshal([]fileIndexEntry{{Path: mk(idxPath), Blob: mk(blob)}})
		man, _ := json.Marshal(Manifest{Format: FormatVersion})
		out := filepath.Join(tmp, "b.tar.gz")
		fh, err := os.Create(out)
		if err != nil {
			t.Skip(err)
		}
		gz := gzip.NewWriter(fh)
		tw := tar.NewWriter(gz)
		for _, e := range []struct {
			name string
			data []byte
		}{{"manifest.json", man}, {"files/index.json", idx}, {mk(entry), []byte("x")}, {mk(blob), []byte("y")}} {
			if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data)), Typeflag: tar.TypeReg}); err != nil {
				continue
			}
			_, _ = tw.Write(e.data)
		}
		_ = tw.Close()
		_ = gz.Close()
		_ = fh.Close()
		_, _ = LoadTarball(out)
	})
}
