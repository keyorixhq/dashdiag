package baseline

import (
	"bytes"
	"compress/zlib"
	"os"
	"path/filepath"
	"testing"
)

// FuzzReadCommitTime fuzzes readCommitTime — the loose-git-object zlib
// decompress + commit-header parse behind the since-deploy baseline. The zlib
// output is bounded (1MiB LimitReader) against a bomb; the parser is
// bytes.IndexByte + field splitting + ParseInt. Lowest-value seam of the ingest
// set (input is a local .git loose object, semi-trusted), included for
// completeness. The harness writes a zlib stream of the fuzz-controlled object
// body at the loose-object path readCommitTime derives from a fixed valid sha.
// Property: never panics; a malformed object is a clean error.
func zlibObject(tb testing.TB, body []byte) []byte {
	tb.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write(body)
	_ = zw.Close()
	return buf.Bytes()
}

func FuzzReadCommitTime(f *testing.F) {
	f.Add([]byte("commit 120\x00tree deadbeef\ncommitter Alice <a@x> 1700000000 +0000\n"))
	f.Add([]byte("commit 0\x00"))
	f.Add([]byte("blob 3\x00abc"))
	f.Add([]byte("no nul byte at all"))
	f.Add([]byte("commit 9\x00committer\n"))
	f.Add([]byte(""))

	const sha = "0123456789abcdef0123456789abcdef01234567"
	f.Fuzz(func(t *testing.T, body []byte) {
		gitDir := t.TempDir()
		objDir := filepath.Join(gitDir, "objects", sha[:2])
		if err := os.MkdirAll(objDir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(objDir, sha[2:]), zlibObject(t, body), 0o600); err != nil {
			t.Fatalf("write object: %v", err)
		}
		_, _ = readCommitTime(gitDir, sha) // success or error both fine; must not panic
	})
}
