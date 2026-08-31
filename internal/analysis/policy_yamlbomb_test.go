package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestLoadPolicy_YAMLAnchorExpansionBounded started as a probe (does
// LoadPolicy bound a "billion laughs"-style YAML anchor/alias expansion, or
// does the decoded node graph grow unbounded from a source file tiny enough
// to sail under the existing 1 MiB maxPolicyFileBytes cap, which only
// bounds bytes READ, not what the decoder expands them into) and stays on
// as a regression guard for the finding: LoadPolicy is safe today, but only
// because PolicyFile is a flat struct of named scalar fields and
// gopkg.in/yaml.v3 discards unrecognized keys (the bomb's anchors) without
// walking their aliased content. That safety is a property of PolicyFile's
// shape, not something LoadPolicy enforces directly — a future PolicyFile
// field typed map[string]any or []any would silently reopen this exact
// vector. This test is what would catch that.
func TestLoadPolicy_YAMLAnchorExpansionBounded(t *testing.T) {
	const refsPerLevel = 15
	const levels = 12 // 15^12 ~= 1.3e14 leaf refs if fully expanded — classic "billion laughs" magnitude

	var b strings.Builder
	b.WriteString("a0: &a0 [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n")
	prev := "a0"
	for i := 1; i < levels; i++ {
		name := fmt.Sprintf("a%d", i)
		b.WriteString(name + ": &" + name + " [")
		for j := 0; j < refsPerLevel; j++ {
			if j > 0 {
				b.WriteString(",")
			}
			b.WriteString("*" + prev)
		}
		b.WriteString("]\n")
		prev = name
	}
	payload := b.String()
	t.Logf("payload size: %d bytes (well under the 1 MiB file-size cap)", len(payload))

	dir := t.TempDir()
	path := filepath.Join(dir, "bomb.yaml")
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}

	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	start := time.Now()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = LoadPolicy(path) // result irrelevant — timing/memory is the point
	}()

	select {
	case <-done:
		runtime.ReadMemStats(&m1)
		elapsed := time.Since(start)
		heapMB := int64(m1.HeapAlloc-m0.HeapAlloc) / 1024 / 1024
		t.Logf("LoadPolicy returned in %v, heap delta ~%d MB", elapsed, heapMB)
		if elapsed > 2*time.Second || heapMB > 200 {
			t.Errorf("LoadPolicy took %v and ~%dMB heap for a %d-byte YAML file with "+
				"nested anchors — unbounded expansion, not rejected", elapsed, heapMB, len(payload))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("LoadPolicy did not return within 15s for a sub-1KB YAML file — unbounded anchor expansion (or worse)")
	}
}
