//go:build linux

package cvedata

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestLoadOVAL_DeeplyNestedCriteriaRejected started as a probe and stays on
// as a regression guard for the finding: ovalCriteria is a genuinely
// recursive struct (Criteria []ovalCriteria `xml:"criteria"`), and
// collectMatches recurses over it too (oval.go:231). Unlike the YAML anchor
// case (--policy, proven safe: unknown keys are cheaply discarded by the
// struct-shaped unmarshal target), XML has no entity/alias expansion in
// Go's stdlib decoder, so there's no exponential-blowup vector here — but a
// maliciously DEEP (not large) document, well under the existing 512MiB
// maxDecompressedFeedBytes cap, could still exhaust the goroutine stack in
// either the XML decoder's own recursive descent or collectMatches's
// recursion. Stack overflow in Go is an unrecoverable, unpanicking process
// crash, which is what this test would have needed to catch. It turns out
// Go's encoding/xml decoder has its own built-in max-depth limit — this is
// stdlib protection dsd inherits for free, not anything dsd added, and this
// test is what would catch that stdlib behavior ever changing out from
// under loadOVAL.
func TestLoadOVAL_DeeplyNestedCriteriaRejected(t *testing.T) {
	const depth = 50000 // ~20 bytes/level => ~1MB source, nowhere near the 512MiB cap

	var b strings.Builder
	b.WriteString(`<oval_definitions><definitions><definition id="d1" class="vulnerability"><metadata><title>t</title></metadata>`)
	for i := 0; i < depth; i++ {
		b.WriteString("<criteria>")
	}
	b.WriteString(`<criterion test_ref="t1" comment="x is installed"/>`)
	for i := 0; i < depth; i++ {
		b.WriteString("</criteria>")
	}
	b.WriteString(`</definition></definitions><tests><rpminfo_test id="t1"><object object_ref="o1"/><state state_ref="s1"/></rpminfo_test></tests>`)
	b.WriteString(`<objects><rpminfo_object id="o1"><name>x</name></rpminfo_object></objects>`)
	b.WriteString(`<states><rpminfo_state id="s1"><evr operation="less than">1.0</evr></rpminfo_state></states></oval_definitions>`)
	payload := b.String()
	t.Logf("payload size: %d bytes, nesting depth: %d (well under the 512MiB decompressed-size cap)", len(payload), depth)

	dir := t.TempDir()
	path := filepath.Join(dir, "deep.xml")
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}

	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	start := time.Now()

	done := make(chan struct{})
	var gotErr error
	go func() {
		defer close(done)
		_, gotErr = loadOVAL(path)
	}()

	select {
	case <-done:
		runtime.ReadMemStats(&m1)
		elapsed := time.Since(start)
		heapMB := int64(m1.HeapAlloc-m0.HeapAlloc) / 1024 / 1024
		t.Logf("loadOVAL returned in %v, heap delta ~%dMB, err=%v", elapsed, heapMB, gotErr)
		if elapsed > 5*time.Second {
			t.Errorf("loadOVAL took %v for a %d-deep, %d-byte document — unbounded, not rejected", elapsed, depth, len(payload))
		}
		if gotErr == nil {
			t.Fatal("loadOVAL accepted a 50,000-level-deep <criteria> document — expected a depth-limit rejection")
		}
		if !strings.Contains(gotErr.Error(), "depth") {
			t.Errorf("loadOVAL rejected the document (good) but the error %q doesn't mention depth — "+
				"confirm this is still the depth-limit rejection and not some other failure mode", gotErr.Error())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("loadOVAL did not return within 20s for a bounded-size deeply-nested document — possible stack-depth hang, the exact risk this test exists to catch")
	}
}
