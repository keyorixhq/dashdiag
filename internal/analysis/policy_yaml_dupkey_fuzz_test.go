package analysis

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	goyaml "go.yaml.in/yaml/v3"
	"gopkg.in/yaml.v3"
)

// FuzzPolicyYAMLDupKeyDifferential feeds an operator-supplied policy file
// (`dsd health --policy`, cmd.loadPolicyIfSet -> LoadPolicy) through three
// parse paths and checks them against each other:
//
//   - main:     gopkg.in/yaml.v3 into PolicyFile, as LoadPolicy does today
//     (LoadPolicy itself is called on the same bytes and must agree);
//   - migrated: go.yaml.in/yaml/v3 into PolicyFile, the library #1179 moves to;
//   - hardened: the #1179 yamlsafe pre-check (test-local copy, see
//     yamlsafe_copy_test.go) followed by the migrated decode.
//
// Oracles:
//
//  1. Linear-cost claim of the hardening (security): when the yamlsafe
//     pre-check accepts a document, the library's own quadratic duplicate-key
//     scan (decode.go mapping(): one error string per equal-Value key pair)
//     must report at most as many pairs as the document has mapping keys.
//     More pairs than keys means the pre-check let through a shape whose
//     library cost grows with n^2 — the exact cost #1179 exists to remove.
//     Checked both for the PolicyFile target and for an `any` target (the
//     generic yamlsafe contract). Documents with a DS1-F1 key shape
//     (non-scalar, merge, NaN) are skipped for this oracle unless
//     DSD_KNOWN_DEFECTS=1; the fuzzer found the non-scalar one in about a
//     second once a repeated-key form was checked.
//  2. Bounded work: the hardened path allocates at most
//     hardenedAllocBase + hardenedAllocPerByte*len(data) bytes.
//  3. Migration differential: main and migrated agree on accept/reject
//     (after validatePolicy) and, when both accept, on every field.
//  4. Hardening differential: whenever migrated accepts, hardened must accept
//     too and decode the same PolicyFile — except when hardened rejects with
//     its own duplicate-key error (it compares decoded keys, so "1" and "0x1"
//     collide; the library compares raw spellings). That exception is counted
//     as an EXPECTED-DIFFERENCE, not a failure.
//
// Every input is also checked in a structured form: its first line (up to 32
// bytes) used as a flow-mapping key keyRepeats times under deny:, since the
// quadratic shapes need repeated identical spellings.
//
// What it does NOT verify:
//   - Inputs over maxFuzzPolicyBytes; the real cap is 1 MiB, so absolute
//     cost at that size is only covered by
//     TestYamlsafeCopy_QuadraticBypassShapes.
//   - That the duplicate-key error text names the right line.
//   - Semantic policy behaviour after load (ApplyPolicy, the health gate).
//   - The real internal/yamlsafe package: it is a copy pinned to cb9cc021;
//     if the branch changes, this proves nothing about the new body.
//   - Multi-document streams beyond the first document.
func FuzzPolicyYAMLDupKeyDifferential(f *testing.F) {
	for _, s := range []string{
		"",
		"ram_warn_pct: 70\nram_crit_pct: 90\ndisk_warn_pct: 75\ndeny:\n  - WARN\n",
		"ram_warn_pct: 70\nram_warn_pct: 80\n",
		"ram_warn_pct: 70\n'ram_warn_pct': 80\n",
		"deny: [warn, CRIT]\nzombie_warn_count: 3\n",
		"deny:\n  - {a: 1, b: 2}\n",
		"x: &a {k: 1}\ny:\n  <<: *a\n  j: 2\n",
		"1: a\n0x1: b\n",
		"a: 1\na: 1\na: 1\na: 1\na: 1\n",
		"disk_warn_pct: .inf\n",
		"io_await_warn_ms: 1e3\nntp_offset_crit_ms: -0\n",
	} {
		f.Add([]byte(s))
	}
	dir := f.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzPolicyBytes {
			return
		}
		checkPolicyYAMLDupKey(t, data, path)
		// Structured amplification: the quadratic shapes need several keys
		// with the same spelling, which byte mutation rarely produces. Also
		// check the first line used as a key repeated keyRepeats times.
		if k, _, _ := strings.Cut(string(data), "\n"); k != "" && len(k) <= 32 {
			doc := "deny:\n  - {" + strings.Repeat(k+": v, ", keyRepeats) + "}\n"
			checkPolicyYAMLDupKey(t, []byte(doc), path)
		}
	})
}

const (
	keyRepeats           = 6
	maxFuzzPolicyBytes   = 2048
	hardenedAllocBase    = 256 << 10
	hardenedAllocPerByte = 1024
)

func checkPolicyYAMLDupKey(t *testing.T, data []byte, path string) {
	t.Helper()
	keys, parsed := countMappingKeys(data)

	// Oracle 1 + 2: hardened path, PolicyFile target, with allocation cap.
	var hardened PolicyFile
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	hErr := yamlsafeUnmarshal(data, &hardened)
	runtime.ReadMemStats(&after)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > hardenedAllocBase+hardenedAllocPerByte*uint64(len(data)) {
		t.Fatalf("hardened path allocated %d bytes for a %d-byte policy (cap %d)",
			alloc, len(data), hardenedAllocBase+hardenedAllocPerByte*uint64(len(data)))
	}
	// DS1-F1: the three key shapes the pre-check is known to skip are left
	// out of oracle 1 unless DSD_KNOWN_DEFECTS=1, so the search keeps looking
	// for a fourth one. Oracles 2-4 still run on them.
	if parsed && (os.Getenv("DSD_KNOWN_DEFECTS") == "1" || !hasKnownBypassKey(data)) {
		if pairs := libraryDupPairs(hErr); pairs > keys {
			t.Fatalf("yamlsafe pre-check passed but the library then reported %d duplicate-key pairs for %d keys (quadratic path reached): %q",
				pairs, keys, truncate(data))
		}
		var generic any
		if pairs := libraryDupPairs(yamlsafeUnmarshal(data, &generic)); pairs > keys {
			t.Fatalf("yamlsafe pre-check passed but the library reported %d duplicate-key pairs for %d keys decoding into any: %q",
				pairs, keys, truncate(data))
		}
	}

	// Oracle 3: main vs migrated library, both through validatePolicy.
	var mainP, migP PolicyFile
	mErr := yaml.Unmarshal(data, &mainP)
	if mErr == nil {
		mErr = validatePolicy(&mainP)
	}
	gErr := goyaml.Unmarshal(data, &migP)
	if gErr == nil {
		gErr = validatePolicy(&migP)
	}
	if (mErr == nil) != (gErr == nil) {
		t.Fatalf("library migration changes verdict: gopkg.in err=%v, go.yaml.in err=%v, input %q", mErr, gErr, truncate(data))
	}
	if mErr == nil && policyString(&mainP) != policyString(&migP) {
		t.Fatalf("library migration changes decoded policy:\n gopkg.in   %s\n go.yaml.in %s", policyString(&mainP), policyString(&migP))
	}

	// The live caller agrees with the main library path it wraps.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	live, lErr := LoadPolicy(path)
	if (lErr == nil) != (mErr == nil) {
		t.Fatalf("LoadPolicy err=%v but gopkg.in+validatePolicy err=%v", lErr, mErr)
	}
	if lErr == nil && policyString(live) != policyString(&mainP) {
		t.Fatalf("LoadPolicy decoded %s, library path %s", policyString(live), policyString(&mainP))
	}

	// Oracle 4: hardened vs migrated.
	if gErr == nil {
		if hErr == nil {
			hErr = validatePolicy(&hardened)
		}
		switch {
		case hErr == nil:
			if policyString(&hardened) != policyString(&migP) {
				t.Fatalf("yamlsafe decodes a different policy:\n yamlsafe %s\n library  %s", policyString(&hardened), policyString(&migP))
			}
		case isPrecheckDupErr(hErr):
			// EXPECTED-DIFFERENCE: decoded-key equality is stricter than the
			// library's raw-spelling equality.
		default:
			t.Fatalf("library accepts but yamlsafe rejects with a non-duplicate error: %v; input %q", hErr, truncate(data))
		}
	}
}

// countMappingKeys parses data once (the same first-document parse yamlsafe
// does) and counts every mapping key in the tree, following no aliases.
func countMappingKeys(data []byte) (int, bool) {
	var root goyaml.Node
	if err := goyaml.Unmarshal(data, &root); err != nil || root.Kind == 0 {
		return 0, false
	}
	n := 0
	var walk func(*goyaml.Node)
	walk = func(x *goyaml.Node) {
		if x.Kind == goyaml.MappingNode {
			n += len(x.Content) / 2
		}
		for _, c := range x.Content {
			walk(c)
		}
	}
	walk(&root)
	return n, true
}

// hasKnownBypassKey reports whether any mapping key in data has one of the
// DS1-F1 shapes: non-scalar, a merge key, or a scalar that decodes to NaN.
func hasKnownBypassKey(data []byte) bool {
	var root goyaml.Node
	if err := goyaml.Unmarshal(data, &root); err != nil {
		return false
	}
	found := false
	var walk func(*goyaml.Node)
	walk = func(x *goyaml.Node) {
		if found {
			return
		}
		if x.Kind == goyaml.MappingNode {
			for i := 0; i+1 < len(x.Content); i += 2 {
				k := x.Content[i]
				if k.Kind == goyaml.AliasNode && k.Alias != nil {
					k = k.Alias
				}
				if k.Kind != goyaml.ScalarNode || k.Tag == "!!merge" {
					found = true
					return
				}
				var v any
				if k.Decode(&v) == nil {
					if f, ok := v.(float64); ok && math.IsNaN(f) {
						found = true
						return
					}
				}
			}
		}
		for _, c := range x.Content {
			walk(c)
		}
	}
	walk(&root)
	return found
}

// libraryDupPairs counts duplicate-key errors produced by the library's
// decoder (a *TypeError listing one line per pair). The yamlsafe pre-check's
// own error is a single plain error and counts as zero.
func libraryDupPairs(err error) int {
	if err == nil || isPrecheckDupErr(err) {
		return 0
	}
	return strings.Count(err.Error(), "already defined at line")
}

func isPrecheckDupErr(err error) bool {
	s := err.Error()
	return !strings.HasPrefix(s, "yaml: ") && strings.Contains(s, "already defined at line")
}

func policyString(p *PolicyFile) string { return fmt.Sprintf("%#v", *p) }

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}

// TestYamlsafeCopy_QuadraticBypassShapes pins DS1-F1: three key shapes the
// #1179 pre-check skips or cannot compare, but which the library still pairs
// up quadratically. A 36 KB policy file costs ~1.2 GB and ~2 s; the 1 MiB file
// cap allows ~30x more keys, i.e. ~900x the cost. The plain-duplicate control
// shows the pre-check working for the case it targets.
//
// Known defect in the PROPOSED hardening (not on main): skipped unless
// DSD_KNOWN_DEFECTS=1 so it does not break CI before #1179 is fixed.
//
// What it does NOT verify: the exact allocation figure (only a 64 MiB cap),
// or any shape beyond these four.
func TestYamlsafeCopy_QuadraticBypassShapes(t *testing.T) {
	cases := []struct {
		name, item string
		knownBad   bool
	}{
		{"plain duplicate (control)", "k: v, ", false},
		{"NaN keys (NaN != NaN in the seen map)", ".nan: v, ", true},
		{"merge keys (skipped by the pre-check)", "<<: {}, ", true},
		{"non-scalar keys (skipped by the pre-check)", "[]: v, ", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.knownBad && os.Getenv("DSD_KNOWN_DEFECTS") != "1" {
				t.Skip("DS1-F1 known defect in proposed yamlsafe (#1179); set DSD_KNOWN_DEFECTS=1 to run")
			}
			doc := []byte("deny:\n  - {" + strings.Repeat(c.item, 4000) + "}\n")
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			var p PolicyFile
			err := yamlsafeUnmarshal(doc, &p)
			runtime.ReadMemStats(&after)
			if err == nil || !strings.Contains(err.Error(), "already defined") {
				t.Fatalf("want a duplicate-key error, got %v", err)
			}
			if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<20 {
				t.Fatalf("%d keys of %q allocated %d MiB through the hardened path; it must stay linear",
					4000, strings.TrimSuffix(c.item, ", "), alloc>>20)
			}
		})
	}
}
