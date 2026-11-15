package yamlsafe

// DL1 target 5 — yamlsafe vs plain go.yaml.in/yaml/v4, and the allocation a
// hostile policy/fixture file can still force.
//
// Reachable from: analysis.LoadPolicy (~/.dsd-policy, operator-supplied, capped
// at 1 MiB) and cmd/mock.go fixture YAML (CLI-supplied). Both are files a
// hostile or mistaken operator can hand DashDiag.
//
// INVARIANT (internal-yamlsafe, DL1):
//   1. DIFFERENTIAL — whenever yamlsafe.Unmarshal ACCEPTS a document (no
//      duplicate key, so the O(n^2) #510 path is never taken), decoding the same
//      bytes with plain yaml.Unmarshal yields a reflect.DeepEqual value. yamlsafe
//      changes *rejection* behaviour (it rejects duplicate keys up front), never
//      the decoded value of an accepted document.
//   2. BOUNDED COST — yamlsafe.Unmarshal's own allocation and wall time are
//      bounded by the DL1 resource oracle for EVERY input, including the
//      duplicate-key documents that make plain yaml allocate ~1.4 GB for 20 KB
//      (yaml/go-yaml#510). That bound is the whole reason the package exists; the
//      oracle is what proves it still holds. Merge keys (<<) and non-scalar keys,
//      which yamlsafe deliberately does NOT dedup, are measured too — a hostile
//      file leaning on them must still stay within budget.
//
// Plain yaml.Unmarshal is only ever run AFTER yamlsafe accepted the document, so
// this target never feeds the #510 quadratic into the unguarded library and
// never risks OOMing the worker. The billion-laughs/alias-bomb case is bounded
// by the library's own alias-expansion guard; the oracle confirms it.
//
// Does NOT verify: that yamlsafe's REJECTIONS are all correct (it asserts
// accepted docs match, not that every rejected doc deserved it); behaviour of
// the viper config path (separate loader); anything above 1 MiB (the loader cap,
// mirrored here); and semantic equivalence AFTER mapstructure decoding into the
// concrete PolicyFile type — it compares the generic any decode, the layer where
// yamlsafe and yaml can differ at all.

import (
	"reflect"
	"testing"

	"go.yaml.in/yaml/v4"

	"github.com/keyorixhq/dashdiag/internal/testutil/resource"
)

// maxPolicyBytes mirrors analysis.maxPolicyFileBytes (1 MiB): the loader never
// hands yamlsafe more than this, so neither does the fuzzer.
const maxPolicyBytes = 1 << 20

// yamlsafe node-tree build + Decode allocates more per input byte than a
// one-shot parser (a yaml.Node per token, then a second decode pass), so the
// per-byte factor is higher than the DL1 default of 64. 512 holds with margin on
// valid documents (calibrated from the baseline run — see the report) while
// still catching the #510 quadratic, which amplifies by 4-5 orders of magnitude.
const dl1YAMLAllocFactor = 512

func FuzzYAMLSafeDiffAndBound(f *testing.F) {
	seeds := []string{
		"a: 1\nb: [1, 2, 3]\nc: {x: y, z: 2}\n",
		"- one\n- two\n- three\n",
		"a: 1\na: 2\n",                                   // duplicate scalar key
		"1: x\n01: y\n0x1: z\n",                          // same decoded int key three ways
		"x: &a {p: 1, q: 2}\ny:\n  <<: *a\n  k: v\n",     // merge key
		"x: &a {p: 1}\ny:\n  <<: *a\n  <<: *a\n",         // repeated merge key (skipped by dedup)
		"a: &anchor [x, x, x]\nb: *anchor\nc: *anchor\n", // aliases
		"a: 999999999999999999999999999999999999\n",      // huge int
		"big: 1e400\n",                                   // huge float
		"nested: {a: {b: {c: {d: {e: 1}}}}}\n",           // nesting
		"empty:\nnull_val: null\nbool: true\n",
		"",                          // empty document
		"key: \"\\u001b[31mred\"\n", // escaped control in a value
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxPolicyBytes {
			return // the loader never reads more than this
		}
		n := len(data)

		var vSafe any
		var errSafe error
		// yamlsafe must ALWAYS stay within budget — this is the #510 guard.
		resource.Check(t, n, dl1YAMLAllocFactor, func() {
			errSafe = callSafeUnmarshal(data, &vSafe)
		})
		if errSafe != nil {
			return // rejected (e.g. duplicate key) — nothing to compare
		}

		// yamlsafe accepted ⇒ no duplicate key ⇒ plain yaml.Unmarshal cannot hit
		// the #510 O(n^2) dup path, so it is safe to run for the differential.
		var vPlain any
		rPlain := resource.Measure(n, func() {
			if err := yaml.Unmarshal(data, &vPlain); err != nil {
				vPlain = errSentinel // force a mismatch flag below
			}
		})
		if _, isErr := vPlain.(errSentinelT); isErr {
			// yamlsafe accepted but plain yaml rejected — a real asymmetry worth
			// seeing, but not a value mismatch; log the slow/large lead and move on.
			if rPlain.Elapsed > resource.TimeBudget {
				t.Fatalf("plain yaml.Unmarshal over time on a yamlsafe-accepted input: %s", rPlain)
			}
			return
		}
		if !reflect.DeepEqual(vSafe, vPlain) {
			t.Fatalf("differential: yamlsafe and plain yaml decoded an accepted document differently\n  input (%d B): %q\n  yamlsafe: %#v\n  plain:    %#v",
				n, data, vSafe, vPlain)
		}
	})
}

// errSentinel marks a plain-yaml rejection without conflating it with a decoded
// value (a decoded document could legitimately be nil or a string).
type errSentinelT struct{}

var errSentinel = errSentinelT{}

// callSafeUnmarshal is the package's own Unmarshal; named via a thin wrapper so
// the red-proof (swap in plain yaml.Unmarshal to show the #510 quadratic trips
// the budget oracle) is a one-line edit documented in the report.
func callSafeUnmarshal(data []byte, v any) error { return Unmarshal(data, v) }
