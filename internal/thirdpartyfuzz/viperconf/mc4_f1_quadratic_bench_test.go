package viperconf

// MC4 F1 bisection bench. Bisects the viper YAML sibling-key quadratic between
// (A) the raw go.yaml.in/yaml/v3 mapping decode viper calls, and (B) viper's
// full ReadConfig (decode + insensitiviseMap key-fold + flatten), with a (C)
// JSON-through-viper linear control. RESULT (go1.27.4, 2 cores, benchtime=1x):
// A and B both scale ~quadratically and track within ~15% (1k→32k: raw
// 5.86ms→5457ms, viper 7.21ms→5314ms, ≈931×/738× over a 32× key increase ≈
// O(n²)); C is linear (1.03ms→34.7ms ≈ 33.7×). CONCLUSION: the quadratic is in
// the go.yaml.in/yaml/v3 mapping decode, NOT viper's insensitivise/flatten
// (whose cost tracks the linear JSON control). See
// .scratch/upstream-drafts/F1-viper-yaml-quadratic.md for the writeup. Run:
//   go test -run=^$ -bench=BenchmarkF1 -benchmem -benchtime=1x ./internal/thirdpartyfuzz/viperconf/
// benchtime=1x gives single-shot numbers (GC/scheduler noise in the per-doubling
// ratios); the overall 1k→32k slope and the A≈B≫C separation are unambiguous.

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/viper"
	yaml "go.yaml.in/yaml/v3"
)

func f1YAMLDoc(n int) []byte {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "k%d: %d\n", i, i)
	}
	return []byte(b.String())
}

var f1Sizes = []int{1000, 2000, 4000, 8000, 16000, 32000}

// A: raw go.yaml.in/yaml/v3 decode into a map (what viper's codec does first).
func BenchmarkF1RawYAMLv3Decode(b *testing.B) {
	for _, n := range f1Sizes {
		doc := f1YAMLDoc(n)
		b.Run(fmt.Sprintf("keys=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var m map[string]interface{}
				if err := yaml.Unmarshal(doc, &m); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// B: viper's full ReadConfig (decode + insensitiviseMap + flatten).
func BenchmarkF1ViperReadConfigYAML(b *testing.B) {
	for _, n := range f1Sizes {
		doc := f1YAMLDoc(n)
		b.Run(fmt.Sprintf("keys=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				v := viper.New()
				v.SetConfigType("yaml")
				if err := v.ReadConfig(bytes.NewReader(doc)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Control: JSON through viper (documented linear), same key counts.
func BenchmarkF1ViperReadConfigJSON(b *testing.B) {
	for _, n := range f1Sizes {
		doc := []byte(manyJSONKeys(n))
		b.Run(fmt.Sprintf("keys=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				v := viper.New()
				v.SetConfigType("json")
				if err := v.ReadConfig(bytes.NewReader(doc)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
