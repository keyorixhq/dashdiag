// Stand-alone reproducer for the go.yaml.in/yaml/v3 O(n^2) mapping-decode issue
// (MC4 F1). No viper, no dsd — just the YAML library. Run: `go run .`
//
// It decodes a flat mapping of N sibling keys for N in {1k..64k} and prints the
// wall time plus the ratio vs the previous N. A ratio trending toward ~4x per
// key-doubling is the quadratic; a linear decoder would hold ~2x.
package main

import (
	"fmt"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

func flatDoc(n int) []byte {
	var b strings.Builder
	b.Grow(n * 10)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "k%d: %d\n", i, i)
	}
	return []byte(b.String())
}

func main() {
	sizes := []int{1000, 2000, 4000, 8000, 16000, 32000, 64000}
	fmt.Printf("%8s  %12s  %8s  %10s\n", "keys", "decode", "ratio", "allocs(map len)")
	var prev time.Duration
	for _, n := range sizes {
		doc := flatDoc(n)
		var m map[string]interface{}
		start := time.Now()
		if err := yaml.Unmarshal(doc, &m); err != nil {
			panic(err)
		}
		d := time.Since(start)
		ratio := 0.0
		if prev > 0 {
			ratio = float64(d) / float64(prev)
		}
		fmt.Printf("%8d  %12s  %7.2fx  %10d\n", n, d.Round(time.Microsecond), ratio, len(m))
		prev = d
	}
	fmt.Println("\nLinear decoder: ratio ~2.0x per doubling. Quadratic: ratio ~4.0x.")
}
