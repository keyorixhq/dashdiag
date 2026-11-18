// Stand-alone reproducer for charmbracelet/x/ansi F3 (MC4): ansi.Strip leaves a
// raw ESC (0x1b) in its output when the ESC is immediately preceded by an invalid
// UTF-8 lead byte. Run: `go run .`
//
// Strip is documented/intended to remove ANSI escape sequences; leaving a raw ESC
// in the output is a robustness gap — a downstream consumer that trusts Strip's
// output to be escape-free (e.g. before writing to a terminal) can be surprised.
package main

import (
	"fmt"

	"github.com/charmbracelet/x/ansi"
)

func main() {
	cases := []struct {
		name string
		in   string
	}{
		{"invalid-lead + ESC", "\xe8\x1b"},
		{"invalid-lead + CSI", "\xe8\x1b[31m"},
		{"valid control baseline (ESC stripped)", "a\x1b[31mb"},
		{"lone ESC on valid text", "x\x1by"},
	}
	anyLeak := false
	for _, c := range cases {
		out := ansi.Strip(c.in)
		hasESC := false
		for i := 0; i < len(out); i++ {
			if out[i] == 0x1b {
				hasESC = true
				break
			}
		}
		if hasESC {
			anyLeak = true
		}
		fmt.Printf("%-40s in=%q -> out=%q  ESC-left=%v\n", c.name, c.in, out, hasESC)
	}
	fmt.Println()
	if anyLeak {
		fmt.Println("RESULT: ansi.Strip left a raw ESC behind (F3 reproduced).")
	} else {
		fmt.Println("RESULT: no ESC survived — F3 not reproduced on this version.")
	}
}
