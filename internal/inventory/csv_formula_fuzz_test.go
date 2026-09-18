package inventory

// FuzzEscapeCSVFormula fuzzes escapeCSVFormula (csv.go), the CWE-1236 spreadsheet formula-injection
// neutraliser applied to every hardware-derived value written into the inventory CSV. Those values
// (drive/DMI vendor/model/serial, NIC names) are attacker-influenceable -- a BadUSB-style device or
// a VM/hypervisor fabricating SMBIOS data controls them -- and flow into a CSV an operator opens in
// Excel/Sheets. The function had only a small table unit test.
//
// Two sound invariants (assert only the safe direction, so neither can false-positive):
//
//   - NO DATA LOSS: escapeCSVFormula only ever prepends a single leading quote (output is exactly v
//     or "'"+v); it never drops or rewrites the value.
//   - NO FORMULA CELL (end-to-end): the neutralised value, written through a real encoding/csv Writer
//     and read back through a real Reader -- the exact path writeCSV takes -- must never produce a
//     cell that begins with a spreadsheet formula trigger (=, +, -, @, TAB, CR). Round-tripping
//     through encoding/csv also guards against the CSV encoding re-introducing a leading trigger.
//
// Pure function + encoding/csv, cross-platform -- CI-runnable.

import (
	"encoding/csv"
	"strings"
	"testing"
)

var csvFormulaTriggers = map[byte]bool{'=': true, '+': true, '-': true, '@': true, '\t': true, '\r': true}

func FuzzEscapeCSVFormula(f *testing.F) {
	for _, s := range []string{
		"", "Samsung SSD 990", "value with, comma",
		"=cmd", "+1", "-2+3", "@SUM(A1)", "\tTAB", "\rCR",
		"=1+2\";=cmd|'/C calc'!A0", " =leading space then eq", "\n=leading lf then eq",
		"ST3000=DM001", "quote\"inside", "line\nbreak", "'already quoted",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, v string) {
		out := escapeCSVFormula(v)

		// Invariant 1: no data loss.
		if out != v && out != "'"+v {
			t.Fatalf("escapeCSVFormula altered data beyond a single leading quote: in=%q out=%q", v, out)
		}

		// An empty cell carries no formula-injection risk and a single empty CSV field encodes as a
		// blank line encoding/csv legitimately drops on read -- nothing to round-trip.
		if out == "" {
			return
		}

		// Invariant 2: end-to-end through encoding/csv, the cell must not begin with a trigger.
		var buf strings.Builder
		w := csv.NewWriter(&buf)
		if err := w.Write([]string{out}); err != nil {
			t.Fatalf("csv write of neutralised cell %q: %v", out, err)
		}
		w.Flush()
		if err := w.Error(); err != nil {
			t.Fatalf("csv writer flush error on %q: %v", out, err)
		}
		rec, err := csv.NewReader(strings.NewReader(buf.String())).Read()
		if err != nil || len(rec) == 0 {
			t.Fatalf("csv read-back of %q failed: err=%v rec=%v", out, err, rec)
		}
		cell := rec[0]
		if len(cell) > 0 && csvFormulaTriggers[cell[0]] {
			t.Fatalf("CSV FORMULA INJECTION: input %q neutralised to %q, but the read-back cell %q begins with a formula trigger %q",
				v, out, cell, string(cell[0]))
		}
	})
}
