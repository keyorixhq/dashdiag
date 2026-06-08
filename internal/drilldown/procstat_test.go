package drilldown

import "testing"

func TestParseProcStatComm(t *testing.T) {
	// comm with a space — the classic "Web Content" hazard. Fields after the
	// last ')' must align: state, ppid, ... utime(idx11), stime(idx12).
	stat := "1234 (Web Content) S 1 1234 1234 0 -1 4194560 " +
		"1000 2000 3 4 111 222 20 0 5 0 9999"
	name, rest, ok := parseProcStatComm(stat)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if name != "Web Content" {
		t.Errorf("name = %q, want %q", name, "Web Content")
	}
	if rest[0] != "S" {
		t.Errorf("state = %q, want S", rest[0])
	}
	if rest[1] != "1" {
		t.Errorf("ppid = %q, want 1", rest[1])
	}
	if rest[11] != "111" || rest[12] != "222" {
		t.Errorf("utime/stime = %q/%q, want 111/222", rest[11], rest[12])
	}

	// comm containing parens.
	n2, _, ok2 := parseProcStatComm("5 (a (b) c) R 1 ...")
	if !ok2 || n2 != "a (b) c" {
		t.Errorf("paren comm = %q ok=%v, want %q", n2, ok2, "a (b) c")
	}

	// malformed: no parens.
	if _, _, ok3 := parseProcStatComm("no parens here"); ok3 {
		t.Error("malformed input should return ok=false")
	}
}
