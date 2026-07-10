//go:build linux

package collectors

import "testing"

// TestExtractQuoted covers the quote-boundary branches directly: the happy
// path is already exercised indirectly via named.conf zone parsing in
// TestBINDCollector_Collect_FullHappyPath (bind_linux_collectors_test.go),
// but the no-quote and single-quote (unterminated) bail-out branches are
// not, since real named.conf zone/file directives always come well-quoted.
func TestExtractQuoted(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		line   string
		want   string
		wantOK bool
	}{
		{"well-quoted zone directive", `zone "example.com" {`, "example.com", true},
		{"well-quoted file directive", `    file "/etc/bind/db.example.com";`, "/etc/bind/db.example.com", true},
		{"no quotes at all", `type master;`, "", false},
		{"single unterminated quote", `zone "example.com {`, "", false},
		{"empty string", "", "", false},
		{"empty quoted value", `file "";`, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, ok := extractQuoted(c.line)
			if got != c.want || ok != c.wantOK {
				t.Errorf("extractQuoted(%q) = (%q, %v), want (%q, %v)", c.line, got, ok, c.want, c.wantOK)
			}
		})
	}
}
