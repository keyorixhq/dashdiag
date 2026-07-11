package selfupdate

import (
	"encoding/base64"
	"testing"
)

func TestParseMinisignPublicKey_ErrorPaths(t *testing.T) {
	cases := []struct {
		name string
		pub  string
	}{
		{"invalid base64", "not-valid-base64!!!"},
		{"wrong length", base64.StdEncoding.EncodeToString([]byte("too short"))},
		{"wrong algorithm prefix", base64.StdEncoding.EncodeToString(append([]byte{'X', 'X'}, make([]byte, 40)...))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := parseMinisignPublicKey(c.pub); err == nil {
				t.Fatalf("parseMinisignPublicKey(%q) expected error, got nil", c.pub)
			}
		})
	}
}

func TestLastDataLine(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"bare line", "abc123==", "abc123=="},
		{"comment then data", "untrusted comment: x\nabc123==", "abc123=="},
		{"trailing blank lines", "abc123==\n\n\n", "abc123=="},
		{"only comments", "untrusted comment: x\ntrusted comment: y", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := lastDataLine(c.in); got != c.want {
				t.Errorf("lastDataLine(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
