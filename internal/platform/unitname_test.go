package platform

import (
	"strings"
	"testing"
)

func TestValidUnitName(t *testing.T) {
	for _, s := range []string{"sshd.service", "getty@tty1.service", "nginx", `dev-disk-by\x2duuid.device`, "a:b_c.d@e-f"} {
		if !ValidUnitName(s) {
			t.Errorf("ValidUnitName(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "--version", "-h", "-", "a b", "a;b", "a/b", "a\n", "$(x)", strings.Repeat("a", 257)} {
		if ValidUnitName(s) {
			t.Errorf("ValidUnitName(%q) = true, want false", s)
		}
	}
}
