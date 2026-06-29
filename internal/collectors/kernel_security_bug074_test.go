package collectors

import "testing"

// TestResolveSELinuxMode guards BUG-074: the world-readable `enforce` node value
// MUST win over an absent `getenforce`. A getenforce-only probe returned
// present=false on a non-root PATH lacking getenforce (openSUSE Leap Micro's
// `nobody`, Tumbleweed's `andrei`) → a false "kernel security module not enforced"
// while SELinux was enforcing. Validated live before/after on both distros; this is
// the unit guard that keeps the resolution order from regressing.
func TestResolveSELinuxMode(t *testing.T) {
	cases := []struct {
		name                string
		enforce, getenforce string
		fsMounted           bool
		wantPresent         bool
		wantMode            string
	}{
		{"enforce wins when getenforce absent (BUG-074)", "enforcing", "", true, true, "enforcing"},
		{"enforce wins — permissive", "permissive", "", true, true, "permissive"},
		{"getenforce fallback when enforce unreadable", "", "enforcing", true, true, "enforcing"},
		{"neither, fs mounted → unknown (not a false 'not enforced')", "", "", true, true, "unknown"},
		{"neither, fs absent → genuinely not present", "", "", false, false, ""},
		{"enforce preferred over a disagreeing getenforce", "enforcing", "permissive", true, true, "enforcing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			present, mode := resolveSELinuxMode(c.enforce, c.getenforce, c.fsMounted)
			if present != c.wantPresent || mode != c.wantMode {
				t.Errorf("resolveSELinuxMode(%q, %q, %v) = (%v, %q), want (%v, %q)",
					c.enforce, c.getenforce, c.fsMounted, present, mode, c.wantPresent, c.wantMode)
			}
		})
	}
}
