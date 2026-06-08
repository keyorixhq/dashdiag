package collectors

import "testing"

func TestIsNVMeController(t *testing.T) {
	cases := []struct {
		base string
		want bool
	}{
		{"nvme0", true},
		{"nvme9", true},
		{"nvme10", true}, // regression: 10+ controllers were wrongly skipped
		{"nvme127", true},
		{"nvme0n1", false},   // namespace
		{"nvme10n2", false},  // namespace on a 2-digit controller
		{"nvme0c0n1", false}, // multipath instance
		{"nvme", false},      // bare prefix, no number
		{"sda", false},       // not an nvme entry
		{"", false},
	}
	for _, c := range cases {
		if got := isNVMeController(c.base); got != c.want {
			t.Errorf("isNVMeController(%q) = %v, want %v", c.base, got, c.want)
		}
	}
}
