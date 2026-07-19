package collectors

import (
	"testing"
)

func TestExtractAVCProcesses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "nil input safe",
			in:   nil,
			want: nil,
		},
		{
			name: "empty slice",
			in:   []string{},
			want: nil,
		},
		{
			name: "single AVC line with comm",
			in: []string{
				`type=AVC msg=audit(1695000000.123:456): avc: denied { read } for pid=1234 comm="nginx" name="secret" dev="sda" ino=12345`,
			},
			want: []string{"nginx"},
		},
		{
			name: "duplicate process names deduped",
			in: []string{
				`type=AVC msg=audit(1695000000.123:456): avc: denied { read } for pid=1234 comm="nginx" name="a"`,
				`type=AVC msg=audit(1695000000.124:457): avc: denied { write } for pid=1235 comm="nginx" name="b"`,
			},
			want: []string{"nginx"},
		},
		{
			name: "multiple different processes order preserved",
			in: []string{
				`type=AVC msg=audit(1695000000.123:456): avc: denied { read } for pid=100 comm="sshd" name="x"`,
				`type=AVC msg=audit(1695000000.124:457): avc: denied { read } for pid=101 comm="nginx" name="y"`,
			},
			want: []string{"sshd", "nginx"},
		},
		{
			name: "line missing comm= field skipped",
			in: []string{
				`type=AVC msg=audit(1695000000.123:456): avc: denied { read } for pid=1234 name="secret"`,
			},
			want: nil,
		},
		{
			name: "empty comm value skipped",
			in: []string{
				`type=AVC msg=audit(1695000000.123:456): avc: denied { read } for pid=1234 comm="" name="secret"`,
			},
			want: nil,
		},
		{
			name: "single char comm accepted",
			in: []string{
				`type=AVC msg=audit(1695000000.123:456): avc: denied { read } for pid=1234 comm="a" name="x"`,
			},
			want: []string{"a"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ExtractAVCProcesses(tc.in)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v (len %d), want %v (len %d)", got, len(got), tc.want, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestIsSafePolicyToken(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{name: "empty string", in: "", want: false},
		{name: "typical policy targeted", in: "targeted", want: true},
		{name: "short policy mls", in: "mls", want: true},
		{name: "hyphen allowed", in: "my-policy", want: true},
		{name: "underscore allowed", in: "my_policy", want: true},
		{name: "digits and uppercase allowed", in: "Policy123", want: true},
		{name: "space not allowed", in: "has space", want: false},
		{name: "slash not allowed", in: "has/slash", want: false},
		{name: "dot not allowed", in: "has.dot", want: false},
		{name: "at sign not allowed", in: "has@at", want: false},
		{name: "null byte not allowed", in: "has\x00null", want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isSafePolicyToken(tc.in)
			if got != tc.want {
				t.Errorf("isSafePolicyToken(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
