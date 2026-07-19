package collectors

import "testing"

func TestIsKernelThread(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{name: "kworker with suffix", in: "kworker/0:1H", want: true},
		{name: "kswapd0", in: "kswapd0", want: true},
		{name: "rcu_sched", in: "rcu_sched", want: true},
		{name: "kthreadd exact", in: "kthreadd", want: true},
		{name: "oom_reaper", in: "oom_reaper", want: true},
		{name: "bash is not kernel", in: "bash", want: false},
		{name: "nginx is not kernel", in: "nginx", want: false},
		{name: "kworker/ prefix only", in: "kworker/", want: true},
		{name: "empty string", in: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isKernelThread(tc.in); got != tc.want {
				t.Errorf("isKernelThread(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsShell(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{name: "bash", in: "bash", want: true},
		{name: "zsh", in: "zsh", want: true},
		{name: "fish", in: "fish", want: true},
		{name: "sh", in: "sh", want: true},
		{name: "ksh", in: "ksh", want: true},
		{name: "ash", in: "ash", want: true},
		{name: "python3 is not a shell", in: "python3", want: false},
		{name: "nginx is not a shell", in: "nginx", want: false},
		{name: "empty string", in: "", want: false},
		{name: "bash2 is not an exact match", in: "bash2", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isShell(tc.in); got != tc.want {
				t.Errorf("isShell(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
