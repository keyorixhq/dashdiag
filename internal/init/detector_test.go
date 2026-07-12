package init_pkg

import (
	"runtime"
	"testing"
)

func TestContainsAny(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		list    []string
		targets []string
		want    bool
	}{
		{"exact match", []string{"nginx", "sshd"}, []string{"nginx"}, true},
		{"case insensitive", []string{"NGINX"}, []string{"nginx"}, true},
		{"no match", []string{"sshd", "cron"}, []string{"nginx", "apache2"}, false},
		{"empty list", nil, []string{"nginx"}, false},
		{"empty targets", []string{"nginx"}, nil, false},
		{"match among many targets", []string{"redis-server"}, []string{"postgres", "mysqld", "redis-server", "mongod"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := containsAny(c.list, c.targets...); got != c.want {
				t.Errorf("containsAny(%v, %v) = %v, want %v", c.list, c.targets, got, c.want)
			}
		})
	}
}

func TestClassifyProfile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		procs []string
		want  string
	}{
		{"nginx present", []string{"bash", "nginx", "sshd"}, "web"},
		{"apache2 present", []string{"apache2"}, "web"},
		{"postgres present", []string{"postgres", "bash"}, "database"},
		{"redis present", []string{"redis-server"}, "database"},
		{"kubelet present", []string{"kubelet", "containerd"}, "kubernetes"},
		{"proxmox present", []string{"pvedaemon"}, "proxmox"},
		{"nothing recognized", []string{"bash", "sshd", "cron"}, "general"},
		{"empty process list", nil, "general"},
		{"web takes priority over database when both present", []string{"nginx", "postgres"}, "web"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := classifyProfile(c.procs); got != c.want {
				t.Errorf("classifyProfile(%v) = %q, want %q", c.procs, got, c.want)
			}
		})
	}
}

// DetectServerProfile hits the real OS process list — smoke test only, per the
// project's own testdata/fixtures rule for anything reading real /proc or ps.
func TestDetectServerProfile_Smoke(t *testing.T) {
	t.Parallel()
	valid := map[string]bool{"web": true, "database": true, "kubernetes": true, "proxmox": true, "general": true}
	got := DetectServerProfile()
	if !valid[got] {
		t.Errorf("DetectServerProfile() = %q, want one of the known profile names", got)
	}
}

// darwinProcessNames shells out to the real "ps aux" and parses its output.
// It isn't gated on runtime.GOOS internally, so it's exercised directly here
// as a smoke test (real "ps" is available on this Linux CI/dev box too, and
// BSD-style "ps aux" column layout — COMMAND as the 11th field — matches).
func TestDarwinProcessNames_Smoke(t *testing.T) {
	t.Parallel()
	names := darwinProcessNames()
	if len(names) == 0 {
		t.Skip("no process names parsed from `ps aux` in this environment")
	}
	for _, n := range names {
		if n == "" {
			t.Errorf("darwinProcessNames() returned an empty name among %v", names)
		}
	}
}

// With PATH cleared, exec.Command("ps", "aux") cannot find the "ps" binary,
// so darwinProcessNames() takes its error branch and returns nil — exercises
// that path without needing a real macOS host. t.Setenv forbids t.Parallel()
// per Go's testing package (same constraint as firstrun_test.go).
func TestDarwinProcessNames_PsNotFound(t *testing.T) {
	t.Setenv("PATH", "")

	if names := darwinProcessNames(); names != nil {
		t.Errorf("darwinProcessNames() = %v, want nil when `ps` is not on PATH", names)
	}
}

// runningProcessNames dispatches on runtime.GOOS. This smoke test just
// confirms it returns without panicking on whichever branch the current
// build/OS takes; the darwin-only branch (runtime.GOOS != "linux") is not
// reachable on this Linux test host and is recorded as a known gap.
func TestRunningProcessNames_Smoke(t *testing.T) {
	t.Parallel()
	_ = runningProcessNames()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("unexpected GOOS for this smoke test")
	}
}
