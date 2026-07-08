package init_pkg

import "testing"

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
