//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func withNginxProcess(b *source.Bundle) {
	b.PutDir("/proc", []string{"100"})
	b.PutDir("/proc/100", []string{"comm", "cgroup"})
	b.PutFile("/proc/100/comm", []byte("nginx\n"))
	// /proc/100/cgroup intentionally unseeded: unreadable -> host, not container.
}

func TestNginxCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewNginxCollector()
	if c.Name() != "Nginx" {
		t.Errorf("Name() = %q, want Nginx", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

// NOTE: withFixtureSource/withCombinedFixture swap a package-level global
// (activeSource) — these tests deliberately do NOT call t.Parallel(),
// matching the established convention in security_linux_source_test.go /
// vmware_linux_collectors_test.go / rabbitmq_linux_test.go.

func TestNginxAvailable(t *testing.T) {
	t.Run("running", func(t *testing.T) {
		withFixtureSource(t, withNginxProcess)
		if !NginxAvailable() {
			t.Error("NginxAvailable() = false, want true")
		}
	})
	t.Run("not running", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/proc", []string{})
		})
		if NginxAvailable() {
			t.Error("NginxAvailable() = true, want false")
		}
	})
}

func TestNginxCollector_Collect_NotDetected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc", []string{})
	})
	c := NewNginxCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NginxInfo)
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

func TestNginxCollector_Collect_FullHappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		withNginxProcess(b)
		b.PutDir("/proc", []string{"100", "200", "201"})
		b.PutDir("/proc/200", []string{"cmdline"})
		b.PutDir("/proc/201", []string{"cmdline"})
		b.PutFile("/proc/200/cmdline", []byte("nginx:\x00worker process\x00"))
		b.PutFile("/proc/201/cmdline", []byte("nginx:\x00worker process\x00"))
		b.PutCmd("nginx", []string{"-v"}, "nginx version: nginx/1.27.0\n", 0)
		b.PutCmd("nginx", []string{"-t"}, "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful\n", 0)
	})

	c := NewNginxCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NginxInfo)
	if !info.Detected || !info.MasterRunning {
		t.Errorf("info = %+v, want Detected/MasterRunning true", info)
	}
	if info.Workers != 2 {
		t.Errorf("Workers = %d, want 2", info.Workers)
	}
	if info.Version != "1.27.0" {
		t.Errorf("Version = %q, want 1.27.0", info.Version)
	}
	if !info.ConfigTested || !info.ConfigValid {
		t.Errorf("info = %+v, want ConfigTested/ConfigValid true", info)
	}
}

func TestCollectNginxConfigTest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("nginx", []string{"-t"}, "nginx: configuration file /etc/nginx/nginx.conf test is successful\n", 0)
		})
		info := &models.NginxInfo{}
		collectNginxConfigTest(context.Background(), info)
		if !info.ConfigTested || !info.ConfigValid {
			t.Errorf("info = %+v, want ConfigTested/ConfigValid true", info)
		}
	})

	t.Run("permission denied phrase", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("nginx", []string{"-t"}, "nginx: [emerg] open() \"/etc/nginx/nginx.conf\" failed (13: Permission denied)\n", 1)
		})
		info := &models.NginxInfo{}
		collectNginxConfigTest(context.Background(), info)
		if info.ConfigTested {
			t.Error("ConfigTested = true, want false (permission failure is 'could not test', not invalid)")
		}
		if info.StatusReason == "" {
			t.Error("expected a StatusReason for the permission failure")
		}
	})

	t.Run("permission denied via (13: marker only", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("nginx", []string{"-t"}, "nginx: [emerg] stat() failed (13: some other wording)\n", 1)
		})
		info := &models.NginxInfo{}
		collectNginxConfigTest(context.Background(), info)
		if info.ConfigTested {
			t.Error("ConfigTested = true, want false (13: marker alone should trigger the permission branch)")
		}
	})

	t.Run("genuine syntax error", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("nginx", []string{"-t"}, "nginx: [emerg] unexpected \"}\" in /etc/nginx/nginx.conf:12\nnginx: configuration file /etc/nginx/nginx.conf test failed\n", 1)
		})
		info := &models.NginxInfo{}
		collectNginxConfigTest(context.Background(), info)
		if !info.ConfigTested {
			t.Fatal("ConfigTested = false, want true (a real syntax error was tested)")
		}
		if info.ConfigValid {
			t.Error("ConfigValid = true, want false")
		}
		if info.ConfigError != `nginx: [emerg] unexpected "}" in /etc/nginx/nginx.conf:12` {
			t.Errorf("ConfigError = %q, want the emerg line", info.ConfigError)
		}
	})

	t.Run("command itself fails to run", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmdNotFound("nginx", []string{"-t"})
		})
		info := &models.NginxInfo{}
		collectNginxConfigTest(context.Background(), info)
		if info.ConfigTested {
			t.Error("ConfigTested = true, want false")
		}
		if info.StatusReason == "" {
			t.Error("expected a StatusReason when nginx -t could not run")
		}
	})
}

func TestFirstNginxError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "emerg line found",
			in:   "some noise\nnginx: [emerg] bad directive\nmore noise\n",
			want: "nginx: [emerg] bad directive",
		},
		{
			name: "error line found",
			in:   "nginx: [error] something failed\n",
			want: "nginx: [error] something failed",
		},
		{
			name: "neither found falls back to first non-empty line",
			in:   "\n  \nfirst real line\nsecond line\n",
			want: "first real line",
		},
		{
			name: "completely empty input",
			in:   "",
			want: "config test failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := firstNginxError(tt.in); got != tt.want {
				t.Errorf("firstNginxError(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestParseNginxVersion_Boundaries covers cases beyond the basic pair already
// guarded by TestParseNginxVersion in pve_io_systemd_parse_test.go (shared
// parseNginxVersion helper, used by both the PVE and Nginx collectors).
func TestParseNginxVersion_Boundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"normal case", "nginx version: nginx/1.27.0\nbuilt by gcc\n", "1.27.0"},
		{"no nginx/ substring", "nginx version: unknown\n", ""},
		{"empty input", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := parseNginxVersion(tt.in); got != tt.want {
				t.Errorf("parseNginxVersion(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCountNginxWorkers(t *testing.T) {
	t.Run("counts matching cmdline entries", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/proc", []string{"100", "200", "notadir.txt"})
			b.PutDir("/proc/100", []string{"cmdline"})
			b.PutDir("/proc/200", []string{"cmdline"})
			b.PutFile("/proc/100/cmdline", []byte("nginx:\x00worker process\x00"))
			b.PutFile("/proc/200/cmdline", []byte("nginx:\x00master process\x00/usr/sbin/nginx\x00"))
		})
		if got := countNginxWorkers(); got != 1 {
			t.Errorf("countNginxWorkers() = %d, want 1", got)
		}
	})

	t.Run("unreadable cmdline skipped", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/proc", []string{"100"})
			// /proc/100/cmdline intentionally unseeded -> readFile errors -> skipped.
		})
		if got := countNginxWorkers(); got != 0 {
			t.Errorf("countNginxWorkers() = %d, want 0", got)
		}
	})

	t.Run("readDirEntries error returns 0", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		if got := countNginxWorkers(); got != 0 {
			t.Errorf("countNginxWorkers() = %d, want 0", got)
		}
	})
}
