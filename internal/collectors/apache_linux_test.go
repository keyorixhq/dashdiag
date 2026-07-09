//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// NOTE: withFixtureSource/withCombinedFixture swap a package-level global
// (activeSource) — these tests deliberately do NOT call t.Parallel(),
// matching the established convention in security_linux_source_test.go /
// nginx_linux_test.go.

func withApacheProcess(name string) func(b *source.Bundle) {
	return func(b *source.Bundle) {
		b.PutDir("/proc", []string{"100"})
		b.PutDir("/proc/100", []string{"comm", "cgroup"})
		b.PutFile("/proc/100/comm", []byte(name+"\n"))
		// /proc/100/cgroup intentionally unseeded: unreadable -> host, not container.
	}
}

func TestApacheCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewApacheCollector()
	if c.Name() != "Apache" {
		t.Errorf("Name() = %q, want Apache", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

func TestApacheAvailable(t *testing.T) {
	t.Run("httpd running", func(t *testing.T) {
		withFixtureSource(t, withApacheProcess("httpd"))
		if !ApacheAvailable() {
			t.Error("ApacheAvailable() = false, want true (httpd)")
		}
	})
	t.Run("apache2 running", func(t *testing.T) {
		withFixtureSource(t, withApacheProcess("apache2"))
		if !ApacheAvailable() {
			t.Error("ApacheAvailable() = false, want true (apache2)")
		}
	})
	t.Run("not running", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutDir("/proc", []string{})
		})
		if ApacheAvailable() {
			t.Error("ApacheAvailable() = true, want false")
		}
	})
}

func TestApacheCollector_Collect_NotDetected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/proc", []string{})
	})
	c := NewApacheCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ApacheInfo)
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

// TestApacheCollector_Collect_FullHappyPath exercises the version + configtest
// candidate chain: apache2ctl is tried first (Debian/Ubuntu), so seeding it
// alone proves the ordering picked it over apachectl/httpd.
func TestApacheCollector_Collect_FullHappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		withApacheProcess("apache2")(b)
		b.PutCmd("apachectl", []string{"-v"}, "Server version: Apache/2.4.58 (Ubuntu)\n", 0)
		b.PutCmd("apache2ctl", []string{"configtest"}, "Syntax OK\n", 0)
	})

	c := NewApacheCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ApacheInfo)
	if !info.Detected {
		t.Fatal("info.Detected = false, want true")
	}
	if info.Version != "2.4.58" {
		t.Errorf("Version = %q, want 2.4.58", info.Version)
	}
	if !info.ConfigTested || !info.ConfigValid {
		t.Errorf("info = %+v, want ConfigTested/ConfigValid true", info)
	}
	if info.ConfigError != "" {
		t.Errorf("ConfigError = %q, want empty on a valid config", info.ConfigError)
	}
}

// TestApacheCollector_Collect_ConfigSyntaxError guards the invalid-config path
// through httpd -t (RHEL family), which is later in the candidate order than
// apache2ctl/apachectl configtest — leaving those unseeded proves the fallback.
func TestApacheCollector_Collect_ConfigSyntaxError(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		withApacheProcess("httpd")(b)
		b.PutCmd("httpd", []string{"-v"}, "Server version: Apache/2.4.62 (Red Hat)\n", 0)
		b.PutCmd("httpd", []string{"-t"},
			"AH00526: Syntax error on line 12 of /etc/httpd/conf/httpd.conf\nSyntax error\n", 1)
	})

	c := NewApacheCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ApacheInfo)
	if !info.Detected {
		t.Fatal("info.Detected = false, want true")
	}
	if info.Version != "2.4.62" {
		t.Errorf("Version = %q, want 2.4.62", info.Version)
	}
	if !info.ConfigTested {
		t.Fatal("ConfigTested = false, want true (a real syntax error was tested)")
	}
	if info.ConfigValid {
		t.Error("ConfigValid = true, want false")
	}
	if info.ConfigError == "" {
		t.Error("expected a non-empty ConfigError")
	}
}

// TestApacheCollector_Collect_ConfigPermissionDenied guards the "couldn't read
// the config" branch: must count as ConfigTested=false, not a false "invalid".
func TestApacheCollector_Collect_ConfigPermissionDenied(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		withApacheProcess("apache2")(b)
		b.PutCmd("apachectl", []string{"-v"}, "Server version: Apache/2.4.58 (Ubuntu)\n", 0)
		b.PutCmd("apache2ctl", []string{"configtest"},
			"AH00526: open() \"/etc/apache2/apache2.conf\" failed (13: Permission denied)\n", 1)
	})

	c := NewApacheCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ApacheInfo)
	if info.ConfigTested {
		t.Error("ConfigTested = true, want false (permission failure is 'could not test', not invalid)")
	}
}

// TestApacheCollector_Collect_NoConfigTestBinariesAvailable guards the case
// where the process is detected but none of the version/configtest candidate
// binaries can run — must not error, just leave the optional fields empty.
func TestApacheCollector_Collect_NoConfigTestBinariesAvailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		withApacheProcess("httpd")(b)
		b.PutCmdNotFound("apachectl", []string{"-v"})
		b.PutCmdNotFound("apache2ctl", []string{"-v"})
		b.PutCmdNotFound("httpd", []string{"-v"})
		b.PutCmdNotFound("apache2ctl", []string{"configtest"})
		b.PutCmdNotFound("apachectl", []string{"configtest"})
		b.PutCmdNotFound("httpd", []string{"-t"})
		b.PutCmdNotFound("apachectl", []string{"-t"})
	})

	c := NewApacheCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.ApacheInfo)
	if !info.Detected {
		t.Fatal("info.Detected = false, want true")
	}
	if info.Version != "" {
		t.Errorf("Version = %q, want empty", info.Version)
	}
	if info.ConfigTested {
		t.Error("ConfigTested = true, want false")
	}
}
