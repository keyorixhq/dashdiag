//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// ── constructor / interface methods ──────────────────────────────────────────

func TestNewRabbitMQCollector_NameAndTimeout(t *testing.T) {
	c := NewRabbitMQCollector()
	if c.Name() != "RabbitMQ" {
		t.Errorf("Name() = %q, want RabbitMQ", c.Name())
	}
	if c.Timeout() != 8*time.Second {
		t.Errorf("Timeout() = %v, want 8s", c.Timeout())
	}
}

// ── rabbitmqCLI ───────────────────────────────────────────────────────────────

func TestRabbitmqCLI_DiagnosticsPreferred(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/rabbitmq-diagnostics": []byte("/usr/sbin/rabbitmq-diagnostics"),
		"lookpath/rabbitmqctl":          []byte("/usr/sbin/rabbitmqctl"),
	}, nil, nil)
	if got := rabbitmqCLI(); got != "rabbitmq-diagnostics" {
		t.Errorf("rabbitmqCLI() = %q, want rabbitmq-diagnostics (preferred over rabbitmqctl)", got)
	}
}

func TestRabbitmqCLI_FallsBackToRabbitmqctl(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/rabbitmqctl": []byte("/usr/sbin/rabbitmqctl"),
	}, nil, nil)
	if got := rabbitmqCLI(); got != "rabbitmqctl" {
		t.Errorf("rabbitmqCLI() = %q, want rabbitmqctl", got)
	}
}

func TestRabbitmqCLI_NeitherInstalled(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	if got := rabbitmqCLI(); got != "" {
		t.Errorf("rabbitmqCLI() = %q, want empty", got)
	}
}

// ── RabbitMQAvailable ─────────────────────────────────────────────────────────

func TestRabbitMQAvailable_ReachableIPv4(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/rabbitmq-diagnostics": []byte("/usr/sbin/rabbitmq-diagnostics"),
		"dial/tcp/127.0.0.1:5672":       {'1'},
	}, nil, nil)
	if !RabbitMQAvailable() {
		t.Error("expected true when the CLI is installed and 127.0.0.1:5672 is reachable")
	}
}

func TestRabbitMQAvailable_ReachableIPv6Only(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/rabbitmq-diagnostics": []byte("/usr/sbin/rabbitmq-diagnostics"),
		"dial/tcp/127.0.0.1:5672":       {'0'},
		"dial/tcp/[::1]:5672":           {'1'},
	}, nil, nil)
	if !RabbitMQAvailable() {
		t.Error("expected true when only the IPv6 loopback probe succeeds")
	}
}

func TestRabbitMQAvailable_CLINotInstalled(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:5672": {'1'},
		"dial/tcp/[::1]:5672":     {'1'},
	}, nil, nil)
	if RabbitMQAvailable() {
		t.Error("expected false when neither rabbitmq-diagnostics nor rabbitmqctl is installed, even if the port answers")
	}
}

func TestRabbitMQAvailable_NotReachable(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/rabbitmq-diagnostics": []byte("/usr/sbin/rabbitmq-diagnostics"),
	}, nil, nil)
	if RabbitMQAvailable() {
		t.Error("expected false when neither loopback family answers 5672")
	}
}

// ── rabbitmqRun ───────────────────────────────────────────────────────────────

// TestRabbitmqRun_AsRoot relies on the real test environment: the golang:1.26
// container runs as root (euid 0), so rabbitmqRun always takes the
// `sudo -n -u rabbitmq --` branch here — mirrors the established pattern of
// testing against genuine container properties (e.g. TestSysPing_NoPingBinary).
func TestRabbitmqRun_AsRoot(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("sudo", []string{"-n", "-u", "rabbitmq", "--", "rabbitmq-diagnostics", "-q", "ping"},
			"Ping succeeded\n", 0)
	})
	out, err := rabbitmqRun(context.Background(), "rabbitmq-diagnostics", "-q", "ping")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "Ping succeeded\n" {
		t.Errorf("out = %q, want Ping succeeded", out)
	}
}

func TestRabbitmqRun_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("sudo", []string{"-n", "-u", "rabbitmq", "--", "rabbitmq-diagnostics", "-q", "ping"})
	})
	if _, err := rabbitmqRun(context.Background(), "rabbitmq-diagnostics", "-q", "ping"); err == nil {
		t.Fatal("expected an error when the sudo invocation fails")
	}
}

// ── firstNonEmptyLine ─────────────────────────────────────────────────────────

func TestFirstNonEmptyLine(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"\n\n  hello\nworld\n", "hello"},
		{"only one line", "only one line"},
		{"\n\n\n", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := firstNonEmptyLine(tt.in); got != tt.want {
			t.Errorf("firstNonEmptyLine(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ── parseRabbitMQAlarms ───────────────────────────────────────────────────────

func TestParseRabbitMQAlarms_NoAlarms(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("sudo", []string{"-n", "-u", "rabbitmq", "--", "rabbitmq-diagnostics", "-q", "alarms"},
			"Reporting alarms...\nno alarms in effect\n", 0)
	})
	info := &models.RabbitMQInfo{}
	parseRabbitMQAlarms(context.Background(), "rabbitmq-diagnostics", info)
	if !info.AlarmsRead || info.MemoryAlarm || info.DiskAlarm {
		t.Errorf("info = %+v, want AlarmsRead=true, no alarms set", info)
	}
}

func TestParseRabbitMQAlarms_MemoryAlarm(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("sudo", []string{"-n", "-u", "rabbitmq", "--", "rabbitmq-diagnostics", "-q", "alarms"},
			"Reporting alarms...\n[{memory,'rabbit@node1'}]\n", 0)
	})
	info := &models.RabbitMQInfo{}
	parseRabbitMQAlarms(context.Background(), "rabbitmq-diagnostics", info)
	if !info.AlarmsRead || !info.MemoryAlarm || info.DiskAlarm {
		t.Errorf("info = %+v, want AlarmsRead+MemoryAlarm true, DiskAlarm false", info)
	}
	if info.AlarmDetail == "" {
		t.Error("expected a non-empty AlarmDetail when an alarm is active")
	}
}

func TestParseRabbitMQAlarms_DiskAlarm(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("sudo", []string{"-n", "-u", "rabbitmq", "--", "rabbitmq-diagnostics", "-q", "alarms"},
			"Reporting alarms...\n[{disk,'rabbit@node1'}]\n", 0)
	})
	info := &models.RabbitMQInfo{}
	parseRabbitMQAlarms(context.Background(), "rabbitmq-diagnostics", info)
	if !info.AlarmsRead || info.MemoryAlarm || !info.DiskAlarm {
		t.Errorf("info = %+v, want AlarmsRead+DiskAlarm true, MemoryAlarm false", info)
	}
}

func TestParseRabbitMQAlarms_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("sudo", []string{"-n", "-u", "rabbitmq", "--", "rabbitmq-diagnostics", "-q", "alarms"})
	})
	info := &models.RabbitMQInfo{}
	parseRabbitMQAlarms(context.Background(), "rabbitmq-diagnostics", info)
	if info.AlarmsRead {
		t.Error("expected AlarmsRead=false when the alarms command fails")
	}
}

// ── Collect ───────────────────────────────────────────────────────────────────

func TestRabbitMQCollector_Collect_NotDetected(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	c := NewRabbitMQCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := result.(*models.RabbitMQInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.RabbitMQInfo", result)
	}
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

func TestRabbitMQCollector_Collect_PingFails(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/rabbitmq-diagnostics": []byte("/usr/sbin/rabbitmq-diagnostics"),
	}, nil, func(b *source.Bundle) {
		b.PutCmdNotFound("sudo", []string{"-n", "-u", "rabbitmq", "--", "rabbitmq-diagnostics", "-q", "ping"})
	})
	c := NewRabbitMQCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := result.(*models.RabbitMQInfo)
	if !info.Detected || !info.Accepting || info.DiagnosticsRead {
		t.Errorf("info = %+v, want Detected/Accepting true, DiagnosticsRead false", info)
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason explaining diagnostics couldn't be read")
	}
}

func TestRabbitMQCollector_Collect_Full(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/rabbitmq-diagnostics": []byte("/usr/sbin/rabbitmq-diagnostics"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("sudo", []string{"-n", "-u", "rabbitmq", "--", "rabbitmq-diagnostics", "-q", "ping"},
			"Ping succeeded\n", 0)
		b.PutCmd("sudo", []string{"-n", "-u", "rabbitmq", "--", "rabbitmq-diagnostics", "-q", "server_version"},
			"3.12.7\n", 0)
		b.PutCmd("sudo", []string{"-n", "-u", "rabbitmq", "--", "rabbitmq-diagnostics", "-q", "alarms"},
			"no alarms in effect\n", 0)
	})
	c := NewRabbitMQCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := result.(*models.RabbitMQInfo)
	if !info.Detected || !info.Accepting || !info.DiagnosticsRead || !info.Pinged {
		t.Errorf("info = %+v, want Detected/Accepting/DiagnosticsRead/Pinged all true", info)
	}
	if info.Version != "3.12.7" {
		t.Errorf("Version = %q, want 3.12.7", info.Version)
	}
	if !info.AlarmsRead || info.MemoryAlarm || info.DiskAlarm {
		t.Errorf("info = %+v, want AlarmsRead=true, no alarms", info)
	}
}
