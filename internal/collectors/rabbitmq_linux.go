//go:build linux

package collectors

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// rabbitmqRun runs a rabbitmq CLI command. RabbitMQ's diagnostics need the Erlang
// cookie, which belongs to the rabbitmq OS user — so as root we run via
// `sudo -n -u rabbitmq` (peer to that user; -n so it never blocks on a password).
// As a non-root user we run directly (works if the caller IS the rabbitmq user).
func rabbitmqRun(ctx context.Context, cli string, args ...string) (string, error) {
	if os.Geteuid() == 0 {
		return runCmd(ctx, "sudo", append([]string{"-n", "-u", "rabbitmq", "--", cli}, args...)...)
	}
	return runCmd(ctx, cli, args...)
}

// rabbitmqCLI returns the rabbitmq diagnostics binary to use, or "" if neither is
// installed (so a non-RabbitMQ AMQP broker on 5672 isn't mislabelled).
func rabbitmqCLI() string {
	for _, bin := range []string{"rabbitmq-diagnostics", "rabbitmqctl"} {
		if _, err := exec.LookPath(bin); err == nil {
			return bin
		}
	}
	return ""
}

// RabbitMQAvailable reports whether a local RabbitMQ broker is installed and its
// AMQP port (5672) is reachable.
func RabbitMQAvailable() bool {
	if rabbitmqCLI() == "" {
		return false
	}
	// RabbitMQ commonly binds the IPv6 wildcard ([::]), so try both loopback
	// families — an IPv4-only probe misses an IPv6-listening broker.
	for _, addr := range []string{"127.0.0.1:5672", "[::1]:5672"} {
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			conn.Close() //nolint:errcheck
			return true
		}
	}
	return false
}

type RabbitMQCollector struct{}

func NewRabbitMQCollector() *RabbitMQCollector { return &RabbitMQCollector{} }

func (c *RabbitMQCollector) Name() string           { return "RabbitMQ" }
func (c *RabbitMQCollector) Timeout() time.Duration { return 8 * time.Second }

func (c *RabbitMQCollector) Collect(ctx context.Context) (interface{}, error) {
	cli := rabbitmqCLI()
	if cli == "" {
		return &models.RabbitMQInfo{Detected: false}, nil
	}
	info := &models.RabbitMQInfo{Detected: true, Accepting: true}

	// ping confirms the node is up AND that we have diagnostics access (the Erlang
	// cookie). A failure here means "couldn't look", not "node down" — the AMQP
	// port already answered.
	if out, err := rabbitmqRun(ctx, cli, "-q", "ping"); err != nil || !strings.Contains(out, "Ping succeeded") {
		info.StatusReason = "rabbitmq diagnostics unavailable (need root or the rabbitmq user / Erlang cookie)"
		return info, nil
	}
	info.DiagnosticsRead = true
	info.Pinged = true

	if v, err := rabbitmqRun(ctx, cli, "-q", "server_version"); err == nil {
		info.Version = strings.TrimSpace(v)
	}
	parseRabbitMQAlarms(ctx, cli, info)
	return info, nil
}

// parseRabbitMQAlarms runs `rabbitmq-diagnostics alarms` and flags an active
// memory or disk resource alarm — the state in which the broker blocks publishers.
func parseRabbitMQAlarms(ctx context.Context, cli string, info *models.RabbitMQInfo) {
	out, err := rabbitmqRun(ctx, cli, "-q", "alarms")
	if err != nil {
		return // AlarmsRead stays false — the heuristic surfaces the unread state
	}
	info.AlarmsRead = true
	low := strings.ToLower(out)
	// "reported no alarms" / "no alarms in effect" ⇒ clean.
	if strings.Contains(low, "no alarms") {
		return
	}
	if strings.Contains(low, "memory") {
		info.MemoryAlarm = true
	}
	if strings.Contains(low, "disk") || strings.Contains(low, "disc") {
		info.DiskAlarm = true
	}
	if info.MemoryAlarm || info.DiskAlarm {
		info.AlarmDetail = firstNonEmptyLine(out)
	}
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if l := strings.TrimSpace(line); l != "" {
			return l
		}
	}
	return ""
}
