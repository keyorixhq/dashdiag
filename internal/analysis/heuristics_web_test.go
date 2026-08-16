package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckNginx(t *testing.T) {
	if got := checkNginx(models.NginxInfo{Detected: false}); got != nil {
		t.Errorf("undetected nginx should be silent, got %+v", got)
	}

	// Running + valid config → silent.
	healthy := checkNginx(models.NginxInfo{Detected: true, MasterRunning: true, ConfigTested: true, ConfigValid: true})
	if len(healthy) != 0 {
		t.Errorf("valid config should be silent, got %+v", healthy)
	}

	// Invalid on-disk config → CRIT with the error.
	bad := checkNginx(models.NginxInfo{
		Detected: true, MasterRunning: true, ConfigTested: true, ConfigValid: false,
		ConfigError: "nginx: [emerg] unknown directive \"servr\" in /etc/nginx/nginx.conf:12",
	})
	if !insightWithMsg(bad, "CRIT", "config is INVALID") {
		t.Fatalf("invalid config should CRIT, got %+v", bad)
	}
	if !insightWithMsg(bad, "CRIT", "unknown directive") {
		t.Errorf("CRIT should carry the nginx error, got %+v", bad)
	}

	// Couldn't test (non-root) → INFO, never a silent OK.
	untested := checkNginx(models.NginxInfo{Detected: true, MasterRunning: true, ConfigTested: false})
	if !insightWithMsg(untested, "INFO", "not validated") {
		t.Errorf("untested config should be INFO, got %+v", untested)
	}
}

// TestWebConfigVerdictCapsConfigError - internal-analysis-13-04: configError is
// unbounded tool stderr; the message must cap it (matching bind_linux.go's
// ConfigError truncateRunes(..., 200) sibling pattern) rather than splicing an
// arbitrarily large string into the insight.
func TestWebConfigVerdictCapsConfigError(t *testing.T) {
	huge := strings.Repeat("x", 5000)
	got := webConfigVerdict("Nginx", true, false, huge)
	if len(got) != 1 {
		t.Fatalf("expected exactly one insight, got %d", len(got))
	}
	msg := got[0].Message
	if len(msg) >= len(huge) {
		t.Errorf("expected configError to be truncated, message length %d not shorter than input %d", len(msg), len(huge))
	}
	if !strings.Contains(msg, "…") {
		t.Errorf("expected truncation ellipsis in message, got %q", msg)
	}
}

func TestCheckApache(t *testing.T) {
	if got := checkApache(models.ApacheInfo{Detected: false}); got != nil {
		t.Errorf("undetected apache should be silent, got %+v", got)
	}
	if got := checkApache(models.ApacheInfo{Detected: true, ConfigTested: true, ConfigValid: true}); len(got) != 0 {
		t.Errorf("valid apache config should be silent, got %+v", got)
	}
	bad := checkApache(models.ApacheInfo{Detected: true, ConfigTested: true, ConfigValid: false, ConfigError: "Syntax error on line 5"})
	if !insightWithMsg(bad, "CRIT", "Apache on-disk config is INVALID") {
		t.Errorf("invalid apache config should CRIT, got %+v", bad)
	}
}

func TestCheckHAProxy(t *testing.T) {
	if got := checkHAProxy(models.HAProxyInfo{Detected: false}); got != nil {
		t.Errorf("undetected haproxy should be silent, got %+v", got)
	}
	bad := checkHAProxy(models.HAProxyInfo{Detected: true, ConfigTested: true, ConfigValid: false, ConfigError: "[ALERT] parsing error"})
	if !insightWithMsg(bad, "CRIT", "HAProxy on-disk config is INVALID") {
		t.Errorf("invalid haproxy config should CRIT, got %+v", bad)
	}
	untested := checkHAProxy(models.HAProxyInfo{Detected: true, ConfigTested: false})
	if !insightWithMsg(untested, "INFO", "not validated") {
		t.Errorf("untested haproxy should be INFO, got %+v", untested)
	}
}
