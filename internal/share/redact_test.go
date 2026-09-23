package share

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactText_SecretsAndIdentifiers(t *testing.T) {
	t.Parallel()
	input := strings.Join([]string{
		"host: web-prod-01",
		"password=hunter2seedvalue",
		"ip 10.20.30.40 reachable",
		"ipv6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 reachable",
		"mac aa:bb:cc:dd:ee:ff seen",
		"path /home/andrei/.ssh/id_rsa",
		"Serial Number: WD-CANARY123456",
		"instance i-0123456789abcdef0 unhealthy",
		"contact admin@example.com for access",
	}, "\n")

	out, counts := RedactText(input, "web-prod-01", RedactOptions{})

	cases := []struct {
		class string
		gone  string
	}{
		{"secrets", "hunter2seedvalue"},
		{"hostnames", "web-prod-01"},
		{"ips", "10.20.30.40"},
		{"ips", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		{"macs", "aa:bb:cc:dd:ee:ff"},
		{"usernames", "andrei"},
		{"serials", "WD-CANARY123456"},
		{"cloud_ids", "i-0123456789abcdef0"},
		{"emails", "admin@example.com"},
	}
	for _, c := range cases {
		if strings.Contains(out, c.gone) {
			t.Errorf("expected %q to be redacted, still present in output:\n%s", c.gone, out)
		}
		if counts[c.class] == 0 {
			t.Errorf("expected counts[%q] > 0, got %v (full output:\n%s)", c.class, counts, out)
		}
	}

	if !strings.Contains(out, "/home/<user>") {
		t.Errorf("expected /home/<user> path prefix preserved, got:\n%s", out)
	}
	if !strings.Contains(out, "Serial Number") {
		t.Errorf("expected 'Serial Number' label preserved, got:\n%s", out)
	}
}

func TestRedactText_NoRedact(t *testing.T) {
	t.Parallel()
	input := "host web-prod-01 password=hunter2seedvalue ip 10.20.30.40 admin@example.com"
	out, counts := RedactText(input, "web-prod-01", RedactOptions{Disabled: true})
	if out != input {
		t.Errorf("expected --no-redact to leave text unchanged, got:\n%s", out)
	}
	if len(counts) != 0 {
		t.Errorf("expected zero counts with Disabled, got %v", counts)
	}
}

func TestRedactText_KeepHostnames(t *testing.T) {
	t.Parallel()
	input := "host web-prod-01 reachable at 10.20.30.40"
	out, counts := RedactText(input, "web-prod-01", RedactOptions{KeepHostnames: true})
	if !strings.Contains(out, "web-prod-01") {
		t.Errorf("expected hostname kept, got:\n%s", out)
	}
	if strings.Contains(out, "10.20.30.40") {
		t.Errorf("expected IP still redacted, got:\n%s", out)
	}
	if counts["hostnames"] != 0 {
		t.Errorf("expected zero hostname redactions, got %d", counts["hostnames"])
	}
	if counts["ips"] == 0 {
		t.Errorf("expected ip redactions to still occur, got %v", counts)
	}
}

func TestRedactText_KeepIPs(t *testing.T) {
	t.Parallel()
	input := "host web-prod-01 reachable at 10.20.30.40"
	out, counts := RedactText(input, "web-prod-01", RedactOptions{KeepIPs: true})
	if strings.Contains(out, "web-prod-01") {
		t.Errorf("expected hostname redacted, got:\n%s", out)
	}
	if !strings.Contains(out, "10.20.30.40") {
		t.Errorf("expected IP kept, got:\n%s", out)
	}
	if counts["ips"] != 0 {
		t.Errorf("expected zero ip redactions, got %d", counts["ips"])
	}
}

func TestRedactText_LoopbackIPKept(t *testing.T) {
	t.Parallel()
	out, counts := RedactText("gateway 127.0.0.1 and 0.0.0.0 present", "host", RedactOptions{})
	if !strings.Contains(out, "127.0.0.1") || !strings.Contains(out, "0.0.0.0") {
		t.Errorf("expected loopback/unspecified IPs to be kept, got:\n%s", out)
	}
	if counts["ips"] != 0 {
		t.Errorf("expected zero ip redactions for loopback-only input, got %d", counts["ips"])
	}
}

func TestRedactJSONBytes_SecretsAndIdentifiers(t *testing.T) {
	t.Parallel()
	input := []byte(`{"hostname":"web-prod-01","note":"password=hunter2seedvalue","ip":"10.20.30.40","contact":"admin@example.com"}`)

	out, counts, err := RedactJSONBytes(input, "web-prod-01", RedactOptions{})
	if err != nil {
		t.Fatalf("RedactJSONBytes: %v", err)
	}
	s := string(out)
	for _, gone := range []string{"hunter2seedvalue", "web-prod-01", "10.20.30.40", "admin@example.com"} {
		if strings.Contains(s, gone) {
			t.Errorf("expected %q redacted from JSON, still present:\n%s", gone, s)
		}
	}
	if counts.Total() == 0 {
		t.Errorf("expected nonzero total redactions, got %v", counts)
	}

	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("redacted output is not valid JSON: %v\n%s", err, s)
	}
}

func TestRedactJSONBytes_Disabled(t *testing.T) {
	t.Parallel()
	input := []byte(`{"hostname":"web-prod-01"}`)
	out, counts, err := RedactJSONBytes(input, "web-prod-01", RedactOptions{Disabled: true})
	if err != nil {
		t.Fatalf("RedactJSONBytes: %v", err)
	}
	if string(out) != string(input) {
		t.Errorf("expected unchanged output with Disabled, got:\n%s", out)
	}
	if len(counts) != 0 {
		t.Errorf("expected zero counts with Disabled, got %v", counts)
	}
}

func TestCounts_Summary(t *testing.T) {
	t.Parallel()
	if got := (Counts{}).Summary(); got != "none" {
		t.Errorf("expected \"none\" for empty Counts, got %q", got)
	}
	c := Counts{"ips": 2, "secrets": 1}
	got := c.Summary()
	want := "2 ips, 1 secrets" // alphabetical by key
	if got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}
	if c.Total() != 3 {
		t.Errorf("Total() = %d, want 3", c.Total())
	}
}
