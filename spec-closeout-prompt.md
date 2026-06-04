# Spec Close-Out Batch — Compose detection + TLS remote endpoints + OOM leak rule

## What this is

Three self-contained additions that close out the remaining buildable gap spec items.
Each is independent — if one fails build, the others are unaffected.

Read `BACKLOG.md` and `DashDiag_Gap_Specs.md` sections referenced below before starting.
Do the changes in order: 1 → 2 → 3. Build and test after each one.

---

## Item 1 — Spec 7d: Docker Compose version detection (30 min)

### Context

Read first:
- `internal/collectors/docker.go` — `collectDaemonHealth()` function (~line 590)
- `internal/models/docker.go` — `DockerDaemon` struct
- `cmd/docker.go` — how the daemon section is rendered (find `printDockerDaemon`)

### What to add to `DockerDaemon` in `internal/models/docker.go`

```go
// Compose detection (Spec 7d)
ComposePlugin     string `json:"compose_plugin,omitempty"`     // "2.29.1" if docker compose plugin found
ComposeStandalone string `json:"compose_standalone,omitempty"` // "1.29.2" if docker-compose standalone found
```

### What to add to `collectDaemonHealth()` in `internal/collectors/docker.go`

After the existing version and storage driver collection, add:

```go
// Spec 7d: Compose version detection
d.ComposePlugin = detectComposePlugin(ctx)
d.ComposeStandalone = detectComposeStandalone(ctx)
```

Add these two functions anywhere in `docker.go`:

```go
// detectComposePlugin returns the docker compose v2 plugin version string,
// or "" when the plugin is not installed or the command fails.
// Uses `docker compose version --short` — exits 0 on v2, exits 1 on older Docker.
func detectComposePlugin(ctx context.Context) string {
	cCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := runCmd(cCtx, "docker", "compose", "version", "--short")
	if err != nil {
		return ""
	}
	// Output: "v2.29.1\n" or "2.29.1\n"
	ver := strings.TrimSpace(out)
	ver = strings.TrimPrefix(ver, "v")
	if ver == "" {
		return ""
	}
	return ver
}

// detectComposeStandalone returns the docker-compose v1 standalone version string,
// or "" when not installed. Uses `docker-compose version --short`.
func detectComposeStandalone(ctx context.Context) string {
	cCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := runCmd(cCtx, "docker-compose", "version", "--short")
	if err != nil {
		return ""
	}
	ver := strings.TrimSpace(out)
	ver = strings.TrimPrefix(ver, "v")
	return ver
}
```

### What to add to heuristics for Compose

In `internal/analysis/heuristics.go`, find `checkDockerDaemon` or wherever
`DockerDaemon` is checked. Add:

```go
// Spec 7d: Compose version
if d.Daemon != nil {
    if d.Daemon.ComposeStandalone != "" && d.Daemon.ComposePlugin != "" {
        out = append(out, insight("WARN", "Docker",
            fmt.Sprintf("both docker-compose v1 (%s) and docker compose v2 (%s) installed — scripts may use the wrong one",
                d.Daemon.ComposeStandalone, d.Daemon.ComposePlugin),
            []string{
                "to fix: remove docker-compose (v1) and use docker compose (v2) plugin only",
                "to inspect: which docker-compose && docker compose version",
            },
        ))
    } else if d.Daemon.ComposeStandalone != "" && d.Daemon.ComposePlugin == "" {
        out = append(out, insight("WARN", "Docker",
            fmt.Sprintf("docker-compose v1 (%s) installed — standalone is deprecated, migrate to docker compose plugin",
                d.Daemon.ComposeStandalone),
            []string{
                "to fix: apt install docker-compose-plugin  OR  dnf install docker-compose-plugin",
                "to migrate: replace 'docker-compose' with 'docker compose' in scripts",
            },
        ))
    }
}
```

### What to add to `cmd/docker.go` rendering

Find where daemon version/storage driver is printed. Add Compose output after it:

```go
// Compose (Spec 7d)
if d.Daemon != nil {
    switch {
    case d.Daemon.ComposePlugin != "" && d.Daemon.ComposeStandalone != "":
        fmt.Printf("  ⚠️   Compose: v%s (plugin) + v%s (standalone) — both present\n",
            d.Daemon.ComposePlugin, d.Daemon.ComposeStandalone)
    case d.Daemon.ComposePlugin != "":
        fmt.Printf("  ✅  Compose: v%s (plugin)\n", d.Daemon.ComposePlugin)
    case d.Daemon.ComposeStandalone != "":
        fmt.Printf("  ⚠️   Compose: v%s (standalone — deprecated)\n", d.Daemon.ComposeStandalone)
    default:
        fmt.Printf("  ℹ️   Compose: not installed\n")
    }
}
```

### Verification for Item 1

```bash
make release
scp dist/dsd-linux-amd64 root@192.168.10.8:/tmp/dsd   # AlmaLinux CT
ssh root@192.168.10.8 '/tmp/dsd docker 2>/dev/null | grep -i compose'
```
Expected: either a version line or "not installed".

---

## Item 2 — TLS remote endpoint expiry check (2h)

### Context

Read first:
- `internal/collectors/tls.go` (142 lines) — existing local cert scanner
- `internal/models/tls.go` — `TLSInfo`, `CertInfo` structs
- `cmd/health.go` lines ~455 — `--tls` flag and `NewTLSCollector()` wiring
- `cmd/disk.go` — pattern for a flag-driven standalone command

The existing `dsd health --tls` only scans local cert files. This adds:
- A new standalone `dsd tls` command (currently missing — only health --tls exists)
- `--endpoint host:port` flag: dial the remote TLS endpoint, parse the cert chain,
  report expiry same as local cert format
- `--endpoints-file path`: read newline-separated `host:port` list from a file

### New file: `cmd/tls.go`

Create a new standalone `dsd tls` command:

```go
package cmd

// tls.go — dsd tls
// Scans local certificate files AND optional remote TLS endpoints for expiry.
// Local scan: same paths as dsd health --tls (existing TLSCollector).
// Remote scan: dials host:port, retrieves the cert chain, checks expiry.
//
// Usage:
//   dsd tls                                    # local certs only
//   dsd tls --endpoint example.com:443         # + remote endpoint
//   dsd tls --endpoints-file /etc/dsd/tls.txt  # + list of endpoints

import (
    ...
)

func init() {
    rootCmd.AddCommand(tlsCmd)
    tlsCmd.Flags().StringArray("endpoint", nil, "remote TLS endpoint to check (host:port)")
    tlsCmd.Flags().String("endpoints-file", "", "file with newline-separated host:port endpoints")
    tlsCmd.Flags().Bool("json", false, "JSON output")
}

var tlsCmd = &cobra.Command{
    Use:   "tls",
    Short: "TLS certificate health — local files + remote endpoint expiry",
    RunE:  runTLS,
}
```

### New file: `internal/collectors/tls_remote.go`

```go
//go:build linux || darwin

package collectors

import (
    "context"
    "crypto/tls"
    "net"
    "time"

    "github.com/keyorixhq/dashdiag/internal/models"
)

// CheckRemoteEndpoint dials host:port over TLS, retrieves the peer certificate
// chain, and returns CertInfo for each cert (leaf first).
// Uses a 5-second dial+handshake timeout. Skips verification so expired certs
// are still readable (we want to *report* expired, not refuse to connect).
func CheckRemoteEndpoint(ctx context.Context, endpoint string) ([]models.CertInfo, error) {
    dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()

    dialer := &net.Dialer{}
    rawConn, err := dialer.DialContext(dialCtx, "tcp", endpoint)
    if err != nil {
        return nil, err
    }
    defer rawConn.Close()

    // Extract host for SNI (strip port)
    host, _, _ := net.SplitHostPort(endpoint)

    tlsConn := tls.Client(rawConn, &tls.Config{
        ServerName:         host,
        InsecureSkipVerify: true, // #nosec G402 — intentional: report expired certs
    })
    tlsConn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

    if err := tlsConn.Handshake(); err != nil {
        // Handshake may fail for expired certs on strict servers — still try to
        // read the peer certs from the connection state.
        if len(tlsConn.ConnectionState().PeerCertificates) == 0 {
            return nil, err
        }
    }

    now := time.Now()
    var certs []models.CertInfo
    for _, cert := range tlsConn.ConnectionState().PeerCertificates {
        expiresIn := int(cert.NotAfter.Sub(now).Hours() / 24)
        certs = append(certs, models.CertInfo{
            Path:         endpoint, // use endpoint as "path" for display
            Subject:      cert.Subject.CommonName,
            Issuer:       cert.Issuer.CommonName,
            ExpiresIn:    expiresIn,
            NotAfter:     cert.NotAfter.Format("2006-01-02"),
            IsSelfSigned: cert.Subject.CommonName == cert.Issuer.CommonName,
        })
    }
    return certs, nil
}
```

### Extend `TLSInfo` in `internal/models/tls.go`

Add one field:

```go
RemoteEndpoints []string `json:"remote_endpoints,omitempty"` // endpoints that were checked
```

(The `Certs` slice already holds all certs — local and remote mixed together.
Remote certs are identified by their `Path` field being a `host:port` string.)

### `runTLS` in `cmd/tls.go`

The function:
1. Runs the existing `TLSCollector` to get local certs
2. For each `--endpoint` arg and each line from `--endpoints-file`: calls
   `CheckRemoteEndpoint()` and appends results to `info.Certs`
3. Prints unified output sorted by `ExpiresIn` ascending (soonest first)

Output format for a remote endpoint:

```
Remote endpoints:
  ❌ 192.168.10.20:8006  CN=pve01.local  expired 3 days ago  [self-signed]
  ✅ example.com:443     CN=example.com  expires in 47 days
```

Local cert format: same as existing `dsd health --tls` output.

Summary line:
```
──────────────────────────────────────────
❌  2 expired, 1 expiring (< 30d), 14 OK
```

`--json` output: serialize `TLSInfo` including the remote certs (same struct,
remote certs have `path` = `host:port`).

### Verification for Item 2

```bash
make release
scp dist/dsd-linux-amd64 root@192.168.10.20:/tmp/dsd
# Proxmox web UI uses a self-signed cert — good test case:
ssh root@192.168.10.20 '/tmp/dsd tls --endpoint 192.168.10.20:8006 2>/dev/null'
# Expected: shows Proxmox self-signed cert with expiry date
/tmp/dsd tls --json 2>/dev/null | python3 -m json.tool | head -20
# Expected: valid JSON with certs array
```

---

## Item 3 — 4th correlation rule: service memory leak pattern (45 min)

### Context

Read first:
- `internal/analysis/correlate.go` lines 370-420 — `CorrelateDeep` and existing deep rules
- `internal/models/oom.go` — `OOMInfo`, `OOMEvent` struct fields
- `internal/analysis/correlate_test.go` lines 405-415 — `makeOOM` helper

### What to check in `OOMEvent`

```bash
grep -n "type OOMEvent\|Process\|Name\|Service" internal/models/oom.go
```

The `OOMEvent.Process` field holds the killed process name. The rule fires when
the same process name appears in ≥2 OOM events within 24h — distinct from the
`ruleHardOOM` (which fires on memory CRIT + logs CRIT regardless of which process).

### New rule in `internal/analysis/correlate.go`

Add to `CorrelateDeep()` after the `ruleIOSingleDeviceDegradation` call:

```go
if c, ok := ruleServiceMemoryLeak(oom); ok {
    out = append(out, c)
}
```

Rule function (add after `ruleIOSingleDeviceDegradation`):

```go
// ruleServiceMemoryLeak fires when the OOM killer repeatedly terminates the
// same process — a pattern that distinguishes a memory leak in one specific
// service from general system memory pressure. General pressure kills
// different processes; a leaking service is killed repeatedly as it grows.
//
// Required signals (raw OOMInfo):
//   - oom.EventsLast24h >= 2
//   - At least one process name appears in ≥ 2 OOMEvent entries
//   - The repeated kills must be of the same named process
func ruleServiceMemoryLeak(oom *models.OOMInfo) (Correlation, bool) {
	if oom == nil || oom.EventsLast24h < 2 || len(oom.RecentEvents) < 2 {
		return Correlation{}, false
	}

	// Count kills per process name
	counts := make(map[string]int)
	for _, e := range oom.RecentEvents {
		if e.Process != "" {
			counts[e.Process]++
		}
	}

	// Find the process killed most often (must be ≥ 2)
	var leaker string
	var maxCount int
	for proc, n := range counts {
		if n > maxCount {
			maxCount = n
			leaker = proc
		}
	}

	if maxCount < 2 || leaker == "" {
		return Correlation{}, false
	}

	return Correlation{
		Name:  "Repeated OOM Kill — Possible Memory Leak",
		Level: "WARN",
		Summary: fmt.Sprintf("%s was OOM-killed %d times in the last 24h — this pattern suggests a memory leak rather than general memory pressure",
			leaker, maxCount),
		Action: fmt.Sprintf("check %s memory growth: ps aux | grep %s && journalctl -u %s --since '24h ago' | grep -i 'memory\\|oom'",
			leaker, leaker, leaker),
		Checks: []string{"OOM"},
	}, true
}
```

### Tests for Item 3

Add to `internal/analysis/correlate_test.go` (after the existing Item 2 correlation tests):

```go
// ── ruleServiceMemoryLeak ─────────────────────────────────────────────────

func TestServiceMemoryLeakFires(t *testing.T) {
	oom := makeOOM(3,
		models.OOMEvent{Process: "nginx"},
		models.OOMEvent{Process: "nginx"},
		models.OOMEvent{Process: "redis-server"},
	)
	// nginx killed twice — should fire
	c, ok := ruleServiceMemoryLeak(oom)
	if !ok {
		t.Fatal("expected rule to fire when same process killed 2+ times")
	}
	if c.Level != "WARN" {
		t.Errorf("expected WARN, got %q", c.Level)
	}
	if !strings.Contains(c.Summary, "nginx") {
		t.Errorf("summary should name the leaking process, got: %q", c.Summary)
	}
	if !strings.Contains(c.Summary, "2 times") {
		t.Errorf("summary should state kill count, got: %q", c.Summary)
	}
}

func TestServiceMemoryLeakDoesNotFireWhenAllDifferent(t *testing.T) {
	oom := makeOOM(3,
		models.OOMEvent{Process: "nginx"},
		models.OOMEvent{Process: "redis-server"},
		models.OOMEvent{Process: "postgres"},
	)
	// All different — general pressure, not a leak
	if _, ok := ruleServiceMemoryLeak(oom); ok {
		t.Error("should not fire when all OOM kills are different processes")
	}
}

func TestServiceMemoryLeakDoesNotFireWithOnlyOneEvent(t *testing.T) {
	oom := makeOOM(1, models.OOMEvent{Process: "nginx"})
	if _, ok := ruleServiceMemoryLeak(oom); ok {
		t.Error("should not fire with only one OOM event")
	}
}

func TestServiceMemoryLeakDoesNotFireWithNilOOM(t *testing.T) {
	if _, ok := ruleServiceMemoryLeak(nil); ok {
		t.Error("should not fire with nil OOMInfo")
	}
}

func TestServiceMemoryLeakDoesNotFireWithNoNamedProcesses(t *testing.T) {
	// Events with empty process names should be ignored
	oom := makeOOM(3,
		models.OOMEvent{Process: ""},
		models.OOMEvent{Process: ""},
		models.OOMEvent{Process: ""},
	)
	if _, ok := ruleServiceMemoryLeak(oom); ok {
		t.Error("should not fire when process names are all empty")
	}
}
```

---

## Verification checklist (all three items)

Run in this order:

```bash
# 1. Build
go build ./...

# 2. Tests
go test -race ./...

# 3. Lint (expect same 5 pre-existing issues, no new ones)
golangci-lint run ./...

# 4. Item 1 — Compose on Docker host
make release
scp dist/dsd-linux-amd64 root@192.168.10.8:/tmp/dsd   # AlmaLinux CT 213
ssh root@192.168.10.8 '/tmp/dsd docker 2>/dev/null | grep -i compose'

# 5. Item 2 — Remote TLS endpoint (Proxmox self-signed cert)
scp dist/dsd-linux-amd64 root@192.168.10.20:/tmp/dsd   # PVE01
ssh root@192.168.10.20 '/tmp/dsd tls --endpoint 192.168.10.20:8006 2>/dev/null'
ssh root@192.168.10.20 '/tmp/dsd tls --json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d[\"certs\"]), \"certs found\")"'

# 6. Item 3 — Correlation rule (unit test coverage sufficient; no live node fires expected)
go test -race ./internal/analysis/... -run "TestServiceMemoryLeak"
```

---

## Commit message

```
feat: Compose detection (7d), TLS remote endpoints, OOM leak correlation rule

feat(docker): Spec 7d — Compose v1/v2 detection in daemon health
- models/docker.go: ComposePlugin, ComposeStandalone fields on DockerDaemon
- collectors/docker.go: detectComposePlugin() + detectComposeStandalone()
  via docker compose version / docker-compose version with 3s timeout
- heuristics.go: WARN when both v1+v2 present, WARN when standalone-only
- cmd/docker.go: Compose line in daemon section output

feat(tls): dsd tls standalone command + remote endpoint expiry check
- cmd/tls.go: new command with --endpoint, --endpoints-file, --json flags
- collectors/tls_remote.go: CheckRemoteEndpoint() — TLS dial with
  InsecureSkipVerify to read expired certs, 5s timeout
- models/tls.go: RemoteEndpoints field
- Verified: Proxmox self-signed cert on 192.168.10.20:8006

feat(correlate): ruleServiceMemoryLeak — same process OOM-killed 2+ times
- Distinguishes memory leak (same process killed repeatedly) from general
  memory pressure (different processes killed)
- correlate_test.go: 5 new tests covering fires/no-fire cases
```
