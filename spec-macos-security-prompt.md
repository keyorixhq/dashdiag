# macOS security checks — security_darwin.go

## What this builds

A new `internal/collectors/security_darwin.go` that replaces the zero-value
stub in `security_notlinux.go` for darwin builds. Adds real security checks
for macOS. Also fixes two false positives from the existing zero-value stub.

Read these files completely before writing anything:
- `internal/collectors/security_notlinux.go` (current stub — 37 lines)
- `internal/collectors/security_linux.go` (reference — specifically parseSSHConfig, parseSSHFileContent, parseSudoers, parseListeningPorts, parseSuspectCrons)
- `internal/models/security.go` (SecurityInfo struct — all fields)
- `internal/collectors/auth_darwin.go` (pattern for darwin build tag + sshdRunningDarwin helper)
- `internal/collectors/thermal_notlinux.go` (pattern for ioreg + runCmd on darwin)
- `internal/analysis/heuristics.go` — find checkSecurity() to understand which SecurityInfo fields drive which insights

---

## The two false positives to fix first

Before building the darwin collector, understand why they fire:

**False positive 1: `SSHStrictModes` WARN in `dsd health`**
`security_notlinux.go` returns `&models.SecurityInfo{}` — all zero values.
`SSHStrictModes bool` defaults to `false`. `checkSecurity()` fires:
```go
if !sec.SSHStrictModes { // fires because false == 0-value }
```
But OpenSSH default is `StrictModes yes`. The fix: set correct defaults
in the darwin collector, same as `parseSSHConfig` does on Linux (line 98-100):
```go
info.SSHStrictModes = true  // OpenSSH default
info.SSHPubkeyAuth = true   // OpenSSH default
info.SSHIgnoreRhosts = true // OpenSSH default
```

**False positive 2: `auditd running, no rules` WARN on macOS**
macOS has a BSM-based `auditd` that is completely different from Linux auditd.
The "no rules configured" WARN from `checkSecurity()` does not apply to macOS.
Fix: do not set `AuditRules` on darwin (leave it at -1 = unavailable, which
the heuristic already guards against).

---

## New file: `internal/collectors/security_darwin.go`

Build tag: `//go:build darwin`

### Struct and constructors

Keep the exact same signatures as `security_notlinux.go` — same type, same
constructor names, same exported functions. The linux, notlinux, and darwin
files are all mutually exclusive via build tags, so they must agree on the
exported surface:

```go
//go:build darwin

package collectors

import (
    "bufio"
    "context"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "time"

    "github.com/keyorixhq/dashdiag/internal/models"
    "github.com/keyorixhq/dashdiag/internal/platform"
)

type SecurityCollector struct {
    profile platform.Profile
}

func NewSecurityCollector() *SecurityCollector { return &SecurityCollector{} }
func NewSecurityCollectorWithProfile(p platform.Profile) *SecurityCollector {
    return &SecurityCollector{profile: p}
}
func (c *SecurityCollector) Name() string           { return "Hardening" }
func (c *SecurityCollector) Timeout() time.Duration { return 8 * time.Second }

func CollectSUSEConnect(_ context.Context, _ *models.SecurityInfo) {}
func ScanSUIDBinaries(_ *models.SecurityInfo)                      {}
```

### Collect() — the main function

```go
func (c *SecurityCollector) Collect(ctx context.Context) (interface{}, error) {
    info := &models.SecurityInfo{}

    parseDarwinSSHConfig(info)
    parseDarwinListeningPorts(ctx, info)
    parseDarwinSudoers(info)
    parseDarwinFirewall(info)
    parseDarwinSystemSecurity(info)
    parseDarwinSuspectLaunchd(ctx, info)

    return info, nil
}
```

### parseDarwinSSHConfig

macOS sshd config is at `/etc/ssh/sshd_config` with drop-ins at
`/etc/ssh/sshd_config.d/*.conf`. `sshd -T` fails without hostkeys
(`sshd: no hostkeys available -- exiting.`) so go directly to file parsing.

**IMPORTANT:** Set OpenSSH defaults before parsing, because the macOS
`sshd_config` ships with everything commented out. The defaults reflect
what OpenSSH applies when a key is absent:

```go
func parseDarwinSSHConfig(info *models.SecurityInfo) {
    // Set OpenSSH defaults — macOS ships sshd_config with all settings
    // commented out. These reflect what OpenSSH uses when absent.
    info.SSHStrictModes = true  // StrictModes yes (default)
    info.SSHPubkeyAuth = true   // PubkeyAuthentication yes (default)
    info.SSHIgnoreRhosts = true // IgnoreRhosts yes (default)
    info.SSHPasswordAuth = true // PasswordAuthentication yes (macOS default — different from Linux hardened defaults)

    // macOS 100-macos.conf drop-in may override — check it
    paths := []string{"/etc/ssh/sshd_config"}
    if dropins, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
        paths = append(paths, dropins...)
    }
    for _, p := range paths {
        parseDarwinSSHFile(p, info)
    }
}
```

`parseDarwinSSHFile` — read the file and call `parseSSHFileContent`. BUT:
`parseSSHFileContent` is defined in `security_linux.go` with `//go:build linux`.
Do NOT call it from the darwin file.

Instead, inline a minimal version that covers the fields used by `checkSecurity()`.
Check which fields `checkSecurity()` actually tests — read it first. Only parse
the keys that drive heuristics:

```go
func parseDarwinSSHFile(path string, info *models.SecurityInfo) {
    data, err := os.ReadFile(path) // #nosec G304 -- well-known config path
    if err != nil {
        return
    }
    scanner := bufio.NewScanner(strings.NewReader(string(data)))
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if strings.HasPrefix(line, "#") || line == "" {
            continue
        }
        fields := strings.Fields(line)
        if len(fields) < 2 {
            continue
        }
        key := strings.ToLower(fields[0])
        val := strings.ToLower(fields[1])
        switch key {
        case "permitrootlogin":
            info.SSHRootLogin = val == "yes"
            info.SSHPermitRoot = val != "no" && val != "prohibit-password" && val != "without-password"
        case "passwordauthentication":
            info.SSHPasswordAuth = val == "yes"
        case "strictmodes":
            info.SSHStrictModes = val != "no"
        case "permitemptypasswords":
            info.SSHPermitEmptyPwd = val == "yes"
        case "maxauthtries":
            if n, err := strconv.Atoi(val); err == nil {
                info.SSHMaxAuthTries = n
            }
        case "clientaliveinterval":
            if n, err := strconv.Atoi(val); err == nil {
                info.SSHClientAliveInterval = n
            }
        }
    }
}
```

Add `"strconv"` to imports.

### parseDarwinListeningPorts

Linux uses `/proc/net/tcp`. macOS doesn't have `/proc`. Use `lsof`:

```go
func parseDarwinListeningPorts(ctx context.Context, info *models.SecurityInfo) {
    // -iTCP:LISTEN  — only TCP listening sockets
    // -n            — no hostname resolution (faster)
    // -P            — no port name resolution (show numbers)
    out, err := runCmd(ctx, "lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P")
    if err != nil {
        return
    }
    seen := map[int]bool{}
    for _, line := range strings.Split(out, "\n") {
        fields := strings.Fields(line)
        if len(fields) < 9 {
            continue
        }
        // COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        // NAME format: *:5432 or 127.0.0.1:5432 or [::]:5432
        name := fields[8]
        colon := strings.LastIndex(name, ":")
        if colon < 0 {
            continue
        }
        portStr := name[colon+1:]
        port, err := strconv.Atoi(portStr)
        if err != nil || seen[port] {
            continue
        }
        seen[port] = true
        procName := fields[0] // command name from lsof
        info.ListeningPorts = append(info.ListeningPorts, models.PortEntry{
            Port:     port,
            Protocol: "tcp",
            Process:  procName,
            Expected: isDarwinExpectedPort(port),
        })
    }
}

func isDarwinExpectedPort(port int) bool {
    switch port {
    case 22, 80, 443:
        return true
    }
    return false
}
```

### parseDarwinSudoers

Same logic as Linux — `/etc/sudoers` + `/private/etc/sudoers.d/` on macOS:

```go
func parseDarwinSudoers(info *models.SecurityInfo) {
    paths := []string{"/etc/sudoers", "/private/etc/sudoers"}
    for _, p := range []string{"/private/etc/sudoers.d", "/etc/sudoers.d"} {
        if entries, err := filepath.Glob(p + "/*"); err == nil {
            paths = append(paths, entries...)
        }
    }
    seen := map[string]bool{}
    for _, p := range paths {
        if seen[p] {
            continue
        }
        seen[p] = true
        parseDarwinSudoersFile(p, info)
    }
}

func parseDarwinSudoersFile(path string, info *models.SecurityInfo) {
    f, err := os.Open(filepath.Clean(path)) // #nosec G304
    if err != nil {
        return
    }
    defer f.Close() //nolint:errcheck
    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if strings.HasPrefix(line, "#") || !strings.Contains(line, "NOPASSWD") {
            continue
        }
        fields := strings.Fields(line)
        if len(fields) > 0 && fields[0] != "ALL" {
            info.SudoNopasswd = append(info.SudoNopasswd, fields[0])
        }
    }
}
```

### parseDarwinFirewall

macOS Application Firewall via `socketfilterfw`:

```go
func parseDarwinFirewall(info *models.SecurityInfo) {
    fw := "/usr/libexec/ApplicationFirewall/socketfilterfw"
    out, err := exec.Command(fw, "--getglobalstate").Output()
    if err != nil {
        return
    }
    lower := strings.ToLower(strings.TrimSpace(string(out)))
    // "Firewall is enabled. (State = 1)"
    // "Firewall is disabled. (State = 0)"
    if strings.Contains(lower, "enabled") {
        info.FirewallActive = true
        info.FirewallType = "macOS Application Firewall"
    }
    // macOS Application Firewall doesn't block SSH port directly;
    // SSH is controlled by System Settings > Sharing > Remote Login.
    // When the firewall is active, assume SSH is allowed (it uses a separate mechanism).
    info.SSHAllowed = true
}
```

### parseDarwinSystemSecurity

The three macOS-specific security checks: FileVault, SIP, Gatekeeper.
Add three new fields to `SecurityInfo` (see Part 2 below).

```go
func parseDarwinSystemSecurity(info *models.SecurityInfo) {
    // FileVault disk encryption
    if out, err := exec.Command("fdesetup", "status").Output(); err == nil {
        info.FileVaultEnabled = strings.Contains(strings.ToLower(string(out)), "filevault is on")
    }

    // System Integrity Protection
    if out, err := exec.Command("csrutil", "status").Output(); err == nil {
        info.SIPEnabled = strings.Contains(strings.ToLower(string(out)), "enabled")
    }

    // Gatekeeper
    if out, err := exec.Command("spctl", "--status").Output(); err == nil {
        info.GatekeeperEnabled = strings.Contains(strings.ToLower(string(out)), "assessments enabled")
    }
}
```

### parseDarwinSuspectLaunchd

Scan `/Library/LaunchDaemons/` for suspicious patterns — equivalent of
`parseSuspectCrons` on Linux. LaunchDaemons run as root and are a common
persistence vector for macOS malware.

```go
func parseDarwinSuspectLaunchd(ctx context.Context, info *models.SecurityInfo) {
    _ = ctx
    dirs := []string{
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
    }
    suspectPatterns := []string{
        "/tmp/", "/var/tmp/",           // executing from world-writable
        "curl ", "wget ",               // downloading at runtime
        "| bash", "| sh", "|bash",     // piping to shell
        "chmod +s", "chmod 4",          // setting SUID
        "/dev/tcp",                     // raw TCP (reverse shell indicator)
    }
    for _, dir := range dirs {
        entries, err := os.ReadDir(dir)
        if err != nil {
            continue
        }
        for _, e := range entries {
            if e.IsDir() || !strings.HasSuffix(e.Name(), ".plist") {
                continue
            }
            path := filepath.Join(dir, e.Name())
            data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304
            if err != nil {
                continue
            }
            content := string(data)
            for _, pat := range suspectPatterns {
                if strings.Contains(content, pat) {
                    entry := e.Name() + ": " + pat
                    info.SuspectCrons = append(info.SuspectCrons, entry)
                    break
                }
            }
        }
    }
}
```

`SuspectCrons` reuses the existing `SecurityInfo.SuspectCrons` field — same
heuristic fires for both Linux cron injections and macOS launchd persistence.
The field name is "crons" but the semantics map cleanly.

---

## Part 2 — Add three new fields to SecurityInfo

**File:** `internal/models/security.go`

Add after the `IsPVE` field at the end of the struct:

```go
// macOS-specific security checks
FileVaultEnabled   bool `json:"filevault_enabled,omitempty"`   // disk encryption on
SIPEnabled         bool `json:"sip_enabled,omitempty"`         // System Integrity Protection
GatekeeperEnabled  bool `json:"gatekeeper_enabled,omitempty"`  // Gatekeeper app validation
```

---

## Part 3 — Add heuristics for the three new fields

**File:** `internal/analysis/heuristics.go`

Find `checkSecurity()` — it already checks `sec.FirewallActive`, `sec.SSHStrictModes`, etc.

Add at the end of `checkSecurity()`, before the final `return out`:

```go
// macOS-specific checks (fields are false on Linux — guards are safe)
if sec.FileVaultEnabled == false && (sec.GatekeeperEnabled || sec.SIPEnabled) {
    // Only warn if at least one macOS check ran (avoid false positive on Linux)
    // Actually: FileVaultEnabled=false AND SIPEnabled=false AND GatekeeperEnabled=false
    // means this is Linux (all omitempty fields). Gate on SIPEnabled presence.
}
```

Actually: the cleanest gate is a new `IsDarwin bool` field on `SecurityInfo`
set to `true` only in the darwin collector. OR, simpler: check if at least one
of the three darwin-specific fields is non-zero (SIPEnabled would be true on a
healthy mac, so its absence means Linux). But that's fragile.

**Better approach:** Add `IsDarwin bool json:"is_darwin,omitempty"` to SecurityInfo,
set `info.IsDarwin = true` in `parseDarwinSystemSecurity`, then gate the
macOS heuristics on `sec.IsDarwin`:

```go
if sec.IsDarwin {
    if !sec.FileVaultEnabled {
        out = append(out, insight("WARN", "Hardening",
            "FileVault disk encryption is off — data is readable if the disk is removed",
            []string{
                "to fix: System Settings → Privacy & Security → FileVault → Turn On",
            },
        ))
    }
    if !sec.SIPEnabled {
        out = append(out, insight("CRIT", "Hardening",
            "System Integrity Protection (SIP) is disabled — system files are unprotected",
            []string{
                "to fix: boot to Recovery, open Terminal, run: csrutil enable",
                "note: SIP disabled is required for some development tools — verify intentional",
            },
        ))
    }
    if !sec.GatekeeperEnabled {
        out = append(out, insight("WARN", "Hardening",
            "Gatekeeper is disabled — unsigned apps can run without quarantine",
            []string{
                "to fix: System Settings → Privacy & Security → set to App Store and identified developers",
                "or: sudo spctl --master-enable",
            },
        ))
    }
}
```

Add `IsDarwin bool json:"is_darwin,omitempty"` to `internal/models/security.go`.

---

## Part 4 — Remove security_notlinux.go and replace

After `security_darwin.go` is working, the `security_notlinux.go` file needs
a more specific build tag so it doesn't also compile on darwin.

**File:** `internal/collectors/security_notlinux.go`

Change the build tag from:
```go
//go:build !linux
```
to:
```go
//go:build !linux && !darwin
```

This makes the build matrix:
- linux → security_linux.go
- darwin → security_darwin.go  (new)
- everything else → security_notlinux.go (zero-value stub, unchanged)

---

## Verification

```bash
# 1. Build — both platforms
go build ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...

# 2. Tests
go test -race ./...
go test -race ./internal/collectors/... -run Darwin
go test -race ./internal/analysis/...

# 3. Lint
golangci-lint run ./...

# 4. Run on macOS — the main verification
./dist/dsd-darwin-arm64 security 2>/dev/null
# Expected sections: SSH Configuration, Listening Ports, Sudo NOPASSWD,
# Firewall, macOS Security (FileVault/SIP/Gatekeeper)
# NOT expected: "auditd: running, no rules configured"

./dist/dsd-darwin-arm64 security --json 2>/dev/null | python3 -m json.tool | \
  grep -E "filevault|sip_enabled|gatekeeper|firewall|strict_modes|is_darwin"
# Expected: filevault_enabled: true, sip_enabled: true,
#           gatekeeper_enabled: true, ssh_strict_modes: true, is_darwin: true

./dist/dsd-darwin-arm64 health 2>/dev/null | grep "Hardening"
# Expected: ✅ or specific real WARNs
# NOT expected: "SSH StrictModes disabled" (was false positive from zero-value)

# 5. FileVault/SIP/Gatekeeper insights
./dist/dsd-darwin-arm64 health 2>/dev/null | grep -i "filevault\|SIP\|gatekeeper"
# Expected: no output (all enabled on this machine)
# To test WARN path: disable Gatekeeper temporarily:
#   sudo spctl --master-disable
#   ./dist/dsd-darwin-arm64 security 2>/dev/null | grep Gatekeeper
#   sudo spctl --master-enable

# 6. Listening ports actually shows processes
./dist/dsd-darwin-arm64 security 2>/dev/null | grep -A10 "Listening Ports"
# Expected: ports with process names (rapportd, postgres, etc.)
# Previously showed "0 total" — this is the key improvement

# 7. Deploy to Linux and confirm no regression
make release
scp dist/dsd-linux-amd64 root@192.168.10.8:/tmp/dsd
ssh root@192.168.10.8 '/tmp/dsd security --json 2>/dev/null | python3 -m json.tool | grep -E "sip|gatekeeper|filevault|is_darwin"'
# Expected: none of these fields (omitempty, not set on Linux)
ssh root@192.168.10.8 '/tmp/dsd security 2>/dev/null | head -5'
# Expected: normal Linux output unchanged
```

---

## Commit message

```
feat(darwin): macOS security checks — FileVault, SIP, Gatekeeper, firewall, ports, sudoers

- internal/collectors/security_darwin.go: new darwin security collector
  parseDarwinSSHConfig: file-based (sshd -T unavailable without hostkeys);
    sets correct OpenSSH defaults before parsing (fixes SSHStrictModes false positive)
  parseDarwinListeningPorts: lsof -iTCP:LISTEN with process names (was: 0 total)
  parseDarwinSudoers: /etc/sudoers + /private/etc/sudoers.d/
  parseDarwinFirewall: socketfilterfw --getglobalstate
  parseDarwinSystemSecurity: FileVault (fdesetup), SIP (csrutil), Gatekeeper (spctl)
  parseDarwinSuspectLaunchd: /Library/LaunchDaemons + LaunchAgents plist scan
- internal/collectors/security_notlinux.go: build tag !linux && !darwin
  (darwin now has its own collector; stub only for other non-linux platforms)
- internal/models/security.go: FileVaultEnabled, SIPEnabled, GatekeeperEnabled,
  IsDarwin fields (omitempty — invisible in Linux JSON output)
- internal/analysis/heuristics.go: checkSecurity() — gated on IsDarwin:
  FileVault off → WARN, SIP disabled → CRIT, Gatekeeper disabled → WARN
- Fixes: SSHStrictModes WARN false positive on macOS (was zero-value default)
- Fixes: auditd no-rules WARN on macOS (BSM auditd ≠ Linux auditd, not applicable)
- Verified: dsd health no longer fires false StrictModes WARN on M3 MBA
```
