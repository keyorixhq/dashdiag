# Spec 8 — platform.Profile Distro Normalization Layer

## Context

DashDiag is a Go CLI system diagnostics tool. The codebase is at v0.6.1, commit a028e3a.
Repo: `/Users/abeshkov/proj/dashdiag`. Everything in `internal/platform/` is the existing
platform detection package. The project bible is `DashDiag_Gap_Specs.md`, spec 8 starts
at line 1735.

**This is a pure internal refactor.** No user-visible behaviour changes. The goal is a
centralized `platform.Profile` struct so SteamOS specs (17, 19, 20) and future distro-
specific paths have a single source of truth instead of scattered `os-release` reads.

Read these files before writing a single line of code:
- `internal/platform/platform.go` (15 lines — what exists)
- `internal/platform/container.go` (142 lines — DetectContainerContext pattern to follow)
- `internal/platform/sysinfo.go` (34 lines — OSPrettyName helper)
- `internal/analysis/thresholds.go` (115 lines — Thresholds struct, PackageManager already there)
- `internal/analysis/heuristics.go` lines 1-70 (ApplyThresholds signature)
- `cmd/health.go` lines 80-100 and 246-270 (how platform is currently used at startup)
- `internal/collectors/logs_linux.go` (find the syslog path hardcoding)
- `internal/collectors/docker.go` lines 785-820 (isRHEL10Plus inline detection)
- `internal/collectors/security_linux.go` line 1377 (os-release read)

## What to build

### 1. `internal/platform/profile.go`

New file. The struct and `Detect()` function. Use dependency injection for testability —
`Detect()` takes no args and reads real files; `detectFromContent()` takes the
`/etc/os-release` content as a string argument so tests can mock it without touching the
filesystem.

```go
type Profile struct {
    // OS identity
    OS            string // "linux", "darwin"
    Distro        string // normalized ID: "rhel", "debian", "ubuntu", "sles", "arch",
                         // "nixos", "opensuse", "steamos", "unknown"
    DistroVersion string // raw VERSION_ID: "10.1", "22.04", "15.6"
    MajorVersion  int    // parsed major: 10, 22, 15
    Codename      string // VERSION_CODENAME: "bookworm", "noble", ""
    IsSteamOS     bool   // ID=steamos OR VARIANT_ID=steamdeck

    // Init system
    InitSystem string // "systemd", "openrc", "unknown"

    // Networking
    NetworkStack string // "networkmanager", "networkd", "netplan", "ifupdown", "unknown"
    HasResolved  bool   // systemd-resolved is active

    // Security modules
    SELinuxMode    string // "enforcing", "permissive", "disabled", "not-present"
    AppArmorActive bool

    // Package manager
    PackageManager string // "apt", "dnf", "yum", "zypper", "pacman", "brew", "unknown"

    // Log paths (distro-resolved)
    SyslogPath   string // "/var/log/syslog" or "/var/log/messages" or ""
    AuthLogPath  string // "/var/log/auth.log" or "/var/log/secure" or ""
    AuditLogPath string // "/var/log/audit/audit.log" or ""
}
```

**Distro normalization rules** (apply to the ID field from `/etc/os-release`):
- `rhel`, `centos`, `rocky`, `almalinux`, `fedora` → `"rhel"`
- `debian` → `"debian"`
- `ubuntu` → `"ubuntu"`
- `sles`, `sle-micro` → `"sles"`
- `opensuse-leap`, `opensuse-tumbleweed` → `"opensuse"`
- `arch`, `manjaro`, `endeavouros` → `"arch"`
- `nixos` → `"nixos"`
- `steamos` → `"steamos"` (also set IsSteamOS=true)
- anything else → keep the raw ID value, don't map to "unknown" — preserves future distros

**Log path rules:**
- `"rhel"`, `"opensuse"`, `"sles"`, `"arch"`: SyslogPath=`/var/log/messages`, AuthLogPath=`/var/log/secure`
- `"debian"`, `"ubuntu"`: SyslogPath=`/var/log/syslog`, AuthLogPath=`/var/log/auth.log`
- AuditLogPath=`/var/log/audit/audit.log` always (checked at runtime, not here)
- For NixOS and steamos, leave SyslogPath/AuthLogPath empty (they use journald only)
- macOS: leave all log paths empty

**Detect() structure:**
```go
func Detect() Profile {
    p := Profile{OS: runtime.GOOS}
    if runtime.GOOS == "darwin" {
        p.PackageManager = "brew"
        return p
    }
    data, err := os.ReadFile("/etc/os-release")
    if err != nil {
        return p
    }
    return detectFromContent(p, string(data))
}

// detectFromContent is the testable core — parses os-release content
// and probes live system state (systemctl, file existence).
func detectFromContent(p Profile, osRelease string) Profile {
    parseOSRelease(&p, osRelease)
    p.InitSystem = detectInitSystem()
    p.NetworkStack = detectNetworkStack()
    p.HasResolved = detectResolved()
    p.SELinuxMode = detectSELinux()
    p.AppArmorActive = detectAppArmor()
    p.PackageManager = detectPackageManager()
    setLogPaths(&p)
    return p
}
```

**detectNetworkStack()** — check in this order:
1. `netplan` binary on PATH AND `/etc/netplan/` dir has ≥1 `.yaml` file → `"netplan"`
2. `systemctl is-active NetworkManager` exit 0 → `"networkmanager"`
3. `systemctl is-active systemd-networkd` exit 0 → `"networkd"`
4. `/etc/network/interfaces` exists → `"ifupdown"`
5. → `"unknown"`

**detectSELinux()** — read `/sys/fs/selinux/enforce`:
- doesn't exist → `"not-present"`
- `"1"` → `"enforcing"`
- `"0"` → `"permissive"`
- else → `"disabled"`

**detectPackageManager()** — check binary existence in order:
`apt-get`, `dnf`, `yum`, `zypper`, `pacman`, `brew` → first match wins.
Use `exec.LookPath`, not subprocess.

**detectAppArmor()** — `/sys/kernel/security/apparmor/profiles` exists AND is non-empty.

**detectInitSystem()** — `/run/systemd/private` exists → `"systemd"`;
`/sbin/openrc` exists → `"openrc"`; else `"unknown"`.

### 2. `internal/platform/profile_test.go`

Test `detectFromContent` with os-release strings for each distro family. The live
system checks (networkstack, selinux, apparmor, initSystem) are tested separately
with small focused unit tests that mock file existence where needed.

Required test cases:
- RHEL 10.1: Distro="rhel", MajorVersion=10, SyslogPath="/var/log/messages", AuthLogPath="/var/log/secure"
- Debian 12: Distro="debian", MajorVersion=12, Codename="bookworm", SyslogPath="/var/log/syslog"
- Ubuntu 24.04: Distro="ubuntu", MajorVersion=24, Codename="noble", SyslogPath="/var/log/syslog"
- SLES 15.6: Distro="sles", MajorVersion=15
- openSUSE Leap 16: Distro="opensuse", SyslogPath="/var/log/messages"
- NixOS 25.05: Distro="nixos", SyslogPath=""
- SteamOS 3.7: Distro="steamos", IsSteamOS=true, SyslogPath=""
- macOS (darwin): OS="darwin", PackageManager="brew", Distro=""
- AlmaLinux 9.4: Distro="rhel" (normalized), MajorVersion=9
- Rocky Linux 10: Distro="rhel", MajorVersion=10

Also test `detectSELinuxFromPath()` with a helper that takes the path as arg
(so tests don't need the real sysfs).

### 3. `cmd/health.go` — wire Profile at startup

After `ctrCtx` and `cloudEnv` are detected (lines ~86-87), add:
```go
profile := platform.Detect()
```

Pass it to `buildHealthCollectors`:
```go
cols := buildHealthCollectors(ctrCtx, profile, ...)
```

Update `buildHealthCollectors` signature to accept `profile platform.Profile`.

Under `--debug` flag, print the profile (add after the existing debug log):
```
[debug] Platform: rhel 10.1, networkmanager, SELinux enforcing, dnf
```
Format: `<Distro> <DistroVersion>, <NetworkStack>, SELinux <SELinuxMode>|AppArmor, <PackageManager>`

### 4. Migrate 3 collectors

**Important pre-read before touching these files:**
- `logs_linux.go` line 865-880: `collectVarLogErrors` already tries both
  `/var/log/syslog` AND `/var/log/messages` in order (line 870). The migration
  here is NOT about the error scan path — it's about making `hasTextLogFallback()`
  (line 514-517) and `detectLogSource()` (line 834) profile-aware so they can
  skip the syslog check entirely on NixOS/SteamOS (journald-only distros).
- `security_linux.go` line 1373: `isOffensiveDistro()` is the only function that
  reads os-release in this file. It checks for Kali/Parrot/BlackArch.
- `docker.go` line 790: `isRHEL10Plus()` reads os-release to check RHEL family
  at major version >= 10.

**`internal/collectors/logs_linux.go`**
Add `profile platform.Profile` field to `LogsCollector`. Update `NewLogsCollector()`
to accept optional profile (or add `NewLogsCollectorWithProfile(p platform.Profile)`).
In `hasTextLogFallback()` and `detectLogSource()`: when `profile.Distro` is `"nixos"`
or `"steamos"`, skip the `/var/log/syslog` and `/var/log/messages` existence checks
and return early (these distros are journald-only).
**DO NOT change** `collectVarLogErrorsFrom` — it already tries both paths correctly.

**`internal/collectors/docker.go`**
Add `profile platform.Profile` field to `DockerCollector`. Add:
```go
func NewDockerCollectorWithProfile(p platform.Profile) *DockerCollector {
    return &DockerCollector{profile: p}
}
```
Replace the two `isRHEL10Plus()` calls with:
```go
c.profile.Distro == "rhel" && c.profile.MajorVersion >= 10
```
Keep `isRHEL10Plus()` function in place (it's used as the zero-profile fallback when
`c.profile.Distro == ""`). This means: if profile is empty, fall back to the existing
inline detection. Zero regressions guaranteed.

**`internal/collectors/security_linux.go`**
Add `profile platform.Profile` field to `SecurityCollector` (or wherever the struct is).
Add `NewSecurityCollectorWithProfile(p platform.Profile)` constructor.
Replace `isOffensiveDistro()` body to use `p.Distro` when profile is set:
```go
func (c *SecurityCollector) isOffensiveDistro() bool {
    if c.profile.Distro != "" {
        d := c.profile.Distro
        return d == "kali" || d == "parrot" || strings.Contains(d, "blackarch")
    }
    // fallback: original os-release read (zero-profile case)
    ...original code...
}
```

### 5. Rules and constraints

**DO NOT:**
- Change the `Collect(ctx context.Context) (interface{}, error)` signature on any collector
- Change the `runner.Result` or `runner.Collector` interface
- Rename any existing exported functions
- Break any existing test
- Touch any file outside `internal/platform/`, `internal/collectors/logs_linux.go`,
  `internal/collectors/docker.go`, `internal/collectors/security_linux.go`, `cmd/health.go`

**DO:**
- Use build tags correctly: `profile.go` has no build tag (works everywhere);
  any Linux-only detection functions go in `profile_linux.go` with `//go:build linux`
- Keep `Detect()` fast: no subprocesses for the core fields — only `exec.LookPath` for
  package manager (no forks) and `os.Stat` / `os.ReadFile` for sysfs/procfs
- `systemctl is-active` calls (for NetworkStack, HasResolved) are acceptable since
  they're fast read-only queries, but wrap each in a 2s timeout

**IMPORTANT — log path fallback logic:**
The existing `LogsCollector` already has fallback logic when log files don't exist.
Don't break it. The profile just pre-resolves which path to try first. The existing
"if file doesn't exist, fall back to journald" logic stays intact.

## Verification steps (run after implementation)

1. `go build ./...` — must exit 0
2. `go test -race ./...` — all green, no new failures
3. `golangci-lint run ./...` — no new issues beyond the pre-existing 5
4. SSH to PVE01 (192.168.10.20): deploy binary, run `dsd health --debug 2>&1 | head -5`
   Expected: `[debug] Platform: debian 13, networkmanager, SELinux not-present, apt` (or similar)
5. SSH to openSUSE VM (192.168.10.56): deploy, `dsd health --debug 2>&1 | head -5`
   Expected: `[debug] Platform: opensuse 16.0, networkmanager, SELinux not-present, zypper`
6. SSH to AlmaLinux CT (192.168.10.8): deploy, `dsd health --debug 2>&1 | head -5`
   Expected: `[debug] Platform: rhel 9.4, networkmanager, SELinux enforcing, dnf`
7. Run `dsd health` on all three — output identical to before (no regression)

## Commit message

```
feat(platform): Profile distro normalization layer (Spec 8)

- platform/profile.go: Profile struct + Detect() — OS, Distro (normalized),
  MajorVersion, InitSystem, NetworkStack, HasResolved, SELinuxMode,
  AppArmorActive, PackageManager, SyslogPath, AuthLogPath, IsSteamOS
- platform/profile_test.go: 10 distro test cases (RHEL, Debian, Ubuntu,
  SLES, openSUSE, NixOS, SteamOS, macOS, AlmaLinux, Rocky)
- cmd/health.go: platform.Detect() at startup; --debug prints profile line
- collectors/logs_linux.go: use profile.SyslogPath/AuthLogPath
- collectors/docker.go: NewDockerCollectorWithProfile for profile-aware path
- collectors/security_linux.go: use profile.Distro/PackageManager
- No user-visible behaviour change; no runner interface changes
- Unblocks Spec 17 (dsd steamos), 19, 20 which need IsSteamOS + NetworkStack
```
