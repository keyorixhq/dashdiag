# Spec 18 — `dsd gpu` Standalone GPU/APU Health Command

## Context

DashDiag is a Go CLI system diagnostics tool. Repo: `/Users/abeshkov/proj/dashdiag`.
Current state: v0.6.1+, Spec 8 (platform.Profile) just landed.

**This builds a proper standalone `dsd gpu` command.** A basic GPU *row* already
exists in `dsd health` (collectors/gpu.go, gpu_linux.go, gpu_darwin.go) — it reads
hwmon sysfs for AMD temps and detects NVIDIA nouveau. This spec replaces that basic
row with a full standalone command including TDP, VRAM, clocks, utilization, Mesa
version, and per-distro NVIDIA install hints.

Read these files before writing a line of code:
- `cmd/gpu.go` — the existing `dsd gpu` command (understand current structure)
- `internal/collectors/gpu.go` — cross-platform collector skeleton
- `internal/collectors/gpu_linux.go` — current Linux implementation
- `internal/collectors/gpu_darwin.go` — current macOS implementation
- `internal/models/gpu.go` — existing GPU model (understand what exists)
- `cmd/disk.go` — pattern for a deep-mode standalone command with fast + deep split
- `internal/render/health.go` lines 1-80 — display patterns to follow

## What to build

### 1. Extend `internal/models/gpu.go`

Add fields to the existing `GPUDevice` struct. Do NOT rename or remove any existing
fields. The current struct already has: `Index`, `Name`, `Vendor`, `TempC`, `UtilPct`,
`MemUsedMB`, `MemTotalMB`, `MemUsedPct`, `PowerDrawW`, `XidErrors`, `Processes`.

New fields to add (check each one doesn't already exist before adding):
```go
// Clock speeds
ClockMHz    int `json:"clock_mhz,omitempty"`     // current GPU core clock
ClockMaxMHz int `json:"clock_max_mhz,omitempty"` // max available clock

// Power / TDP (more precise than existing PowerDrawW — that stays for NVIDIA compat)
TDPLimitW   float64 `json:"tdp_limit_w,omitempty"`  // configured TDP cap
TDPMaxW     float64 `json:"tdp_max_w,omitempty"`     // hardware max
Throttling  bool    `json:"throttling,omitempty"`    // draw >= 95% of cap

// VRAM in GB (complement to existing MemUsedMB/MemTotalMB — GB is cleaner for display)
VRAMUsedGB  float64 `json:"vram_used_gb,omitempty"`
VRAMTotalGB float64 `json:"vram_total_gb,omitempty"`
IsAPU       bool    `json:"is_apu,omitempty"`        // shared system RAM (Steam Deck)

// Thermal extras
TempJunctionC int `json:"temp_junction_c,omitempty"` // hotspot / die temp
TempMemC      int `json:"temp_mem_c,omitempty"`       // GDDR temp

// Memory bus utilization
MemBusyPct int `json:"mem_busy_pct,omitempty"`

// Driver / Mesa
MesaVersion   string `json:"mesa_version,omitempty"`   // e.g. "24.3.1"
DRMDriver     string `json:"drm_driver,omitempty"`     // "amdgpu", "i915", "nouveau"

// Deep-only
PowerDPMLevel string `json:"power_dpm_level,omitempty"` // "auto", "low", "high"
```

Note: `TDPLimitW` and the existing `PowerDrawW` coexist — `PowerDrawW` is populated
by NVIDIA nvidia-smi, `TDPLimitW`/`TDPCurrentW` are AMD sysfs paths. For AMD,
set `PowerDrawW = TDPCurrentW` as well (so the existing heuristics still work).

### 2. Extend `internal/collectors/gpu_linux.go`

The current implementation reads edge temperature and detects AMD/NVIDIA. Extend it
to collect the full dataset. Keep all existing logic — only add to it.

**AMD GPU data collection (all from sysfs, zero external tools required):**

Temperature:
- Edge: already collected — keep as-is
- Junction (`temp2_input` where hwmon name=amdgpu): TempJunctionC
  Flag WARN at 90°C junction, CRIT at 100°C junction in heuristics
- Memory (`temp3_input` if present): TempMemC

GPU clock:
- `/sys/class/drm/card*/device/pp_dpm_sclk` — parse the line with `*` marker
  Format: `0: 200Mhz\n1: 700Mhz\n2: 1600Mhz *` → current=1600, max=1600
  If file absent or unreadable: skip (no error)

TDP / Power:
- `/sys/class/hwmon/hwmon*/power1_cap` → TDPLimitW (microwatts → watts: /1e6)
- `/sys/class/hwmon/hwmon*/power1_cap_max` → TDPMaxW
- `/sys/class/hwmon/hwmon*/power1_input` → TDPCurrentW
  Throttling = TDPCurrentW >= 0.95 * TDPLimitW
  All three files under the SAME hwmon as the AMD GPU — match by name=amdgpu

VRAM:
- `/sys/class/drm/card*/device/mem_info_vram_total` → bytes → GB
- `/sys/class/drm/card*/device/mem_info_vram_used` → bytes → GB
  IsAPU: check if total VRAM < 2GB AND `/sys/class/drm/card*/device/mem_info_gtt_total`
  exists (GTT memory pool = APU shared memory indicator)

GPU utilization (1-second sample):
- Read `/sys/class/drm/card*/device/gpu_busy_percent` once
- Sleep 1 second
- Read again
- Use the second reading (instantaneous, not average — matches htop/MangoHud)
  Do this in a goroutine to avoid blocking; if the file doesn't exist, skip.

Memory bus busy:
- `/sys/class/drm/card*/device/mem_busy_percent` (same dir as gpu_busy_percent)

DRM driver:
- `/sys/class/drm/card*/device/driver` → symlink target basename (e.g. "amdgpu")

Mesa version:
- Try parsing `glxinfo -B 2>/dev/null` output for "OpenGL version string"
  OR read `/proc/driver/nvidia/version` (NVIDIA only)
  OR check output of `vulkaninfo --summary 2>/dev/null` for "driverVersion"
  Mesa specifically: look for "Mesa" in the OpenGL renderer string
  Timeout: 2s on glxinfo. If it fails or times out: leave MesaVersion empty.
  Note: glxinfo requires DISPLAY env — only attempt if DISPLAY or WAYLAND_DISPLAY is set.

Deep-only (only collected when deep=true flag is set):
- `/sys/class/drm/card*/device/power_dpm_force_performance_level` → PowerDPMLevel
  Flag WARN if value is "low" (stuck in low-power mode after failed TDP management)

**NVIDIA GPU data collection:**
- Existing logic detects nouveau kernel module — keep as-is
- If `nvidia-smi` binary is present, additionally run:
  `nvidia-smi --query-gpu=temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,power.limit --format=csv,noheader,nounits`
  with a 3s timeout. Parse CSV → TempEdgeC, UtilPct, VRAMUsedGB, VRAMTotalGB,
  TDPCurrentW, TDPLimitW. If nvidia-smi fails: just show what sysfs gives.

**Intel GPU data collection:**
- Temperature: hwmon where name=i915 → `temp1_input`
- Power: `/sys/class/drm/card*/device/hwmon/hwmon*/power1_input` if present
- No clock or VRAM data available without root + debugfs — skip those fields

**Important: preserve the existing `gpu_busy_percent` goroutine pattern.**
The 1-second sleep for utilization must not block the rest of the collector.
Use a done channel or run the sleep in a goroutine, then read the result at
the end of Collect(). The timeout for the whole collector is already 10s so
the 1s sleep is safe.

### 3. Extend `cmd/gpu.go` — standalone `dsd gpu` command

Currently `dsd gpu` exists but is minimal. Extend it into a full standalone command
with the same fast/deep pattern as `dsd disk`.

The command already works — keep the structure. Add:
- `--deep` flag (same as `dsd disk --deep`)
- `--json` flag for machine-readable output
- Pass `deep` bool to the collector

**Output format (human):**

```
🎮 GPU

[AMD Radeon Graphics (VANGOGH)]  Driver: amdgpu  Mesa 24.3.1  RADV

  Temperature
    ✅ Edge:      54°C
    ⚠️  Junction:  88°C  (approaching thermal limit — 90°C threshold)
    ✅ Memory:    48°C

  Performance
    ✅ Clock:       1600 / 1600 MHz  (100%)
    ⚠️  TDP:         15.0 / 15.0 W limit  (current: 14.8W) ← throttling
    ✅ VRAM:        2.1 / 16.0 GB  (13%)  [shared APU memory]
    ✅ Utilization: 72%

────────────────────────────────────────────────────
⚠️  Junction temperature 88°C — approaching 90°C threshold
   → Check thermal paste and fan curve if sustained
⚠️  TDP throttling — GPU at power limit (14.8W / 15.0W)
   → On Steam Deck: increase TDP limit in Performance settings when plugged in
```

For systems with no GPU data (LXC/VM without GPU passthrough):
```
GPU   ℹ️  no GPU detected (virtual machine or no sysfs data)
```

For Intel-only (minimal data):
```
[Intel UHD Graphics 630]  Driver: i915

  Temperature
    ✅ 41°C
```

**`--json` output:** serialize the full GPUInfo struct as JSON.
Print `[]` for an empty GPU list (not an error — just no GPU).

### 4. `internal/analysis/heuristics.go` — extend `checkGPU()`

Find the existing `checkGPU` function. Add new insight rules:

```go
// Junction temperature — hotspot, not edge
if dev.TempJunctionC >= 100 {
    // CRIT — emergency thermal threshold
}
if dev.TempJunctionC >= 90 {
    // WARN — approaching thermal limit
}

// TDP throttling
if dev.Throttling {
    // WARN — at TDP limit
    // Hint differs for SteamOS vs standard Linux
}

// VRAM high usage
if dev.VRAMUsedPct >= 90 {
    // WARN — high VRAM pressure
}

// DPM stuck in low (deep only)
if dev.PowerDPMLevel == "low" {
    // WARN — stuck in low-power mode
}
```

For hint text: check if `profile.IsSteamOS` (if profile is available) to give
Steam Deck-specific hints. If not available, give generic hints.

### 5. Rules and constraints

**DO NOT:**
- Remove or rename any existing fields in `models/gpu.go`
- Break the existing `dsd health` GPU row (it uses the same collector)
- Change the `Collect(ctx context.Context) (interface{}, error)` signature
- Add external binary dependencies for AMD — all AMD data comes from sysfs

**DO:**
- Build tag `//go:build linux` for linux-specific sysfs reads
- Gracefully skip any sysfs path that doesn't exist — no errors, just empty fields
- Use `os.ReadFile` for sysfs (fast, simple). For `/proc/driver/nvidia/version`, same.
- The 1-second GPU utilization sleep: use `time.Sleep` inside a goroutine with
  a result channel. Start it early in Collect(), read the result at the end.
- All power values in sysfs are in microwatts — divide by 1_000_000.0 for watts.
- Temperatures in sysfs are in millidegrees Celsius — divide by 1000 for °C.

**hwmon matching pattern** (critical to get right):
```go
// Find hwmon dirs whose 'name' file contains "amdgpu"
entries, _ := os.ReadDir("/sys/class/hwmon")
for _, e := range entries {
    name, _ := os.ReadFile("/sys/class/hwmon/" + e.Name() + "/name")
    if strings.TrimSpace(string(name)) == "amdgpu" {
        // this is the AMD GPU hwmon dir — read power1_cap, temp2_input etc here
    }
}
```

**DRM card matching pattern** (for VRAM + clock + utilization):
```go
// Find drm card dirs whose driver symlink points to amdgpu
entries, _ := os.ReadDir("/sys/class/drm")
for _, e := range entries {
    if !strings.HasPrefix(e.Name(), "card") || strings.Contains(e.Name(), "-") {
        continue // skip renderD*, card0-HDMI-* etc
    }
    driverLink, _ := os.Readlink("/sys/class/drm/" + e.Name() + "/device/driver")
    if filepath.Base(driverLink) == "amdgpu" {
        // this card belongs to AMD GPU
    }
}
```

## Infrastructure note

**Test hardware available:**
- PVE host (192.168.10.20): Intel i7-6700 with Intel HD 530 → i915 driver, temp data
- VM 214 (192.168.10.56): openSUSE Leap 16 — no GPU passthrough, will show "no GPU"
- AlmaLinux LXC (192.168.10.8): no GPU

Intel i915 path is testable on PVE host directly. AMD path should be written
and tested against the sysfs paths documented in spec — they're stable across
all amdgpu distros.

Deploy pattern (macOS → Linux):
```bash
make release
scp dist/dsd-linux-amd64 root@192.168.10.20:/tmp/dsd
ssh root@192.168.10.20 '/tmp/dsd gpu'
```

## Verification steps (run in this order)

1. `go build ./...` — exit 0
2. `go test -race ./...` — all green, no new failures
3. `golangci-lint run ./...` — no new issues beyond pre-existing 5
4. Deploy to PVE host (192.168.10.20): `dsd gpu` should show Intel HD 530 with temp
5. Deploy to AlmaLinux CT (192.168.10.8): `dsd gpu` should show "no GPU" gracefully
6. `dsd health` on both nodes — existing GPU row still works (no regression)
7. `dsd gpu --json` produces valid JSON on both nodes

## Commit message template

```
feat(gpu): dsd gpu standalone command with TDP, VRAM, clocks, utilization

- models/gpu.go: new fields — ClockMHz, TDPCurrentW, TDPLimitW, Throttling,
  VRAMUsedGB, VRAMTotalGB, IsAPU, TempJunctionC, TempMemC, MesaVersion,
  DRMDriver, UtilPct, PowerDPMLevel
- collectors/gpu_linux.go: AMD hwmon (junction/mem temp, TDP, power1_cap*),
  DRM sysfs (clocks, VRAM, busy%), 1s utilization sample via goroutine,
  Intel i915 temperature, NVIDIA nvidia-smi optional fallback
- cmd/gpu.go: --deep and --json flags, formatted output with temp/perf/power
  sections, graceful "no GPU" for VM/LXC
- heuristics.go: junction CRIT@100°C/WARN@90°C, TDP throttling WARN,
  VRAM@90% WARN, DPM stuck-low WARN
- Tested: Intel HD 530 on PVE host (i915 path)
```
