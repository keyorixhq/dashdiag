# DashDiag — Sprint 0: Task 0.10 Part A
## Collectors: collector.go + cpu.go + memory.go + swap.go
## Paste into Claude Code as one prompt

---

## Context
Module: github.com/keyorixhq/dashdiag
Already implemented: internal/models/, internal/runner/, internal/platform/, internal/output/
Run after completion: go build ./... && go test ./internal/collectors/... -v -race

---

## TASK 0.10 Part A — collector interface + cpu + memory + swap

Paste this into Claude Code:

```
Read .cursorrules section "DASHDIAG-SPECIFIC PATTERNS" before writing any code.
Focus on rules 1 (cgroup-aware), 2 (two-sample IO), 3 (injectable readers), 8 (context propagation).

STEP 1: Create internal/collectors/collector.go

package collectors

import ("context"; "time")

// Collector matches runner.Collector exactly.
type Collector interface {
    Name()    string
    Timeout() time.Duration
    Collect(ctx context.Context) (interface{}, error)
}

---

STEP 2: Create internal/collectors/cpu.go

CPUInfo model (from internal/models/cpu.go — do not redefine, import it):
  Cores, LoadAvg1, LoadAvg5, LoadAvg15 float64
  PercentUsed float64
  LoadPct float64   // LoadAvg1 / Cores * 100
  InContainer bool
  CPUQuota float64  // container CPU quota in cores, 0=unlimited
  Status, StatusReason string  // DO NOT set these — analysis layer only

Injectable reader pattern (mandatory — enables testing without /proc):
  type cpuReaders struct {
      loadAvgOpen func() (io.ReadCloser, error)
      statOpen    func() (io.ReadCloser, error)
  }
  type CPUCollector struct {
      readers      cpuReaders
      ContainerCtx platform.ContainerContext
  }
  func NewCPUCollector(ctx platform.ContainerContext) *CPUCollector {
      return &CPUCollector{
          ContainerCtx: ctx,
          readers: cpuReaders{
              loadAvgOpen: func() (io.ReadCloser, error) { return os.Open("/proc/loadavg") },
              statOpen:    func() (io.ReadCloser, error) { return os.Open("/proc/stat") },
          },
      }
  }
  func (c *CPUCollector) Name()    string        { return "CPU" }
  func (c *CPUCollector) Timeout() time.Duration { return 500 * time.Millisecond }

Pure parsers (no OS calls — take io.Reader):
  func parseLoadAvg(r io.Reader) (load1, load5, load15 float64, err error)
    // Format: "0.52 0.43 0.32 3/412 8932"
  func parseCPUStat(r io.Reader) (idle, total uint64, err error)
    // Parse first "cpu " line: fields are user,nice,system,idle,iowait,irq,softirq...
    // idle = field[3], total = sum of all fields

Collect():
  - Read /proc/loadavg via reader.loadAvgOpen()
  - macOS fallback (runtime.GOOS == "darwin"): exec sysctl -n vm.loadavg
    macOS format: "{ 0.52 0.43 0.32 }"
  - Two reads of /proc/stat with 500ms gap:
      r1, _ := reader.statOpen(); idle1, total1, _ := parseCPUStat(r1); r1.Close()
      select { case <-ctx.Done(): return nil, ctx.Err()
               case <-time.After(500*time.Millisecond): }
      r2, _ := reader.statOpen(); idle2, total2, _ := parseCPUStat(r2); r2.Close()
      usagePct = (1 - float64(idle2-idle1)/float64(total2-total1)) * 100
  - ContainerCtx: if CPULimitCores > 0, set Cores = int(CPULimitCores)
  - Return *models.CPUInfo — DO NOT set Status or StatusReason

Create testdata/fixtures/cpu/linux_healthy.txt:
  0.52 0.43 0.32 3/412 8932

Create internal/collectors/cpu_test.go:
  TestParseLoadAvg table-driven (t.Parallel()):
    {"healthy", "0.52 0.43 0.32 3/412 8932", 0.52, 0.43, 0.32, nil}
    {"zero load", "0.00 0.00 0.00 1/100 100", 0.00, 0.00, 0.00, nil}
    {"high load", "16.5 12.3 8.1 5/200 9999", 16.5, 12.3, 8.1, nil}
    {"malformed", "garbage", 0, 0, 0, non-nil error}
    {"empty", "", 0, 0, 0, non-nil error}
  FuzzParseLoadAvg: must never panic on any input

---

STEP 3: Create internal/collectors/memory.go

MemoryInfo model (import from internal/models/memory.go):
  TotalGB, FreeGB, UsedPct float64
  SlabMB, CommitLimitMB, CommittedAsMB float64
  OverCommitted bool
  Status, StatusReason string  // DO NOT set

Injectable path:
  type MemoryCollector struct {
      meminfoPath  string  // "/proc/meminfo" by default
      ContainerCtx platform.ContainerContext
  }
  func NewMemoryCollector(ctx platform.ContainerContext) *MemoryCollector {
      return &MemoryCollector{meminfoPath: "/proc/meminfo", ContainerCtx: ctx}
  }
  func (c *MemoryCollector) Name()    string        { return "Memory" }
  func (c *MemoryCollector) Timeout() time.Duration { return 200 * time.Millisecond }

Pure parser:
  func parseMeminfo(r io.Reader) (map[string]uint64, error)
  // Parse lines: "MemTotal:       16384000 kB"
  // Return map: {"MemTotal": 16384000, "MemFree": 8192000, ...}

Collect():
  - gopsutil/v3/mem VirtualMemory() for basic stats
  - parseMeminfo from meminfoPath for Slab, CommitLimit, Committed_AS fields
  - OverCommitted = CommittedAsMB > CommitLimitMB
  - ContainerCtx: if MemLimitMB > 0, override TotalGB = MemLimitMB/1024
  - macOS: /proc/meminfo absent → set SlabMB=-1, CommitLimitMB=-1, OverCommitted=false
  - Return *models.MemoryInfo

Create testdata/fixtures/memory/linux_healthy.txt:
  MemTotal:       16384000 kB
  MemFree:         8192000 kB
  MemAvailable:    9000000 kB
  Slab:             512000 kB
  CommitLimit:    20000000 kB
  Committed_AS:   10000000 kB

Create internal/collectors/memory_test.go with TestParseMeminfo and FuzzParseMeminfo.

---

STEP 4: Create internal/collectors/swap.go

SwapInfo model (import from internal/models/swap.go):
  Configured bool
  TotalGB, UsedGB, UsedPct float64
  SwapInPerSec, SwapOutPerSec float64  // per-second rates, -1 on macOS
  ZramPresent bool
  ZramUsedPct float64
  Status, StatusReason string  // DO NOT set

Pure parser:
  func parseVMStat(r io.Reader) (pswpin, pswpout uint64, err error)
  // Find "pswpin N" and "pswpout N" lines and parse the integer

Collect():
  TWO reads of /proc/vmstat with exactly 1s gap:
    read1: open /proc/vmstat, parseVMStat, close
    select { case <-ctx.Done(): return nil, ctx.Err()
             case <-time.After(1*time.Second): }
    read2: open /proc/vmstat, parseVMStat, close
    SwapInPerSec  = float64(pswpin2  - pswpin1)
    SwapOutPerSec = float64(pswpout2 - pswpout1)
  /proc/swaps: read to get Configured, TotalGB, UsedGB
  ZramPresent: check os.Stat("/sys/block/zram0") != nil (no error = present)
  macOS: exec vm_stat, parse "Pages swapped in/out" (single snapshot, SwapInPerSec=-1)
  Return *models.SwapInfo

Create testdata/fixtures/swap/vmstat_healthy.txt:
  nr_free_pages 1234567
  pswpin 0
  pswpout 0

Create testdata/fixtures/swap/vmstat_active.txt:
  nr_free_pages 100000
  pswpin 142
  pswpout 89

Create FuzzParseVMStat test.

Run: go build ./internal/collectors/... && go test ./internal/collectors/... -v -race
```
