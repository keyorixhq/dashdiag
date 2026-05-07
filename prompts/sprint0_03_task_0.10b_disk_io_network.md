# DashDiag — Sprint 0: Task 0.10 Part B
## Collectors: disk.go + io.go + network_quick.go
## Paste into Claude Code as one prompt

---

## TASK 0.10 Part B — disk + io + network_quick collectors

Paste this into Claude Code:

```
Read .cursorrules rules 2 (two-sample IO), 3 (injectable readers), 8 (context propagation).

STEP 1: Create internal/collectors/disk.go

DiskInfo model (import from internal/models/disk.go — do not redefine):
  Device, MountPoint, FSType string
  TotalGB, UsedGB, FreeGB float64
  UsedPct, InodesUsedPct float64
  ReadOnly bool
  Status, StatusReason string  // DO NOT set

Name: "Disk", Timeout: 1s

Injectable reader:
  type DiskCollector struct {
      mountsPath string  // "/proc/mounts" by default
  }
  func NewDiskCollector() *DiskCollector {
      return &DiskCollector{mountsPath: "/proc/mounts"}
  }

Pure parser:
  func readMounts(r io.Reader) ([]mountEntry, error)
  type mountEntry struct { device, mountPoint, fsType string }
  Skip these FS types: tmpfs, devtmpfs, overlay, squashfs, proc, sysfs,
    cgroup, cgroup2, devpts, pstore, securityfs, debugfs, hugetlbfs, mqueue, fusectl

Collect():
  - Open mountsPath, parse via readMounts
  - For each non-skipped mountPoint: syscall.Statfs(mountPoint, &stat)
  - TotalGB = float64(stat.Blocks) * float64(stat.Bsize) / 1e9
  - FreeGB  = float64(stat.Bfree)  * float64(stat.Bsize) / 1e9
  - UsedPct = (1 - float64(stat.Bfree)/float64(stat.Blocks)) * 100
  - InodesUsedPct = (1 - float64(stat.Ffree)/float64(stat.Files)) * 100 (only if Files > 0)
  - macOS: same syscall.Statfs works on darwin
  - Return []models.DiskInfo

testdata/fixtures/disk/mounts_linux.txt:
  sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
  proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
  /dev/sda1 / ext4 rw,relatime 0 0
  /dev/sda2 /data ext4 rw,relatime 0 0
  tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime 0 0

Create TestReadMounts with table-driven cases including skip verification.

---

STEP 2: Create internal/collectors/io.go

IOInfo model (import from internal/models/io.go):
  Device string
  IsRotational bool
  UtilPct float64
  AwaitMs float64
  ReadMBps, WriteMBps float64
  QueueDepth float64
  Status, StatusReason string  // DO NOT set

Name: "IO", Timeout: 4s (needs 1s sample gap plus overhead)

Pure parser:
  type diskStatRaw struct {
      reads, writes uint64
      readSectors, writeSectors uint64
      readTimeMs, writeTimeMs uint64
      ioTimeMs uint64
  }
  func parseDiskstats(r io.Reader) (map[string]diskStatRaw, error)
  // Parse /proc/diskstats — space separated:
  // field[2]=name, [5]=reads, [6]=readMerges, [7]=readSectors, [8]=readTimeMs,
  // [9]=writes, [10]=writeMerges, [11]=writeSectors, [12]=writeTimeMs, [13]=ioInProgress, [14]=ioTimeMs
  // Only keep devices matching: sd[a-z]+ OR nvme[0-9]+n[0-9]+ OR vd[a-z]+ OR xvd[a-z]+

Collect():
  CRITICAL: TWO reads with exactly 1s gap — single read gives meaningless cumulative numbers
  open1, _ := os.Open("/proc/diskstats"); before, _ := parseDiskstats(open1); open1.Close()
  select {
    case <-ctx.Done(): return nil, ctx.Err()
    case <-time.After(1 * time.Second):
  }
  open2, _ := os.Open("/proc/diskstats"); after, _ := parseDiskstats(open2); open2.Close()

  For each device in after:
    b := before[name] (or zero value if missing)
    ReadMBps  = float64(after.readSectors  - b.readSectors)  * 512 / 1e6
    WriteMBps = float64(after.writeSectors - b.writeSectors) * 512 / 1e6
    UtilPct   = float64(after.ioTimeMs - b.ioTimeMs) / 10.0  // 1000ms window = 100%
    ops       := (after.reads+after.writes) - (b.reads+b.writes)
    timeMs    := (after.readTimeMs+after.writeTimeMs) - (b.readTimeMs+b.writeTimeMs)
    if ops > 0 { AwaitMs = float64(timeMs) / float64(ops) }

  IsRotational: read /sys/block/<dev>/queue/rotational
    "1" = HDD, "0" or error = SSD (assume SSD on error)
  macOS: gopsutil/v3/disk IOCounters() — no rotational detection, IsRotational=false
  Return []models.IOInfo

testdata/fixtures/io/diskstats_healthy.txt:
   8       0 sda 71816 2896 3467354 44032 37952 7292 819728 83776 0 76256 127808

Create TestParseDiskstats and FuzzParseDiskstats.

---

STEP 3: Create internal/collectors/network_quick.go

NetworkInfo model (import from internal/models/network.go):
  Interfaces []InterfaceInfo
  GatewayPingMs, InternetPingMs, DNSResolvesMs float64
  CloseWaitCount int
  NATDetected bool
  Status, StatusReason string  // DO NOT set

InterfaceInfo: Name, Up bool, IP string, RxDrops, TxDrops uint64

Name: "Network", Timeout: 3s

All network operations run concurrently — total must complete within 3s ctx timeout.

Collect():
  var wg sync.WaitGroup
  var mu sync.Mutex
  result := &models.NetworkInfo{}

  // 1. Interfaces (fast, no network)
  ifaces, _ := gopsutilnet.Interfaces()
  for _, iface := range ifaces {
      name := iface.Name
      // Skip: lo, docker0, br-*, veth*, virbr*
      if name == "lo" || strings.HasPrefix(name, "veth") ||
         strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "virbr") ||
         name == "docker0" { continue }
      // Add to result.Interfaces
  }

  // 2. Detect default gateway from /proc/net/route
  gw := detectDefaultGateway()  // returns "192.168.1.1" or ""

  // 3. Concurrent pings + DNS
  wg.Add(3)
  go func() { defer wg.Done()
      if gw != "" { result.GatewayPingMs = pingRTT(ctx, gw) } }()
  go func() { defer wg.Done()
      result.InternetPingMs = pingRTT(ctx, "8.8.8.8") }()
  go func() { defer wg.Done()
      start := time.Now()
      net.DefaultResolver.LookupHost(ctx, "github.com")
      result.DNSResolvesMs = float64(time.Since(start).Milliseconds()) }()
  wg.Wait()

  // 4. CLOSE_WAIT count
  conns, _ := gopsutilnet.Connections("tcp")
  for _, c := range conns {
      if c.Status == "CLOSE_WAIT" { result.CloseWaitCount++ }
  }
  return result, nil

func pingRTT(ctx context.Context, host string) float64
  // go-ping with 3 pings, 500ms timeout each, return average RTT in ms
  // CAP_NET_RAW fallback: try privileged first, then unprivileged UDP ping
  // Return -1 on failure (not 0, which would mean 0ms RTT)

func detectDefaultGateway() string
  // Linux: parse /proc/net/route
  // Find row with Destination == "00000000", parse Gateway field (little-endian hex)
  // macOS: exec route -n get default, parse "gateway:" line

Run: go build ./internal/collectors/... && go test ./internal/collectors/... -v -race
```
