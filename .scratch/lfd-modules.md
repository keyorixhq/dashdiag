# LFD — modules swept

One row per library / API surface. "Reachable?" = does DashDiag feed this entry point
untrusted input, and as which user. Minutes = cumulative native `go test -fuzz` wall time
on pve01 (nice -n 10, GOMAXPROCS=2, -parallel 2).

| Module | API surface (entry point) | Harness pkg | Fuzz/skip | Min | Result |
|--------|---------------------------|-------------|-----------|-----|--------|
| shirou/gopsutil/v4 mem | `mem.VirtualMemory/SwapMemory` ← /proc/meminfo | gopsutilfs.FuzzMeminfo | fuzz | — | clean |
| shirou/gopsutil/v4 disk | `disk.IOCounters` ← /proc/diskstats | gopsutilfs.FuzzDiskstats | fuzz | — | clean |
| shirou/gopsutil/v4 disk | `disk.Partitions` ← /proc/1/mountinfo | gopsutilfs.FuzzMountinfo | fuzz | — | clean |
| shirou/gopsutil/v4 disk | `disk.Partitions` ← /proc/1/mounts | gopsutilfs.FuzzMounts | fuzz | — | clean |
| shirou/gopsutil/v4 net | `net.IOCounters` ← /proc/net/dev | gopsutilfs.FuzzNetDev | fuzz | — | clean |
| shirou/gopsutil/v4 net | `net.ProtoCounters` ← /proc/net/snmp | (not committed) | DEFECT | <1 | **panic** → gopsutil-1.md |
| golang.org/x/net/icmp | `icmp.ParseMessage` (v4/v6) | icmpfs | fuzz | — | clean |
| golang.org/x/net/{icmp,ipv4,ipv6} | header parsers | icmpfs | fuzz | — | clean |
| modelcontextprotocol/go-sdk | `jsonrpc.DecodeMessage` + round-trip | mcpfs | fuzz | — | clean |
| skip2/go-qrcode | `qrcode.New` / `qrcode.Encode` | qrcodefs | fuzz | — | clean |
| pelletier/go-toml/v2 | `toml.Unmarshal` (+ Marshal round-trip) | tomlfs | fuzz | — | clean |
| spf13/viper | `ReadConfig`+`Unmarshal` (yaml/toml/json) | viperfs | fuzz | — | clean |
| charmbracelet/x/ansi | `StringWidth/Truncate/Wrap/Strip` (crash-only) | termwidth | fuzz | — | clean (no panic) |
| charmbracelet/x/ansi | `Strip` as sanitizer (property) | (not committed) | SECURITY-DEFECT | <1 | **bypass** → x-ansi-1.md |
| charmbracelet/x/ansi | `Truncate` width property | (not committed) | DEFECT | <1 | **overflow** → x-ansi-2.md |

### Skipped / not separately harnessed (and why)

- **gopkg.in/yaml.v3, go.yaml.in/yaml/v4, subosito/gotenv** — ALREADY COVERED (registry /
  other session); viper's YAML/dotenv codecs route through these, so viperfs does not
  re-fuzz them as a unit.
- **spf13/cobra, spf13/pflag** — argument parsing. DashDiag's CLI args are operator-supplied,
  not a remote attack surface; cobra/pflag parse `[]string` argv, not a bytes/Reader parser.
  Lower priority; left for a follow-up (noted as a gap in the report).
- **charmbracelet/bubbletea, lipgloss (full render), termenv** — lipgloss.Width is covered
  via termwidth; full TUI rendering is driven by DashDiag's own output, interactive, and not
  a pure parser of untrusted bytes.
- **prometheus-community/pro-bing** — its reply handling is unexported; the hostile-bytes
  surface it exposes is `golang.org/x/net/icmp.ParseMessage`, which IS fuzzed (icmpfs).
- **ini / hcl / properties viper codecs** — the backing libs are not in DashDiag's build
  (`go list -m all`), so those config formats cannot actually be decoded; nothing to fuzz.
