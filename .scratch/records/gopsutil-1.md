# gopsutil/v4 `net.ProtoCountersWithContext` panics on a truncated /proc/net/snmp line

- **Module:** github.com/shirou/gopsutil/v4
- **Version:** v4.26.10 (latest in module cache; checked v4.26.x is newest tag present)
- **Class:** DEFECT (library panic on hostile/malformed input) — crash-only
- **Severity:** Low–Medium (DoS of the calling goroutine via panic; recovered only if caller wraps in recover()). Not a memory-safety escape.
- **Public entry point:** `net.ProtoCounters([]string)` / `net.ProtoCountersWithContext(ctx, protocols)`
- **File read:** `HOST_PROC/net/snmp` (default `/proc/net/snmp`), redirectable by any caller via `common.EnvMap{common.HostProcEnvKey: dir}` injected into the context (documented API).

## Trigger

`net_linux.go:184` (v4.26.10):

```go
line := lines[i]
r := strings.IndexRune(line, ':')     // colon position on THIS line
...
statNames := strings.Split(line[r+2:], " ")   // (184) slices line at r+2
...
i++
statValues := strings.Split(lines[i][r+2:], " ")  // (188) uses NEXT line, r from prev line, no i bound check
```

Two distinct out-of-range bugs on malformed input:

1. **`line[r+2:]` (line 184):** if the colon is at or near the end of a *matched* protocol
   header line, `r+2 > len(line)` → `slice bounds out of range`.
   Minimal input: a single line `Tcp:` → proto `tcp` matches the default set,
   colon at index 3, `len==4`, `line[5:]` → `panic: slice bounds out of range [5:4]`. **Confirmed.**

2. **`lines[i]` after `i++` (line 188):** if a matched protocol header is the **last**
   line (no data line follows), `i` reaches `len(lines)` → `index out of range`.
   Also `lines[i][r+2:]` reuses `r` from the previous line against the next line,
   so a short data line panics too.

## Minimal reproducer (Go test, red/green)

```go
//go:build linux
package repro

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/shirou/gopsutil/v4/common"
	gnet "github.com/shirou/gopsutil/v4/net"
)

func TestSNMPPanic(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	// A single truncated protocol header line.
	os.WriteFile(filepath.Join(dir, "net", "snmp"), []byte("Tcp:\n"), 0o644)
	ctx := context.WithValue(context.Background(), common.EnvKey,
		common.EnvMap{common.HostProcEnvKey: dir})
	// Panics without the fix; returns an error with it.
	_, _ = gnet.ProtoCountersWithContext(ctx, nil)
}
```

Replayed 3×: panics deterministically every time (`slice bounds out of range [5:4]`).

## Expected vs actual

- **Expected:** a malformed `/proc/net/snmp` yields an `error` (the function already
  returns descriptive errors for other malformations, e.g. missing `:` and column-count
  mismatch).
- **Actual:** `panic` on `line[r+2:]` / `lines[i]`.

## Suggested fix

Bound-check before slicing and before advancing `i`:

```go
if r+2 > len(line) { return nil, fmt.Errorf("%s: malformed header line", filename) }
...
if i+1 >= linecount { return nil, fmt.Errorf("%s: missing data line for %s", filename, proto) }
i++
if r+2 > len(lines[i]) { return nil, fmt.Errorf("%s: malformed data line", filename) }
```

## DashDiag reachability

**NOT reached.** DashDiag imports `gopsutil/v4/net` and calls `InterfacesWithContext`,
`IOCountersWithContext(ctx, true)` and `ConnectionsWithContext(ctx, "tcp")`
(internal/collectors/network_quick.go), but never `ProtoCounters`. The input source
would be the real kernel `/proc/net/snmp`, which is trusted when DashDiag runs as root
on a host whose kernel is not itself compromised. This is therefore a **library defect**
surfaced by the sweep, not a DashDiag vulnerability. Worth an upstream report; no
DashDiag code change required.
