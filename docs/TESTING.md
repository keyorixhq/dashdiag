# Testing Guide

## Quick Reference

```bash
make test                  # unit tests (race detector) — run constantly
make cover                 # unit tests + HTML coverage report
make test-integration      # real syscalls — run before pushing
make test-all              # unit + integration + contract
make golden-update         # update golden files after intentional output change
go test -fuzz=FuzzX ./... -fuzztime=60s   # fuzz a specific parser
```

## The Testing Pyramid

```
Unit (70%)       → mocked interfaces, deterministic, fast
Integration (15%) → real syscalls, build-tagged, slower
Contract (5%)    → JSON schema stability
Fuzz (5%)        → parser panic prevention
E2E (5%)         → real binary in real containers
```

## 1. Unit Tests

**Rule: never touch real `/proc`, `/sys`, or system commands.**

### The interface injection pattern

```go
// internal/collectors/memory.go
type MemoryReader interface {
    VirtualMemory() (*mem.VirtualMemoryStat, error)
}

type MemoryCollector struct {
    Reader       MemoryReader
    ContainerCtx platform.ContainerContext
}

func NewMemoryCollector(ctx platform.ContainerContext) *MemoryCollector {
    return &MemoryCollector{Reader: &gopsutilMemReader{}, ContainerCtx: ctx}
}
```

```go
// internal/collectors/memory_test.go
type mockMemReader struct{ vmem *mem.VirtualMemoryStat; err error }
func (m *mockMemReader) VirtualMemory() (*mem.VirtualMemoryStat, error) {
    return m.vmem, m.err
}
```

### Table-driven tests — always

```go
func TestMyCollector(t *testing.T) {
    t.Parallel()
    cases := []struct{ name string; input string; wantStatus string }{
        {"healthy",      "...", "OK"},
        {"warn boundary","...", "WARN"},
        {"crit boundary","...", "CRIT"},
        {"malformed",    "garbage", ""},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()
            // test here
        })
    }
}
```

### File-based parsers — use testdata/fixtures

```go
// Pure parser — no OS calls, injectable in tests
func parseVMStat(r io.Reader) (swapIn, swapOut uint64, err error) { ... }

// Test uses fixture file
func TestParseVMStat(t *testing.T) {
    f, _ := os.Open("testdata/fixtures/swap/vmstat_healthy.txt")
    defer f.Close()
    in, out, err := parseVMStat(f)
    // assert
}
```

Fixture files in `testdata/fixtures/<collector>/`:
```
linux_healthy.txt    ← real /proc content, healthy system
linux_warn.txt       ← content triggering WARN
linux_crit.txt       ← content triggering CRIT
macos_healthy.txt    ← macOS equivalent if different
```

## 2. Fuzz Tests

```go
func FuzzReadVMStat(f *testing.F) {
    f.Add("pswpin 0\npswpout 0\n")
    f.Add("")
    f.Add("garbage")
    f.Fuzz(func(t *testing.T, content string) {
        // must never panic
        _, _, _ = parseVMStat(strings.NewReader(content))
    })
}
```

Fuzz corpus committed in `testdata/fuzz/<parser>/`.

## 3. Golden File Tests

```go
var update = flag.Bool("update", false, "update golden files")

func testGolden(t *testing.T, name string, got string) {
    t.Helper()
    path := "testdata/golden/" + name + ".txt"
    if *update {
        os.WriteFile(path, []byte(got), 0644)
        return
    }
    want, err := os.ReadFile(path)
    if err != nil {
        t.Fatalf("golden file missing — run: make golden-update")
    }
    if string(want) != got {
        t.Errorf("output changed — run: make golden-update")
    }
}
```

Update: `make golden-update` → review diff → commit.

## 4. Integration Tests

```go
//go:build integration

func TestCPUCollector_Real(t *testing.T) {
    col := NewCPUCollector(platform.ContainerContext{})
    result, err := col.Collect(context.Background())
    require.NoError(t, err)
    info := result.(models.CPUInfo)
    assert.Greater(t, info.NumCPU, 0)
    assert.Contains(t, []string{"OK", "WARN", "CRIT"}, info.Status)
}
```

Run: `make test-integration` or `go test -tags integration ./...`

## Coverage Requirements

| Package | Minimum |
|---|---|
| `collectors/*.go` | 85% |
| `analysis/heuristics.go` | 95% |
| `output/tty.go` | 100% |
| `render/*.go` | 80% |

Check: `make cover` → opens `coverage.html`

## Writing Good Tests — Checklist

- [ ] `t.Parallel()` at top of every test and sub-test
- [ ] Table-driven with: healthy / WARN boundary / CRIT boundary / error
- [ ] No real `/proc` reads — use fixtures or mock interfaces
- [ ] Fixture files for all file-based parsers
- [ ] Golden file for every renderer output
- [ ] Fuzz test for every non-trivial parser
- [ ] `t.TempDir()` for any test that writes files
