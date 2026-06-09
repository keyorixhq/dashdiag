# DashDiag — Getting Started Guide
## For developers returning to code after a long break

---

## Step 1 — Install Go

Download from **https://go.dev/dl/** and install.

Verify:
```bash
go version   # should show go1.22+
```

## Step 2 — Install dev tools

```bash
cd /Users/andreibeshkov/dev/dashdiag
make tools
```

## Step 3 — Install the pre-commit hook

```bash
cp scripts/hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Step 4 — Verify everything works

```bash
make build
./dist/dsd --version
./dist/dsd --help
```

---

## Go in 10 Minutes (Perl comparison)

```
Perl                          Go
──────────────────────────────────────────────
my $x = 5                     x := 5
my @arr = (1, 2, 3)           arr := []int{1, 2, 3}
my %hash = (a => 1)           m := map[string]int{"a": 1}
sub myFunc { ... }            func myFunc() { ... }
die "error"                   return fmt.Errorf("error")
print "hello\n"               fmt.Println("hello")
```

**The three Go rules that catch every beginner:**

1. Every declared variable must be used (or use `_`)
2. Every imported package must be used
3. Opening brace must be on the SAME LINE as the statement

**Errors are values, not exceptions:**
```go
result, err := someFunction()
if err != nil {
    return nil, fmt.Errorf("calling someFunction: %w", err)
}
// use result here — you know it is valid
```

---

## The Development Loop

1. Read relevant docs/ARCHITECTURE.md section
2. Open Cursor Composer (Cmd+I)
3. Paste prompt from `DashDiag_Cursor_Guide.md`
4. Review output before accepting
5. `go build ./...` — must compile
6. `go test ./...` — must pass
7. `git commit`

---

## Reading Go Compiler Errors

```
./internal/collectors/cpu.go:15:2: x declared and not used
```
→ File `cpu.go`, line 15: declared `x` but never used it.

```
./internal/collectors/cpu.go:23:15: cannot use "hello" (type string) as type int
```
→ Wrong type — put a string where int is expected.

```
./internal/collectors/cpu.go:5:2: "fmt" imported and not used
```
→ Delete the `"fmt"` import line.

**When stuck:** copy the error, paste into Cursor Chat (Cmd+L), ask "how do I fix this?"

---

## Running Tests

```bash
go test ./...                          # all tests
go test ./... -race                    # with race detector (always use this)
go test ./internal/collectors/... -v  # verbose, one package
go test ./... -run TestCPUCollector   # one test by name
```

---

## Quick Reference

```bash
# Build
go build ./...          # compile (catches errors)
make build              # compile with version info → dist/dsd

# Test
make test               # unit tests with race detector
make cover              # tests + coverage.html

# Quality
make check              # format + vet + lint
make fmt                # auto-format all Go files

# Git
git status              # what changed
git diff                # changes inside files
git add .               # stage everything
git commit -m "feat: ..." # commit
git log --oneline       # history
git reset HEAD~1        # undo last commit (keep changes)
```

---

## When You Get Stuck

1. **Cursor Chat (Cmd+L):** paste the error, ask what it means
2. **https://gobyexample.com** — practical Go examples
3. **https://go.dev/tour/** — interactive Go tutorial (2 hours, worth it)
4. **https://play.golang.org** — run Go in browser without installing

---

## Checklist: Am I Ready to Start?

- [ ] `go version` shows 1.22+
- [ ] `make build` succeeds
- [ ] `./dist/dsd --version` prints a version
- [ ] `./dist/dsd --help` shows commands
- [ ] Pre-commit hook installed
- [ ] docs/ARCHITECTURE.md is in the project root
- [ ] `.cursorrules` is in the project root
- [ ] Cursor opens the project and finds `.cursorrules`

When all boxes are checked: open Cursor, open Composer (Cmd+I), and paste
Sprint 0 Prompt 1 from `DashDiag_Cursor_Guide.md`.
