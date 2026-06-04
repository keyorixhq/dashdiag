# GTM Prep + BUG-021 Zombie Subprocess Investigation

Two independent tasks. Do them in order. Both are short.

---

## Task 1 — Wire Formspree into the landing page email capture

### Repo and file

Landing page repo: `/Users/abeshkov/proj/dashdiag-landing/`
File to edit: `index.html` (single file, 644 lines)

The email capture is currently stubbed at lines 621–637.
Formspree provides a zero-backend form endpoint — POST to their URL,
they store the email and can forward it. Free tier: 50 submissions/month.

### What to change

**Step 1: Create a free Formspree form**
URL to open in browser: https://formspree.io/register
After registering, create a new form for "dashdiag.sh email signup".
Formspree will give you an endpoint like: `https://formspree.io/f/XXXXXXXX`

**This step requires the user (Andrei) to do manually** — Claude Code cannot
create accounts. Once the endpoint URL is known, proceed with Step 2.

**Step 2: Replace the stub with a real Formspree fetch**

Find the stub block (lines ~621–637):
```javascript
// STUB: no backend yet. Wire to Formspree/Tally later.
msg.style.color = '#6fcf8e';
msg.textContent = '// got it — you\'re on the list. (demo: not stored yet)';
input.value = '';
console.log('[stub] captured email:', v, '— wire to a backend before launch');
```

Replace the entire `submit()` function body with:

```javascript
function submit() {
  const v = input.value.trim();
  const valid = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v);
  if (!valid) {
    msg.style.color = '#ef7565';
    msg.textContent = '// that doesn\'t look like an email — try again';
    return;
  }
  btn.disabled = true;
  msg.style.color = 'var(--text-dim)';
  msg.textContent = '// sending...';

  fetch('https://formspree.io/f/REPLACE_WITH_FORM_ID', {
    method: 'POST',
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: v, _subject: 'DashDiag signup: ' + v })
  })
  .then(r => r.json())
  .then(data => {
    if (data.ok) {
      msg.style.color = '#6fcf8e';
      msg.textContent = '// you\'re on the list — one email when it ships.';
      input.value = '';
    } else {
      msg.style.color = '#ef7565';
      msg.textContent = '// something went wrong — try again or email andrei@keyorix.com';
    }
  })
  .catch(() => {
    msg.style.color = '#ef7565';
    msg.textContent = '// network error — try again in a moment';
  })
  .finally(() => { btn.disabled = false; });
}
```

Leave `REPLACE_WITH_FORM_ID` as a literal placeholder — Andrei will swap it
with the real Formspree form ID once he registers. The page should still
compile and render correctly with the placeholder in place.

### Also add a `netlify.toml` to the landing repo

Create `/Users/abeshkov/proj/dashdiag-landing/netlify.toml`:

```toml
[build]
  publish = "."

[[headers]]
  for = "/*"
  [headers.values]
    X-Frame-Options = "DENY"
    X-Content-Type-Options = "nosniff"
    Referrer-Policy = "strict-origin-when-cross-origin"
    Content-Security-Policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://formspree.io; img-src 'self' data:; font-src 'self'"

[[redirects]]
  from = "/*"
  to = "/index.html"
  status = 200
```

The CSP `connect-src` includes `formspree.io` — required for the fetch call.
`unsafe-inline` is needed because the page has inline `<script>` and `<style>`.

### Verification for Task 1

```bash
cd /Users/abeshkov/proj/dashdiag-landing
# Confirm the placeholder is in place
grep "REPLACE_WITH_FORM_ID" index.html
# Confirm netlify.toml exists
cat netlify.toml
# Confirm no syntax errors in JS (basic check)
node -e "const fs = require('fs'); const html = fs.readFileSync('index.html', 'utf8'); console.log('HTML length:', html.length, 'OK');"
```

### Commit for Task 1

```bash
cd /Users/abeshkov/proj/dashdiag-landing
git add index.html netlify.toml
git commit -m "feat: wire Formspree email capture + add netlify.toml

- index.html: replace stub submit() with real Formspree fetch
  Endpoint: REPLACE_WITH_FORM_ID placeholder (swap before launch)
  Handles: sending state, success, error, network failure
  Error message: fallback email address for manual signup
- netlify.toml: publish='.', security headers, CSP includes formspree.io,
  SPA redirect rule for clean URLs
  Ready to connect to Netlify once dashdiag.sh domain is registered"
git push
```

---

## Task 2 — BUG-021: Zombie subprocess investigation

### Context

Read `BUGS.md` at the end — BUG-021 section. Then read:
- `internal/collectors/collector.go` — `runCmd()` function (31 lines)
- `internal/collectors/network_deep.go` — check for any direct `exec.Command` usage
- `internal/collectors/timeline_hints.go` — check for goroutine subprocess patterns

### What to investigate

The symptom: a zombie `<defunct>` subprocess appears during `dsd health` on PVE01
(Debian-based). PIDs 48436 (parent) and 48451 (child).

The `runCmd()` function uses `cmd.Run()` which calls `cmd.Wait()` internally —
should not leave zombies. The suspect patterns are:

**Pattern A:** A collector that uses `cmd.Start()` + manual `Stdout` reading
without calling `cmd.Wait()` on the error path.

**Pattern B:** A goroutine that starts a subprocess and returns early (e.g. on
context cancellation) before calling `cmd.Wait()`.

**Pattern C:** A subprocess that exits before its parent has set up a wait,
combined with a parent that holds the process reference but never calls Wait.

### Search steps

```bash
cd /Users/abeshkov/proj/dashdiag

# Find any direct exec.Command usage outside of runCmd
grep -rn "exec.Command\b\|exec.CommandContext\b" internal/collectors/ --include="*.go" | grep -v "runCmd\|func runCmd"

# Find any cmd.Start() usage (Start without Wait = zombie risk)
grep -rn "\.Start()\|cmd\.Start\b" internal/ --include="*.go"

# Find any goroutine-launched subprocesses
grep -rn "go func\|go run\|go collect\|goroutine" internal/collectors/*.go | grep -i "cmd\|exec\|run\|process" | head -20
```

### The fix

Once the offending pattern is found:

**If it's a `cmd.Start()` without `cmd.Wait()`:** Add `defer cmd.Wait()` or
add `cmd.Wait()` on all return paths, including the error path. Note:
`cmd.Wait()` must be called even when the process fails — otherwise the OS
keeps the process table entry until the parent exits.

**If it's a context-cancelled goroutine:** Ensure the goroutine always calls
`cmd.Wait()` before returning, even after context cancellation. The pattern:
```go
cmd.Start()
// ... read stdout ...
// On context cancel:
cmd.Process.Kill()  // send signal
cmd.Wait()          // reap the zombie — MUST be called
```

**If `runCmd()` itself is the issue:** The current implementation uses
`cmd.Run()` which handles Wait internally. However, `cmd.WaitDelay` combined
with context cancellation may have an edge case on older kernels — add
`defer cmd.Wait()` as a safety net if `cmd.Run()` returns an error.

### If no offending code is found

The zombie may be a one-time PVE host artifact (PVE itself spawning subprocesses
that briefly appear as children of dsd). In that case:
1. Add a comment to BUG-021 in BUGS.md noting no offending code found
2. Add a `// #nosec subprocess-wait` comment near `cmd.WaitDelay` in runCmd
3. Close the bug as "cannot reproduce / likely external"

### Verification for Task 2

```bash
# Build and deploy to PVE01
make release
scp dist/dsd-linux-amd64 root@192.168.10.20:/tmp/dsd

# Run health and watch for zombies
ssh root@192.168.10.20 '/tmp/dsd health > /dev/null 2>&1 & PID=$!; sleep 2; ps aux | grep defunct | grep -v grep; wait $PID'
# Expected: no defunct processes shown
```

### Commit for Task 2 (only if a fix is found)

```
fix(collectors): prevent zombie subprocess in <collector_name>

- <describe what was wrong>
- <describe the fix: defer cmd.Wait(), or whatever was needed>
- BUG-021: resolved
```

If no fix is needed, update BUGS.md only:
```
docs(bugs): BUG-021 — no offending subprocess code found, likely external
```

---

## Final note on sequencing

Task 1 (landing page) can be committed immediately — it doesn't need the domain.
The `REPLACE_WITH_FORM_ID` placeholder means Andrei can register Formspree,
swap one string, and push — that's the entire GTM backend integration.

Task 2 (BUG-021) is investigation-first — if no bug found, just close it in BUGS.md.
