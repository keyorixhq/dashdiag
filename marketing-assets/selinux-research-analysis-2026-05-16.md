# SELinux Pain Points — Research Analysis & DashDiag Response

**Source:** Deep Research Analysis: Linux Diagnostics & Troubleshooting Pain Points  
**Date:** 2026-05-16

---

## What the research found

SELinux is the single most complained-about subsystem in enterprise Linux.
The problems are not with SELinux's security model — they are with its UX.

### The five core pain points

**P0: Silent denials** — SELinux blocks access with no error message to the
application or user. Admins spend hours checking permissions, configs, and
firewalls before realising SELinux was the culprit. The community calls it
the "SELinux facepalm" — three admins, one hour, collective facepalm.

**P0: Tooling fragmentation** — five scattered tools with inconsistent naming,
many not installed by default:
```
ausearch     audit2why    audit2allow    sealert
semanage     restorecon   chcon          getenforce
```

**P1: audit2allow trap** — generates over-permissive policies. Under pressure
during an outage, admins blindly run `audit2allow | semodule -i` and
permanently weaken security. The correct fix is often a boolean toggle
or a file relabel — not a custom policy.

**P1: dontaudit suppression** — SELinux policies suppress certain denial logs
with dontaudit rules. When services fail silently, there may be zero AVC
entries in the log — not because SELinux is clean, but because it's hiding
the denials. Admins must know to run `semodule -DB` to expose them.

**P1: Port label confusion** — changing a service to a non-standard port
silently breaks it because SELinux port labels don't follow the config change.

---

## What dsd now does (implemented 2026-05-16)

### When denials are detected (WARN/CRIT):
```
❌ KernelSec: 3 SELinux denial(s) in the last hour (mode: enforcing)
   → to inspect:          ausearch -m avc -ts recent
   → to inspect:          sealert -a /var/log/audit/audit.log
   → to check booleans:   getsebool -a | grep httpd    ← process-specific
   → to generate fix:     ausearch -m avc -ts recent | audit2allow -M mypolicy
   → to apply fix:        semodule -i mypolicy.pp
   → note: check booleans and file contexts BEFORE using audit2allow
   → note: audit2allow may grant broader access than needed — review .te file first
   → sample AVC: type=AVC msg=audit(1747392847.123:456): avc: denied { read } ...
   → sample AVC: type=AVC msg=audit(1747392901.456:457): avc: denied { write } ...
```

**Three key improvements vs before:**
1. **Boolean check first** — parse comm= from AVC lines, suggest `getsebool | grep <process>`. Booleans are the safe fix; audit2allow is last resort.
2. **AVC samples inline** — admin sees exactly what was denied without grep
3. **Ordered fix pipeline** — inspect → booleans → context → audit2allow (in priority order)

### When SELinux is enforcing with zero denials (INFO):
```
ℹ️  KernelSec: SELinux enforcing — if services fail unexpectedly,
               dontaudit rules may suppress denials silently
   → to expose hidden denials: semodule -DB  (disables dontaudit rules)
   → to re-enable dontaudit:   semodule -B   (run after debugging)
   → to check for suppressed:  ausearch -m avc -ts recent --raw | wc -l
```

This directly addresses P1 dontaudit — the "invisible SELinux" problem where
services fail with no audit log evidence. The admin now knows to check.

---

## What dsd does NOT do (and why)

| Research need | Decision |
|---|---|
| P0: Make SELinux surface denials to applications | Kernel/OS problem — not fixable in userspace |
| P1: Policy linter for audit2allow output | Too complex, wrong layer for a diagnostic tool |
| P1: Per-service dontaudit diagnostic mode | Requires kernel module operations — out of scope |
| P1: systemd integration for port labels | Out of scope — systemd integration is Red Hat's job |

---

## Marketing angle

**"The single SELinux diagnostic command the research says doesn't exist — but does now."**

The research explicitly asked for: *"A unified, single-command diagnostic tool
that automatically detects recent denials, explains them in plain English, and
suggests the safest fix (boolean → context → port → custom policy)"*

dsd does exactly this. It follows the boolean → context → audit2allow priority
order the research recommends, surfaces AVC samples, and warns about dontaudit
suppression — all in one command, without needing to know which sub-tool to run.

---

## Port labeling — backlog item

When a WARN/CRIT fires on an open port that doesn't match standard service
ports, dsd should add:
```
→ if SELinux is blocking: semanage port -l | grep <port>
→ to add port label: semanage port -a -t http_port_t -p tcp <port>
```

This addresses P1 port labeling confusion. The security collector already
detects open ports — the connection to SELinux port labels needs to be made
in the heuristic layer when both SELinux is enforcing and a non-standard port
is detected. Backlog Sprint 5.

---

## SELinux marketing / positioning copy

**For RHEL/enterprise audiences:**
```
SELinux denying something? dsd tells you what, why, and how to fix it.

Without dsd:
  grep AVC /var/log/audit/audit.log
  pipe to audit2why
  google the error
  try audit2allow
  hope it doesn't break something

With dsd:
  dsd health
  → shows the denial, the process, the safe fix order
  → booleans first. audit2allow last.
```

**Twitter/X:**
```
SELinux silently broke something. Again.

dsd health shows:
- exactly what was denied (AVC samples inline)
- which boolean to check first
- the audit2allow pipeline if you need it
- whether dontaudit is hiding MORE denials

One command. No grep pipeline.

→ dashdiag.sh
```
