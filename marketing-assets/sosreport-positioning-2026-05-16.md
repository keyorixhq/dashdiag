# DashDiag vs sosreport/supportconfig — Positioning

**Created:** 2026-05-16  
**Use for:** Landing page copy, objection handling, positioning

---

## What sosreport and supportconfig are

sosreport (Red Hat) and supportconfig (SUSE) are vendor support data
collection tools. They gather hundreds of files, logs, and command
outputs into a compressed archive (often gigabytes) that you send to
Red Hat or SUSE support engineers to diagnose your system remotely.

They are not self-diagnosis tools. They are "give us everything and
we'll figure it out for you" tools.

---

## The complaints

- Hangs for 15+ minutes on large systems (lshw, RPM database checks)
- Timeout bugs that don't actually kill hung processes
- Slow startup — even before doing any real work
- 2 GB archives for a support ticket

These are not gaps dsd should fill. These are sosreport's own bugs.
The users want sosreport to work better, not a different tool.

---

## Where dsd fits

dsd is what you run **before** you need support.

```
sosreport / supportconfig:
  "Something is broken. I need to send Red Hat all my logs
   so they can figure out what happened."

dsd --report:
  "Something might be wrong. Let me see what's going on
   and share a summary with my team."
```

dsd's `--report` flag generates a clean markdown file with:
- Every check result with status
- Fix commands for every finding
- CVE advisory summary
- Hardware details

No 2 GB archive. No sending data to a vendor. No waiting for support
to call back. Just a markdown file you can paste into a Slack message
or attach to a ticket — in 2 seconds.

---

## Positioning copy (public-facing)

### One line
- "Understand your system before you need to call support."
- "The diagnostic report you can actually read."
- "2 seconds, not 2 gigabytes."

### vs the archive
```
sosreport generates a 2 GB archive for Red Hat support engineers.
dsd --report generates a readable markdown summary for you and your team.

Same 30-second SSH session. Completely different output.
```

### Landing page blurb
```
Not a support bundle. A readable report.

dsd --report generates a clean markdown health summary —
every finding, every fix command, every CVE — in 2 seconds.

Paste it in Slack. Attach it to a ticket. Share it with your team.
No gigabyte archives. No vendor logins. No waiting.
```

---

## LinkedIn post angle

```
sosreport can take 15 minutes to run.
The archive it produces is gigabytes.
It's designed for Red Hat support engineers, not for you.

dsd --report takes 2 seconds.
The output is a markdown file you can read in Slack.
It's designed for the person who needs to know what's wrong right now.

Two tools. Same problem. Very different philosophy.

→ dashdiag.sh

#linux #sysadmin #devops #rhel #observability
```

---

## Twitter / X

```
sosreport: 15 minutes, 2 GB archive, designed for vendor support.
dsd --report: 2 seconds, markdown file, designed for you.

→ dashdiag.sh
```

---

## Objection handling (sales conversations)

**"We already use sosreport for diagnostics."**

sosreport is for opening support tickets with Red Hat.
dsd is for understanding your system before you need to.
They solve different problems. Most teams need both — sosreport
when something breaks badly enough to call Red Hat, dsd for
everything before that point.

**"We need to collect logs for our support team."**

dsd --report gives your support team a structured health summary
with findings and fix commands — not raw logs. It's designed to
be readable by anyone, not just the engineer who ran it.

---

## Key differentiators

| | sosreport | dsd --report |
|--|-----------|-------------|
| Runtime | 5–15 min | 2 seconds |
| Output size | Gigabytes | ~10 KB markdown |
| Readable by | Red Hat engineers | Anyone |
| Network required | Yes (upload to Red Hat) | No |
| Designed for | Vendor support | Self-diagnosis + team sharing |
| Fix commands | No | Yes |
