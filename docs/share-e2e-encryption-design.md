# DashDiag --share: End-to-End Encryption Design

**Status:** Planned — not yet implemented  
**Decision date:** 2026-05-16  
**Privacy guarantee:** dashdiag.sh operators cannot read shared reports

---

## The Core Idea

The share URL contains two parts:

```
https://dashdiag.sh/s/ABC123#KEY456
                      │        │
                      │        └─ AES-256 decryption key (after #)
                      └─ Report ID (sent to server on fetch)
```

The `#fragment` part of a URL is a browser-only local value — it is **never
sent to the server** by HTTP specification. The server stores only the
encrypted ciphertext identified by the report ID. The decryption key travels
exclusively in the URL that the user shares manually (Slack, email, Jira, etc.).

**Result:**
- Server stores: encrypted blob it cannot read
- Attacker who breaches server gets: useless ciphertext
- Anyone with the full URL: can read the report in a browser
- dashdiag.sh operators: cannot read any shared report

---

## Full Flow

### Sharing (User 1, dsd CLI)

```
1. dsd health --share

2. CLI generates a random 256-bit AES key locally
   key = crypto/rand(32 bytes)

3. CLI serialises the health report to JSON

4. CLI encrypts: ciphertext = AES-256-GCM(key, reportJSON)

5. CLI uploads ONLY the ciphertext to dashdiag.sh
   POST /api/share
   Body: { ciphertext: base64(ciphertext), ttl_hours: 24 }
   Response: { id: "ABC123" }

6. CLI builds the share URL locally:
   url = "https://dashdiag.sh/s/ABC123#" + base64url(key)

7. CLI prints:
   Share: https://dashdiag.sh/s/ABC123#KEY456
   Expires: 24 hours
   ⚠ Treat this URL as a secret — anyone with it can read the report
```

### Reading (User 2, browser — no dsd required)

```
1. User 2 clicks link: https://dashdiag.sh/s/ABC123#KEY456

2. Browser requests: GET /s/ABC123
   → Fragment (#KEY456) is NOT sent to server

3. Server returns: HTML page + encrypted blob for ABC123

4. Browser JavaScript:
   a. Reads KEY456 from window.location.hash
   b. Decodes base64url(KEY456) → raw key bytes
   c. Fetches or uses inline ciphertext
   d. Decrypts: AES-256-GCM(key, ciphertext)
   e. Renders the report as a web page

5. Key never touches the server at any point
```

---

## What the Server Stores

```sql
CREATE TABLE shares (
  id         TEXT PRIMARY KEY,  -- random, opaque, no PII
  ciphertext BLOB NOT NULL,     -- AES-256-GCM encrypted report
  created_at TIMESTAMP,
  expires_at TIMESTAMP,
  -- NO: hostname, IP, username, key, plaintext content
);
```

The server cannot correlate reports across users. It has no identity data.
IDs are random, not derived from user identity.

---

## Security Properties

| Threat | Protection |
|--------|-----------|
| Server operator reads reports | ❌ Cannot — no decryption key |
| Database breach | ❌ Attacker gets encrypted blobs only |
| Network interception | ❌ HTTPS encrypts transport |
| Link shared publicly by mistake | ✅ Anyone with full URL can read (user responsibility) |
| Server stores link permanently | ✅ TTL enforced server-side — ciphertext deleted on expiry |
| Attacker has report ID but not key | ❌ Cannot decrypt without key |

---

## CLI Implementation (Go)

```go
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
)

func shareReport(report interface{}, ttlHours int) (string, error) {
    // 1. Serialise report
    plaintext, err := json.Marshal(report)
    if err != nil {
        return "", err
    }

    // 2. Generate random key locally — never leaves this function except in URL
    key := make([]byte, 32)
    if _, err := rand.Read(key); err != nil {
        return "", err
    }

    // 3. Encrypt with AES-256-GCM
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, gcm.NonceSize())
    rand.Read(nonce)
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

    // 4. Upload ciphertext only
    id, err := uploadCiphertext(ciphertext, ttlHours)
    if err != nil {
        return "", err
    }

    // 5. Build URL with key in fragment
    keyB64 := base64.RawURLEncoding.EncodeToString(key)
    url := fmt.Sprintf("https://dashdiag.sh/s/%s#%s", id, keyB64)
    return url, nil
}
```

---

## Browser Decryption (JavaScript)

```javascript
// Runs on dashdiag.sh/s/:id page
// Framework: vanilla JS — no dependencies needed for crypto

async function decryptReport() {
  // 1. Key is in URL fragment — browser never sent this to server
  const keyB64 = window.location.hash.slice(1); // remove leading #
  if (!keyB64) {
    showError("No decryption key in URL — share link may be incomplete");
    return;
  }

  // 2. Decode key
  const keyBytes = base64urlDecode(keyB64);
  const cryptoKey = await crypto.subtle.importKey(
    "raw", keyBytes,
    { name: "AES-GCM" },
    false, ["decrypt"]
  );

  // 3. Fetch ciphertext (report ID from URL path, key NOT included in request)
  const id = window.location.pathname.split("/").pop();
  const res = await fetch(`/api/share/${id}`);
  if (!res.ok) {
    showError(res.status === 404 ? "Report expired or not found" : "Failed to fetch");
    return;
  }
  const { ciphertext } = await res.json();
  const ciphertextBytes = base64Decode(ciphertext);

  // 4. Decrypt
  const nonceSize = 12; // GCM standard nonce
  const nonce = ciphertextBytes.slice(0, nonceSize);
  const encrypted = ciphertextBytes.slice(nonceSize);

  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      cryptoKey,
      encrypted
    );
    const report = JSON.parse(new TextDecoder().decode(plaintext));
    renderReport(report);
  } catch (e) {
    showError("Decryption failed — key may be wrong or data corrupted");
  }
}

decryptReport();
```

---

## Server Implementation (minimal)

The server is intentionally simple — it is a dumb encrypted blob store.

```
POST /api/share
  Body: { ciphertext: string, ttl_hours: int }
  → Stores blob, returns { id: string }
  → Server never inspects ciphertext contents

GET /api/share/:id
  → Returns { ciphertext: string } or 404 if expired/not found

DELETE /api/share/:id
  → Owner can request deletion (no auth needed — ID is unguessable)
```

No auth, no accounts, no logs of IPs or user agents beyond standard
web server access logs (which do NOT include the URL fragment).

---

## Privacy Decisions Locked In

These cannot be changed without a major version and public announcement:

1. **Key never touches the server** — generated locally, lives only in the URL
2. **Redaction by default** — before encryption, strip hostname, IPs, MACs
   - Opt-in to include: `dsd health --share --include-identity`
3. **TTL enforced** — default 24h, max 7 days, no permanent shares
4. **No account required** — anonymous upload only
5. **No logs of decryption** — server cannot know when/if a link was used
   (it only serves the ciphertext blob, the decryption happens in the browser)
6. **EU data residency** — server hosted in EU (GDPR)
7. **Open source server** — users can verify the server does what we claim
8. **`--report` always remains the zero-network alternative**

---

## What the Link Warning Should Say

```
dsd health --share

✅ Report encrypted locally with AES-256-GCM
✅ Hostname and IPs redacted (use --include-identity to include)
✅ dashdiag.sh cannot read this report
✅ Expires in 24 hours

Share: https://dashdiag.sh/s/ABC123#KEY456

⚠  This URL IS the decryption key. Treat it like a password.
   Anyone with the full link can read the report.
   Do not post in public channels.
```

---

## Multi-User Scenarios

### Scenario 1: Colleague review (most common)
```
User 1 → dsd health --share → gets URL
User 1 → pastes URL in Slack DM to User 2
User 2 → clicks URL in browser → sees report (no dsd needed)
```

### Scenario 2: Incident channel
```
User 1 → dsd health --share → gets URL
User 1 → posts URL in private incident Slack channel
All channel members → click URL → see report
```

### Scenario 3: Support ticket
```
User → dsd health --share → gets URL
User → attaches URL to support ticket to dashdiag.sh support team
Support → clicks URL → sees report
Note: dashdiag.sh support can read this (user shared the full URL with them)
      but dashdiag.sh DATABASE cannot be read by anyone
```

### Scenario 4: High security (future, requires accounts)
```
User 1 → dsd health --share --to user2@company.com
         → encrypts report to User 2's public key
         → User 2 decrypts with their private key
         → Nobody else can read it, not even User 1 after sharing
         → Requires account + key management — out of scope for v1
```

---

## Why This Architecture Makes Us a Boring Hacker Target

A breach of dashdiag.sh servers yields:
- Encrypted blobs with no associated metadata
- No usernames, emails, IPs, hostnames
- No decryption keys (never stored server-side)
- No way to know whose data is whose
- Data auto-deleted after TTL

This is significantly less valuable than a breach of a typical SaaS company
where plaintext customer data is stored. Attackers seek high-value targets.
A server full of unreadable encrypted blobs with no identifying metadata
is not worth the effort.

---

## Implementation Checklist (when ready to build)

### CLI (Go)
- [ ] `crypto/rand` key generation
- [ ] AES-256-GCM encryption
- [ ] Report redaction (strip hostname, IPs, MACs by default)
- [ ] HTTPS upload to share API
- [ ] URL construction with key in fragment
- [ ] Warning message with expiry and security note
- [ ] `--share --include-identity` flag
- [ ] `--share --ttl 4h` flag (1h, 4h, 24h, 7d)

### Server
- [ ] Minimal Go or Rust HTTP server
- [ ] POST /api/share — store encrypted blob
- [ ] GET /api/share/:id — return blob or 404
- [ ] DELETE /api/share/:id — manual deletion
- [ ] TTL enforcement (cron or lazy deletion on read)
- [ ] Rate limiting per IP (prevent abuse)
- [ ] No logging of URL fragments (already impossible — browser doesn't send them)
- [ ] EU hosting (Hetzner Finland or similar)

### Frontend (minimal)
- [ ] Single HTML page with inline JS
- [ ] Web Crypto API decryption
- [ ] Report renderer (reuse dsd --report markdown format)
- [ ] Error states (expired, wrong key, not found)
- [ ] No external JS dependencies (zero supply chain risk)

### Privacy audit before launch
- [ ] Verify server logs do not contain fragments (impossible by HTTP spec, but verify)
- [ ] Verify no plaintext stored anywhere in pipeline
- [ ] Penetration test of blob store
- [ ] Publish server source code
- [ ] Update PRIVACY.md with implementation details

---

## References

- Web Crypto API: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
- URL fragment privacy: https://www.rfc-editor.org/rfc/rfc9110#section-4.2.3
- AES-GCM in Go: https://pkg.go.dev/crypto/cipher#NewGCM
- Similar implementations: Privatebin, Pastebin (encrypted), age encryption tool
