package canaryoracle

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/share"
	"github.com/keyorixhq/dashdiag/internal/source"
)

type ctx struct {
	name    string
	inClaim bool
	// text is a template with one %s for the canary raw value.
	text string
}

var contexts = []ctx{
	// in-claim
	{"kv-password", true, "db_password=%s\n"},
	{"kv-password-colon", true, "password: %s\n"},
	{"kv-api-key", true, "API_KEY=%s\n"},
	{"kv-token", true, "auth_token = %s\n"},
	{"kv-secret-quoted", true, "client_secret=\"%s\"\n"},
	{"kv-access-key", true, "aws_secret_access_key=%s\n"},
	{"bearer", true, "Authorization: Bearer %s\n"},
	{"url-userinfo", true, "https://admin:%s@registry.example.com/v2/\n"},
	{"url-userinfo-db", true, "postgres://app:%s@10.0.0.5:5432/db\n"},
	{"netrc", true, "machine example.com login bob password %s\n"},
	{"jwt", true, "token seen: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.%s\n"},
	{"shadow", true, "root:$6$saltsalt$%s:19000:0:99999:7:::\n"},
	{"pem", true, "-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----\n"},
	// out-of-claim (documented best-effort)
	{"flag-space", false, "mysql --user=root --password %s db\n"},
	{"flag-short", false, "mysql -u root -p%s db\n"},
	{"curl-u", false, "curl -u admin:%s https://example.com\n"},
	{"redis-a", false, "redis-cli -a %s ping\n"},
	{"prose", false, "the admin password is %s, do not share\n"},
	{"env-prefixed", false, "MYAPP_DB_PASS=%s ./run.sh\n"},
}

type redactor struct {
	name string
	fn   func(string) string
}

func redactors() []redactor {
	return []redactor{
		{"share.RedactText", func(s string) string { o, _ := share.RedactText(s, "host1", share.RedactOptions{}); return o }},
		{"source.RedactSecretsText", func(s string) string { o, _ := source.RedactSecretsText([]byte(s)); return string(o) }},
	}
}

func jsonRedactors() []redactor {
	return []redactor{
		{"share.RedactJSONBytes", func(s string) string {
			o, _, err := share.RedactJSONBytes([]byte(s), "host1", share.RedactOptions{})
			if err != nil {
				return s
			}
			return string(o)
		}},
		{"source.RedactJSONSecrets", func(s string) string {
			o, err := source.RedactJSONSecrets([]byte(s))
			if err != nil {
				return s
			}
			return string(o)
		}},
	}
}

func seed() uint64 {
	if v := os.Getenv("CANARY_SEED"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return 1
}

type finding struct {
	Redactor, Context, Variant string
	InClaim                    bool
}

func TestRedactorsCanary(t *testing.T) {
	var found []finding
	run := func(r redactor, c ctx, label, input string, can Canary) {
		out := r.fn(input)
		sc := NewScanner(can)
		for _, h := range sc.Scan("out", []byte(out)) {
			found = append(found, finding{r.name, label, h.Variant, c.inClaim})
		}
	}
	for i, c := range contexts {
		can := New("ctx-"+c.name, Secret, seed()+uint64(i), false)
		in := fmt.Sprintf(c.text, can.Raw)
		for _, r := range redactors() {
			run(r, c, c.name, in, can)
		}
		// JSON forms: secret-named key and CLI argv array element.
		var jsonIn string
		if c.inClaim {
			b, _ := json.Marshal(map[string]any{"line": in, "k": "v"})
			jsonIn = string(b)
		} else {
			b, _ := json.Marshal(map[string]any{"cmdline": strings.Fields(in)})
			jsonIn = string(b)
		}
		for _, r := range jsonRedactors() {
			run(r, c, c.name+"/json", jsonIn, can)
		}
	}
	// JSON secret-named keys (in-claim) for the JSON redactors.
	for i, k := range []string{"password", "api_key", "token", "client_secret", "db_password"} {
		can := New("jk-"+k, Secret, seed()+100+uint64(i), true)
		b, _ := json.Marshal(map[string]any{k: can.Raw, "other": "x"})
		for _, r := range jsonRedactors() {
			run(r, ctx{k, true, ""}, "jsonkey-"+k, string(b), can)
		}
	}
	bad := 0
	seen := map[string]bool{}
	for _, f := range found {
		key := f.Redactor + "|" + f.Context + "|" + f.Variant
		if seen[key] {
			continue
		}
		seen[key] = true
		if f.InClaim {
			bad++
			t.Errorf("IN-CLAIM survivor: redactor=%s context=%s variant=%s", f.Redactor, f.Context, f.Variant)
		}
	}
	if p := os.Getenv("CANARY_OUT"); p != "" {
		b, _ := json.MarshalIndent(found, "", " ")
		_ = os.WriteFile(p, b, 0o600)
	}
	t.Logf("survivors total=%d in-claim-unique=%d", len(seen), bad)
}
