//go:build linux

package collectors

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestSelinuxDeepDiagnosisGate covers the shared gate for both §6-add-2 (port
// labels) and §6-add-3 (chcon detection): SELinux must be active AND at least
// one AVC denial must already be present — mirrors the primer's escalation
// order and avoids extra shell-outs on a quiet enforcing host.
func TestSelinuxDeepDiagnosisGate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		info models.SecurityInfo
		want bool
	}{
		{"enforcing with denials", models.SecurityInfo{SELinuxMode: "enforcing", SELinuxDenials: 3}, true},
		{"permissive with denials", models.SecurityInfo{SELinuxMode: "permissive", SELinuxDenials: 1}, true},
		{"enforcing with zero denials", models.SecurityInfo{SELinuxMode: "enforcing", SELinuxDenials: 0}, false},
		{"enforcing with unavailable denial count (-1 sentinel)", models.SecurityInfo{SELinuxMode: "enforcing", SELinuxDenials: -1}, false},
		{"disabled/absent SELinux", models.SecurityInfo{SELinuxMode: "", SELinuxDenials: 5}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := selinuxDeepDiagnosisGate(&tt.info); got != tt.want {
				t.Errorf("selinuxDeepDiagnosisGate(%+v) = %v, want %v", tt.info, got, tt.want)
			}
		})
	}
}

func TestParseSemanagePortRanges(t *testing.T) {
	t.Parallel()

	const out = `SELinux Port Type              Proto  Port Number

http_port_t                    tcp    80, 443, 8008-8010
ssh_port_t                     tcp    22
dns_port_t                     udp    53
`
	ranges := parseSemanagePortRanges(out)

	tests := []struct {
		proto string
		port  int
		want  bool
	}{
		{"tcp", 80, true},
		{"tcp", 443, true},
		{"tcp", 8009, true}, // inside the 8008-8010 range
		{"tcp", 8011, false},
		{"tcp", 22, true},
		{"udp", 53, true},
		{"tcp", 53, false}, // dns_port_t is udp-only
		{"tcp", 9999, false},
	}
	for _, tt := range tests {
		if got := portRangeContains(ranges, tt.proto, tt.port); got != tt.want {
			t.Errorf("portRangeContains(%s/%d) = %v, want %v", tt.proto, tt.port, got, tt.want)
		}
	}
}

func TestParseSELinuxUnlabeledPorts(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("semanage", []string{"port", "-l"}, "SELinux Port Type              Proto  Port Number\n\nssh_port_t                      tcp    22\nhttp_port_t                     tcp    80, 443\n", 0)
	})

	listening := []models.PortEntry{
		{Port: 22, Protocol: "tcp", Process: "sshd"},
		{Port: 8080, Protocol: "tcp", Process: "nginx"}, // not in the semanage list — unlabeled
	}
	unlabeled := parseSELinuxUnlabeledPorts(context.Background(), listening)
	if len(unlabeled) != 1 || unlabeled[0].Port != 8080 {
		t.Fatalf("expected only port 8080 flagged unlabeled, got %+v", unlabeled)
	}
}

func TestParseSELinuxUnlabeledPorts_SemanageUnavailable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("semanage", []string{"port", "-l"})
	})
	got := parseSELinuxUnlabeledPorts(context.Background(), []models.PortEntry{{Port: 8080, Protocol: "tcp"}})
	if got != nil {
		t.Errorf("semanage unavailable must report nil (unknown), not a false 'unlabeled', got %+v", got)
	}
}

func TestParseFcontextRules(t *testing.T) {
	t.Parallel()

	const out = `SELinux fcontext                                  type               Context

/data/app(/.*)?                                    all files          system_u:object_r:httpd_sys_content_t:s0
/srv/myapp/logs(/.*)?                              regular file       system_u:object_r:httpd_log_t:s0
`
	rules := parseFcontextRules(out)
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d: %+v", len(rules), rules)
	}
	if !rules[0].pattern.MatchString("/data/app/config.ini") {
		t.Errorf("rule 0 should match /data/app/config.ini")
	}
	if rules[0].context != "system_u:object_r:httpd_sys_content_t:s0" {
		t.Errorf("rule 0 context = %q", rules[0].context)
	}
}

func TestFcontextCovers(t *testing.T) {
	t.Parallel()

	rules := parseFcontextRules(`SELinux fcontext                                  type               Context

/data/app(/.*)?                                    all files          system_u:object_r:httpd_sys_content_t:s0
`)

	tests := []struct {
		name   string
		path   string
		actual string
		want   bool
	}{
		{"covered path, matching type", "/data/app/config.ini", "unconfined_u:object_r:httpd_sys_content_t:s0", true},
		{"covered path, DIFFERENT type — chcon set a type semanage doesn't grant", "/data/app/config.ini", "unconfined_u:object_r:admin_home_t:s0", false},
		{"path outside any customization", "/etc/other/config.ini", "unconfined_u:object_r:admin_home_t:s0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := fcontextCovers(rules, tt.path, tt.actual); got != tt.want {
				t.Errorf("fcontextCovers(%s, %s) = %v, want %v", tt.path, tt.actual, got, tt.want)
			}
		})
	}
}

func TestSelinuxContextType(t *testing.T) {
	t.Parallel()

	tests := []struct{ ctx, want string }{
		{"system_u:object_r:httpd_sys_content_t:s0", "httpd_sys_content_t"},
		{"unconfined_u:object_r:admin_home_t:s0", "admin_home_t"},
		{"malformed", ""},
	}
	for _, tt := range tests {
		if got := selinuxContextType(tt.ctx); got != tt.want {
			t.Errorf("selinuxContextType(%q) = %q, want %q", tt.ctx, got, tt.want)
		}
	}
}

// TestParseSELinuxContextIssues_ChconDetected covers the full chcon-vs-semanage
// path: a denial-implicated file whose actual context differs from the policy
// default with no matching semanage customization must be flagged.
func TestParseSELinuxContextIssues_ChconDetected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("semanage", []string{"fcontext", "-C", "-l"}, "SELinux fcontext                                  type               Context\n", 0)
		b.PutCmd("matchpathcon", []string{"-n", "/data/app/config.ini"}, "system_u:object_r:admin_home_t:s0\n", 0)
		b.PutCmd("ls", []string{"-dZ", "/data/app/config.ini"}, "unconfined_u:object_r:httpd_sys_content_t:s0 /data/app/config.ini\n", 0)
	})

	groups := []models.SELinuxAVCGroup{{Scontext: "httpd_t", Tcontext: "admin_home_t", Tclass: "file", Paths: []string{"/data/app/config.ini"}}}
	issues := parseSELinuxContextIssues(context.Background(), groups)
	want := []models.SELinuxContextIssue{{
		Path: "/data/app/config.ini", ActualContext: "unconfined_u:object_r:httpd_sys_content_t:s0", ExpectedContext: "system_u:object_r:admin_home_t:s0",
	}}
	if !reflect.DeepEqual(issues, want) {
		t.Errorf("got %+v, want %+v", issues, want)
	}
}

// TestParseSELinuxContextIssues_CoveredBySemanage covers the "not an issue"
// case: the context differs from the policy default, but a matching semanage
// fcontext rule covers it — a legitimate, permanent customization.
func TestParseSELinuxContextIssues_CoveredBySemanage(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("semanage", []string{"fcontext", "-C", "-l"},
			"SELinux fcontext                                  type               Context\n\n"+
				"/data/app(/.*)?                                    all files          system_u:object_r:httpd_sys_content_t:s0\n", 0)
		b.PutCmd("matchpathcon", []string{"-n", "/data/app/config.ini"}, "system_u:object_r:admin_home_t:s0\n", 0)
		b.PutCmd("ls", []string{"-dZ", "/data/app/config.ini"}, "system_u:object_r:httpd_sys_content_t:s0 /data/app/config.ini\n", 0)
	})

	groups := []models.SELinuxAVCGroup{{Tclass: "file", Paths: []string{"/data/app/config.ini"}}}
	issues := parseSELinuxContextIssues(context.Background(), groups)
	if issues != nil {
		t.Errorf("a semanage-covered context difference must not be flagged, got %+v", issues)
	}
}

// TestParseAVCGroups_PathExtraction covers the Paths field added to
// SELinuxAVCGroup for the chcon-vs-semanage check (§6-add-3): an absolute
// name= on a file/dir-class denial is captured, a relative name= is dropped
// (there's no reliable way to resolve it to a full path from the AVC record
// alone), and a non-file-class denial (e.g. tclass=bpf) never contributes a path.
func TestParseAVCGroups_PathExtraction(t *testing.T) {
	now := time.Now()
	recent := now.Add(-30 * time.Second).Unix()

	absolute := fmt.Sprintf(`type=AVC msg=audit(%d.123:456): avc:  denied  { write } for  pid=1234 comm="httpd" name="/data/app/config.ini" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:admin_home_t:s0 tclass=file permissive=0`, recent)
	relative := fmt.Sprintf(`type=AVC msg=audit(%d.124:457): avc:  denied  { write } for  pid=1234 comm="httpd" name="config.ini" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:admin_home_t:s0 tclass=file permissive=0`, recent)
	nonFile := fmt.Sprintf(`type=AVC msg=audit(%d.125:458): avc:  denied  { prog_run } for  pid=1234 comm="init" name="/should/not/appear" scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:kernel_t:s0 tclass=bpf permissive=0`, recent)

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/var/log/audit/audit.log", []byte(absolute+"\n"+relative+"\n"+nonFile+"\n"))
	})

	groups := parseAVCGroups(context.Background(), time.Hour)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups (httpd/file and init/bpf), got %d: %+v", len(groups), groups)
	}
	for _, g := range groups {
		switch g.Tclass {
		case "file":
			if !reflect.DeepEqual(g.Paths, []string{"/data/app/config.ini"}) {
				t.Errorf("file group Paths = %v, want only the absolute path (relative name= dropped)", g.Paths)
			}
		case "bpf":
			if len(g.Paths) != 0 {
				t.Errorf("bpf group must never carry a path, got %v", g.Paths)
			}
		}
	}
}

func TestUniqueAVCPaths(t *testing.T) {
	t.Parallel()

	groups := []models.SELinuxAVCGroup{
		{Paths: []string{"/a", "/b"}},
		{Paths: []string{"/b", "/c"}}, // /b duplicated across groups
	}
	got := uniqueAVCPaths(groups)
	want := []string{"/a", "/b", "/c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("uniqueAVCPaths() = %v, want %v", got, want)
	}
}

// TestParseSELinuxContextIssues_MatchpathconEmpty covers security_linux.go:951-952 —
// the `continue` when matchpathconContext returns "" (the command is not seeded,
// so runCmd returns ErrNotRecorded → matchpathconContext returns ""). The
// `expected == ""` condition triggers and the loop body is skipped, resulting in
// a nil return despite non-empty paths.
func TestParseSELinuxContextIssues_MatchpathconEmpty(t *testing.T) {
	// No t.Parallel(): withFixtureSource swaps the package-global source.
	withFixtureSource(t, func(_ *source.Bundle) {
		// matchpathcon and ls -dZ intentionally not seeded → both return "" →
		// `expected == ""` fires → continue.
	})
	groups := []models.SELinuxAVCGroup{
		{Scontext: "httpd_t", Tcontext: "admin_home_t", Tclass: "file", Paths: []string{"/data/file"}},
	}
	issues := parseSELinuxContextIssues(t.Context(), groups)
	if issues != nil {
		t.Errorf("expected nil when matchpathconContext returns empty, got %+v", issues)
	}
}
