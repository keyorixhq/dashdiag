package srcpath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRepoRootHoldsRootModule(t *testing.T) {
	root := RepoRoot()
	if got := modulePath(filepath.Join(root, "go.mod")); got != rootModule {
		t.Fatalf("RepoRoot() = %s, go.mod module = %q, want %q", root, got, rootModule)
	}
	if !filepath.IsAbs(root) {
		t.Fatalf("RepoRoot() = %q, want absolute path", root)
	}
}

func TestPkgDirIsThisPackage(t *testing.T) {
	if got, want := filepath.Base(PkgDir()), "srcpath"; got != want {
		t.Fatalf("PkgDir() base = %q, want %q", got, want)
	}
}

// Not parallel: t.Chdir mutates process state.
func TestChdirAfterInitDoesNotMovePaths(t *testing.T) {
	root, pkg := RepoRoot(), PkgDir()
	t.Chdir(t.TempDir())
	if got := RepoRoot(); got != root {
		t.Errorf("RepoRoot() after Chdir = %s, want %s", got, root)
	}
	if got := PkgDir(); got != pkg {
		t.Errorf("PkgDir() after Chdir = %s, want %s", got, pkg)
	}
	if _, err := os.Stat(filepath.Join(RepoRoot(), "go.mod")); err != nil {
		t.Errorf("go.mod unreachable after Chdir: %v", err)
	}
}

func TestModulePathParsing(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"module github.com/x/y\n\ngo 1.26\n":  "github.com/x/y",
		"module \"github.com/x/y\"\n":         "github.com/x/y",
		"// c\nmodule   github.com/x/y  \r\n": "github.com/x/y",
		"go 1.26\n":                           "",
		"modulefoo github.com/x/y\n":          "",
	}
	for body, want := range cases {
		p := filepath.Join(t.TempDir(), "go.mod")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := modulePath(p); got != want {
			t.Errorf("modulePath(%q) = %q, want %q", body, got, want)
		}
	}
	if got := modulePath(filepath.Join(t.TempDir(), "absent")); got != "" {
		t.Errorf("modulePath(missing) = %q, want empty", got)
	}
}
