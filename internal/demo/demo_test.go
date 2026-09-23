package demo

import (
	"os"
	"testing"
)

// TestEmbeddedScenariosMatchFixtures guards against internal/demo/scenarios/
// silently drifting from fixtures/, which stays the source of truth (see
// CLAUDE.md's "keep fixtures/ as the source of truth" instruction for `dsd
// demo`). Each embedded copy must be byte-identical to the fixture it was
// copied from — run `make demo-sync` to re-copy after editing a fixture.
func TestEmbeddedScenariosMatchFixtures(t *testing.T) {
	t.Parallel()
	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			embedded, err := scenariosFS.ReadFile("scenarios/" + s.Name + ".yaml")
			if err != nil {
				t.Fatalf("reading embedded scenario: %v", err)
			}
			source, err := os.ReadFile("../../fixtures/" + s.Name + ".yaml")
			if err != nil {
				t.Fatalf("reading source fixture: %v", err)
			}
			if string(embedded) != string(source) {
				t.Errorf("internal/demo/scenarios/%s.yaml has drifted from fixtures/%s.yaml — "+
					"fixtures/ is the source of truth; run `make demo-sync` to re-copy", s.Name, s.Name)
			}
		})
	}
}

func TestLoadUnknownScenario(t *testing.T) {
	t.Parallel()
	if _, err := Load("does-not-exist"); err == nil {
		t.Fatal("Load(\"does-not-exist\") = nil error, want an error naming the valid scenarios")
	}
}

func TestLoadEveryListedScenario(t *testing.T) {
	t.Parallel()
	for _, s := range List() {
		raw, err := Load(s.Name)
		if err != nil {
			t.Errorf("Load(%q): %v", s.Name, err)
			continue
		}
		if len(raw) == 0 {
			t.Errorf("Load(%q) returned empty content", s.Name)
		}
	}
}

func TestDefaultIsAValidScenario(t *testing.T) {
	t.Parallel()
	found := false
	for _, s := range scenarios {
		if s.Name == Default() {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Default() = %q is not in the scenario list", Default())
	}
}
