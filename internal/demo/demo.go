// Package demo embeds the fixture-derived scenarios `dsd demo` renders. It is a
// dependency-free leaf (like internal/source, internal/platform): it owns only
// the embedded YAML bytes and scenario metadata. Parsing the YAML and driving
// the render pipeline stays in cmd/ (cmd/demo.go), reusing the exact fixture
// struct and rendering code `dsd mock` already uses — this package never
// touches models/render/runner, so it can't drift into doing that work twice.
package demo

import (
	"embed"
	"fmt"
	"sort"
)

//go:embed scenarios/*.yaml
var scenariosFS embed.FS

// Scenario is one selectable `dsd demo <name>` target.
type Scenario struct {
	Name        string
	Description string
}

// scenarios is the curated demo set. Each entry's YAML file lives in both
// fixtures/ (source of truth) and scenarios/ (embedded copy, kept in sync —
// see TestEmbeddedScenariosMatchFixtures) and carries its own header comment
// declaring whether it's grounded in a real validated finding or synthetic.
var scenarios = []Scenario{
	{
		Name:        "failing-drive",
		Description: "A SMART-FAILED drive surfaced as a back-up-now CRIT, corroborated by I/O errors in dmesg",
	},
	{
		Name:        "proxmox-backup-gap",
		Description: "A Proxmox node with a healthy backup age that hides four guests with no backup job at all",
	},
	{
		Name:        "vmware-guest-scsi-timeout",
		Description: "A vSphere guest one storage failover away from going read-only — SCSI timeout below VMware's recommendation",
	},
	{
		Name:        "docker-host-meltdown",
		Description: "A crash-looping container, OOM kills, and a docker.sock footgun, correlated on one host",
	},
	{
		Name:        "cve-actively-exploited",
		Description: "Two CVEs from CISA's Known Exploited Vulnerabilities catalog sitting unpatched",
	},
}

// defaultScenario is the flagship `dsd demo` renders with no arguments: the
// clearest single symptom -> structural-cause -> fix chain in the set (elevated
// I/O latency -> SMART FAILED drive -> corroborating dmesg errors -> back up
// now), and the highest-stakes finding class (imminent data loss) of the five.
const defaultScenario = "failing-drive"

// Default returns the name of the flagship scenario.
func Default() string { return defaultScenario }

// List returns every scenario in display order.
func List() []Scenario {
	out := make([]Scenario, len(scenarios))
	copy(out, scenarios)
	return out
}

// Names returns every valid scenario name, sorted.
func Names() []string {
	out := make([]string, 0, len(scenarios))
	for _, s := range scenarios {
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out
}

// Load returns the raw YAML bytes for a named scenario, or an error naming the
// valid choices when name isn't one of them.
func Load(name string) ([]byte, error) {
	for _, s := range scenarios {
		if s.Name == name {
			return scenariosFS.ReadFile("scenarios/" + name + ".yaml")
		}
	}
	return nil, fmt.Errorf("unknown demo scenario %q (known: %v)", name, Names())
}
