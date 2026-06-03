package cmd

// mock.go — dsd mock <fixture.yaml>
//
// Renders a DashDiag health output from a YAML fixture file, using the
// exact same render pipeline as a real run. No collectors are invoked.
//
// Use cases:
//   - Marketing screenshots without needing the target hardware
//   - Reproducing a specific finding for documentation
//   - Testing render output for new row types
//   - Demo fixtures for CI/CD pipeline checks
//
// Fixture format (YAML):
//
//	host: "web-prod-01"
//	os: "Ubuntu 22.04 LTS"
//	version: "v0.4.1"
//	rows:
//	  - name: "CPU Load"
//	    inline: "2%"
//	  - name: "Memory"
//	    inline: "3.1/32 GB (10%)"
//	  - name: "Packages"
//	    level: CRIT
//	    message: "14 critical security update(s) available (apt)"
//	    hints:
//	      - "to fix: apt-get upgrade"

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/render"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/version"
)

// MockFixture is the top-level YAML structure.
type MockFixture struct {
	Host    string    `yaml:"host"`
	OS      string    `yaml:"os"`
	Version string    `yaml:"version"`
	Rows    []MockRow `yaml:"rows"`
	// Optional standalone report sections captured from other commands.
	// Stored as raw JSON so mock can decode them back into the exact model
	// types the live collectors return and replay via the real print funcs.
	CVEJSON      string `yaml:"cve,omitempty"`      // dsd cve --all --json
	TimelineJSON string `yaml:"timeline,omitempty"` // dsd timeline --json
}

// MockRow defines one output row.
type MockRow struct {
	Name    string   `yaml:"name"`
	Level   string   `yaml:"level"`         // OK (default), WARN, CRIT, INFO
	Inline  string   `yaml:"inline"`        // shown on OK rows
	Message string   `yaml:"message"`       // shown on WARN/CRIT/INFO rows
	Hints   []string `yaml:"hints"`         // action hints shown in summary
	RawJSON string   `yaml:"raw,omitempty"` // raw disk JSON (SMART/LVM/ZFS/IO) for hardware-free replay
}

var mockCmd = &cobra.Command{
	Use:   "mock <fixture.yaml>",
	Short: "Render a health output from a YAML fixture — no hardware needed",
	Long: `Renders a DashDiag health output from a YAML fixture file.
Uses the exact same render pipeline as a real run.

Useful for:
  - Marketing screenshots without target hardware
  - Reproducing specific findings for documentation
  - Testing render output

Example fixture (legion.yaml):
  host: "andrei-Legion"
  os: "Linux Mint 22.3"
  rows:
    - name: "CPU Load"
      inline: "0%"
    - name: "GPU"
      inline: "2 GPUs: NVIDIA GeForce RTX 3070 Laptop GPU 34°C · amdgpu 41°C"
    - name: "Packages"
      level: CRIT
      message: "14 critical security update(s) available (apt)"
      hints:
        - "to fix: apt-get upgrade"`,
	Args:             cobra.ExactArgs(1),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {}, // suppress root brand header
	RunE:             runMock,
}

func init() {
	rootCmd.AddCommand(mockCmd)
}

func runMock(cmd *cobra.Command, args []string) error {
	path := args[0]

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read fixture %s: %w", path, err)
	}

	var fix MockFixture
	if err := yaml.Unmarshal(data, &fix); err != nil {
		return fmt.Errorf("invalid fixture YAML: %w", err)
	}

	// Print brand header using fixture metadata
	v := fix.Version
	if v == "" {
		v = version.Version
	}
	host := fix.Host
	if host == "" {
		host = "mock-host"
	}
	osName := fix.OS
	if osName == "" {
		osName = "Linux"
	}
	fmt.Fprintf(os.Stderr, "⚡ DashDiag (dsd) %s — %s · %s\n", v, host, osName)
	fmt.Fprintf(os.Stderr, "System health — read only checks, usually under 5s\n")
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("─", 56))

	// Convert fixture rows to runner.Result + models.Insight
	var results []runner.Result
	var insights []models.Insight

	for _, row := range fix.Rows {
		level := strings.ToUpper(row.Level)
		if level == "" {
			level = "OK"
		}

		// runner.Result — carries the name for ordering.
		// If the row preserved raw disk data, decode it back to the real model
		// type so the renderer sees exactly what a live collector would return.
		// Falls back to the text-only stub when raw is absent or fails to decode.
		var data interface{} = &mockData{inline: row.Inline}
		if d := mockRawData(row.Name, row.RawJSON); d != nil {
			data = d
		}
		results = append(results, runner.Result{
			Name: row.Name,
			Data: data,
		})

		// Only emit an insight for non-OK rows
		if level != "OK" {
			insights = append(insights, models.Insight{
				Level:   level,
				Check:   row.Name,
				Message: row.Message,
				Hints:   row.Hints,
			})
		}
	}

	mode := output.ModeHuman
	r := render.NewRenderer(mode)
	r.PrintAllMock(results, insights, mockInlineFunc(fix.Rows))

	start := time.Now().Add(-3 * time.Second) // simulate 3s run
	r.PrintSummary(insights, time.Since(start))

	// Replay optional standalone report sections through the real print
	// functions, so mocked CVE / timeline output is byte-identical to a
	// live run. Each is gated on presence and decoded back to its model type.
	if err := mockReplayCVE(fix.CVEJSON); err != nil {
		return err
	}
	if err := mockReplayTimeline(fix.TimelineJSON); err != nil {
		return err
	}

	return nil
}

// mockReplayCVE decodes a captured `dsd cve --all --json` report and renders it
// via the real printAllCVEs, so the mocked output matches a live scan exactly.
func mockReplayCVE(raw string) error {
	if raw == "" {
		return nil
	}
	var r models.CVEAllResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return fmt.Errorf("decoding captured cve section: %w", err)
	}
	printAllCVEs(&r)
	return nil
}

// mockReplayTimeline decodes a captured `dsd timeline --json` report and renders
// it via the real printTimeline with a simulated elapsed, matching a live run.
func mockReplayTimeline(raw string) error {
	if raw == "" {
		return nil
	}
	var info models.TimelineInfo
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		return fmt.Errorf("decoding captured timeline section: %w", err)
	}
	printTimeline(&info, 3*time.Second) // simulate 3s run
	return nil
}

// mockRawData decodes preserved raw disk JSON back into the concrete model type
// the live collector returns, keyed by check name. Returns nil when there is no
// raw data or it fails to decode — the caller then falls back to the text-only
// stub, so fixtures without raw data (and malformed raw) replay unchanged.
func mockRawData(name, raw string) interface{} {
	if raw == "" {
		return nil
	}
	var dest interface{}
	switch name {
	case "Disk":
		dest = &models.DiskInfo{}
	case "LVM":
		dest = &models.LVMInfo{}
	case "ZFS":
		dest = &models.ZFSInfo{}
	case "IO":
		dest = &models.IOInfo{}
	default:
		// "Drives" is already covered by DiskInfo; other names have no model mapping.
		return nil
	}
	if err := json.Unmarshal([]byte(raw), dest); err != nil {
		return nil // fall back to text-only replay — no regression
	}
	return dest
}

// mockData is a stub collector result so the renderer has something to type-switch on.
type mockData struct{ inline string }

// mockInlineFunc returns the inline text for a given row name from the fixture.
func mockInlineFunc(rows []MockRow) func(name string) string {
	m := make(map[string]string, len(rows))
	for _, row := range rows {
		m[row.Name] = row.Inline
	}
	return func(name string) string { return m[name] }
}
