package cmd

// capture.go — dsd capture
//
// Reads dsd health --json from stdin, writes a fixture YAML to stdout.
// The fixture can then be replayed on any machine with: dsd mock <file.yaml>
//
// Typical workflow:
//
//   # On the target machine (SSH or local):
//   sudo dsd health --gpu --json > /tmp/capture.json
//
//   # Transfer and convert:
//   scp user@host:/tmp/capture.json .
//   dsd capture < capture.json > fixtures/my-host.yaml
//
//   # Reproduce anywhere:
//   dsd mock fixtures/my-host.yaml
//
// Or in one step over SSH:
//   ssh user@host 'sudo dsd health --gpu --json' | dsd capture > fixtures/my-host.yaml

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/render"
)

var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Convert dsd health --json output into a replayable fixture YAML",
	Long: `Reads dsd health --json from stdin and writes a fixture YAML to stdout.

The fixture can be replayed on any machine without hardware using: dsd mock <file>

Workflow:
  # Capture from remote host:
  ssh user@host 'sudo dsd health --gpu --json' | dsd capture > fixtures/my-host.yaml

  # Or capture locally:
  sudo dsd health --json | dsd capture > fixtures/local.yaml

  # Capture with disk details:
  sudo dsd health --json | dsd capture > fixtures/my-host.yaml
  # (disk raw data — SMART, LVM, ZFS, drives — is automatically included)

  # Replay anywhere:
  dsd mock fixtures/my-host.yaml`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {}, // suppress brand header
	RunE:             runCapture,
}

func init() {
	rootCmd.AddCommand(captureCmd)
	captureCmd.Flags().String("cve", "", "fold in a `dsd cve --all --json` report from FILE")
	captureCmd.Flags().String("timeline", "", "fold in a `dsd timeline --json` report from FILE")
}

// captureInsight mirrors the JSON insight structure for unmarshalling.
type captureInsight struct {
	Check   string   `json:"check"`
	Level   string   `json:"level"`
	Message string   `json:"message"`
	Hints   []string `json:"hints"`
}

// captureCheck mirrors the JSON check structure for unmarshalling.
type captureCheck struct {
	Name   string          `json:"name"`
	Status string          `json:"status"`
	Inline string          `json:"inline"`
	Raw    json.RawMessage `json:"raw,omitempty"`
}

// diskRawChecks names the checks whose raw struct is preserved into the fixture
// so dsd mock can replay disk findings (SMART, LVM, btrfs, drives) without hardware.
var diskRawChecks = map[string]bool{
	"Disk":   true,
	"Drives": true,
	"LVM":    true,
	"ZFS":    true,
	"IO":     true,
	"Btrfs":  true,
}

// captureInput is the full JSON structure from dsd health --json.
type captureInput struct {
	Hostname string           `json:"hostname"`
	OS       string           `json:"os"`
	Version  string           `json:"version"`
	Checks   []captureCheck   `json:"checks"`
	Insights []captureInsight `json:"insights"`
}

func runCapture(cmd *cobra.Command, args []string) error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	var input captureInput
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("invalid JSON — run: sudo dsd health --json | dsd capture\nerror: %w", err)
	}

	if len(input.Checks) == 0 {
		return fmt.Errorf("no checks found in JSON — make sure input is from dsd health --json")
	}

	// Build insight map: check name → highest-severity insight
	insightMap := make(map[string]captureInsight, len(input.Insights))
	for _, ins := range input.Insights {
		prev, ok := insightMap[ins.Check]
		if !ok || severityRank(ins.Level) > severityRank(prev.Level) {
			insightMap[ins.Check] = ins
		}
	}

	// Build fixture rows in the same canonical order as the renderer
	rowOrder := render.DisplayOrder()
	ordered := make([]MockRow, 0, len(input.Checks))
	unordered := make([]MockRow, 0)

	checkMap := make(map[string]captureCheck, len(input.Checks))
	for _, c := range input.Checks {
		checkMap[c.Name] = c
	}

	seen := make(map[string]bool)
	for _, name := range rowOrder {
		c, ok := checkMap[name]
		if !ok {
			continue
		}
		seen[name] = true
		ordered = append(ordered, buildFixtureRow(c, insightMap))
	}
	for _, c := range input.Checks {
		if !seen[c.Name] {
			unordered = append(unordered, buildFixtureRow(c, insightMap))
		}
	}
	rows := append(ordered, unordered...)

	fix := MockFixture{
		Host:    input.Hostname,
		OS:      input.OS,
		Version: input.Version,
		Rows:    rows,
	}

	// Optionally fold in standalone report sections from other commands.
	// Each is validated against its real model type so a malformed or
	// wrong-command file fails loudly at capture time, not silently at replay.
	if cvePath, _ := cmd.Flags().GetString("cve"); cvePath != "" {
		j, err := readReportJSON(cvePath, func(b []byte) error {
			return strictUnmarshal(b, &models.CVEAllResult{})
		})
		if err != nil {
			return fmt.Errorf("--cve %s: %w (expected output of: dsd cve --all --json)", cvePath, err)
		}
		fix.CVEJSON = j
	}
	if tlPath, _ := cmd.Flags().GetString("timeline"); tlPath != "" {
		j, err := readReportJSON(tlPath, func(b []byte) error {
			return strictUnmarshal(b, &models.TimelineInfo{})
		})
		if err != nil {
			return fmt.Errorf("--timeline %s: %w (expected output of: dsd timeline --json)", tlPath, err)
		}
		fix.TimelineJSON = j
	}

	out, err := yaml.Marshal(fix)
	if err != nil {
		return fmt.Errorf("marshalling fixture: %w", err)
	}

	header := fmt.Sprintf("# fixture captured from %s (%s)\n# replay with: dsd mock <this-file>\n\n",
		input.Hostname, input.OS)

	_, err = os.Stdout.Write(append([]byte(header), out...))
	return err
}

func buildFixtureRow(c captureCheck, insightMap map[string]captureInsight) MockRow {
	level := strings.ToUpper(c.Status)
	if level == "" {
		level = "OK"
	}

	row := MockRow{Name: c.Name}

	// Preserve raw disk data so dsd mock can replay disk findings without hardware.
	// Stored regardless of level — OK disk rows carry useful detail for replay too.
	if diskRawChecks[c.Name] && len(c.Raw) > 0 {
		row.RawJSON = string(c.Raw)
	}

	if level == "OK" {
		row.Inline = c.Inline
		return row
	}

	// Find the best-matching insight — exact name match first,
	// then prefix match (e.g. "Sysctl" matches "Sysctl: swappiness").
	ins, ok := insightMap[c.Name]
	if !ok {
		prefix := c.Name + " "
		slash := c.Name + "/"
		for check, i := range insightMap {
			if strings.HasPrefix(check, prefix) || strings.HasPrefix(check, slash) {
				if !ok || severityRank(i.Level) > severityRank(ins.Level) {
					ins = i
					ok = true
				}
			}
		}
	}

	row.Level = level
	if ok {
		row.Message = ins.Message
		row.Hints = ins.Hints
	}
	return row
}

func severityRank(level string) int {
	switch level {
	case "CRIT":
		return 3
	case "WARN":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

// readReportJSON reads a JSON report file, validates it against the supplied
// decoder (which unmarshals into the expected model type), and returns the raw
// JSON string for embedding into the fixture. Validation at capture time means
// a wrong or malformed file is rejected here rather than failing silently when
// the fixture is later replayed with dsd mock.
func readReportJSON(path string, validate func([]byte) error) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading file: %w", err)
	}
	if len(b) == 0 {
		return "", fmt.Errorf("file is empty")
	}
	if err := validate(b); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}
	return string(b), nil
}

// strictUnmarshal decodes JSON into dest, rejecting unknown fields. This makes
// the section validators discriminating: a timeline report fed to --cve (or
// vice versa) is rejected because its keys don't match the target model, rather
// than silently unmarshalling into a zero-value struct. The top-level model
// structs share no field names, so cross-feeding always trips an unknown field.
func strictUnmarshal(b []byte, dest interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(dest)
}
