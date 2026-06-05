//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// CloudInitCollector reports cloud-init provisioning state — primarily whether
// the instance finished configuring or errored out mid-boot ("booted but never
// configured"). All work is gated behind CloudInitAvailable() so this is
// zero-cost on hosts without cloud-init.
type CloudInitCollector struct{}

func NewCloudInitCollector() *CloudInitCollector { return &CloudInitCollector{} }

func (c *CloudInitCollector) Name() string           { return "CloudInit" }
func (c *CloudInitCollector) Timeout() time.Duration { return 5 * time.Second }

// CloudInitAvailable reports whether cloud-init is present on this host. Cheap
// gate (same pattern as KVMAvailable/SteamOSAvailable): true when the CLI is on
// PATH or the runtime status file exists (covers minimal images where the CLI is
// pruned but the datasource still ran).
func CloudInitAvailable() bool {
	if _, err := exec.LookPath("cloud-init"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/cloud-init/status.json"); err == nil {
		return true
	}
	return false
}

func (c *CloudInitCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.CloudInitInfo{Available: true}

	// `cloud-init status` (without --wait) just reads /run/cloud-init/status.json
	// and returns immediately — never blocks. NEVER add --wait here.
	out, err := runCmd(ctx, "cloud-init", "status", "--format=json")
	if err == nil && strings.TrimSpace(out) != "" {
		if parseCloudInitJSON(out, info) {
			return info, nil
		}
	}

	// Fallback for old cloud-init without --format=json: plain text "status: X".
	if txt, terr := runCmd(ctx, "cloud-init", "status"); terr == nil {
		parseCloudInitText(txt, info)
	}
	return info, nil
}

// cloudInitStatusJSON mirrors the fields of `cloud-init status --format=json`.
// recoverable_errors is keyed by level (WARNING/ERROR) → list of messages.
type cloudInitStatusJSON struct {
	Status            string              `json:"status"`
	ExtendedStatus    string              `json:"extended_status"`
	BootStatusCode    string              `json:"boot_status_code"`
	Datasource        string              `json:"datasource"`
	Errors            []string            `json:"errors"`
	RecoverableErrors map[string][]string `json:"recoverable_errors"`
	LastUpdate        string              `json:"last_update"`
}

// parseCloudInitJSON fills info from JSON output. Returns false if the payload
// could not be parsed (caller falls back to text).
func parseCloudInitJSON(out string, info *models.CloudInitInfo) bool {
	var j cloudInitStatusJSON
	if err := json.Unmarshal([]byte(out), &j); err != nil {
		return false
	}
	info.Status = strings.TrimSpace(j.Status)
	info.ExtendedStatus = strings.TrimSpace(j.ExtendedStatus)
	info.BootStatusCode = strings.TrimSpace(j.BootStatusCode)
	info.Datasource = strings.TrimSpace(j.Datasource)
	info.LastUpdate = strings.TrimSpace(j.LastUpdate)
	for _, e := range j.Errors {
		if e = strings.TrimSpace(e); e != "" {
			info.Errors = append(info.Errors, e)
		}
	}
	info.RecoverableErrors = flattenRecoverable(j.RecoverableErrors)
	return info.Status != "" || info.ExtendedStatus != ""
}

// flattenRecoverable turns the {level: [msgs]} map into a flat, stably-ordered
// list of "LEVEL: msg" strings (sorted by level for deterministic output).
func flattenRecoverable(m map[string][]string) []string {
	if len(m) == 0 {
		return nil
	}
	levels := make([]string, 0, len(m))
	for lvl := range m {
		levels = append(levels, lvl)
	}
	sort.Strings(levels)
	var out []string
	for _, lvl := range levels {
		for _, msg := range m[lvl] {
			if msg = strings.TrimSpace(msg); msg != "" {
				out = append(out, lvl+": "+msg)
			}
		}
	}
	return out
}

// parseCloudInitText handles the plain `cloud-init status` output of old
// versions: a single "status: <value>" line.
func parseCloudInitText(txt string, info *models.CloudInitInfo) {
	for _, line := range strings.Split(txt, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "status:"); ok {
			info.Status = strings.TrimSpace(v)
			return
		}
	}
}
