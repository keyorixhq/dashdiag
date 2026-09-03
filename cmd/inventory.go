package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/dashdiag/internal/collectors"
	"github.com/keyorixhq/dashdiag/internal/inventory"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
	"github.com/keyorixhq/dashdiag/internal/version"
)

var inventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Export hardware/software inventory for a CMDB",
	Long: `Emit this host's technical facts — hardware identity, specs, and an
installed-software summary — in a CMDB-ingestable format. Built from data
DashDiag already collects during diagnosis plus a few cheap identity reads;
nothing new or expensive is probed.

Covers: host identity (hostname, OS, kernel, arch, machine-id), system
vendor/model/serial, CPU, RAM + DIMM layout, physical drives (model/serial/
capacity), NICs (MAC/driver), GPUs (model/VRAM/driver), cloud placement
(provider/instance-type/region), and package count.

This is the technical-facts layer only — it does NOT supply the administrative
layer (owner, asset tag, warranty, location, licences), which is not visible
from the box.

Examples:
  dsd inventory                JSON (default — feed a CMDB API)
  dsd inventory --csv          flat key,value CSV (spreadsheet / bulk import)
  dsd inventory --csv --out inventory.csv
  dsd inventory --out host.json`,
	RunE: runInventory,
}

func init() {
	rootCmd.AddCommand(inventoryCmd)
	inventoryCmd.Flags().Bool("csv", false, "flat key,value CSV output instead of JSON")
}

func runInventory(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
	defer cancel()

	// Reuse collectors already run by dsd — hardware, GPU, and cloud metadata.
	var hw *models.HardwareInfo
	var gpu *models.GPUInfo
	var cloud *models.CloudInfo
	cols := []runner.Collector{
		collectors.NewHardwareCollector(),
		collectors.NewGPUCollector(),
		collectors.NewCloudMetaCollector(),
	}
	for r := range runner.RunAll(ctx, cols) {
		switch v := r.Data.(type) {
		case *models.HardwareInfo:
			hw = v
		case *models.GPUInfo:
			gpu = v
		case *models.CloudInfo:
			cloud = v
		}
	}

	collectedAt := time.Now().UTC().Format(time.RFC3339)
	inv := inventory.Build(hw, gpu, cloud, platform.Detect(), version.Version, collectedAt)

	csvOut, _ := cmd.Flags().GetBool("csv")
	var out string
	if csvOut {
		s, err := inventory.ToCSV(inv)
		if err != nil {
			return err
		}
		out = s
	} else {
		data, err := json.MarshalIndent(inv, "", "  ")
		if err != nil {
			return err
		}
		out = string(data) + "\n"
	}

	outFile, _ := cmd.Flags().GetString("out")
	if outFile != "" {
		// writeFileNoFollow, not os.WriteFile: same symlink-follow hardening as
		// dsd health --out (cmd/root.go's createOutFile) -- this site predates
		// that fix and was simply missed. Mode stays 0o644 (not createOutFile's
		// 0o600): inventory output is non-sensitive technical facts, not a full
		// diagnostic capture, so the world-readable default is unchanged.
		if err := writeFileNoFollow(outFile, []byte(out), 0o644); err != nil { //nolint:gosec // inventory is non-sensitive technical facts
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote inventory to %s\n", outFile)
		return nil
	}
	fmt.Print(out)
	return nil
}
