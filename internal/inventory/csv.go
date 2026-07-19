package inventory

import (
	"bytes"
	"encoding/csv"
	"io"
	"strconv"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ToCSV renders the inventory as a flat key,value table — the shape most CMDBs
// ingest directly. List items get indexed keys (drive.0.model, nic.1.mac, …).
func ToCSV(inv models.Inventory) (string, error) {
	var buf bytes.Buffer
	if err := writeCSV(&buf, inv); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// writeCSV encodes inv as CSV into dst. Extracted so tests can inject a failing
// io.Writer to exercise the error path.
func writeCSV(dst io.Writer, inv models.Inventory) error {
	w := csv.NewWriter(dst)
	rows := [][]string{{"key", "value"}}

	add := func(k, v string) {
		if v != "" {
			rows = append(rows, []string{k, v})
		}
	}
	addInt := func(k string, v int) {
		if v != 0 {
			rows = append(rows, []string{k, strconv.Itoa(v)})
		}
	}
	addFloat := func(k string, v float64) {
		if v != 0 {
			rows = append(rows, []string{k, strconv.FormatFloat(v, 'f', -1, 64)})
		}
	}

	add("collected_at", inv.CollectedAt)
	add("tool", inv.Tool)
	add("tool_version", inv.ToolVersion)

	add("host.hostname", inv.Host.Hostname)
	add("host.os", inv.Host.OS)
	add("host.distro", inv.Host.Distro)
	add("host.distro_version", inv.Host.DistroVersion)
	add("host.kernel", inv.Host.Kernel)
	add("host.arch", inv.Host.Arch)
	add("host.machine_id", inv.Host.MachineID)

	add("system.vendor", inv.System.Vendor)
	add("system.model", inv.System.Model)
	add("system.board", inv.System.Board)
	add("system.serial", inv.System.Serial)

	add("cpu.model", inv.CPU.Model)
	addInt("cpu.cores", inv.CPU.Cores)
	addInt("cpu.threads", inv.CPU.Threads)

	addFloat("memory.total_gb", inv.Memory.TotalGB)
	for i, s := range inv.Memory.Slots {
		p := "memory.slot." + strconv.Itoa(i) + "."
		add(p+"locator", s.Locator)
		addFloat(p+"size_gb", s.SizeGB)
		add(p+"type", s.Type)
		addInt(p+"speed_mt", s.SpeedMT)
	}

	for i, d := range inv.Drives {
		p := "drive." + strconv.Itoa(i) + "."
		add(p+"device", d.Device)
		add(p+"model", d.Model)
		add(p+"serial", d.Serial)
		addFloat(p+"size_gb", d.SizeGB)
	}

	for i, n := range inv.NICs {
		p := "nic." + strconv.Itoa(i) + "."
		add(p+"name", n.Name)
		add(p+"mac", n.MAC)
		addInt(p+"speed_mbps", n.SpeedMbps)
		add(p+"driver", n.Driver)
	}

	for i, g := range inv.GPUs {
		p := "gpu." + strconv.Itoa(i) + "."
		addInt(p+"index", g.Index)
		add(p+"name", g.Name)
		add(p+"vendor", g.Vendor)
		addFloat(p+"vram_total_gb", g.VRAMTotalGB)
		add(p+"drm_driver", g.DRMDriver)
		add(p+"mesa_version", g.MesaVersion)
		if g.NoDriver {
			rows = append(rows, []string{p + "no_driver", "true"})
		}
	}

	if c := inv.Cloud; c != nil {
		add("cloud.provider", c.Provider)
		add("cloud.instance_id", c.InstanceID)
		add("cloud.instance_type", c.InstanceType)
		add("cloud.region", c.Region)
	}

	add("software.package_manager", inv.Software.PackageManager)
	addInt("software.package_count", inv.Software.PackageCount)

	if err := w.WriteAll(rows); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}
