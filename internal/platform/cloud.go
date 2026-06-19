package platform

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CloudEnvironment int

const (
	EnvUnknown CloudEnvironment = iota
	EnvBareMetal
	EnvAWSEBS
	EnvAWSNVMe
	EnvGCP
	EnvAzure
	EnvDigitalOcean
	EnvHetzner
	EnvOracleCloud
	EnvVultr
	// EnvVirtualized is an on-prem hypervisor guest (VMware/KVM/QEMU/Xen/VirtualBox/
	// Hyper-V) that is not a recognized public cloud. Its storage is virtual, so it
	// gets the relaxed (cloud-like) IO-latency thresholds rather than bare-metal's
	// aggressive ones — a few ms of virtual-disk await is normal, not a fault.
	EnvVirtualized
)

func DetectCloudEnvironment() CloudEnvironment {
	return detectCloudEnvironmentFromPaths(
		"/sys/class/dmi/id",
		"/sys/hypervisor/uuid",
		"/sys/block",
		"http://169.254.169.254",
	)
}

func detectCloudEnvironmentFromPaths(dmiDir, hypervisorUUID, blockDir, imdsURL string) CloudEnvironment {
	// Read all useful DMI fields — sys_vendor and board_vendor are often
	// more reliable than product_name on cloud VMs.
	productName := readFileTrimmed(filepath.Join(dmiDir, "product_name"))
	sysVendor := readFileTrimmed(filepath.Join(dmiDir, "sys_vendor"))
	biosVendor := readFileTrimmed(filepath.Join(dmiDir, "bios_vendor"))
	boardVendor := readFileTrimmed(filepath.Join(dmiDir, "board_vendor"))
	chassisVendor := readFileTrimmed(filepath.Join(dmiDir, "chassis_vendor"))

	// Combine all DMI fields for easier matching
	dmiAll := strings.ToLower(productName + " " + sysVendor + " " + biosVendor + " " + boardVendor + " " + chassisVendor)

	// AWS — check product_name, bios_vendor, sys_vendor
	if strings.Contains(productName, "Amazon EC2") ||
		strings.Contains(sysVendor, "Amazon EC2") ||
		strings.Contains(biosVendor, "Amazon") {
		return detectAWSStorageTypeFromPaths(blockDir)
	}

	// GCP
	if strings.Contains(productName, "Google Compute") ||
		strings.Contains(sysVendor, "Google") ||
		strings.Contains(boardVendor, "Google") {
		return EnvGCP
	}

	// Azure — the chassis asset tag is the definitive marker (the value
	// WALinuxAgent and cloud-init key on). A "Microsoft Corporation" sys_vendor
	// or a "Virtual Machine" product name is NOT enough: every on-prem Hyper-V
	// guest reports exactly that DMI, so the old broad clauses misclassified
	// datacenter/dev Hyper-V VMs as Azure.
	chassisAssetTag := readFileTrimmed(filepath.Join(dmiDir, "chassis_asset_tag"))
	if chassisAssetTag == "7783-7084-3265-9085-8269-3286-77" ||
		strings.Contains(dmiAll, "microsoft azure") {
		return EnvAzure
	}

	// DigitalOcean
	if strings.Contains(sysVendor, "DigitalOcean") ||
		strings.Contains(productName, "Droplet") {
		return EnvDigitalOcean
	}

	// Hetzner
	if strings.Contains(sysVendor, "Hetzner") ||
		strings.Contains(productName, "Hetzner") ||
		strings.Contains(boardVendor, "Hetzner") {
		return EnvHetzner
	}

	// Oracle Cloud (OCI)
	if strings.Contains(sysVendor, "Oracle") ||
		strings.Contains(productName, "OracleCloud") ||
		strings.Contains(chassisVendor, "Oracle") {
		return EnvOracleCloud
	}

	// Vultr
	if strings.Contains(sysVendor, "Vultr") ||
		strings.Contains(productName, "Vultr") {
		return EnvVultr
	}

	// On-prem hypervisor guest (not a recognized public cloud) — virtual storage, so
	// it must NOT get bare-metal's aggressive IO thresholds. Checked before the EC2
	// UUID / IMDS fallbacks so a clearly-virtualized guest short-circuits the IMDS
	// network probe. (Cloud providers above already matched on their own DMI.)
	if isVirtualizedDMI(dmiAll) {
		return EnvVirtualized
	}

	// EC2 hypervisor UUID fallback
	uuid := readFileTrimmed(hypervisorUUID)
	if strings.HasPrefix(strings.ToLower(uuid), "ec2") {
		return detectAWSStorageTypeFromPaths(blockDir)
	}

	// IMDS last resort — only if nothing else matched
	if imdsURL != "" && checkIMDS(imdsURL) {
		return detectAWSStorageTypeFromPaths(blockDir)
	}

	return EnvBareMetal
}

func checkIMDS(url string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

func detectAWSStorageTypeFromPaths(blockDir string) CloudEnvironment {
	entries, err := os.ReadDir(blockDir)
	if err != nil {
		return EnvAWSEBS
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "nvme") {
			continue
		}
		model := readFileTrimmed(filepath.Join(blockDir, e.Name(), "device", "model"))
		if strings.Contains(model, "Instance Storage") {
			return EnvAWSNVMe
		}
	}
	return EnvAWSEBS
}

func readFileTrimmed(path string) string {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// isVirtualizedDMI reports whether the combined DMI string names an on-prem
// hypervisor (VMware/KVM/QEMU/VirtualBox/Xen/Hyper-V). Used as the last classifier
// before bare-metal so a virtual guest gets relaxed virtual-storage IO thresholds.
func isVirtualizedDMI(dmiAll string) bool {
	for _, marker := range []string{"vmware", "qemu", "kvm", "virtualbox", "innotek", "xen", "bochs"} {
		if strings.Contains(dmiAll, marker) {
			return true
		}
	}
	// On-prem Hyper-V (Azure already matched above on its asset tag).
	return strings.Contains(dmiAll, "microsoft") && strings.Contains(dmiAll, "virtual")
}

// String returns a human-readable name for the cloud environment.
func (e CloudEnvironment) String() string {
	switch e {
	case EnvBareMetal:
		return "bare-metal"
	case EnvAWSEBS:
		return "aws-ebs"
	case EnvAWSNVMe:
		return "aws-nvme"
	case EnvGCP:
		return "gcp"
	case EnvAzure:
		return "azure"
	case EnvDigitalOcean:
		return "digitalocean"
	case EnvHetzner:
		return "hetzner"
	case EnvOracleCloud:
		return "oracle-cloud"
	case EnvVultr:
		return "vultr"
	case EnvVirtualized:
		return "virtualized"
	default:
		return "unknown"
	}
}

// IsCloud returns true when running on any cloud provider.
func (e CloudEnvironment) IsCloud() bool {
	return e != EnvBareMetal && e != EnvUnknown && e != EnvVirtualized
}
