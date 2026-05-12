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

	// Azure
	if strings.Contains(productName, "Virtual Machine") && strings.Contains(sysVendor, "Microsoft") ||
		strings.Contains(dmiAll, "microsoft azure") ||
		strings.Contains(sysVendor, "Microsoft Corporation") {
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
	default:
		return "unknown"
	}
}

// IsCloud returns true when running on any cloud provider.
func (e CloudEnvironment) IsCloud() bool {
	return e != EnvBareMetal && e != EnvUnknown
}
