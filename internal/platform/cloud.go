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
	productName := readFileTrimmed(filepath.Join(dmiDir, "product_name"))
	if strings.Contains(productName, "Google Compute") {
		return EnvGCP
	}
	if strings.Contains(productName, "Microsoft Azure") {
		return EnvAzure
	}
	if strings.Contains(productName, "Amazon EC2") {
		return detectAWSStorageTypeFromPaths(blockDir)
	}

	biosVendor := readFileTrimmed(filepath.Join(dmiDir, "bios_vendor"))
	if strings.Contains(biosVendor, "Amazon") {
		return detectAWSStorageTypeFromPaths(blockDir)
	}

	uuid := readFileTrimmed(hypervisorUUID)
	if strings.HasPrefix(strings.ToLower(uuid), "ec2") {
		return detectAWSStorageTypeFromPaths(blockDir)
	}

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
