package platform

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeDMIDir(t *testing.T, productName, biosVendor string) (dir string, dmiDir string) {
	t.Helper()
	dir = t.TempDir()
	dmiDir = filepath.Join(dir, "dmi")
	_ = os.MkdirAll(dmiDir, 0755)
	if productName != "" {
		_ = os.WriteFile(filepath.Join(dmiDir, "product_name"), []byte(productName+"\n"), 0644)
	}
	if biosVendor != "" {
		_ = os.WriteFile(filepath.Join(dmiDir, "bios_vendor"), []byte(biosVendor+"\n"), 0644)
	}
	return dir, dmiDir
}

func TestDetectCloud_GCP(t *testing.T) {
	dir, dmiDir := makeDMIDir(t, "Google Compute Engine", "")
	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), filepath.Join(dir, "block"), "")
	if got != EnvGCP {
		t.Errorf("expected EnvGCP, got %v", got)
	}
}

func TestDetectCloud_Azure(t *testing.T) {
	dir, dmiDir := makeDMIDir(t, "Microsoft Azure Virtual Machine", "")
	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), filepath.Join(dir, "block"), "")
	if got != EnvAzure {
		t.Errorf("expected EnvAzure, got %v", got)
	}
}

func TestDetectCloud_AWSEBS_ProductName(t *testing.T) {
	dir, dmiDir := makeDMIDir(t, "Amazon EC2", "")
	blockDir := filepath.Join(dir, "block")
	_ = os.MkdirAll(blockDir, 0755)

	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), blockDir, "")
	if got != EnvAWSEBS {
		t.Errorf("expected EnvAWSEBS, got %v", got)
	}
}

func TestDetectCloud_AWSNVMe_BiosVendor(t *testing.T) {
	dir, dmiDir := makeDMIDir(t, "", "Amazon")
	blockDir := filepath.Join(dir, "block")
	nvmeDevDir := filepath.Join(blockDir, "nvme0", "device")
	_ = os.MkdirAll(nvmeDevDir, 0755)
	_ = os.WriteFile(filepath.Join(nvmeDevDir, "model"), []byte("Amazon EC2 NVMe Instance Storage\n"), 0644)

	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), blockDir, "")
	if got != EnvAWSNVMe {
		t.Errorf("expected EnvAWSNVMe, got %v", got)
	}
}

func TestDetectCloud_AWSEBS_HypervisorUUID(t *testing.T) {
	dir, dmiDir := makeDMIDir(t, "", "")
	uuidFile := filepath.Join(dir, "uuid")
	_ = os.WriteFile(uuidFile, []byte("ec2abcdef-1234-5678-abcd-ef0123456789\n"), 0644)
	blockDir := filepath.Join(dir, "block")
	_ = os.MkdirAll(blockDir, 0755)

	got := detectCloudEnvironmentFromPaths(dmiDir, uuidFile, blockDir, "")
	if got != EnvAWSEBS {
		t.Errorf("expected EnvAWSEBS, got %v", got)
	}
}

func TestDetectCloud_BareMetal(t *testing.T) {
	dir, dmiDir := makeDMIDir(t, "Standard PC", "")
	blockDir := filepath.Join(dir, "block")
	_ = os.MkdirAll(blockDir, 0755)

	// Use a server that immediately closes so IMDS check fails fast
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not aws", http.StatusNotFound)
	}))
	ts.Close() // close so connections are refused immediately

	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), blockDir, ts.URL)
	if got != EnvBareMetal {
		t.Errorf("expected EnvBareMetal, got %v", got)
	}
}

func TestDetectCloud_IMDSTimeout(t *testing.T) {
	dir, dmiDir := makeDMIDir(t, "", "")
	blockDir := filepath.Join(dir, "block")
	_ = os.MkdirAll(blockDir, 0755)

	// Server that never responds within 150ms
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer ts.Close()

	start := time.Now()
	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), blockDir, ts.URL)
	elapsed := time.Since(start)

	if got != EnvBareMetal {
		t.Errorf("expected EnvBareMetal after IMDS timeout, got %v", got)
	}
	if elapsed > 350*time.Millisecond {
		t.Errorf("IMDS check took %v, expected ~150ms timeout", elapsed)
	}
}

func TestDetectCloud_IMDS_Reachable(t *testing.T) {
	dir, dmiDir := makeDMIDir(t, "", "")
	blockDir := filepath.Join(dir, "block")
	_ = os.MkdirAll(blockDir, 0755)

	// Server that responds immediately (simulates reachable IMDS)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), blockDir, ts.URL)
	if got != EnvAWSEBS {
		t.Errorf("expected EnvAWSEBS when IMDS reachable, got %v", got)
	}
}
