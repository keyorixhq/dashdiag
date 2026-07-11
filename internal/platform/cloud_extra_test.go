package platform

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCloudEnvironment_String_Unknown covers the default branch — any value
// outside the declared consts (e.g. a future const not yet given a case, or
// garbage from a bad cast) must render as "unknown", not panic or misreport.
func TestCloudEnvironment_String_Unknown(t *testing.T) {
	t.Parallel()
	var bogus CloudEnvironment = 999
	if got := bogus.String(); got != "unknown" {
		t.Errorf("String() for out-of-range value = %q, want unknown", got)
	}
	if got := EnvUnknown.String(); got != "unknown" {
		t.Errorf("EnvUnknown.String() = %q, want unknown", got)
	}
	if got := EnvVirtualized.String(); got != "virtualized" {
		t.Errorf("EnvVirtualized.String() = %q, want virtualized", got)
	}
	if got := EnvAWSNVMe.String(); got != "aws-nvme" {
		t.Errorf("EnvAWSNVMe.String() = %q, want aws-nvme", got)
	}
	if got := EnvAzure.String(); got != "azure" {
		t.Errorf("EnvAzure.String() = %q, want azure", got)
	}
}

// TestCheckIMDS_MalformedURL exercises checkIMDS's request-construction error
// path (http.NewRequestWithContext failing on an invalid URL), distinct from
// the network-failure and timeout paths already covered via httptest.
func TestCheckIMDS_MalformedURL(t *testing.T) {
	t.Parallel()
	if checkIMDS("://not-a-valid-url") {
		t.Error("checkIMDS(malformed URL) = true, want false")
	}
}

// TestDetectAWSStorageTypeFromPaths covers the branches TestDetectCloud_* don't:
// a ReadDir error (block dir missing entirely) and an nvme device present whose
// model does NOT mention Instance Storage (falls through to EBS).
func TestDetectAWSStorageTypeFromPaths(t *testing.T) {
	t.Parallel()

	t.Run("block dir missing", func(t *testing.T) {
		t.Parallel()
		got := detectAWSStorageTypeFromPaths(filepath.Join(t.TempDir(), "does-not-exist"))
		if got != EnvAWSEBS {
			t.Errorf("missing block dir = %v, want EnvAWSEBS (readdir-error fallback)", got)
		}
	})

	t.Run("nvme present but not instance storage", func(t *testing.T) {
		t.Parallel()
		blockDir := t.TempDir()
		devDir := filepath.Join(blockDir, "nvme0", "device")
		if err := os.MkdirAll(devDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(devDir, "model"), []byte("Amazon Elastic Block Store\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got := detectAWSStorageTypeFromPaths(blockDir)
		if got != EnvAWSEBS {
			t.Errorf("nvme EBS-backed model = %v, want EnvAWSEBS", got)
		}
	})

	t.Run("non-nvme entries are skipped", func(t *testing.T) {
		t.Parallel()
		blockDir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(blockDir, "sda"), 0o755); err != nil {
			t.Fatal(err)
		}
		got := detectAWSStorageTypeFromPaths(blockDir)
		if got != EnvAWSEBS {
			t.Errorf("non-nvme block device = %v, want EnvAWSEBS", got)
		}
	})
}
