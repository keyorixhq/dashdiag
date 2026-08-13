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

func makeDMIFull(t *testing.T, fields map[string]string) (dir string, dmiDir string) {
	t.Helper()
	dir = t.TempDir()
	dmiDir = filepath.Join(dir, "dmi")
	_ = os.MkdirAll(dmiDir, 0755)
	for k, v := range fields {
		_ = os.WriteFile(filepath.Join(dmiDir, k), []byte(v+"\n"), 0644)
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

func TestDetectCloud_AzureByAssetTag(t *testing.T) {
	// Gen2 Azure VMs may carry only the chassis asset tag, not "azure" in DMI.
	dir, dmiDir := makeDMIFull(t, map[string]string{
		"sys_vendor":        "Microsoft Corporation",
		"product_name":      "Virtual Machine",
		"chassis_asset_tag": "7783-7084-3265-9085-8269-3286-77",
	})
	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), filepath.Join(dir, "block"), "")
	if got != EnvAzure {
		t.Errorf("Azure asset tag should detect EnvAzure, got %v", got)
	}
}

func TestDetectCloud_HyperVNotAzure(t *testing.T) {
	// An on-prem Hyper-V guest reports the same Microsoft DMI as Azure but has
	// no Azure asset tag — it must NOT be misclassified as Azure.
	dir, dmiDir := makeDMIFull(t, map[string]string{
		"sys_vendor":   "Microsoft Corporation",
		"product_name": "Virtual Machine",
	})
	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), filepath.Join(dir, "block"), "")
	if got == EnvAzure {
		t.Error("on-prem Hyper-V guest must not be detected as Azure")
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

// TestDetectCloud_DMIDirUnreadable is the regression test for the false-OK
// fix: a DMI directory that EXISTS but can't be read (a permission error —
// e.g. a hardened container or a restricted /sys view) must return
// EnvUnknown, not silently fall through every vendor check (all reading ""
// from the unreadable dir) to the confident EnvBareMetal default — which
// selects the STRICTEST IO-latency thresholds of any branch. Distinct from
// TestDetectCloud_BareMetal, where the directory is genuinely readable and
// simply empty of recognized vendor markers.
func TestDetectCloud_DMIDirUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — a 0000-mode directory is still readable by root, can't exercise this path")
	}
	dir := t.TempDir()
	dmiDir := filepath.Join(dir, "dmi")
	if err := os.MkdirAll(dmiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dmiDir, "product_name"), []byte("Standard PC\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dmiDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dmiDir, 0o755) }) // let t.TempDir() clean up

	blockDir := filepath.Join(dir, "block")
	_ = os.MkdirAll(blockDir, 0o755)
	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), blockDir, "")
	if got != EnvUnknown {
		t.Errorf("detectCloudEnvironmentFromPaths() = %v, want EnvUnknown when the DMI dir exists but can't be stat'd", got)
	}
}

// TestDetectCloud_DMIDirAbsent_NotUnknown is the control: a DMI directory
// that simply doesn't exist (the common case — non-x86 arch, or a container
// without /sys/class/dmi mounted) must NOT return EnvUnknown — that's the
// legitimate "no DMI concept here" case every vendor check is designed to
// fall through on, distinct from an active read failure.
func TestDetectCloud_DMIDirAbsent_NotUnknown(t *testing.T) {
	dir := t.TempDir()
	dmiDir := filepath.Join(dir, "does-not-exist")
	blockDir := filepath.Join(dir, "block")
	_ = os.MkdirAll(blockDir, 0o755)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not aws", http.StatusNotFound)
	}))
	ts.Close()

	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), blockDir, ts.URL)
	if got == EnvUnknown {
		t.Error("detectCloudEnvironmentFromPaths() = EnvUnknown, want a real classification when the DMI dir simply doesn't exist")
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

// TestDetectCloud_DSD_OFFLINE_SkipsIMDSProbe is a regression guard for
// cmd-04-04: DetectCloudEnvironment's IMDS fallback (checkIMDS) is the one
// outbound network call cloud-environment detection makes, and it used to
// fire unconditionally with no opt-out — reached from every standalone
// subcommand's exit-code path (cmd/exitcode.go's recordResultSeverity), not
// just `dsd health`. With DSD_OFFLINE set, a host whose DMI is silent about
// being EC2 must fall through to EnvBareMetal WITHOUT ever dialing the IMDS
// server — proven here the same way as the redirect regression test: the
// server records whether it was hit at all.
func TestDetectCloud_DSD_OFFLINE_SkipsIMDSProbe(t *testing.T) {
	t.Setenv("DSD_OFFLINE", "1")
	dir, dmiDir := makeDMIDir(t, "", "")
	blockDir := filepath.Join(dir, "block")
	_ = os.MkdirAll(blockDir, 0755)

	var hit bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), blockDir, ts.URL)
	if got != EnvBareMetal {
		t.Errorf("expected EnvBareMetal under DSD_OFFLINE (IMDS probe must be skipped), got %v", got)
	}
	if hit {
		t.Error("DSD_OFFLINE must prevent checkIMDS from ever contacting the metadata endpoint")
	}
}

// TestDetectCloud_IMDS_DoesNotFollowRedirect mirrors the collectors-side
// regression (internal-collectors-02-02): checkIMDS must not follow a
// redirect off the metadata endpoint to an attacker-chosen host.
func TestDetectCloud_IMDS_DoesNotFollowRedirect(t *testing.T) {
	dir, dmiDir := makeDMIDir(t, "", "")
	blockDir := filepath.Join(dir, "block")
	_ = os.MkdirAll(blockDir, 0755)

	var attackerHit bool
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attackerHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer attacker.Close()

	imds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL, http.StatusFound)
	}))
	defer imds.Close()

	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), blockDir, imds.URL)
	if attackerHit {
		t.Fatal("checkIMDS followed the redirect and dialed the attacker-controlled host")
	}
	if got != EnvBareMetal {
		t.Errorf("a refused redirect must not read as a reachable IMDS, got %v", got)
	}
}

func TestDetectCloud_Hetzner(t *testing.T) {
	dir, dmiDir := makeDMIFull(t, map[string]string{
		"sys_vendor":   "Hetzner",
		"product_name": "cx22",
	})
	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), filepath.Join(dir, "block"), "")
	if got != EnvHetzner {
		t.Errorf("expected EnvHetzner, got %v", got)
	}
}

func TestDetectCloud_DigitalOcean(t *testing.T) {
	dir, dmiDir := makeDMIFull(t, map[string]string{
		"sys_vendor":   "DigitalOcean",
		"product_name": "Droplet",
	})
	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), filepath.Join(dir, "block"), "")
	if got != EnvDigitalOcean {
		t.Errorf("expected EnvDigitalOcean, got %v", got)
	}
}

func TestDetectCloud_OracleCloud(t *testing.T) {
	dir, dmiDir := makeDMIFull(t, map[string]string{
		"sys_vendor":   "Oracle Corporation",
		"product_name": "OracleCloud",
	})
	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), filepath.Join(dir, "block"), "")
	if got != EnvOracleCloud {
		t.Errorf("expected EnvOracleCloud, got %v", got)
	}
}

func TestDetectCloud_Vultr(t *testing.T) {
	dir, dmiDir := makeDMIFull(t, map[string]string{
		"sys_vendor": "Vultr",
	})
	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), filepath.Join(dir, "block"), "")
	if got != EnvVultr {
		t.Errorf("expected EnvVultr, got %v", got)
	}
}

func TestCloudEnvironment_String(t *testing.T) {
	cases := []struct {
		env  CloudEnvironment
		want string
	}{
		{EnvBareMetal, "bare-metal"},
		{EnvAWSEBS, "aws-ebs"},
		{EnvGCP, "gcp"},
		{EnvHetzner, "hetzner"},
		{EnvDigitalOcean, "digitalocean"},
		{EnvOracleCloud, "oracle-cloud"},
		{EnvVultr, "vultr"},
	}
	for _, tc := range cases {
		if got := tc.env.String(); got != tc.want {
			t.Errorf("%v.String() = %q, want %q", tc.env, got, tc.want)
		}
	}
}

func TestCloudEnvironment_IsCloud(t *testing.T) {
	if EnvBareMetal.IsCloud() {
		t.Error("EnvBareMetal.IsCloud() should be false")
	}
	if !EnvHetzner.IsCloud() {
		t.Error("EnvHetzner.IsCloud() should be true")
	}
	if !EnvAWSEBS.IsCloud() {
		t.Error("EnvAWSEBS.IsCloud() should be true")
	}
}

func TestDetectCloud_VMwareVirtualized(t *testing.T) {
	dir, dmiDir := makeDMIFull(t, map[string]string{
		"sys_vendor":   "VMware, Inc.",
		"product_name": "VMware Virtual Platform",
	})
	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), filepath.Join(dir, "block"), "")
	if got != EnvVirtualized {
		t.Errorf("VMware guest should be EnvVirtualized, got %v", got)
	}
	if got.IsCloud() {
		t.Error("EnvVirtualized.IsCloud() should be false")
	}
}

func TestDetectCloud_KVMVirtualized(t *testing.T) {
	dir, dmiDir := makeDMIFull(t, map[string]string{
		"sys_vendor":   "QEMU",
		"product_name": "Standard PC (Q35 + ICH9, 2009)",
	})
	got := detectCloudEnvironmentFromPaths(dmiDir, filepath.Join(dir, "uuid"), filepath.Join(dir, "block"), "")
	if got != EnvVirtualized {
		t.Errorf("QEMU/KVM guest should be EnvVirtualized, got %v", got)
	}
}
