package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestAWSInstanceTypeLabel(t *testing.T) {
	if got := awsInstanceTypeLabel(&models.AWSInfo{InstanceType: "c7i.large"}); got != "c7i.large" {
		t.Errorf("got %q, want c7i.large", got)
	}
	if got := awsInstanceTypeLabel(&models.AWSInfo{}); got != "instance" {
		t.Errorf("empty instance type should fall back to 'instance', got %q", got)
	}
}

func TestAzureAcceleratedNetworkingLabel(t *testing.T) {
	if got := azureAcceleratedNetworkingLabel(&models.AzureInfo{HasVF: true}); got != "active" {
		t.Errorf("HasVF should report active, got %q", got)
	}
	if got := azureAcceleratedNetworkingLabel(&models.AzureInfo{SyntheticNICs: []string{"eth0"}}); got != "synthetic path (no VF)" {
		t.Errorf("synthetic NIC without a VF should report the fallback path, got %q", got)
	}
	if got := azureAcceleratedNetworkingLabel(&models.AzureInfo{}); got != "unknown" {
		t.Errorf("neither VF nor synthetic NIC info should report unknown, got %q", got)
	}
}

func TestGCPNetworkingLabel(t *testing.T) {
	if got := gcpNetworkingLabel(&models.GCPInfo{UsesGVNIC: true, NICDriver: "gvnic"}); got != "gVNIC" {
		t.Errorf("gVNIC should take priority over the raw driver name, got %q", got)
	}
	if got := gcpNetworkingLabel(&models.GCPInfo{NICDriver: "virtio_net"}); got != "virtio_net" {
		t.Errorf("non-gVNIC driver should be reported by name, got %q", got)
	}
	if got := gcpNetworkingLabel(&models.GCPInfo{}); got != "synthetic" {
		t.Errorf("no driver info should fall back to synthetic, got %q", got)
	}
}

func TestVMwareProductLabel(t *testing.T) {
	if got := vmwareProductLabel(&models.VMwareInfo{ProductName: "VMware7,1"}); got != "VMware7,1" {
		t.Errorf("got %q, want VMware7,1", got)
	}
	if got := vmwareProductLabel(&models.VMwareInfo{}); got != "VMware" {
		t.Errorf("empty product name should fall back to VMware, got %q", got)
	}
}

func TestKVMGuestProductLabel(t *testing.T) {
	if got := kvmGuestProductLabel(&models.KVMGuestInfo{ProductName: "Standard PC (Q35)"}); got != "Standard PC (Q35)" {
		t.Errorf("got %q, want Standard PC (Q35)", got)
	}
	if got := kvmGuestProductLabel(&models.KVMGuestInfo{}); got != "QEMU/KVM" {
		t.Errorf("empty product name should fall back to QEMU/KVM, got %q", got)
	}
}

func TestContainerGuestIdentity(t *testing.T) {
	if got := containerGuestIdentity(&models.ContainerGuestInfo{Runtime: "docker"}); got != "📦 Container (docker)" {
		t.Errorf("got %q", got)
	}
	if got := containerGuestIdentity(&models.ContainerGuestInfo{}); got != "📦 Container (container)" {
		t.Errorf("empty runtime should fall back to generic 'container', got %q", got)
	}
	// A container running inside a hypervisor VM must surface that nesting —
	// the resource limits shown are the container's, not the VM's.
	got := containerGuestIdentity(&models.ContainerGuestInfo{Runtime: "docker", UnderlyingVM: "KVM"})
	want := "📦 Container (docker)  →  on a KVM VM"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestContainerHealthyMsg guards the #589 unverified-negative false-OK: a
// cgroup v1 host that couldn't actually read throttle/OOM counters must not
// claim "no throttling or OOM-kills" — that's a claim about something never
// measured, not a verified clean result.
func TestContainerHealthyMsg(t *testing.T) {
	v2 := containerHealthyMsg(&models.ContainerGuestInfo{CgroupV2: true})
	if got := v2; got != "container healthy — limits set, non-root, no throttling or OOM-kills" {
		t.Errorf("cgroup v2 should claim the full healthy message, got %q", got)
	}
	v1Measured := containerHealthyMsg(&models.ContainerGuestInfo{CgroupV1Measured: true})
	if got := v1Measured; got != "container healthy — limits set, non-root, no throttling or OOM-kills" {
		t.Errorf("cgroup v1 with readable counters should claim the full healthy message, got %q", got)
	}
	v1Unmeasured := containerHealthyMsg(&models.ContainerGuestInfo{})
	if got := v1Unmeasured; got != "container healthy — limits set, non-root (throttle/OOM not readable on this cgroup v1 host)" {
		t.Errorf("cgroup v1 with unreadable counters must NOT claim no-throttling/no-OOM, got %q", got)
	}
}
