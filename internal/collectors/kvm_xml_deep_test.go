//go:build linux

package collectors

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// kvmXMLFakeSource fakes `virsh dumpxml` output plus a fixed set of files that
// exist on disk, letting kvmCollectXMLDeep be exercised without a real libvirt.
type kvmXMLFakeSource struct {
	source.Source
	xmlOut string
	exists map[string]bool
}

func (s kvmXMLFakeSource) Run(_ context.Context, name string, args ...string) (source.Result, error) {
	if name == "virsh" && len(args) > 0 && args[0] == "dumpxml" {
		return source.Result{Stdout: []byte(s.xmlOut), ExitCode: 0}, nil
	}
	return source.Result{}, errors.New("unexpected command")
}

func (s kvmXMLFakeSource) Stat(p string) (source.FileMeta, error) {
	if s.exists[p] {
		return source.FileMeta{}, nil
	}
	return source.FileMeta{}, errors.New("no such file or directory")
}

// TestKVMCollectXMLDeep pins the three deep-only findings: an emulated NIC, an
// emulated disk bus on a real disk (a cdrom's ide bus must NOT count — that's
// normal), and a missing backing file.
func TestKVMCollectXMLDeep(t *testing.T) {
	const domXML = `<domain type='kvm'>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/libvirt/images/vm1.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <source file='/var/lib/libvirt/images/install.iso'/>
      <target dev='hda' bus='ide'/>
    </disk>
    <disk type='file' device='disk'>
      <source file='/var/lib/libvirt/images/vm1-data.qcow2'/>
      <target dev='sdb' bus='sata'/>
    </disk>
    <interface type='network'>
      <mac address='52:54:00:aa:bb:cc'/>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <interface type='bridge'>
      <mac address='52:54:00:11:22:33'/>
      <source bridge='br0'/>
      <model type='e1000'/>
    </interface>
  </devices>
</domain>`

	defer SetSource(SetSource(kvmXMLFakeSource{
		xmlOut: domXML,
		exists: map[string]bool{
			"/var/lib/libvirt/images/vm1.qcow2":   true,
			"/var/lib/libvirt/images/install.iso": true,
			// vm1-data.qcow2 deliberately absent — the missing-disk-file case.
		},
	}))

	vm := &models.KVMVM{Name: "vm1"}
	kvmCollectXMLDeep(context.Background(), vm)

	if len(vm.EmulatedNICs) != 1 || vm.EmulatedNICs[0] != "52:54:00:11:22:33 (e1000)" {
		t.Errorf("EmulatedNICs = %v, want one e1000 entry", vm.EmulatedNICs)
	}
	if len(vm.EmulatedDisks) != 1 || vm.EmulatedDisks[0] != "sdb (sata)" {
		t.Errorf("EmulatedDisks = %v, want only the sata data disk (cdrom's ide bus must be excluded)", vm.EmulatedDisks)
	}
	if vm.MissingDiskPath != "/var/lib/libvirt/images/vm1-data.qcow2" {
		t.Errorf("MissingDiskPath = %q, want the vm1-data.qcow2 path", vm.MissingDiskPath)
	}
}

// TestKVMCollectXMLDeep_HealthyVMIsClean is the false-WARN regression guard: an
// all-VirtIO VM with its backing file present must produce zero findings.
func TestKVMCollectXMLDeep_HealthyVMIsClean(t *testing.T) {
	const domXML = `<domain type='kvm'>
  <devices>
    <disk type='file' device='disk'>
      <source file='/var/lib/libvirt/images/vm2.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <mac address='52:54:00:aa:bb:dd'/>
      <model type='virtio'/>
    </interface>
  </devices>
</domain>`

	defer SetSource(SetSource(kvmXMLFakeSource{
		xmlOut: domXML,
		exists: map[string]bool{"/var/lib/libvirt/images/vm2.qcow2": true},
	}))

	vm := &models.KVMVM{Name: "vm2"}
	kvmCollectXMLDeep(context.Background(), vm)

	if len(vm.EmulatedNICs) != 0 || len(vm.EmulatedDisks) != 0 || vm.MissingDiskPath != "" {
		t.Errorf("expected a clean all-VirtIO VM to produce no deep findings, got %+v", vm)
	}
}

// TestKVMCollectXMLDeep_NetworkDiskNotFlagged confirms a network-backed disk
// (rbd/nbd — no Source.File attribute) is never guessed at as "missing".
func TestKVMCollectXMLDeep_NetworkDiskNotFlagged(t *testing.T) {
	const domXML = `<domain type='kvm'>
  <devices>
    <disk type='network' device='disk'>
      <source protocol='rbd' name='pool/vm3-disk'/>
      <target dev='vda' bus='virtio'/>
    </disk>
  </devices>
</domain>`

	defer SetSource(SetSource(kvmXMLFakeSource{xmlOut: domXML, exists: map[string]bool{}}))

	vm := &models.KVMVM{Name: "vm3"}
	kvmCollectXMLDeep(context.Background(), vm)

	if vm.MissingDiskPath != "" {
		t.Errorf("MissingDiskPath = %q, want empty — a network-backed disk has no local file to check", vm.MissingDiskPath)
	}
}
