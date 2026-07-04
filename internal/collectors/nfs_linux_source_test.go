//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestParseNFSMounts(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/mounts", []byte(
			"nfsserver:/export/data /mnt/data nfs4 rw,relatime 0 0\n"+
				"/dev/sda1 / ext4 rw,relatime 0 0\n"+ // non-NFS, must be skipped
				"192.168.1.5:/srv /mnt/backup nfs rw,vers=3 0 0\n",
		))
	})
	mounts := parseNFSMounts()
	if len(mounts) != 2 {
		t.Fatalf("expected 2 NFS mounts (the ext4 line must be skipped), got %d: %+v", len(mounts), mounts)
	}
	if mounts[0].Server != "nfsserver" || mounts[0].Export != "/export/data" || mounts[0].FSType != "nfs4" {
		t.Errorf("nfs4 mount parsed wrong: %+v", mounts[0])
	}
	if mounts[1].Server != "192.168.1.5" || mounts[1].FSType != "nfs" {
		t.Errorf("nfs mount parsed wrong: %+v", mounts[1])
	}
}

func TestNFSReadStats(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/rpc/nfs", []byte("net 100 0 0 100\nrpc 5000 12 0\n"))
	})
	info := &models.NFSInfo{}
	nfsReadStats(info)
	if info.RPCCalls != 5000 || info.RetransPerMin != 12 {
		t.Errorf("rpc calls/retrans should be parsed from the rpc line, got %+v", info)
	}
}
