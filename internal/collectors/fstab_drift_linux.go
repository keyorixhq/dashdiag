//go:build linux

package collectors

import (
	"context"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// FstabDriftCollector flags /etc/fstab entries whose UUID=/PARTUUID= reference
// matches no present device — the cloned-VM / replaced-disk boot failure where
// fstab still names an old filesystem id. Verified against the udev tag symlinks
// (/dev/disk/by-uuid, by-partuuid) which are world-readable and source-routed, so
// the check works non-root and replays faithfully.
type FstabDriftCollector struct{}

func NewFstabDriftCollector() *FstabDriftCollector { return &FstabDriftCollector{} }

func (c *FstabDriftCollector) Name() string           { return "Fstab" }
func (c *FstabDriftCollector) Timeout() time.Duration { return 3 * time.Second }

// FstabAvailable gates the collector on /etc/fstab being present (essentially every
// real Linux host; absent on many minimal containers and some immutable images).
func FstabAvailable() bool { return fileExists("/etc/fstab") }

func (c *FstabDriftCollector) Collect(_ context.Context) (interface{}, error) {
	data, err := readFile("/etc/fstab")
	if err != nil {
		return &models.FstabInfo{Checked: false}, nil
	}
	byUUID := lowerDirNameSet("/dev/disk/by-uuid")
	byPart := lowerDirNameSet("/dev/disk/by-partuuid")
	// Without the udev tag dirs we can't tell a missing device from a missing udev —
	// don't verify (a false drift on every entry would be the worst outcome).
	if len(byUUID) == 0 && len(byPart) == 0 {
		return &models.FstabInfo{Checked: false}, nil
	}
	return &models.FstabInfo{Checked: true, Drifts: parseFstabDrifts(string(data), byUUID, byPart)}, nil
}

// lowerDirNameSet returns the lowercased entry names of dir as a set, or nil if it
// can't be read. Lowercased so UUID matching is case-insensitive (vfat ids are
// uppercase, ext/xfs lowercase) — avoids a case mismatch reading as a false drift.
func lowerDirNameSet(dir string) map[string]bool {
	names, err := readDirNames(dir)
	if err != nil || len(names) == 0 {
		return nil
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[strings.ToLower(n)] = true
	}
	return m
}

// parseFstabDrifts returns fstab entries whose UUID=/PARTUUID= reference is absent
// from the present-device sets. CONSERVATIVE: only UUID=/PARTUUID= specs are
// checked — device paths (/dev/...), LABEL=, and pseudo/network filesystems are
// skipped (not a verifiable id), `noauto` entries are skipped (not mounted at
// boot) as are `nofail` entries (an absent nofail device does not fail boot), and
// a tag class is only judged when its set is non-empty (so a host with
// no /dev/disk/by-partuuid never false-flags PARTUUID= entries). Result: a flagged
// entry is unambiguously a configured-but-absent device, never a reachable mount.
func parseFstabDrifts(fstab string, byUUID, byPart map[string]bool) []models.FstabDrift {
	var out []models.FstabDrift
	for _, line := range strings.Split(fstab, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		spec, mnt := f[0], f[1]
		opts := ""
		if len(f) >= 4 {
			opts = f[3]
		}
		if hasMountOpt(opts, "noauto") {
			continue // not mounted at boot — not a boot-failure risk
		}
		if hasMountOpt(opts, "nofail") {
			continue // nofail tolerates an absent device — boot proceeds, so the
			// "this mount will fail at boot" WARN would be a false alarm. nofail is
			// exactly what admins set for optional/removable devices (USB, backup
			// disks, network targets) that are legitimately absent at times.
		}

		var set map[string]bool
		var val string
		switch {
		case strings.HasPrefix(spec, "UUID="):
			val, set = unquote(strings.TrimPrefix(spec, "UUID=")), byUUID
		case strings.HasPrefix(spec, "PARTUUID="):
			val, set = unquote(strings.TrimPrefix(spec, "PARTUUID=")), byPart
		default:
			continue // /dev path, LABEL=, pseudo, or network fs — not a verifiable id
		}
		if len(set) == 0 || val == "" {
			continue // this tag class can't be verified on this host
		}
		if !set[strings.ToLower(val)] {
			out = append(out, models.FstabDrift{
				Spec:       spec,
				MountPoint: mnt,
				BootMount:  mnt == "/" || mnt == "/boot" || mnt == "/boot/efi",
			})
		}
	}
	return out
}

func hasMountOpt(opts, want string) bool {
	for _, o := range strings.Split(opts, ",") {
		if o == want {
			return true
		}
	}
	return false
}

func unquote(s string) string { return strings.Trim(s, `"`) }
