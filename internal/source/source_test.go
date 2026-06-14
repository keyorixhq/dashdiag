package source

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordReplayRoundTrip(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	if err := os.WriteFile(present, []byte("AMD k10temp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")

	rec := NewRecorder(Live{})
	ctx := context.Background()

	if _, err := rec.ReadFile(present); err != nil {
		t.Fatalf("read present: %v", err)
	}
	if _, err := rec.ReadFile(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing should be ErrNotExist, got %v", err)
	}
	if _, err := rec.Run(ctx, "sh", "-c", "printf abc"); err != nil {
		t.Fatalf("run sh: %v", err)
	}
	if _, err := rec.Run(ctx, "false"); err != nil {
		t.Fatalf("run false should not be exec error: %v", err)
	}
	if _, err := rec.Run(ctx, "dsd-no-such-binary-zzz"); err == nil {
		t.Fatal("absent binary should return exec error")
	}

	rp := NewReplay(rec.Bundle())

	if got, _ := rp.ReadFile(present); string(got) != "AMD k10temp\n" {
		t.Fatalf("replay present = %q", got)
	}
	if _, err := rp.ReadFile(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replay missing should be ErrNotExist, got %v", err)
	}
	if _, err := rp.ReadFile(filepath.Join(dir, "never-touched")); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("unrecorded read should be ErrNotRecorded, got %v", err)
	}
	if res, _ := rp.Run(ctx, "sh", "-c", "printf abc"); string(res.Stdout) != "abc" {
		t.Fatalf("replay sh stdout = %q", res.Stdout)
	}
	if res, _ := rp.Run(ctx, "false"); res.ExitCode != 1 {
		t.Fatalf("replay false exit = %d, want 1", res.ExitCode)
	}
	if _, err := rp.Run(ctx, "dsd-no-such-binary-zzz"); err == nil {
		t.Fatal("replay absent binary should return exec error")
	}
	if _, err := rp.Run(ctx, "uptime"); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("unrecorded run should be ErrNotRecorded, got %v", err)
	}
}

func TestSaveLoad(t *testing.T) {
	src := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(src, []byte("Tctl 45000\n"), 0o644)

	rec := NewRecorder(Live{})
	_, _ = rec.ReadFile(src)
	_, _ = rec.Run(context.Background(), "false")

	out := t.TempDir()
	if err := rec.Bundle().Save(out); err != nil {
		t.Fatalf("save: %v", err)
	}
	b2, err := Load(out)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rp := NewReplay(b2)
	if got, _ := rp.ReadFile(src); string(got) != "Tctl 45000\n" {
		t.Fatalf("loaded read = %q", got)
	}
	if res, _ := rp.Run(context.Background(), "false"); res.ExitCode != 1 {
		t.Fatalf("loaded exit = %d", res.ExitCode)
	}
}

func TestFromSnapshot(t *testing.T) {
	hwmon := "===== /sys/class/hwmon/hwmon0/name =====\nk10temp\n\n" +
		"===== /sys/class/hwmon/hwmon0/temp1_label =====\nTctl\n\n"
	tarball := writeTestTarball(t, map[string]string{
		"hwsnap-host-x/hwmon.txt":      hwmon,
		"hwsnap-host-x/os-release.txt": "ID=debian\n",
		"hwsnap-host-x/MANIFEST.txt":   "ignore me",
	})

	b, err := FromSnapshot(tarball)
	if err != nil {
		t.Fatalf("from snapshot: %v", err)
	}
	rp := NewReplay(b)

	got, err := rp.ReadFile("/sys/class/hwmon/hwmon0/name")
	if err != nil {
		t.Fatalf("read hwmon name: %v", err)
	}
	if strings.TrimSpace(string(got)) != "k10temp" {
		t.Fatalf("hwmon name = %q", got)
	}
	if got, _ := rp.ReadFile("/sys/class/hwmon/hwmon0/temp1_label"); strings.TrimSpace(string(got)) != "Tctl" {
		t.Fatalf("temp1_label = %q", got)
	}
	if got, _ := rp.ReadFile("/etc/os-release"); string(got) != "ID=debian\n" {
		t.Fatalf("os-release = %q", got)
	}
}

func writeTestTarball(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "snap.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTarballRoundTrip(t *testing.T) {
	src := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(src, []byte("Tctl 50000\n"), 0o644)

	rec := NewRecorder(Live{})
	_, _ = rec.ReadFile(src)
	_, _ = rec.Run(context.Background(), "false")
	rec.Bundle().Manifest.Host = "amd-box"

	out := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := rec.Bundle().SaveTarball(out); err != nil {
		t.Fatalf("save tarball: %v", err)
	}
	b2, err := LoadTarball(out)
	if err != nil {
		t.Fatalf("load tarball: %v", err)
	}
	if b2.Manifest.Host != "amd-box" {
		t.Fatalf("manifest host = %q", b2.Manifest.Host)
	}
	rp := NewReplay(b2)
	if got, _ := rp.ReadFile(src); string(got) != "Tctl 50000\n" {
		t.Fatalf("tarball replay read = %q", got)
	}
	if res, _ := rp.Run(context.Background(), "false"); res.ExitCode != 1 {
		t.Fatalf("tarball replay exit = %d", res.ExitCode)
	}
}
