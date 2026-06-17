package source

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSanitizeTarballRoundTrip exercises the exact flow `dsd sanitize` uses:
// write a bundle, load it, Sanitize(), save it, reload — and assert the secret is
// gone while non-secret content (and the manifest) survives the round-trip.
func TestSanitizeTarballRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.tar.gz")
	out := filepath.Join(dir, "out.tar.gz")

	b := NewBundle()
	b.Manifest = Manifest{Format: FormatVersion, Host: "amd-laptop"}
	b.PutFile("/etc/app.conf", []byte("api_key=PLANTED_SECRET_XYZ\nport=9090"))
	b.PutFile("/proc/loadavg", []byte("0.10 0.20 0.30 1/200 1234"))
	if err := b.SaveTarball(in); err != nil {
		t.Fatalf("SaveTarball: %v", err)
	}

	// load → sanitize → save (what runSanitize does)
	loaded, err := LoadTarball(in)
	if err != nil {
		t.Fatalf("LoadTarball: %v", err)
	}
	rep := loaded.Sanitize(SanitizeOptions{})
	if rep.TotalRedactions != 1 {
		t.Errorf("expected 1 redaction, got %+v", rep)
	}
	if err := loaded.SaveTarball(out); err != nil {
		t.Fatalf("SaveTarball(out): %v", err)
	}

	// reload the sanitized bundle and verify
	final, err := LoadTarball(out)
	if err != nil {
		t.Fatalf("LoadTarball(out): %v", err)
	}
	if final.Manifest.Host != "amd-laptop" {
		t.Errorf("manifest lost across round-trip: %+v", final.Manifest)
	}
	conf, ok := final.getFile("/etc/app.conf")
	if !ok {
		t.Fatal("config file lost across round-trip")
	}
	if strings.Contains(string(conf.data), "PLANTED_SECRET_XYZ") {
		t.Errorf("secret survived sanitize round-trip: %q", conf.data)
	}
	if !strings.Contains(string(conf.data), "port=9090") {
		t.Errorf("non-secret content dropped: %q", conf.data)
	}
	if la, _ := final.getFile("/proc/loadavg"); string(la.data) != "0.10 0.20 0.30 1/200 1234" {
		t.Errorf("non-secret file altered: %q", la.data)
	}
}
