package source

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SaveTarball writes the bundle as a gzipped tar in the raw-v1 layout. This is
// the artifact `dsd capture --raw` hands back: one self-contained file.
func (b *Bundle) SaveTarball(path string) error {
	tmp, err := os.MkdirTemp("", "dsd-raw-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := b.Save(tmp); err != nil {
		return err
	}
	return tarGzDir(tmp, path)
}

// LoadTarball reads a bundle previously written by SaveTarball.
func LoadTarball(path string) (*Bundle, error) {
	tmp, err := os.MkdirTemp("", "dsd-raw-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := untarGz(path, tmp); err != nil {
		return nil, err
	}
	return Load(tmp)
}

func tarGzDir(srcDir, dstPath string) error {
	f, err := os.Create(dstPath) // #nosec G304 -- operator-chosen output path
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	return filepath.Walk(srcDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		rel, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p) // #nosec G304 -- path from Walk under our temp dir
		if err != nil {
			return err
		}
		hdr := &tar.Header{Name: rel, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
}

func untarGz(srcPath, dstDir string) error {
	f, err := os.Open(srcPath) // #nosec G304 -- operator-supplied bundle path
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Guard against path traversal in a crafted archive.
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			continue
		}
		dst := filepath.Join(dstDir, clean)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		out, err := os.Create(dst) // #nosec G304 -- dst is under our temp dir
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil { // #nosec G110 -- our own bundle, bounded
			out.Close()
			return err
		}
		out.Close()
	}
	return nil
}
