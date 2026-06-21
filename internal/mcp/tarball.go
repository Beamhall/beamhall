package mcp

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Decompression bounds: a hostile tarball must not exhaust the appliance
// (zip-bomb defense). The compressed cap is maxTarballBytes (server.go).
const (
	maxExtractBytes = 64 << 20
	maxExtractFiles = 4096
)

// extractTarGz unpacks an agent-supplied gzip tarball into dst, refusing
// anything that could write outside dst: absolute paths, "..", non-local
// symlink targets, and non-file/dir/symlink entry types. The result feeds
// the managed-repo snapshot — the same place the git transport lands.
func extractTarGz(r io.Reader, dst string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("source_tarball is not a gzip stream: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var total int64
	files := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tarball: %w", err)
		}
		name := filepath.Clean(hdr.Name)
		if name == "." {
			continue
		}
		if !filepath.IsLocal(name) {
			return fmt.Errorf("tarball entry %q escapes the source directory", hdr.Name)
		}
		if files++; files > maxExtractFiles {
			return fmt.Errorf("tarball has more than %d entries", maxExtractFiles)
		}
		path := filepath.Join(dst, name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if total += hdr.Size; total > maxExtractBytes {
				return fmt.Errorf("tarball decompresses past the %d MB limit", maxExtractBytes>>20)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if hdr.FileInfo().Mode()&0o100 != 0 {
				mode = 0o755 // preserve the exec bit only — no setuid/sticky
			}
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			// +1 so a lying header (size < actual) still trips the cap.
			n, err := io.Copy(f, io.LimitReader(tr, maxExtractBytes-total+1))
			f.Close()
			if err != nil {
				return err
			}
			if total += n - hdr.Size; total > maxExtractBytes {
				return fmt.Errorf("tarball decompresses past the %d MB limit", maxExtractBytes>>20)
			}
		case tar.TypeSymlink:
			target := hdr.Linkname
			if filepath.IsAbs(target) || !filepath.IsLocal(filepath.Join(filepath.Dir(name), target)) {
				return fmt.Errorf("tarball symlink %q → %q escapes the source directory", hdr.Name, target)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(target, path); err != nil {
				return err
			}
		default:
			if strings.HasPrefix(name, "._") || hdr.Typeflag == tar.TypeXGlobalHeader {
				continue // macOS resource forks / pax global headers
			}
			return fmt.Errorf("tarball entry %q has unsupported type %c", hdr.Name, hdr.Typeflag)
		}
	}
}
