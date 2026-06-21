// Package backup creates and restores a Beamhall appliance backup: a single
// archive holding a consistent snapshot of the control-plane store, the secret
// root key, and the managed git repos (PLAN §8 Phase 4). The secret root key is
// the crown jewel — without it every stored secret is unrecoverable — so the
// archive is written 0600 and is exactly as sensitive as the appliance itself.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Beamhall/beamhall/internal/store"
)

const (
	dbName       = "beamhall.db"
	keyName      = "secret.key"
	reposDir     = "repos"
	manifestName = "MANIFEST.json"
	formatV1     = "beamhall-backup-v1"
)

// Manifest is the archive's self-description.
type Manifest struct {
	Format    string `json:"format"`
	CreatedAt string `json:"created_at"` // RFC3339
	HasKey    bool   `json:"has_secret_key"`
	HasRepos  bool   `json:"has_repos"`
}

// Create writes a backup of dataDir to outPath (a .tar.gz). The store is
// snapshotted online (VACUUM INTO) so a live appliance can be backed up; the
// secret key and git repos are copied as-is. now stamps the manifest.
//
// keyPath is the secret root key to embed. Production runs the key out-of-band
// (it is not in dataDir), so the caller passes its real location; pass "" to
// use the legacy in-data-dir default (<dataDir>/secret.key).
func Create(ctx context.Context, dataDir, keyPath, outPath string, now time.Time) error {
	staging, err := os.MkdirTemp("", "beamhall-backup-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)

	// Consistent DB snapshot via the store's online backup.
	st, err := store.Open(ctx, filepath.Join(dataDir, dbName))
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	snapPath := filepath.Join(staging, dbName)
	snapErr := st.Snapshot(ctx, snapPath)
	st.Close()
	if snapErr != nil {
		return snapErr
	}

	if keyPath == "" {
		keyPath = filepath.Join(dataDir, keyName)
	}
	if !fileExists(keyPath) {
		return fmt.Errorf("secret root key %s is missing — refusing to write an unrecoverable backup", keyPath)
	}
	reposPath := filepath.Join(dataDir, reposDir)
	hasRepos := dirExists(reposPath)

	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)

	man := Manifest{Format: formatV1, CreatedAt: now.UTC().Format(time.RFC3339), HasKey: true, HasRepos: hasRepos}
	manBytes, _ := json.MarshalIndent(man, "", "  ")
	if err := writeTarBytes(tw, manifestName, 0o600, manBytes); err != nil {
		return err
	}
	if err := writeTarFile(tw, snapPath, dbName, 0o600); err != nil {
		return err
	}
	if err := writeTarFile(tw, keyPath, keyName, 0o600); err != nil {
		return err
	}
	if hasRepos {
		if err := writeTarTree(tw, reposPath, reposDir); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return out.Sync()
}

// Verify opens an archive and checks it is a well-formed Beamhall backup with
// the database and secret key present, returning its manifest.
func Verify(archivePath string) (Manifest, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return Manifest{}, fmt.Errorf("%s is not a gzip archive: %w", archivePath, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var man Manifest
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Manifest{}, err
		}
		seen[h.Name] = true
		if h.Name == manifestName {
			if err := json.NewDecoder(tr).Decode(&man); err != nil {
				return Manifest{}, fmt.Errorf("manifest: %w", err)
			}
		}
	}
	if man.Format != formatV1 {
		return Manifest{}, fmt.Errorf("not a Beamhall backup (format %q)", man.Format)
	}
	if !seen[dbName] || !seen[keyName] {
		return Manifest{}, fmt.Errorf("archive is missing the database or secret key")
	}
	return man, nil
}

// Restore extracts an archive into dataDir. The appliance MUST be stopped:
// restore overwrites the live database, secret key, and repos. Existing files
// are moved aside to <name>.pre-restore first so a failed restore is
// recoverable. dataDir is created if absent.
func Restore(archivePath, dataDir string) error {
	man, err := Verify(archivePath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	// Preserve current state.
	for _, name := range []string{dbName, keyName, reposDir} {
		p := filepath.Join(dataDir, name)
		if fileExists(p) || dirExists(p) {
			_ = os.RemoveAll(p + ".pre-restore")
			if err := os.Rename(p, p+".pre-restore"); err != nil {
				return fmt.Errorf("preserve %s: %w", name, err)
			}
		}
	}

	f, err := os.Open(archivePath)
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
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if h.Name == manifestName {
			continue
		}
		name := filepath.Clean(h.Name)
		if !filepath.IsLocal(name) {
			return fmt.Errorf("archive entry %q escapes the data directory", h.Name)
		}
		dst := filepath.Join(dataDir, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return err
			}
			mode := os.FileMode(h.Mode) & 0o777
			out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			_, cerr := io.Copy(out, tr)
			out.Close()
			if cerr != nil {
				return cerr
			}
		}
	}
	_ = man
	return nil
}

// --- tar helpers ----------------------------------------------------------

func writeTarBytes(tw *tar.Writer, name string, mode int64, b []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

func writeTarFile(tw *tar.Writer, srcPath, name string, mode int64) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: fi.Size(), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

func writeTarTree(tw *tar.Writer, srcRoot, archivePrefix string) error {
	return filepath.Walk(srcRoot, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(filepath.Join(archivePrefix, rel))
		if fi.IsDir() {
			return tw.WriteHeader(&tar.Header{Name: name + "/", Mode: 0o700, Typeflag: tar.TypeDir})
		}
		if !fi.Mode().IsRegular() {
			return nil // skip symlinks/specials in the managed repos
		}
		return writeTarFile(tw, path, name, int64(fi.Mode()&0o777))
	})
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
