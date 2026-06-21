// Package build is the source→pinned-image pipeline (PLAN §5.5, §4): per-beam
// managed git repositories (embedded go-git — the appliance needs no system
// git), snapshot imports that converge every source path (git push, MCP
// tarball) to a commit SHA, and Cloud Native Buildpacks builds executed
// against a separate non-userns-remapped build context that --publish to the
// appliance's internal registry. The runtime daemon never builds; it pulls
// the pinned digest and runs it (lab-verified constraint,
// docs/lab-phase0-validation.md).
package build

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// mainRef is the branch every snapshot lands on.
const mainRef = "refs/heads/main"

// Repos manages the per-beam bare repositories under root, laid out as
// <root>/<beamhall-slug>/<beam-slug>.git. The smart-HTTP transport that lets
// agents `git push` arrives with the HTTP layer (item 5); until then sources
// enter through ImportSnapshot.
type Repos struct {
	root string
}

// NewRepos returns a Repos rooted at root (created on first Ensure).
func NewRepos(root string) *Repos { return &Repos{root: root} }

// Ensure initializes the bare repository for a beam if absent and returns its
// path. Idempotent.
func (r *Repos) Ensure(beamhallSlug, beamSlug string) (string, error) {
	path := filepath.Join(r.root, beamhallSlug, beamSlug+".git")
	if _, err := os.Stat(filepath.Join(path, "HEAD")); err == nil {
		return path, nil
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return "", err
	}
	repo, err := git.PlainInit(path, true)
	if err != nil {
		return "", fmt.Errorf("init bare repo %s: %w", path, err)
	}
	// Point HEAD at main so pushes and snapshots agree on the branch.
	if err := repo.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, mainRef)); err != nil {
		return "", err
	}
	return path, nil
}

// Retire moves a beam's repository aside (into <root>/<hall>/.retired/) so its
// slug can be reused with a FRESH, empty repo, while the archived source is
// preserved under the retired name. No-op if the repo is absent. The id keeps
// retired repos for a reused slug from colliding. The .retired/ dir is not a
// valid <slug>.git path, so the git server never serves it.
func (r *Repos) Retire(beamhallSlug, beamSlug, id string) error {
	src := filepath.Join(r.root, beamhallSlug, beamSlug+".git")
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	dstDir := filepath.Join(r.root, beamhallSlug, ".retired")
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return err
	}
	return os.Rename(src, filepath.Join(dstDir, beamSlug+"-"+id+".git"))
}

// ImportSnapshot commits the full content of srcDir onto main as one
// snapshot commit (replacing the previous tree wholesale) and returns the
// commit SHA — the immutable Build.source_ref every source path converges to.
// Regular files, the executable bit, and symlinks are preserved.
func (r *Repos) ImportSnapshot(ctx context.Context, repoPath, srcDir, message string) (string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return "", fmt.Errorf("open repo %s: %w", repoPath, err)
	}
	treeHash, n, err := importTree(repo, srcDir)
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", fmt.Errorf("source directory %s is empty", srcDir)
	}

	var parents []plumbing.Hash
	if ref, err := repo.Reference(plumbing.ReferenceName(mainRef), true); err == nil {
		parents = append(parents, ref.Hash())
	}

	sig := object.Signature{Name: "beamhall", Email: "backplane@beamhall.local", When: time.Now()}
	commit := &object.Commit{
		Author:       sig,
		Committer:    sig,
		Message:      message,
		TreeHash:     treeHash,
		ParentHashes: parents,
	}
	obj := repo.Storer.NewEncodedObject()
	if err := commit.Encode(obj); err != nil {
		return "", err
	}
	commitHash, err := repo.Storer.SetEncodedObject(obj)
	if err != nil {
		return "", err
	}
	if err := repo.Storer.SetReference(plumbing.NewHashReference(plumbing.ReferenceName(mainRef), commitHash)); err != nil {
		return "", err
	}
	return commitHash.String(), nil
}

// CheckoutTo materializes the tree of a commit into dstDir (which must exist
// and be empty) — the build working directory `pack` consumes.
func (r *Repos) CheckoutTo(ctx context.Context, repoPath, sha, dstDir string) error {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return fmt.Errorf("open repo %s: %w", repoPath, err)
	}
	commit, err := repo.CommitObject(plumbing.NewHash(sha))
	if err != nil {
		return fmt.Errorf("commit %s: %w", sha, err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return err
	}
	return tree.Files().ForEach(func(f *object.File) error {
		target := filepath.Join(dstDir, filepath.FromSlash(f.Name))
		if !strings.HasPrefix(target, filepath.Clean(dstDir)+string(os.PathSeparator)) {
			return fmt.Errorf("path %q escapes the checkout directory", f.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rd, err := f.Reader()
		if err != nil {
			return err
		}
		defer rd.Close()
		if f.Mode == filemode.Symlink {
			link, err := io.ReadAll(rd)
			if err != nil {
				return err
			}
			return os.Symlink(string(link), target)
		}
		perm := os.FileMode(0o644)
		if f.Mode == filemode.Executable {
			perm = 0o755
		}
		w, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, rd); err != nil {
			w.Close()
			return err
		}
		return w.Close()
	})
}

// importTree recursively writes dir's content as blob/tree objects and
// returns the root tree hash plus the number of files imported.
func importTree(repo *git.Repository, dir string) (plumbing.Hash, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return plumbing.ZeroHash, 0, err
	}
	var treeEntries []object.TreeEntry
	count := 0
	for _, e := range entries {
		name := e.Name()
		if name == ".git" {
			continue
		}
		full := filepath.Join(dir, name)
		switch {
		case e.IsDir():
			sub, n, err := importTree(repo, full)
			if err != nil {
				return plumbing.ZeroHash, 0, err
			}
			if n == 0 {
				continue // git has no empty trees
			}
			count += n
			treeEntries = append(treeEntries, object.TreeEntry{Name: name, Mode: filemode.Dir, Hash: sub})
		case e.Type()&os.ModeSymlink != 0:
			link, err := os.Readlink(full)
			if err != nil {
				return plumbing.ZeroHash, 0, err
			}
			h, err := writeBlob(repo, []byte(link))
			if err != nil {
				return plumbing.ZeroHash, 0, err
			}
			count++
			treeEntries = append(treeEntries, object.TreeEntry{Name: name, Mode: filemode.Symlink, Hash: h})
		case e.Type().IsRegular():
			data, err := os.ReadFile(full)
			if err != nil {
				return plumbing.ZeroHash, 0, err
			}
			h, err := writeBlob(repo, data)
			if err != nil {
				return plumbing.ZeroHash, 0, err
			}
			mode := filemode.Regular
			if info, err := e.Info(); err == nil && info.Mode()&0o111 != 0 {
				mode = filemode.Executable
			}
			count++
			treeEntries = append(treeEntries, object.TreeEntry{Name: name, Mode: mode, Hash: h})
		default:
			return plumbing.ZeroHash, 0, fmt.Errorf("unsupported file type %q in source: %s", e.Type(), full)
		}
	}
	sortTreeEntries(treeEntries)
	tree := &object.Tree{Entries: treeEntries}
	obj := repo.Storer.NewEncodedObject()
	if err := tree.Encode(obj); err != nil {
		return plumbing.ZeroHash, 0, err
	}
	h, err := repo.Storer.SetEncodedObject(obj)
	return h, count, err
}

func writeBlob(repo *git.Repository, data []byte) (plumbing.Hash, error) {
	obj := repo.Storer.NewEncodedObject()
	obj.SetType(plumbing.BlobObject)
	w, err := obj.Writer()
	if err != nil {
		return plumbing.ZeroHash, err
	}
	if _, err := w.Write(data); err != nil {
		w.Close()
		return plumbing.ZeroHash, err
	}
	if err := w.Close(); err != nil {
		return plumbing.ZeroHash, err
	}
	return repo.Storer.SetEncodedObject(obj)
}

// sortTreeEntries sorts in canonical git tree order: byte-wise by name, with
// directories compared as if their name had a trailing slash.
func sortTreeEntries(entries []object.TreeEntry) {
	key := func(e object.TreeEntry) string {
		if e.Mode == filemode.Dir {
			return e.Name + "/"
		}
		return e.Name
	}
	sort.Slice(entries, func(i, j int) bool { return key(entries[i]) < key(entries[j]) })
}
