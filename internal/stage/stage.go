// Package stage builds the public tree of a canonical commit from git objects.
package stage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/manifest"
)

// Result is the public tree staged from one commit.
type Result struct {
	Commit       string             // X, the canonical commit
	Manifest     *manifest.Manifest // read from X
	Public       []gitobj.Entry     // the entries of the public tree
	Internal     []string
	Unclassified []string // non-empty: nothing may be published from X
	Tree         string   // H, the hash of the public tree; empty when Unclassified is non-empty
}

// ErrNoManifest is returned when the commit carries no manifest.
var ErrNoManifest = errors.New("the commit carries no " + manifest.File)

// Build stages the public tree of rev. It reads the manifest and every file
// from rev's git objects; the working tree and the index are never read.
func Build(r *gitobj.Repo, rev string) (*Result, error) {
	x, err := r.ResolveCommit(rev)
	if err != nil {
		return nil, err
	}
	data, ok, err := r.FileAt(x, manifest.File)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%s: %w", x, ErrNoManifest)
	}
	m, err := manifest.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s at %s: %w", manifest.File, x, err)
	}
	es, err := r.Tree(x)
	if err != nil {
		return nil, err
	}
	res := &Result{Commit: x, Manifest: m}
	for _, e := range es {
		switch m.Classify(e.Path).Class {
		case manifest.Public:
			res.Public = append(res.Public, e)
		case manifest.Internal:
			res.Internal = append(res.Internal, e.Path)
		default:
			res.Unclassified = append(res.Unclassified, e.Path)
		}
	}
	if len(res.Unclassified) > 0 {
		return res, nil
	}
	if res.Tree, err = r.WriteTree(res.Public); err != nil {
		return nil, err
	}
	return res, nil
}

// Files reads the content of the public entries.
func (res *Result) Files(r *gitobj.Repo) ([]gitobj.File, error) {
	return r.Files(res.Public)
}

// Export writes the public files into dir, which must be absent or empty:
// regular files with their executable bit, symlinks as symlinks. A gitlink
// becomes an empty directory.
func Export(r *gitobj.Repo, res *Result, dir string) error {
	if ents, err := os.ReadDir(dir); err == nil && len(ents) > 0 {
		return fmt.Errorf("stage: %s is not empty", dir)
	}
	fs, err := res.Files(r)
	if err != nil {
		return err
	}
	for _, f := range fs {
		p := filepath.Join(dir, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		switch f.Mode {
		case gitobj.ModeSymlink:
			err = os.Symlink(string(f.Data), p)
		case gitobj.ModeGitlink:
			err = os.MkdirAll(p, 0o755)
		case gitobj.ModeExecutable:
			err = os.WriteFile(p, f.Data, 0o755)
		default:
			err = os.WriteFile(p, f.Data, 0o644)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
