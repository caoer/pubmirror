package gitobj

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// newRepo makes a repository with one commit: a file, an executable and a
// symlink, then leaves an untracked file and a modified tracked file in the
// working tree.
func newRepo(t *testing.T) (*Repo, string) {
	t.Helper()
	dir := t.TempDir()
	r := &Repo{Dir: dir, Env: []string{
		"GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Alice Example", "GIT_AUTHOR_EMAIL=alice@host.example",
		"GIT_COMMITTER_NAME=Alice Example", "GIT_COMMITTER_EMAIL=alice@host.example",
	}}
	must := func(_ []byte, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(r.Run("init", "-q", "-b", "main"))
	write(t, dir, "a.txt", "alpha\n", 0o644)
	write(t, dir, "bin/run.sh", "#!/bin/sh\n", 0o755)
	if err := os.Symlink("a.txt", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	must(r.Run("add", "-A"))
	must(r.Run("commit", "-q", "-m", "first\n\nbody line"))
	head, err := r.ResolveCommit("HEAD")
	if err != nil {
		t.Fatal(err)
	}
	write(t, dir, "untracked.txt", "left behind\n", 0o644)
	write(t, dir, "a.txt", "changed in the working tree\n", 0o644)
	return r, head
}

func write(t *testing.T, dir, name, data string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

func TestTreeAndFilesReadObjectsNotWorkingTree(t *testing.T) {
	r, head := newRepo(t)
	es, err := r.Tree(head)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, e := range es {
		paths = append(paths, e.Path)
	}
	if !slices.Equal(paths, []string{"a.txt", "bin/run.sh", "link"}) {
		t.Fatalf("paths = %v", paths)
	}
	fs, err := r.Files(es)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		mode uint32
		data string
	}{
		"a.txt":      {ModeFile, "alpha\n"},
		"bin/run.sh": {ModeExecutable, "#!/bin/sh\n"},
		"link":       {ModeSymlink, "a.txt"},
	}
	for _, f := range fs {
		w := want[f.Path]
		if f.Mode != w.mode || string(f.Data) != w.data {
			t.Errorf("%s: mode %o data %q, want %o %q", f.Path, f.Mode, f.Data, w.mode, w.data)
		}
	}
}

func TestIndex(t *testing.T) {
	r, _ := newRepo(t)
	if _, err := r.Run("add", "untracked.txt"); err != nil {
		t.Fatal(err)
	}
	es, err := r.Index()
	if err != nil {
		t.Fatal(err)
	}
	fs, err := r.Files(es)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range fs {
		got[f.Path] = string(f.Data)
	}
	// The staged file is in; the unstaged edit to a.txt is not.
	if got["untracked.txt"] != "left behind\n" || got["a.txt"] != "alpha\n" {
		t.Fatalf("index files = %v", got)
	}
}

func TestWriteTreeRoundTrip(t *testing.T) {
	r, head := newRepo(t)
	c, err := r.ReadCommit(head)
	if err != nil {
		t.Fatal(err)
	}
	es, _ := r.Tree(head)
	h, err := r.WriteTree(es)
	if err != nil {
		t.Fatal(err)
	}
	if h != c.Tree {
		t.Fatalf("rewritten tree %s, commit tree %s", h, c.Tree)
	}
	sub, err := r.WriteTree(es[:1])
	if err != nil || sub == h {
		t.Fatalf("subset tree %s err %v", sub, err)
	}
	empty, err := r.WriteTree(nil)
	if err != nil || empty != EmptyTree {
		t.Fatalf("empty tree %s err %v", empty, err)
	}
	// The repository's own index is untouched.
	idx, _ := r.Index()
	if len(idx) != 3 {
		t.Fatalf("index has %d entries", len(idx))
	}
}

func TestCommitTreeAndAncestry(t *testing.T) {
	r, head := newRepo(t)
	c, _ := r.ReadCommit(head)
	if c.Message != "first\n\nbody line" || c.AuthorEmail != "alice@host.example" || len(c.Parents) != 0 {
		t.Fatalf("commit = %+v", c)
	}
	sig := Signature{Name: "Bob Example", Email: "bob@host.example", Date: "1700000000 +0000"}
	next, err := r.CommitTree(c.Tree, []string{head}, "second\n\nTrailer: x\n", sig, sig)
	if err != nil {
		t.Fatal(err)
	}
	nc, _ := r.ReadCommit(next)
	if nc.AuthorName != "Bob Example" || nc.Parents[0] != head || nc.Message != "second\n\nTrailer: x" {
		t.Fatalf("new commit = %+v", nc)
	}
	if ok, err := r.IsAncestor(head, next); !ok || err != nil {
		t.Fatalf("head ancestor of next: %v %v", ok, err)
	}
	if ok, err := r.IsAncestor(next, head); ok || err != nil {
		t.Fatalf("next ancestor of head: %v %v", ok, err)
	}
	revs, err := r.RevList(head + ".." + next)
	if err != nil || !slices.Equal(revs, []string{next}) {
		t.Fatalf("rev-list %v %v", revs, err)
	}
	if r.Exists("0123456789012345678901234567890123456789") {
		t.Fatal("a missing commit exists")
	}
}

func TestRange(t *testing.T) {
	r, head := newRepo(t)
	commit := func(msg string) string {
		t.Helper()
		if _, err := r.Run("add", "-A"); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Run("commit", "-q", "-m", msg); err != nil {
			t.Fatal(err)
		}
		h, _ := r.ResolveCommit("HEAD")
		return h
	}
	// A value added in one commit and removed in the next: absent from the
	// tip, present in the range.
	write(t, r.Dir, "b.txt", "planted value\n", 0o644)
	commit("add b") // also commits the working-tree edit of a.txt and untracked.txt
	if err := os.Remove(filepath.Join(r.Dir, "b.txt")); err != nil {
		t.Fatal(err)
	}
	tip := commit("remove b")

	files, commits, err := r.Range(head, tip)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range files {
		got[f.Path] = string(f.Data)
	}
	if got["b.txt"] != "planted value\n" || got["a.txt"] != "changed in the working tree\n" || len(got) != 3 {
		t.Fatalf("range files = %v", got)
	}
	if len(commits) != 2 || commits[0].Hash != tip || commits[1].Message != "add b" {
		t.Fatalf("range commits = %+v", commits)
	}
	all, commits, err := r.Range("", tip)
	if err != nil || len(commits) != 3 || len(all) != 6 {
		t.Fatalf("whole history: %d files %d commits %v", len(all), len(commits), err)
	}
}

func TestFileAtAndDiff(t *testing.T) {
	r, head := newRepo(t)
	data, ok, err := r.FileAt(head, "bin/run.sh")
	if err != nil || !ok || string(data) != "#!/bin/sh\n" {
		t.Fatalf("FileAt = %q %v %v", data, ok, err)
	}
	if _, ok, err := r.FileAt(head, "untracked.txt"); ok || err != nil {
		t.Fatalf("untracked file found: %v %v", ok, err)
	}
	cs, err := r.Diff(EmptyTree, head)
	if err != nil || len(cs) != 3 || cs[0].Status != 'A' {
		t.Fatalf("diff = %+v %v", cs, err)
	}
}
