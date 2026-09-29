package stage

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/gittest"
)

func paths(es []gitobj.Entry) []string {
	var ps []string
	for _, e := range es {
		ps = append(ps, e.Path)
	}
	return ps
}

func TestUntrackedNeverStagedAndDeterministic(t *testing.T) {
	r := gittest.Init(t)
	x := gittest.Commit(t, r, "first", map[string]string{
		".pubmirror.toml": gittest.Manifest("snapshot", "/nowhere"),
		"src/main.go":     "package main\n",
		"README.md":       "# demo\n",
		"notes/plan.md":   "internal notes\n",
	})
	// Left behind in the working tree by an earlier step: untracked, and an
	// uncommitted edit to a public file. Neither may reach the staged tree.
	gittest.Write(t, r, map[string]string{
		"src/generated.go": "package main // untracked\n",
		"src/main.go":      "package main // edited, not committed\n",
	})
	gittest.Git(t, r, "add", "src/generated.go") // even staged in the index

	a, err := Build(r, x)
	if err != nil {
		t.Fatal(err)
	}
	if got := paths(a.Public); !slices.Equal(got, []string{"README.md", "src/main.go"}) {
		t.Fatalf("public = %v", got)
	}
	if !slices.Equal(a.Internal, []string{".pubmirror.toml", "notes/plan.md"}) {
		t.Fatalf("internal = %v", a.Internal)
	}
	fs, _ := a.Files(r)
	if string(fs[1].Data) != "package main\n" {
		t.Fatalf("src/main.go staged from the working tree: %q", fs[1].Data)
	}

	b, err := Build(r, "main")
	if err != nil {
		t.Fatal(err)
	}
	if a.Tree == "" || a.Tree != b.Tree || b.Commit != x {
		t.Fatalf("two stagings of %s: %s and %s", x, a.Tree, b.Tree)
	}
	// H is the git tree of exactly the public files.
	want := gittest.Git(t, r, "rev-parse", x+"^{tree}")
	if a.Tree == want {
		t.Fatal("public tree equals the full tree; internal files leaked")
	}
	if got := gittest.Git(t, r, "ls-tree", "-r", "--name-only", a.Tree); got != "README.md\nsrc/main.go" {
		t.Fatalf("tree H lists %q", got)
	}
}

func TestUnclassifiedBlocksTheTree(t *testing.T) {
	r := gittest.Init(t)
	x := gittest.Commit(t, r, "first", map[string]string{
		".pubmirror.toml": gittest.Manifest("snapshot", "/nowhere"),
		"src/main.go":     "package main\n",
		"scratch.txt":     "who knows\n",
	})
	res, err := Build(r, x)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Unclassified, []string{"scratch.txt"}) || res.Tree != "" {
		t.Fatalf("unclassified %v tree %q", res.Unclassified, res.Tree)
	}
}

func TestExactPublishesTheWholeTree(t *testing.T) {
	r := gittest.Init(t)
	x := gittest.Commit(t, r, "first", map[string]string{
		".pubmirror.toml": gittest.Manifest("exact", "/nowhere"),
		"src/main.go":     "package main\n",
	})
	res, err := Build(r, x)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tree != gittest.Git(t, r, "rev-parse", x+"^{tree}") {
		t.Fatalf("exact: staged tree %s differs from the commit's tree", res.Tree)
	}
}

func TestNoManifest(t *testing.T) {
	r := gittest.Init(t)
	x := gittest.Commit(t, r, "first", map[string]string{"src/main.go": "package main\n"})
	if _, err := Build(r, x); !errors.Is(err, ErrNoManifest) {
		t.Fatalf("err = %v", err)
	}
}

func TestExport(t *testing.T) {
	r := gittest.Init(t)
	gittest.Write(t, r, map[string]string{
		".pubmirror.toml": gittest.Manifest("snapshot", "/nowhere"),
		"src/run.sh":      "#!/bin/sh\n",
		"notes/x":         "internal\n",
	})
	if err := os.Chmod(filepath.Join(r.Dir, "src/run.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("run.sh", filepath.Join(r.Dir, "src/link")); err != nil {
		t.Fatal(err)
	}
	x := gittest.Commit(t, r, "first", nil)
	res, err := Build(r, x)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "public")
	if err := Export(r, res, out); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(out, "src/run.sh")); err != nil || st.Mode()&0o111 == 0 {
		t.Fatalf("run.sh: %v %v", st, err)
	}
	if tgt, err := os.Readlink(filepath.Join(out, "src/link")); err != nil || tgt != "run.sh" {
		t.Fatalf("link: %q %v", tgt, err)
	}
	if _, err := os.Stat(filepath.Join(out, "notes")); !os.IsNotExist(err) {
		t.Fatal("internal directory exported")
	}
	if err := Export(r, res, out); err == nil {
		t.Fatal("export into a non-empty directory succeeded")
	}
}
