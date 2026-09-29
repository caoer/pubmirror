package publish

import (
	"strings"
	"testing"
	"time"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/gittest"
	"github.com/caoer/pubmirror/internal/scan"
	"github.com/caoer/pubmirror/internal/stage"
)

type noTokens struct{}

func (noTokens) ScanTokens([]scan.File) ([]scan.Finding, error) { return nil, nil }

const planted = "zebra-codename"

func denylist(t *testing.T) *scan.Denylist {
	t.Helper()
	d, err := scan.ParseDenylist([]byte(planted + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// world is a canonical bare repository, a developer clone that pushes to it,
// and an empty public bare repository.
type world struct {
	t      *testing.T
	dev    *gitobj.Repo
	canon  string
	public string
	mode   string
}

func newWorld(t *testing.T, mode string) *world {
	w := &world{t: t, canon: gittest.Bare(t), public: gittest.Bare(t), mode: mode}
	w.dev = gittest.Init(t)
	if mode == "exact" {
		w.dev.Env = append(w.dev.Env, "GIT_AUTHOR_NAME=Alice Example", "GIT_AUTHOR_EMAIL=alice@host.example", "GIT_COMMITTER_NAME=Alice Example", "GIT_COMMITTER_EMAIL=alice@host.example")
	}
	gittest.Git(t, w.dev, "remote", "add", "origin", w.canon)
	return w
}

// commit adds a commit on the developer's main and pushes it to canonical.
func (w *world) commit(msg string, files map[string]string) string {
	w.t.Helper()
	if _, ok, _ := w.dev.FileAt("HEAD", ".pubmirror.toml"); !ok {
		if files == nil {
			files = map[string]string{}
		}
		files[".pubmirror.toml"] = gittest.Manifest(w.mode, w.public)
	}
	x := gittest.Commit(w.t, w.dev, msg, files)
	gittest.Git(w.t, w.dev, "push", "-q", "origin", "HEAD:main")
	return x
}

// clone is a fresh publisher clone of canonical, as CI would make.
func (w *world) clone() *gitobj.Repo {
	w.t.Helper()
	r := &gitobj.Repo{Dir: w.t.TempDir(), Env: gittest.Env}
	gittest.Git(w.t, r, "clone", "-q", w.canon, ".")
	return r
}

// approve stages x the way a reviewer would and returns its approval.
func (w *world) approve(x string) Approval {
	w.t.Helper()
	st, err := stage.Build(w.dev, x)
	if err != nil {
		w.t.Fatal(err)
	}
	return Approval{Commit: st.Commit, Tree: st.Tree, Denylist: denylist(w.t).Hash()}
}

func (w *world) opts(a Approval) Options {
	return Options{
		Repo: w.clone(), Canonical: "origin", Approval: a,
		Denylist: denylist(w.t), Tokens: noTokens{},
		Now: func() time.Time { return time.Date(2031, 5, 6, 7, 8, 9, 0, time.FixedZone("X", 5*3600)) },
	}
}

func (w *world) publicRepo() *gitobj.Repo { return &gitobj.Repo{Dir: w.public, Env: gittest.Env} }

func (w *world) publicTip() string {
	w.t.Helper()
	tip, err := w.publicRepo().ResolveCommit("refs/heads/main")
	if err != nil {
		return ""
	}
	return tip
}

func (w *world) publicRefs() string {
	return gittest.Git(w.t, w.publicRepo(), "for-each-ref", "--format=%(refname)")
}

func mustRefuse(t *testing.T, err error, want string) {
	t.Helper()
	if !IsRefusal(err) || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want a refusal containing %q", err, want)
	}
}

var files1 = map[string]string{"src/main.go": "package main\n", "README.md": "# demo\n", "notes/plan.md": "internal: " + planted + "\n"}

func TestPublishSnapshotCommit(t *testing.T) {
	w := newWorld(t, "snapshot")
	x := w.commit("first", files1)
	a := w.approve(x)
	o := w.opts(a)
	o.Summary = "first public release"
	res, err := Run(o)
	if err != nil || res.Outcome != Published {
		t.Fatalf("publish: %+v %v", res, err)
	}
	pub := w.publicRepo()
	raw := gittest.Git(t, pub, "cat-file", "-p", res.PublicTip)
	t.Logf("git cat-file -p %s\n%s", res.PublicTip, raw)
	for _, want := range []string{
		"tree " + a.Tree,
		"author Alice Example <alice@host.example> 1935799689 +0000",
		"committer Alice Example <alice@host.example> 1935799689 +0000",
		"publish " + x[:12] + "\n\nfirst public release\n\nCanonical-Commit: " + x,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("public commit lacks %q", want)
		}
	}
	if strings.Contains(raw, "\nparent ") {
		t.Error("first publish has a parent")
	}
	// The internal file, which holds the planted value, is not public.
	if got := gittest.Git(t, pub, "ls-tree", "-r", "--name-only", "main"); got != "README.md\nsrc/main.go" {
		t.Fatalf("public tree: %q", got)
	}
}

func TestNotOnCanonicalMain(t *testing.T) {
	w := newWorld(t, "snapshot")
	w.commit("first", files1)
	gittest.Git(t, w.dev, "switch", "-q", "-c", "agent/x")
	b := gittest.Commit(t, w.dev, "branch work", map[string]string{"src/b.go": "package main\n"})
	gittest.Git(t, w.dev, "push", "-q", "origin", "agent/x")
	_, err := Run(w.opts(w.approve(b)))
	mustRefuse(t, err, "not on main")

	a := w.approve(b)
	a.Commit = strings.Repeat("0", 40)
	_, err = Run(w.opts(a))
	mustRefuse(t, err, "not on main")
	if w.publicTip() != "" {
		t.Fatal("something was published")
	}
}

func TestTreeMismatch(t *testing.T) {
	w := newWorld(t, "snapshot")
	x1 := w.commit("first", files1)
	x2 := w.commit("second", map[string]string{"src/two.go": "package main\n"})
	a := w.approve(x2)
	a.Tree = w.approve(x1).Tree // the reviewer read another tree
	_, err := Run(w.opts(a))
	mustRefuse(t, err, "tree mismatch")
}

func TestDenylistMismatch(t *testing.T) {
	w := newWorld(t, "snapshot")
	a := w.approve(w.commit("first", files1))
	a.Denylist = "0123456789abcdef" // the read used another denylist
	_, err := Run(w.opts(a))
	mustRefuse(t, err, "denylist mismatch")
}

func TestFindingInPublicTreeRefuses(t *testing.T) {
	w := newWorld(t, "snapshot")
	x := w.commit("first", map[string]string{"src/main.go": "// " + planted + "\npackage main\n", "README.md": "x\n"})
	_, err := Run(w.opts(w.approve(x)))
	mustRefuse(t, err, "denylist")
	if w.publicTip() != "" {
		t.Fatal("published despite a finding")
	}
}

func TestRerunOfPublishedCommit(t *testing.T) {
	w := newWorld(t, "snapshot")
	a := w.approve(w.commit("first", files1))
	first, err := Run(w.opts(a))
	if err != nil {
		t.Fatal(err)
	}
	again, err := Run(w.opts(a))
	if err != nil || again.Outcome != UpToDate || again.PublicTip != first.PublicTip || w.publicTip() != first.PublicTip {
		t.Fatalf("re-run: %+v %v", again, err)
	}
}

func TestOlderRunPushesFirst(t *testing.T) {
	w := newWorld(t, "snapshot")
	a1 := w.approve(w.commit("first", files1))
	a2 := w.approve(w.commit("second", map[string]string{"src/two.go": "package main\n"}))

	newer := w.opts(a2)
	newer.beforePush = once(func() {
		// The older run wins the race.
		if res, err := Run(w.opts(a1)); err != nil || res.Outcome != Published {
			t.Fatalf("older run: %+v %v", res, err)
		}
	})
	res, err := Run(newer)
	if err != nil || res.Outcome != Published {
		t.Fatalf("newer run: %+v %v", res, err)
	}
	// The newer run restaged on top of the older one's commit.
	pub := w.publicRepo()
	tip, _ := pub.ReadCommit("main")
	parent, _ := pub.ReadCommit("main^")
	if tip.Tree != a2.Tree || !strings.Contains(tip.Message, "Canonical-Commit: "+a2.Commit) ||
		!strings.Contains(parent.Message, "Canonical-Commit: "+a1.Commit) || len(parent.Parents) != 0 {
		t.Fatalf("public history: tip %+v parent %+v", tip, parent)
	}
}

func TestNewerRunPushesFirst(t *testing.T) {
	w := newWorld(t, "snapshot")
	a1 := w.approve(w.commit("first", files1))
	a2 := w.approve(w.commit("second", map[string]string{"src/two.go": "package main\n"}))

	older := w.opts(a1)
	older.beforePush = once(func() {
		if res, err := Run(w.opts(a2)); err != nil || res.Outcome != Published {
			t.Fatalf("newer run: %+v %v", res, err)
		}
	})
	res, err := Run(older)
	if err != nil || res.Outcome != Superseded || res.Canonical != a2.Commit {
		t.Fatalf("older run: %+v %v", res, err)
	}
	if n := gittest.Git(t, w.publicRepo(), "rev-list", "--count", "main"); n != "1" {
		t.Fatalf("public main has %s commits", n)
	}
	// And a later run of the older approval is superseded without pushing.
	res, err = Run(w.opts(a1))
	if err != nil || res.Outcome != Superseded {
		t.Fatalf("late older run: %+v %v", res, err)
	}
}

func TestPublicTipWithoutCanonicalCommit(t *testing.T) {
	w := newWorld(t, "snapshot")
	a1 := w.approve(w.commit("first", files1))
	if _, err := Run(w.opts(a1)); err != nil {
		t.Fatal(err)
	}
	// Someone commits on the public side by hand.
	hand := gittest.Init(t)
	gittest.Git(t, hand, "pull", "-q", w.public, "main")
	gittest.Commit(t, hand, "fix typo on GitHub", map[string]string{"README.md": "# demo!\n"})
	gittest.Git(t, hand, "push", "-q", w.public, "HEAD:main")
	before := w.publicTip()

	a2 := w.approve(w.commit("second", map[string]string{"src/two.go": "package main\n"}))
	_, err := Run(w.opts(a2))
	mustRefuse(t, err, "carries no Canonical-Commit")
	if w.publicTip() != before {
		t.Fatal("public main moved")
	}
}

func TestPublicStartsWithReadme(t *testing.T) {
	w := newWorld(t, "snapshot")
	// The public repository was created with a README: not empty, and not ours.
	gh := gittest.Init(t)
	gittest.Commit(t, gh, "Initial commit", map[string]string{"README.md": "# demo\n"})
	gittest.Git(t, gh, "push", "-q", w.public, "HEAD:main")
	before := w.publicTip()

	_, err := Run(w.opts(w.approve(w.commit("first", files1))))
	mustRefuse(t, err, "carries no Canonical-Commit")
	if w.publicTip() != before {
		t.Fatal("public main moved")
	}
}

func TestOnlyMainIsWritten(t *testing.T) {
	w := newWorld(t, "snapshot")
	x1 := w.commit("first", files1)
	gittest.Git(t, w.dev, "tag", "v1", x1)
	gittest.Git(t, w.dev, "tag", "-a", "-m", "annotated", "v1a", x1)
	gittest.Git(t, w.dev, "branch", "agent/y")
	gittest.Git(t, w.dev, "push", "-q", "origin", "--tags", "agent/y")
	a1 := w.approve(x1)
	if _, err := Run(w.opts(a1)); err != nil {
		t.Fatal(err)
	}
	a2 := w.approve(w.commit("second", map[string]string{"src/two.go": "package main\n"}))
	if _, err := Run(w.opts(a2)); err != nil {
		t.Fatal(err)
	}
	if refs := w.publicRefs(); refs != "refs/heads/main" {
		t.Fatalf("public refs: %q", refs)
	}
}

func TestExactPushesTheCommitAndChecksHistory(t *testing.T) {
	w := newWorld(t, "exact")
	x1 := w.commit("first", map[string]string{"src/main.go": "package main\n", "README.md": "x\n"})
	res, err := Run(w.opts(w.approve(x1)))
	if err != nil || res.PublicTip != x1 {
		t.Fatalf("exact publish: %+v %v", res, err)
	}
	// A value added and removed between two publishes.
	w.commit("oops", map[string]string{"src/leak.go": "// " + planted + "\n"})
	x3 := w.commit("remove", map[string]string{"src/leak.go": ""})
	_, err = Run(w.opts(w.approve(x3)))
	mustRefuse(t, err, "denylist")
	if w.publicTip() != x1 {
		t.Fatal("public main moved")
	}
}

func TestExactIdentity(t *testing.T) {
	w := newWorld(t, "exact")
	w.dev.Env = append(w.dev.Env, gittest.Env...) // back to Dev Example, not the manifest's author
	x := w.commit("first", map[string]string{"src/main.go": "package main\n", "README.md": "x\n"})
	_, err := Run(w.opts(w.approve(x)))
	mustRefuse(t, err, "identity")
}

func TestParseApproval(t *testing.T) {
	x, h := strings.Repeat("a", 40), strings.Repeat("b", 40)
	if a, err := ParseApproval(x + ":" + h + ":0123456789abcdef"); err != nil || a.Tree != h {
		t.Fatalf("%+v %v", a, err)
	}
	for _, bad := range []string{"", x, x + ":" + h, x + ":" + h + ":0123", "HEAD:" + h + ":0123456789abcdef"} {
		if _, err := ParseApproval(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// once makes a hook fire on the first push attempt only.
func once(f func()) func() {
	done := false
	return func() {
		if !done {
			done = true
			f()
		}
	}
}
