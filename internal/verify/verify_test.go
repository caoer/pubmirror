package verify

import (
	"strings"
	"testing"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/gittest"
	"github.com/caoer/pubmirror/internal/scan"
	"github.com/caoer/pubmirror/internal/stage"
)

type noTokens struct{}

func (noTokens) ScanTokens([]scan.File) ([]scan.Finding, error) { return nil, nil }

const planted = "zebra-codename"

var alice = gitobj.Signature{Name: "Alice Example", Email: "alice@host.example", Date: "1700000000 +0000"}

// setup makes a canonical repository whose manifest points at a public bare
// repository, stages its tip, and returns both with the staged result.
func setup(t *testing.T, verifyCmd string) (*gitobj.Repo, string, *stage.Result) {
	t.Helper()
	public := gittest.Bare(t)
	canon := gittest.Init(t)
	man := gittest.Manifest("snapshot", public)
	if verifyCmd != "" {
		man += "\n[verify]\ncommands = [\"" + verifyCmd + "\"]\n"
	}
	x := gittest.Commit(t, canon, "first", map[string]string{
		".pubmirror.toml": man,
		"src/main.go":     "package main\n",
		"notes/plan.md":   "internal: " + planted + "\n",
	})
	st, err := stage.Build(canon, x)
	if err != nil {
		t.Fatal(err)
	}
	return canon, public, st
}

// publishAs writes public history into the bare repository by hand: an
// optional earlier commit with extra files, then the staged tree carrying X.
func publishAs(t *testing.T, canon *gitobj.Repo, public string, st *stage.Result, earlier map[string]string) {
	t.Helper()
	var parents []string
	if earlier != nil {
		es := append([]gitobj.Entry(nil), st.Public...)
		for p, data := range earlier {
			obj, err := canon.RunInput(strings.NewReader(data), "hash-object", "-w", "--stdin")
			if err != nil {
				t.Fatal(err)
			}
			es = append(es, gitobj.Entry{Path: p, Mode: gitobj.ModeFile, Object: strings.TrimSpace(string(obj))})
		}
		tree, err := canon.WriteTree(es)
		if err != nil {
			t.Fatal(err)
		}
		c, err := canon.CommitTree(tree, nil, "publish earlier\n\nCanonical-Commit: "+st.Commit+"\n", alice, alice)
		if err != nil {
			t.Fatal(err)
		}
		parents = []string{c}
	}
	tip, err := canon.CommitTree(st.Tree, parents, "publish "+st.Commit[:12]+"\n\nCanonical-Commit: "+st.Commit+"\n", alice, alice)
	if err != nil {
		t.Fatal(err)
	}
	gittest.Git(t, canon, "push", "-q", public, tip+":refs/heads/main")
}

func run(t *testing.T, canon *gitobj.Repo, st *stage.Result) *Report {
	t.Helper()
	d, err := scan.ParseDenylist([]byte(planted + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	rep, err := Run(Options{Repo: canon, Commit: st.Commit, Tree: st.Tree, Denylist: d, Tokens: noTokens{}, Log: &log})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("verify log:\n%s", log.String())
	return rep
}

func TestVerifyPasses(t *testing.T) {
	canon, public, st := setup(t, "test -f src/main.go && test ! -e notes")
	publishAs(t, canon, public, st, nil)
	if rep := run(t, canon, st); rep.Failed() {
		t.Fatalf("verify failed: %+v", rep)
	}
}

func TestPlantedValueInPublicHistoryFails(t *testing.T) {
	canon, public, st := setup(t, "")
	// The tip is clean and matches H; an earlier public commit held the value.
	publishAs(t, canon, public, st, map[string]string{"src/old.go": "// " + planted + "\n"})
	rep := run(t, canon, st)
	if len(rep.Findings) == 0 || rep.Findings[0].Rule != "denylist" || rep.Findings[0].Path != "src/old.go" {
		t.Fatalf("findings = %+v problems = %v", rep.Findings, rep.Problems)
	}
	if len(rep.Problems) != 0 {
		t.Fatalf("problems = %v", rep.Problems)
	}
}

func TestTreeMismatchExtraRefAndFailingCommand(t *testing.T) {
	canon, public, st := setup(t, "false")
	publishAs(t, canon, public, st, nil)
	gittest.Git(t, canon, "push", "-q", public, st.Commit+":refs/tags/v1")
	st.Tree = gitobj.EmptyTree
	rep := run(t, canon, st)
	got := strings.Join(rep.Problems, "\n")
	for _, want := range []string{"the public tree is", "a ref other than main: refs/tags/v1", `verify command "false"`} {
		if !strings.Contains(got, want) {
			t.Errorf("problems lack %q:\n%s", want, got)
		}
	}
}

func TestAnonymousURL(t *testing.T) {
	cases := map[string]string{
		"git@github.com:OWNER/repo.git":              "https://github.com/OWNER/repo.git",
		"ssh://git@host.example:2222/alice/repo.git": "https://host.example/alice/repo.git",
		"https://github.com/OWNER/repo.git":          "https://github.com/OWNER/repo.git",
		"/srv/git/repo.git":                          "/srv/git/repo.git",
		"file:///srv/git/repo.git":                   "file:///srv/git/repo.git",
	}
	for in, want := range cases {
		if got := AnonymousURL(in); got != want {
			t.Errorf("AnonymousURL(%q) = %q, want %q", in, got, want)
		}
	}
}
