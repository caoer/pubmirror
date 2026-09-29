package hooks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture: a clone whose .git/hooks holds a pre-existing pre-commit and
// post-checkout, a second worktree on a branch that predates adoption, and a
// stub pubmirror that logs each call and exits with the code in $STUB_EXIT.
type fixture struct {
	t        *testing.T
	main     string // main worktree
	old      string // worktree on the pre-adoption branch
	log      string // stub pubmirror's call log
	chainLog string // pre-existing hooks' log
	env      []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{
		t:        t,
		main:     filepath.Join(root, "repo"),
		old:      filepath.Join(root, "old"),
		log:      filepath.Join(root, "pubmirror.log"),
		chainLog: filepath.Join(root, "chained.log"),
	}
	stub := filepath.Join(root, "bin", "pubmirror")
	must(t, os.MkdirAll(filepath.Dir(stub), 0o755))
	must(t, os.WriteFile(stub, []byte(`#!/bin/sh
{ printf '%s|' "$(basename "$PWD")" "$@"; printf 'stdin=%s\n' "$(cat | tr '\n' ' ')"; } >>"$STUB_LOG"
exit "${STUB_EXIT:-0}"
`), 0o755))
	f.env = append(os.Environ(),
		"PUBMIRROR="+stub, "STUB_LOG="+f.log, "CHAIN_LOG="+f.chainLog,
		"GIT_AUTHOR_NAME=alice", "GIT_AUTHOR_EMAIL=alice@host.example",
		"GIT_COMMITTER_NAME=alice", "GIT_COMMITTER_EMAIL=alice@host.example",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
	)

	f.git(root, "init", "-q", "-b", "main", f.main)
	for _, h := range []string{"pre-commit", "post-checkout"} {
		must(t, os.WriteFile(filepath.Join(f.main, ".git", "hooks", h),
			[]byte("#!/bin/sh\necho \""+h+" $(basename \"$PWD\")\" >>\"$CHAIN_LOG\"\n"), 0o755))
	}
	f.commit(f.main, "a.txt", "one")
	f.git(f.main, "branch", "old")
	f.commit(f.main, ".pubmirror.toml", "version = 1\n")
	f.git(f.main, "worktree", "add", "-q", f.old, "old")
	must(t, os.Truncate(f.chainLog, 0))
	return f
}

func (f *fixture) git(dir string, args ...string) (string, error) {
	f.t.Helper()
	return f.gitEnv(dir, nil, args...)
}

func (f *fixture) gitEnv(dir string, extra []string, args ...string) (string, error) {
	f.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, f.env...), extra...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (f *fixture) commit(dir, name, body string, extra ...string) (string, error) {
	f.t.Helper()
	must(f.t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644))
	if out, err := f.git(dir, "add", name); err != nil {
		f.t.Fatalf("git add: %v\n%s", err, out)
	}
	return f.gitEnv(dir, extra, "commit", "-q", "-m", "add "+name)
}

func (f *fixture) read(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestInstallRunsInEveryWorktreeAndChains(t *testing.T) {
	f := newFixture(t)
	r, err := Install(f.old) // from the pre-adoption worktree: the common dir is the same
	must(t, err)
	if want := filepath.Join(f.main, ".git", Dir); r.HooksPath != realpath(t, want) && r.HooksPath != want {
		t.Fatalf("HooksPath = %s, want %s", r.HooksPath, want)
	}
	if got := strings.Join(r.Shims, ","); got != "commit-msg,post-checkout,pre-commit,pre-push" {
		t.Fatalf("shims = %s", got)
	}
	if len(r.Worktrees) != 2 {
		t.Fatalf("worktrees = %+v", r.Worktrees)
	}
	for _, w := range r.Worktrees {
		if !w.OK {
			t.Fatalf("worktree %s resolves core.hooksPath %q", w.Path, w.HooksPath)
		}
	}

	for _, dir := range []string{f.main, f.old} {
		if out, err := f.commit(dir, "b.txt", dir); err != nil {
			t.Fatalf("commit in %s: %v\n%s", dir, err, out)
		}
	}
	log := f.read(f.log)
	for _, want := range []string{"repo|check|--staged|", "old|check|--staged|", "repo|check-msg|", "old|check-msg|"} {
		if !strings.Contains(log, want) {
			t.Errorf("pubmirror log lacks %q:\n%s", want, log)
		}
	}
	chain := f.read(f.chainLog)
	for _, want := range []string{"pre-commit repo", "pre-commit old"} {
		if !strings.Contains(chain, want) {
			t.Errorf("chained hook log lacks %q:\n%s", want, chain)
		}
	}

	// A pass-through shim: git-annex-style post-checkout still runs.
	if out, err := f.git(f.main, "checkout", "-q", "-b", "side"); err != nil {
		t.Fatalf("checkout: %v\n%s", err, out)
	}
	if !strings.Contains(f.read(f.chainLog), "post-checkout repo") {
		t.Errorf("post-checkout did not chain:\n%s", f.read(f.chainLog))
	}
}

func TestExitCodes(t *testing.T) {
	f := newFixture(t)
	_, err := Install(f.main)
	must(t, err)

	out, err := f.commit(f.main, "c.txt", "x", "STUB_EXIT=2")
	if err != nil {
		t.Fatalf("exit 2 must warn and let the commit through: %v\n%s", err, out)
	}
	if !strings.Contains(out, "could not run (exit 2)") {
		t.Errorf("no warning on exit 2:\n%s", out)
	}

	out, err = f.commit(f.main, "d.txt", "x", "STUB_EXIT=1")
	if err == nil {
		t.Fatalf("exit 1 must refuse the commit:\n%s", out)
	}
	if !strings.Contains(out, "pre-commit refused") {
		t.Errorf("no refusal message:\n%s", out)
	}

	out, err = f.commit(f.main, "e.txt", "x", "PUBMIRROR=/nonexistent/pubmirror")
	if err != nil || !strings.Contains(out, "not found") {
		t.Fatalf("a missing binary must warn and let the commit through: %v\n%s", err, out)
	}
}

func TestPrePushPassesRefsToBoth(t *testing.T) {
	f := newFixture(t)
	must(t, os.WriteFile(filepath.Join(f.main, ".git", "hooks", "pre-push"),
		[]byte("#!/bin/sh\necho \"pre-push $1 $(cat | cut -d' ' -f1)\" >>\"$CHAIN_LOG\"\n"), 0o755))
	_, err := Install(f.main)
	must(t, err)

	bare := filepath.Join(t.TempDir(), "remote.git")
	if out, err := f.git(f.main, "init", "-q", "--bare", bare); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := f.git(f.main, "push", "-q", bare, "main"); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	if !strings.Contains(f.read(f.chainLog), "pre-push "+bare+" refs/heads/main") {
		t.Errorf("chained pre-push did not get the refs:\n%s", f.read(f.chainLog))
	}
	if !strings.Contains(f.read(f.log), "guard-push|"+bare+"|"+bare+"|stdin=refs/heads/main ") {
		t.Errorf("guard-push did not get the refs:\n%s", f.read(f.log))
	}

	if out, err := f.gitEnv(f.main, []string{"STUB_EXIT=1"}, "push", "-q", bare, "main:other"); err == nil {
		t.Fatalf("exit 1 from guard-push must refuse the push:\n%s", out)
	}
}

func TestInstallTwiceDoesNotChainToItself(t *testing.T) {
	f := newFixture(t)
	r1, err := Install(f.main)
	must(t, err)
	r2, err := Install(f.main)
	must(t, err)
	if r1.Chained != r2.Chained || strings.HasSuffix(r2.Chained, Dir) {
		t.Fatalf("chained %q then %q", r1.Chained, r2.Chained)
	}
	if out, err := f.commit(f.main, "f.txt", "x"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if n := strings.Count(f.read(f.chainLog), "pre-commit repo"); n != 1 {
		t.Fatalf("chained pre-commit ran %d times", n)
	}
}

func TestRelativeHooksPathRefused(t *testing.T) {
	f := newFixture(t)
	if out, err := f.git(f.main, "config", "core.hooksPath", ".githooks"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := Install(f.main); err == nil || !strings.Contains(err.Error(), "relative") {
		t.Fatalf("err = %v", err)
	}
}

func realpath(t *testing.T, p string) string {
	r, err := filepath.EvalSymlinks(filepath.Dir(p))
	must(t, err)
	return filepath.Join(r, filepath.Base(p))
}
