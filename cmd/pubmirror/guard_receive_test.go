package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/gittest"
)

// The test binary doubles as the forge's pre-receive hook, so a real git push
// runs guard-receive with the pushed objects in quarantine.
func TestMain(m *testing.M) {
	if os.Getenv("PUBMIRROR_TEST_PRE_RECEIVE") == "1" {
		os.Exit(guardReceive(nil, os.Stdin, ".", os.Stderr))
	}
	os.Exit(m.Run())
}

const publicRemote = "https://github.com/alice/repo.git"

// alice commits as the manifest's public author.
var alice = []string{
	"GIT_AUTHOR_NAME=Alice Example", "GIT_AUTHOR_EMAIL=alice@host.example",
	"GIT_COMMITTER_NAME=Alice Example", "GIT_COMMITTER_EMAIL=alice@host.example",
}

// forge makes a bare canonical repository guarded by guard-receive and a clone
// that pushes to it.
func forge(t *testing.T) (r *gitobj.Repo, bare string) {
	t.Helper()
	bare = gittest.Bare(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	hook := "#!/bin/sh\nPUBMIRROR_TEST_PRE_RECEIVE=1 exec '" + exe + "'\n"
	if err := os.WriteFile(filepath.Join(bare, "hooks", "pre-receive"), []byte(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	r = gittest.Init(t)
	gittest.Git(t, r, "remote", "add", "origin", bare)
	return r, bare
}

// push reports whether the forge accepted the refspecs, with git's output.
func push(t *testing.T, r *gitobj.Repo, refspecs ...string) (bool, string) {
	t.Helper()
	c := exec.Command("git", append([]string{"push", "origin"}, refspecs...)...)
	c.Dir = r.Dir
	c.Env = append(os.Environ(), r.Env...)
	out, err := c.CombinedOutput()
	return err == nil, string(out)
}

func remoteRef(t *testing.T, r *gitobj.Repo, ref string) string {
	t.Helper()
	sha, err := r.RemoteRef("origin", ref)
	if err != nil {
		t.Fatal(err)
	}
	return sha
}

func TestGuardReceiveNoManifest(t *testing.T) {
	// Without a manifest nothing is judged, so the denylist is not needed.
	t.Setenv("PUBMIRROR_DENYLIST", filepath.Join(t.TempDir(), "absent.txt"))
	r, _ := forge(t)
	gittest.Commit(t, r, "plain", map[string]string{"a.txt": "see " + planted + "\n"})
	if ok, out := push(t, r, "main"); !ok || strings.Contains(out, "pubmirror") {
		t.Fatalf("push without a manifest: accepted %v\n%s", ok, out)
	}
}

func TestGuardReceiveExact(t *testing.T) {
	needGitleaks(t)
	withDenylist(t, planted+"\n")
	r, bare := forge(t)
	r.Env = append(r.Env, alice...)
	someoneElse := &gitobj.Repo{Dir: r.Dir, Env: gittest.Env}
	accept := func(what string, refspecs ...string) string {
		t.Helper()
		ok, out := push(t, r, refspecs...)
		if !ok {
			t.Fatalf("%s: refused\n%s", what, out)
		}
		return out
	}
	refuse := func(what, want string, refspecs ...string) {
		t.Helper()
		if ok, out := push(t, r, refspecs...); ok || !strings.Contains(out, want) || !strings.Contains(out, "pubmirror guard-receive: refused") {
			t.Fatalf("%s: accepted %v, want a refusal naming %q\n%s", what, ok, want, out)
		}
	}

	gittest.Commit(t, r, "adopt", map[string]string{
		".pubmirror.toml": gittest.Manifest("exact", publicRemote), "src/a.txt": "one\n",
	})
	if out := accept("clean push", "main"); !strings.Contains(out, "(1 commits): 2 files, 0 findings; denylist ") {
		t.Fatalf("clean push: no summary line\n%s", out)
	}
	good := gittest.Git(t, r, "rev-parse", "HEAD")

	gittest.Commit(t, r, "leak", map[string]string{"src/a.txt": "see " + planted + "\n"})
	refuse("planted value", "denylist: token #1", "main")
	if got := remoteRef(t, r, "refs/heads/main"); got != good {
		t.Fatalf("refused push moved main to %s", got)
	}
	gittest.Git(t, r, "reset", "-q", "--hard", good)

	gittest.Commit(t, someoneElse, "by someone else", map[string]string{"src/b.txt": "two\n"})
	refuse("another identity", "identity: Dev Example ", "main")
	gittest.Git(t, r, "reset", "-q", "--hard", good)

	gittest.Git(t, r, "tag", "-a", "v1", "-m", "release for "+planted)
	refuse("tag message", "message:1: denylist: token #1", "refs/tags/v1")
	gittest.Git(t, r, "tag", "-d", "v1")
	gittest.Git(t, r, "tag", "-a", "v1", "-m", "release")
	accept("clean tag", "refs/tags/v1")
	accept("deletion", ":refs/tags/v1")

	// History the forge already holds is not judged again: a finding that
	// landed before the guard does not block later pushes.
	hook := filepath.Join(bare, "hooks", "pre-receive")
	if err := os.Rename(hook, hook+".off"); err != nil {
		t.Fatal(err)
	}
	gittest.Commit(t, r, "landed before the guard", map[string]string{"src/old.txt": planted + "\n"})
	accept("unguarded push", "main")
	if err := os.Rename(hook+".off", hook); err != nil {
		t.Fatal(err)
	}
	gittest.Commit(t, r, "after the guard", map[string]string{"src/new.txt": "three\n"})
	if out := accept("push on top of old history", "main"); !strings.Contains(out, "(1 commits)") {
		t.Fatalf("judged more than the new commit\n%s", out)
	}
	accept("new branch, no new commit", "main:refs/heads/topic")

	t.Setenv("PUBMIRROR_DENYLIST", filepath.Join(t.TempDir(), "absent.txt"))
	gittest.Commit(t, r, "without a denylist", map[string]string{"src/c.txt": "four\n"})
	refuse("denylist missing", "denylist missing", "main")
}

func TestGuardReceiveSnapshot(t *testing.T) {
	needGitleaks(t)
	withDenylist(t, planted+"\n")
	r, _ := forge(t)
	gittest.Commit(t, r, "adopt", map[string]string{
		".pubmirror.toml": gittest.Manifest("snapshot", publicRemote),
		"src/a.txt":       "one\n",
		"notes/n.txt":     "about " + planted + "\n", // internal: never published
	})
	if ok, out := push(t, r, "main"); !ok || !strings.Contains(out, "public set: 1 files, 0 findings") {
		t.Fatalf("clean public set: accepted %v\n%s", ok, out)
	}
	gittest.Commit(t, r, "leak", map[string]string{"src/a.txt": "see " + planted + "\n"})
	if ok, out := push(t, r, "HEAD:refs/heads/topic"); !ok || strings.Contains(out, "pubmirror") {
		t.Fatalf("a branch other than main is not judged: accepted %v\n%s", ok, out)
	}
	if ok, out := push(t, r, "main"); ok || !strings.Contains(out, "src/a.txt:1: denylist: token #1") {
		t.Fatalf("finding in the public set of main: accepted %v\n%s", ok, out)
	}
}
