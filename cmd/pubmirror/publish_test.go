package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/gittest"
	"github.com/caoer/pubmirror/internal/stage"
)

// fakeSSH puts an ssh on PATH that logs its arguments, one line per
// connection, and runs git's remote command locally, so ssh:// URLs to any
// host name reach local repositories.
func fakeSSH(t *testing.T) (log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "ssh.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + log + "'\nfor a; do last=$a; done\nexec sh -c \"git ${last#git-}\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func readLog(t *testing.T, log string) []string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(log)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// On a dev host whose ssh setup would hand the owner's key to every
// connection, publish offers the deploy key alone to the public remote, the
// canonical remote keeps the host's setup, and verify offers no key.
func TestPublishIdentityIgnoresHostSSH(t *testing.T) {
	needGitleaks(t)
	log := fakeSSH(t)
	t.Setenv("GIT_SSH_COMMAND", "ssh -i /owner/key")
	t.Setenv("SSH_AUTH_SOCK", "/owner/agent.sock")
	t.Setenv("PLUGIN_DEPLOY_KEY", "fictional deploy key")
	withDenylist(t, planted+"\n")
	dl, err := coreDenylist()
	if err != nil {
		t.Fatal(err)
	}

	canon, public := gittest.Bare(t), gittest.Bare(t)
	canonURL, publicURL := "ssh://git@canonical.example"+canon, "ssh://git@public.example"+public
	dev := gittest.Init(t)
	x := gittest.Commit(t, dev, "first", map[string]string{
		".pubmirror.toml": gittest.Manifest("snapshot", publicURL),
		"src/main.go":     "package main\n",
	})
	gittest.Git(t, dev, "push", "-q", canon, "HEAD:main")
	st, err := stage.Build(dev, x)
	if err != nil {
		t.Fatal(err)
	}
	approval := x + ":" + st.Tree + ":" + dl.Hash()
	clone := &gitobj.Repo{Dir: t.TempDir(), Env: gittest.Env}
	gittest.Git(t, clone, "clone", "-q", canon, ".")

	if rc := runPublish([]string{"--repo", clone.Dir, "--canonical", canonURL, "--approve", approval}); rc != exitClean {
		t.Fatalf("publish: rc %d", rc)
	}
	sole := "-F /dev/null -o IdentityAgent=none -o IdentitiesOnly=yes -o IdentityFile="
	var toPublic, toCanonical int
	for _, l := range readLog(t, log) {
		t.Log("publish: ssh " + l)
		switch {
		case strings.Contains(l, "public.example"):
			toPublic++
			if !strings.Contains(l, sole) || !strings.Contains(l, "/deploy_key") || strings.Contains(l, "/owner/") {
				t.Errorf("public connection does not offer the deploy key alone: %s", l)
			}
		case strings.Contains(l, "canonical.example"):
			toCanonical++
			if !strings.Contains(l, "-i /owner/key") || strings.Contains(l, "deploy_key") {
				t.Errorf("canonical connection lost the host's setup or got the deploy key: %s", l)
			}
		}
	}
	if toPublic == 0 || toCanonical == 0 {
		t.Fatalf("connections: %d public, %d canonical", toPublic, toCanonical)
	}

	if rc := runVerify([]string{"--repo", clone.Dir, "--url", publicURL, "--approve", approval}); rc != exitClean {
		t.Fatalf("verify: rc %d", rc)
	}
	for _, l := range readLog(t, log) {
		t.Log("verify: ssh " + l)
		if !strings.Contains(l, sole+"none ") || strings.Contains(l, "/owner/") {
			t.Errorf("verify connection offers a key: %s", l)
		}
	}
}
