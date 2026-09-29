package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/caoer/pubmirror/internal/gittest"
)

func TestCICheckMode(t *testing.T) {
	needGitleaks(t)
	r := gittest.Init(t)
	sha := gittest.Commit(t, r, "adopt", map[string]string{
		".pubmirror.toml": gittest.Manifest("snapshot", "git@host.example:alice/repo.git"),
		"src/a.txt":       "reaches " + planted + "\n",
	})
	wd, _ := os.Getwd()
	if err := os.Chdir(r.Dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)
	t.Setenv("PUBMIRROR_DENYLIST", "")
	t.Setenv("CI_COMMIT_SHA", sha)
	t.Setenv("PLUGIN_DENYLIST", planted+"\n")

	run := func(mode string) (int, string) {
		t.Setenv("PLUGIN_MODE", mode)
		var out, errb bytes.Buffer
		rc := runCI(nil, &out, &errb)
		return rc, out.String() + errb.String()
	}
	rc, out := run("check")
	if rc != exitFindings || !strings.Contains(out, "token #1") || strings.Contains(out, planted) {
		t.Fatalf("check mode with the denylist from settings: rc %d\n%s", rc, out)
	}
	if rc, out := run(""); rc != exitCannot || !strings.Contains(out, "mode setting") {
		t.Fatalf("no mode: rc %d\n%s", rc, out)
	}
}
