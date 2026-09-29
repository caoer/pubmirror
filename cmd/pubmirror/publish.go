package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/publish"
	"github.com/caoer/pubmirror/internal/scan"
)

func init() {
	register("publish", "write an approved commit X:H:D to the public main", runPublish)
}

// In CI the publisher runs as a Woodpecker plugin step, which carries no
// arguments or environment of its own. Its inputs:
//
//	PUBMIRROR_APPROVE   the approval, when --approve is absent (a manual-run variable)
//	PUBMIRROR_SUMMARY   the summary line, when --summary is absent
//	PLUGIN_DEPLOY_KEY   the public repository's write key (private key text)
//	PLUGIN_DENYLIST     the denylist text, when PUBMIRROR_DENYLIST is unset
//	CI_REPO_CLONE_URL   the canonical repository, when --canonical is absent
//	CI_NETRC_MACHINE, CI_NETRC_USERNAME, CI_NETRC_PASSWORD   its credentials
func runPublish(args []string) int {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	approve := fs.String("approve", os.Getenv("PUBMIRROR_APPROVE"), "the approval X:H:D")
	summary := fs.String("summary", os.Getenv("PUBMIRROR_SUMMARY"), "optional summary line of a snapshot commit")
	canonical := fs.String("canonical", "", "canonical remote name or URL (default $CI_REPO_CLONE_URL, else origin)")
	repoDir := fs.String("repo", ".", "a clone of the canonical repository")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return exitCannot
	}
	a, err := publish.ParseApproval(*approve)
	if err != nil {
		return exitFor("publish", err)
	}
	if *canonical == "" {
		*canonical = orDefault(os.Getenv("CI_REPO_CLONE_URL"), "origin")
	}
	r, err := gitobj.Open(*repoDir)
	if err != nil {
		return exitFor("publish", err)
	}
	publicEnv, cleanup, err := publisherEnv(r)
	defer cleanup()
	if err != nil {
		return exitFor("publish", err)
	}
	dl, err := coreDenylist()
	if err != nil {
		return exitFor("publish", err)
	}

	res, err := publish.Run(publish.Options{
		Repo: r, Canonical: *canonical, PublicEnv: publicEnv, Approval: a, Summary: *summary,
		Denylist: dl, Tokens: scan.Gitleaks{}, Log: os.Stdout,
	})
	if publish.IsRefusal(err) {
		fmt.Fprintln(os.Stderr, "pubmirror publish: refused:", err)
		return exitFindings
	}
	if err != nil {
		return exitFor("publish", err)
	}
	fmt.Printf("%s: public main %s carries %s\n", res.Outcome, res.PublicTip, res.Canonical)
	return exitClean
}

// publisherEnv sets the CI credential for the canonical remote on r, an https
// credential helper answering only for the canonical host, and returns the
// environment for the public remote: ssh with the deploy key as its only
// identity, whatever the host's ssh config or agent holds.
func publisherEnv(r *gitobj.Repo) (publicEnv []string, cleanup func(), err error) {
	cleanup = func() {}
	var cfg [][2]string
	if os.Getenv("CI_NETRC_PASSWORD") != "" {
		cfg = append(cfg, [2]string{"credential.helper", `!f() { test "$1" = get || exit 0; h=; while IFS== read -r k v; do test "$k" = host && h=$v; done; test "${h%%:*}" = "$CI_NETRC_MACHINE" || exit 0; echo "username=$CI_NETRC_USERNAME"; echo "password=$CI_NETRC_PASSWORD"; }; f`})
	}
	if n := len(cfg); n > 0 {
		r.Env = append(r.Env, fmt.Sprintf("GIT_CONFIG_COUNT=%d", n))
		for i, kv := range cfg {
			r.Env = append(r.Env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
		}
	}
	key := os.Getenv("PLUGIN_DEPLOY_KEY")
	if key == "" {
		return nil, cleanup, nil
	}
	dir, err := os.MkdirTemp("", "pubmirror-key-")
	if err != nil {
		return nil, cleanup, err
	}
	cleanup = func() { os.RemoveAll(dir) }
	f := filepath.Join(dir, "deploy_key")
	if !strings.HasSuffix(key, "\n") {
		key += "\n"
	}
	if err := os.WriteFile(f, []byte(key), 0o600); err != nil {
		return nil, cleanup, err
	}
	return []string{"GIT_SSH_COMMAND=" + gitobj.SSHCommand(f)}, cleanup, nil
}

// coreDenylist loads the denylist: $PLUGIN_DENYLIST's text when
// $PUBMIRROR_DENYLIST is unset, else the file scan.DenylistPath names.
func coreDenylist() (*scan.Denylist, error) {
	if os.Getenv("PUBMIRROR_DENYLIST") == "" {
		if text := os.Getenv("PLUGIN_DENYLIST"); text != "" {
			return scan.ParseDenylist([]byte(text))
		}
	}
	p, err := scan.DenylistPath()
	if err != nil {
		return nil, err
	}
	return scan.LoadDenylist(p)
}

func orDefault(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// exitFor prints an error that kept a command from running and returns exit 2.
func exitFor(name string, err error) int {
	fmt.Fprintf(os.Stderr, "pubmirror %s: %v\n", name, err)
	return exitCannot
}
