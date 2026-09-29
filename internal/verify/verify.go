// Package verify checks a published repository from the outside: an
// anonymous clone, a rescan of its whole history, its tree against the
// approved hash, and the manifest's verify commands.
package verify

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/manifest"
	"github.com/caoer/pubmirror/internal/scan"
)

// Options configure one verification.
type Options struct {
	Repo     *gitobj.Repo // the canonical clone, for the manifest at Commit
	Commit   string       // X
	Tree     string       // H
	URL      string       // clone URL; empty means the anonymous form of the manifest's remote
	Denylist *scan.Denylist
	Tokens   scan.TokenScanner
	Log      io.Writer
}

// Report lists what failed. An empty report is a pass.
type Report struct {
	URL       string
	PublicTip string
	Problems  []string
	Findings  []scan.Finding
	Allowed   []scan.AllowUse
}

// Failed reports whether anything failed.
func (r *Report) Failed() bool { return len(r.Problems) > 0 || len(r.Findings) > 0 }

var trailerRE = regexp.MustCompile(`(?m)^Canonical-Commit: ([0-9a-f]{40})$`)

// Run verifies. An error means the verification could not run (exit 2).
func Run(o Options) (*Report, error) {
	if o.Log == nil {
		o.Log = io.Discard
	}
	if o.Denylist == nil {
		return nil, scan.ErrNoDenylist
	}
	x, err := o.Repo.ResolveCommit(o.Commit)
	if err != nil {
		return nil, err
	}
	data, ok, err := o.Repo.FileAt(x, manifest.File)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%s carries no %s", x, manifest.File)
	}
	m, err := manifest.Parse(data)
	if err != nil {
		return nil, err
	}
	rep := &Report{URL: o.URL}
	if rep.URL == "" {
		rep.URL = AnonymousURL(m.Public.Remote)
	}
	problem := func(format string, a ...any) { rep.Problems = append(rep.Problems, fmt.Sprintf(format, a...)) }

	tmp, err := os.MkdirTemp("", "pubmirror-verify-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	home := filepath.Join(tmp, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		return nil, err
	}
	// Anonymous: no user or system git config, no credential helper, no
	// netrc, no prompt, and over ssh no key. ssh finds ~/.ssh by the account,
	// not $HOME, so only its own flags keep the host's identity out.
	anon := &gitobj.Repo{Dir: tmp, Env: []string{
		"HOME=" + home, "XDG_CONFIG_HOME=" + home,
		"GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=",
		"GIT_SSH_COMMAND=" + gitobj.SSHCommand(""),
	}}

	// One ref is published.
	out, err := anon.Run("ls-remote", "--end-of-options", rep.URL)
	if err != nil {
		return nil, fmt.Errorf("anonymous read of %s: %w", rep.URL, err)
	}
	hasMain := false
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		_, ref, ok := strings.Cut(line, "\t")
		switch {
		case !ok || ref == "HEAD":
		case ref == "refs/heads/main":
			hasMain = true
		default:
			problem("the public repository has a ref other than main: %s", ref)
		}
	}
	if !hasMain {
		problem("the public repository has no main")
		return rep, nil
	}

	dir := filepath.Join(tmp, "clone")
	if _, err := anon.Run("clone", "--quiet", "--no-tags", "--single-branch", "--branch", "main", "--end-of-options", rep.URL, dir); err != nil {
		return nil, fmt.Errorf("anonymous clone of %s: %w", rep.URL, err)
	}
	pub := &gitobj.Repo{Dir: dir, Env: anon.Env}
	tip, err := pub.ReadCommit("HEAD")
	if err != nil {
		return nil, err
	}
	rep.PublicTip = tip.Hash
	fmt.Fprintf(o.Log, "public main %s, tree %s\n", tip.Hash, tip.Tree)

	if tip.Tree != o.Tree {
		problem("the public tree is %s, the approval names %s", tip.Tree, o.Tree)
	}
	switch m.Mode {
	case manifest.ModeExact:
		if tip.Hash != x {
			problem("the public main is %s, not %s", tip.Hash, x)
		}
	default:
		ms := trailerRE.FindAllStringSubmatch(tip.Message, -1)
		if len(ms) == 0 {
			problem("the public main %s carries no Canonical-Commit", tip.Hash)
		} else if c := ms[len(ms)-1][1]; c != x {
			problem("the public main carries canonical commit %s, not %s", c, x)
		}
	}

	// The whole public history, every blob and every commit, against every
	// rule; every public commit must carry the public author.
	files, commits, err := pub.Range("", "HEAD")
	if err != nil {
		return nil, err
	}
	sfiles := make([]scan.File, len(files))
	for i, f := range files {
		sfiles[i] = scan.File(f)
	}
	scommits := make([]scan.Commit, len(commits))
	for i, c := range commits {
		scommits[i] = scan.Commit{
			ID:        c.Hash,
			Author:    c.AuthorName + " <" + c.AuthorEmail + ">",
			Committer: c.CommitterName + " <" + c.CommitterEmail + ">",
			Message:   c.Message,
		}
	}
	cfg := scan.Config{Denylist: o.Denylist, Author: m.Public.Author, Exact: true, Tokens: o.Tokens}
	for _, a := range m.Allows {
		cfg.Allow = append(cfg.Allow, scan.Allow(a))
	}
	for _, f := range m.Fixtures {
		cfg.Fixtures = append(cfg.Fixtures, scan.Fixture(f))
	}
	sr, err := scan.Scan(cfg, sfiles, scommits)
	if err != nil {
		return nil, err
	}
	rep.Findings, rep.Allowed = sr.Findings, sr.Allowed
	fmt.Fprintf(o.Log, "rescanned %d commits, %d files\n", len(commits), len(files))

	// The manifest's verify commands, in the clone.
	for _, c := range m.Verify.Commands {
		fmt.Fprintf(o.Log, "$ %s\n", c)
		cmd := exec.Command("sh", "-c", c)
		cmd.Dir = dir
		cmd.Stdout, cmd.Stderr = o.Log, o.Log
		if err := cmd.Run(); err != nil {
			problem("verify command %q: %v", c, err)
		}
	}
	return rep, nil
}

var (
	scpRE = regexp.MustCompile(`^(?:[^@/]+@)?([^:/]+):(.+)$`)
	sshRE = regexp.MustCompile(`^ssh://(?:[^@/]+@)?([^:/]+)(?::\d+)?/(.+)$`)
)

// AnonymousURL turns an ssh remote into its https form; any other remote is
// returned as it is.
func AnonymousURL(remote string) string {
	if m := sshRE.FindStringSubmatch(remote); m != nil {
		return "https://" + m[1] + "/" + m[2]
	}
	if !strings.Contains(remote, "://") && !filepath.IsAbs(remote) {
		if m := scpRE.FindStringSubmatch(remote); m != nil {
			return "https://" + m[1] + "/" + strings.TrimPrefix(m[2], "/")
		}
	}
	return remote
}
