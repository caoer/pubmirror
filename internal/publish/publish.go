// Package publish writes an approved canonical commit to the public
// repository's main, behind the publisher guards of DESIGN.md.
package publish

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/manifest"
	"github.com/caoer/pubmirror/internal/scan"
	"github.com/caoer/pubmirror/internal/stage"
)

// Local refs the publisher fetches into. They are never pushed.
const (
	canonicalRef = "refs/pubmirror/canonical-main"
	publicRef    = "refs/pubmirror/public-main"
	mainRef      = "refs/heads/main"
)

// Approval is the tuple X:H:D.
type Approval struct {
	Commit   string // X, 40 hex
	Tree     string // H, 40 hex
	Denylist string // D, 16 hex
}

var approvalRE = regexp.MustCompile(`^([0-9a-f]{40}):([0-9a-f]{40}):([0-9a-f]{16})$`)

// ParseApproval parses "X:H:D".
func ParseApproval(s string) (Approval, error) {
	m := approvalRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Approval{}, fmt.Errorf("approval %q is not X:H:D (40, 40 and 16 lower-case hex digits)", s)
	}
	return Approval{m[1], m[2], m[3]}, nil
}

func (a Approval) String() string { return a.Commit + ":" + a.Tree + ":" + a.Denylist }

// Refusal is a guard that refused: the publisher ran and said no (exit 1).
// Any other error means it could not run (exit 2).
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }

func refuse(format string, a ...any) error { return &Refusal{fmt.Sprintf(format, a...)} }

// Outcome of a publish that did not refuse.
type Outcome int

const (
	Published  Outcome = iota // the public main now carries X
	UpToDate                  // the public main already carried X
	Superseded                // the public main carries a descendant of X
)

func (o Outcome) String() string {
	return [...]string{"published", "up to date", "superseded"}[o]
}

// Result of a publish.
type Result struct {
	Outcome   Outcome
	PublicTip string // the public main after the run
	Canonical string // the canonical commit PublicTip carries
}

// Options configure one publish.
type Options struct {
	Repo      *gitobj.Repo // a clone of the canonical repository
	Canonical string       // remote name or URL of the canonical repository
	Public    string       // the public remote; empty means the manifest's
	PublicEnv []string     // extra environment for the git calls that reach the public remote: its credentials
	Approval  Approval
	Summary   string // optional summary line of a snapshot commit
	Denylist  *scan.Denylist
	Tokens    scan.TokenScanner
	Now       func() time.Time
	Log       io.Writer

	// beforePush runs between building the commit and pushing it; tests
	// use it to make another run win the race.
	beforePush func()
}

const maxAttempts = 5

// Run executes the publisher guards and the push.
func Run(o Options) (*Result, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	r, a := o.Repo, o.Approval
	if o.Denylist == nil {
		return nil, scan.ErrNoDenylist
	}

	// X is on a fresh fetch of canonical main.
	if err := r.Unshallow(o.Canonical); err != nil {
		return nil, fmt.Errorf("completing a shallow clone: %w", err)
	}
	canonMain, err := r.Fetch(o.Canonical, mainRef, canonicalRef)
	if err != nil {
		return nil, fmt.Errorf("fetching canonical main: %w", err)
	}
	if !r.Exists(a.Commit) {
		return nil, refuse("not on main: %s is not in the canonical repository", a.Commit)
	}
	if on, err := r.IsAncestor(a.Commit, canonMain); err != nil {
		return nil, err
	} else if !on {
		return nil, refuse("not on main: %s is not reachable from canonical main %s", a.Commit, canonMain)
	}

	// The tree staged from X hashes to H, the denylist to D.
	st, err := stage.Build(r, a.Commit)
	if err != nil {
		return nil, err
	}
	m := st.Manifest
	if len(st.Unclassified) > 0 {
		return nil, refuse("%d unclassified paths at %s: %s", len(st.Unclassified), a.Commit, strings.Join(st.Unclassified, ", "))
	}
	if st.Tree != a.Tree {
		return nil, refuse("tree mismatch: %s stages to %s, the approval names %s", a.Commit, st.Tree, a.Tree)
	}
	if d := o.Denylist.Hash(); d != a.Denylist {
		return nil, refuse("denylist mismatch: the loaded denylist hashes to %s, the approval names %s", d, a.Denylist)
	}
	public := o.Public
	if public == "" {
		public = m.Public.Remote
	}
	// The public remote's credentials reach no other remote.
	pubRepo := &gitobj.Repo{Dir: r.Dir, Env: append(r.Env[:len(r.Env):len(r.Env)], o.PublicEnv...)}
	p := &publisher{Options: o, st: st, m: m, public: public, pubRepo: pubRepo, canonMain: canonMain}

	tip, err := p.fetchPublic()
	if err != nil {
		return nil, err
	}
	res, err := p.decide(tip)
	if err != nil || res != nil {
		return res, err
	}
	if err := p.scan(tip); err != nil {
		return nil, err
	}
	msg := p.message()
	for attempt := 1; ; attempt++ {
		head := a.Commit
		if m.Mode == manifest.ModeSnapshot {
			if head, err = p.commit(tip, msg); err != nil {
				return nil, err
			}
		}
		if o.beforePush != nil {
			o.beforePush()
		}
		rejected, err := p.push(head)
		if err != nil {
			return nil, err
		}
		if !rejected {
			fmt.Fprintf(o.Log, "published %s as %s on %s main\n", a.Commit, head, public)
			return &Result{Outcome: Published, PublicTip: head, Canonical: a.Commit}, nil
		}
		fmt.Fprintf(o.Log, "push rejected (attempt %d): public main moved; refetching\n", attempt)
		if tip, err = p.fetchPublic(); err != nil {
			return nil, err
		}
		if res, err = p.decide(tip); err != nil || res != nil {
			return res, err
		}
		if attempt == maxAttempts {
			return nil, fmt.Errorf("public main kept moving: %d pushes rejected", attempt)
		}
	}
}

type publisher struct {
	Options
	st        *stage.Result
	m         *manifest.Manifest
	public    string
	pubRepo   *gitobj.Repo // Repo, with the public remote's credentials
	canonMain string
}

// fetchPublic returns the public main, fetched into publicRef, or "" when the
// public repository has no main.
func (p *publisher) fetchPublic() (string, error) {
	tip, err := p.pubRepo.RemoteRef(p.public, mainRef)
	if err != nil {
		return "", fmt.Errorf("reading the public main: %w", err)
	}
	if tip == "" {
		return "", nil
	}
	if tip, err = p.pubRepo.Fetch(p.public, mainRef, publicRef); err != nil {
		return "", fmt.Errorf("fetching the public main: %w", err)
	}
	return tip, nil
}

var trailerRE = regexp.MustCompile(`(?m)^Canonical-Commit: ([0-9a-f]{40})$`)

// canonicalOf returns the canonical commit a public commit carries, or "".
func (p *publisher) canonicalOf(tip string) (string, error) {
	if p.m.Mode == manifest.ModeExact {
		return tip, nil
	}
	c, err := p.Repo.ReadCommit(tip)
	if err != nil {
		return "", err
	}
	ms := trailerRE.FindAllStringSubmatch(c.Message, -1)
	if len(ms) == 0 {
		return "", nil
	}
	return ms[len(ms)-1][1], nil
}

// decide compares the public tip's canonical commit with X. A nil result and
// nil error means: publish on top of tip.
func (p *publisher) decide(tip string) (*Result, error) {
	x := p.Approval.Commit
	if tip == "" {
		return nil, nil
	}
	c, err := p.canonicalOf(tip)
	if err != nil {
		return nil, err
	}
	alarm := func(why string) error {
		return refuse("public main %s %s: the public side was written outside the publisher; repairing it takes a force push, which is the owner's call", tip, why)
	}
	if c == "" {
		return nil, alarm("carries no Canonical-Commit")
	}
	if !p.Repo.Exists(c) {
		return nil, alarm("carries canonical commit " + c + ", which the canonical repository does not have")
	}
	if on, err := p.Repo.IsAncestor(c, p.canonMain); err != nil {
		return nil, err
	} else if !on {
		return nil, alarm("carries canonical commit " + c + ", which is not on canonical main")
	}
	if c == x {
		fmt.Fprintf(p.Log, "nothing to do: public main %s already carries %s\n", tip, x)
		return &Result{Outcome: UpToDate, PublicTip: tip, Canonical: c}, nil
	}
	if newer, err := p.Repo.IsAncestor(x, c); err != nil {
		return nil, err
	} else if newer {
		fmt.Fprintf(p.Log, "superseded: public main %s carries %s, a descendant of %s\n", tip, c, x)
		return &Result{Outcome: Superseded, PublicTip: tip, Canonical: c}, nil
	}
	if older, err := p.Repo.IsAncestor(c, x); err != nil {
		return nil, err
	} else if !older {
		return nil, refuse("public main %s carries %s, which is neither an ancestor nor a descendant of %s; approve a commit that contains it", tip, c, x)
	}
	return nil, nil
}

// scan runs every rule over the public tree, the snapshot message, and in
// exact mode every blob and commit since the last publish.
func (p *publisher) scan(tip string) error {
	files, err := p.st.Files(p.Repo)
	if err != nil {
		return err
	}
	var commits []*gitobj.Commit
	if p.m.Mode == manifest.ModeExact {
		hist, cs, err := p.Repo.Range(tip, p.Approval.Commit)
		if err != nil {
			return err
		}
		files, commits = append(files, hist...), cs
	}
	sfiles := make([]scan.File, len(files))
	for i, f := range files {
		sfiles[i] = scan.File(f)
	}
	var scommits []scan.Commit
	if p.m.Mode == manifest.ModeSnapshot {
		scommits = append(scommits, scan.Commit{ID: "publish message", Author: p.m.Public.Author, Committer: p.m.Public.Author, Message: p.message()})
	}
	for _, c := range commits {
		scommits = append(scommits, scan.Commit{
			ID:        c.Hash,
			Author:    c.AuthorName + " <" + c.AuthorEmail + ">",
			Committer: c.CommitterName + " <" + c.CommitterEmail + ">",
			Message:   c.Message,
		})
	}
	rep, err := scan.Scan(ScanConfig(p.m, p.Denylist, p.Tokens), sfiles, scommits)
	if err != nil {
		return err
	}
	for _, u := range rep.Allowed {
		fmt.Fprintf(p.Log, "allowed: %s %q in %s (%s), %d times\n", u.Allow.Rule, u.Allow.Match, u.Allow.Path, u.Allow.Reason, u.Count)
	}
	if len(rep.Findings) > 0 {
		lines := make([]string, len(rep.Findings))
		for i, f := range rep.Findings {
			lines[i] = f.String()
		}
		return refuse("%d findings:\n%s", len(rep.Findings), strings.Join(lines, "\n"))
	}
	return nil
}

// ScanConfig is the scanner configuration a manifest implies.
func ScanConfig(m *manifest.Manifest, d *scan.Denylist, tokens scan.TokenScanner) scan.Config {
	cfg := scan.Config{Denylist: d, Author: m.Public.Author, Exact: m.Mode == manifest.ModeExact, Tokens: tokens}
	for _, a := range m.Allows {
		cfg.Allow = append(cfg.Allow, scan.Allow(a))
	}
	for _, f := range m.Fixtures {
		cfg.Fixtures = append(cfg.Fixtures, scan.Fixture(f))
	}
	return cfg
}

// message is the snapshot commit message.
func (p *publisher) message() string {
	x := p.Approval.Commit
	msg := "publish " + x[:12] + "\n\n"
	if s := strings.TrimSpace(p.Summary); s != "" {
		msg += s + "\n\n"
	}
	return msg + "Canonical-Commit: " + x + "\n"
}

// commit writes the snapshot commit on top of parent.
func (p *publisher) commit(parent, msg string) (string, error) {
	name, addr, err := p.m.AuthorParts()
	if err != nil {
		return "", err
	}
	sig := gitobj.Signature{Name: name, Email: addr, Date: strconv.FormatInt(p.Now().UTC().Unix(), 10) + " +0000"}
	var parents []string
	if parent != "" {
		parents = []string{parent}
	}
	return p.Repo.CommitTree(p.st.Tree, parents, msg, sig, sig)
}

// push writes head to the public main, never forced and never any other ref.
// rejected reports a push the remote refused because main moved.
func (p *publisher) push(head string) (rejected bool, err error) {
	out, err := p.pubRepo.Run("push", "--porcelain", "--no-verify", "--no-follow-tags", "--end-of-options", p.public, head+":"+mainRef)
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.HasPrefix(line, "!\t") && strings.Contains(line, ":"+mainRef+"\t") {
			if strings.Contains(line, "fetch first") || strings.Contains(line, "non-fast-forward") {
				return true, nil
			}
			return false, fmt.Errorf("push to %s refused: %s", p.public, strings.TrimSpace(line))
		}
	}
	if err != nil {
		return false, fmt.Errorf("push to %s: %w", p.public, err)
	}
	return false, nil
}

// IsRefusal reports whether err is a guard's refusal (exit 1).
func IsRefusal(err error) bool {
	var r *Refusal
	return errors.As(err, &r)
}
