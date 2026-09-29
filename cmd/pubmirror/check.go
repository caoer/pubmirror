package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/manifest"
	"github.com/caoer/pubmirror/internal/scan"
	"github.com/caoer/pubmirror/internal/stage"
)

func init() {
	register("check", "classify and scan the public set of a commit, the index, a directory or a range", func(args []string) int {
		return check(args, ".", os.Stdout, os.Stderr)
	})
}

const checkUsage = `usage:
  pubmirror check [--commit X]            the public set of commit X (default HEAD)
  pubmirror check --staged                the public set of the index
  pubmirror check --history A..B          every blob, message and identity A..B introduces (B alone: all history)
  pubmirror check --dir DIR [PATH...]     plain mode: the files under DIR (git's tracked and untracked-not-ignored
                                          files when DIR is a work tree), limited to PATHs when given
      --manifest FILE                     plain mode: classify and exempt with this manifest (default DIR/.pubmirror.toml)
      --author "Name <address>"           plain mode without a manifest: the one address the email rule passes
The denylist is $PUBMIRROR_DENYLIST, else ~/.config/pubmirror/denylist.txt.
exit codes: 0 clean, 1 findings, 2 could not run`

// checkInput is what one check judges.
type checkInput struct {
	what         string
	m            *manifest.Manifest // nil in plain mode without a manifest
	author       string
	files        []scan.File
	unclassified []string
}

func check(args []string, cwd string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("check", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	staged := fl.Bool("staged", false, "")
	commit := fl.String("commit", "", "")
	history := fl.String("history", "", "")
	dir := fl.String("dir", "", "")
	manifestFile := fl.String("manifest", "", "")
	author := fl.String("author", "", "")
	var dl *scan.Denylist // once loaded, every message is masked
	fail := func(format string, a ...any) int {
		fmt.Fprintln(stderr, dl.Mask(fmt.Sprintf("pubmirror check: "+format, a...)))
		return exitCannot
	}
	if err := fl.Parse(args); err != nil {
		fmt.Fprintln(stderr, checkUsage)
		return fail("%v", err)
	}
	modes := 0
	for _, on := range []bool{*staged, *commit != "", *history != "", *dir != ""} {
		if on {
			modes++
		}
	}
	if modes > 1 || fl.NArg() > 0 && *dir == "" || (*manifestFile != "" || *author != "") && *dir == "" {
		fmt.Fprintln(stderr, checkUsage)
		return fail("conflicting arguments")
	}

	// The denylist first: without it nothing can be judged.
	dlPath, err := scan.DenylistPath()
	if err != nil {
		return fail("%v", err)
	}
	if dl, err = scan.LoadDenylist(dlPath); err != nil {
		return fail("%v", err)
	}

	if *dir != "" {
		d := *dir
		if !filepath.IsAbs(d) {
			d = filepath.Join(cwd, d)
		}
		in, err := dirInput(d, *manifestFile, *author, fl.Args())
		if in != nil {
			in.what = "directory " + *dir
		}
		if err != nil {
			return fail("%v", err)
		}
		return judge(dl, in, stdout, stderr)
	}

	repo, err := gitobj.Open(cwd)
	if err != nil {
		return fail("%v", err)
	}
	if *history != "" {
		return checkHistory(repo, dl, *history, stdout, stderr)
	}
	var in *checkInput
	if *staged {
		in, err = indexInput(repo)
	} else {
		rev := *commit
		if rev == "" {
			rev = "HEAD"
		}
		in, err = commitInput(repo, rev)
	}
	if err != nil {
		return fail("%v", err)
	}
	return judge(dl, in, stdout, stderr)
}

func config(dl *scan.Denylist, m *manifest.Manifest, author string) scan.Config {
	c := scan.Config{Denylist: dl, Author: author, Tokens: scan.Gitleaks{}}
	if m != nil {
		c.Author = m.Public.Author
		c.Exact = m.Mode == manifest.ModeExact
		for _, a := range m.Allows {
			c.Allow = append(c.Allow, scan.Allow(a))
		}
		for _, f := range m.Fixtures {
			c.Fixtures = append(c.Fixtures, scan.Fixture(f))
		}
	}
	return c
}

func judge(dl *scan.Denylist, in *checkInput, stdout, stderr io.Writer) int {
	rep, err := scan.Scan(config(dl, in.m, in.author), in.files, nil)
	if err != nil {
		fmt.Fprintln(stderr, dl.Mask("pubmirror check: "+err.Error()))
		return exitCannot
	}
	return report(dl, in.what, len(in.files), in.unclassified, rep, stdout)
}

func report(dl *scan.Denylist, what string, nfiles int, unclassified []string, rep scan.Report, w io.Writer) int {
	for _, p := range unclassified {
		fmt.Fprintf(w, "%s: unclassified\n", dl.Mask(p))
	}
	perRule := map[string]int{}
	for _, f := range rep.Findings {
		fmt.Fprintln(w, f)
		perRule[f.Rule]++
	}
	for _, u := range rep.Allowed {
		a := u.Allow
		fmt.Fprintf(w, "allowed: %s %q in %s (%s): %d\n", a.Rule, dl.Mask(a.Match), dl.Mask(a.Path), dl.Mask(a.Reason), u.Count)
	}
	rules := make([]string, 0, len(perRule))
	for r := range perRule {
		rules = append(rules, r)
	}
	sort.Strings(rules)
	var counts []string
	for _, r := range rules {
		counts = append(counts, fmt.Sprintf("%s %d", r, perRule[r]))
	}
	summary := fmt.Sprintf("%s: %d files, %d findings", what, nfiles, len(rep.Findings))
	if len(counts) > 0 {
		summary += " (" + strings.Join(counts, ", ") + ")"
	}
	if len(unclassified) > 0 {
		summary += fmt.Sprintf(", %d unclassified", len(unclassified))
	}
	fmt.Fprintf(w, "pubmirror check: %s; denylist %s\n", dl.Mask(summary), dl.Hash())
	if len(rep.Findings) > 0 || len(unclassified) > 0 {
		return exitFindings
	}
	return exitClean
}

func commitInput(r *gitobj.Repo, rev string) (*checkInput, error) {
	res, err := stage.Build(r, rev)
	if err != nil {
		return nil, err
	}
	gf, err := r.Files(res.Public)
	if err != nil {
		return nil, err
	}
	return &checkInput{
		what: "commit " + short(res.Commit), m: res.Manifest,
		files: toScan(gf), unclassified: res.Unclassified,
	}, nil
}

func indexInput(r *gitobj.Repo) (*checkInput, error) {
	es, err := r.Index()
	if err != nil {
		return nil, err
	}
	var m *manifest.Manifest
	for _, e := range es {
		if e.Path != manifest.File {
			continue
		}
		fs, err := r.Files([]gitobj.Entry{e})
		if err != nil {
			return nil, err
		}
		if m, err = manifest.Parse(fs[0].Data); err != nil {
			return nil, fmt.Errorf("%s in the index: %w", manifest.File, err)
		}
	}
	if m == nil {
		return nil, fmt.Errorf("the index carries no %s", manifest.File)
	}
	in := &checkInput{what: "index", m: m}
	var public []gitobj.Entry
	for _, e := range es {
		switch m.Classify(e.Path).Class {
		case manifest.Public:
			public = append(public, e)
		case manifest.Unclassified:
			in.unclassified = append(in.unclassified, e.Path)
		}
	}
	gf, err := r.Files(public)
	if err != nil {
		return nil, err
	}
	in.files = toScan(gf)
	return in, nil
}

// dirInput reads files from a directory: plain mode, for trees that carry no
// manifest yet. In a git work tree it reads git's tracked and
// untracked-not-ignored files, so build output and ignored files stay out.
func dirInput(dir, manifestFile, author string, only []string) (*checkInput, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	in := &checkInput{what: "directory " + dir, author: author}
	if manifestFile == "" {
		if p := filepath.Join(dir, manifest.File); fileExists(p) {
			manifestFile = p
		}
	}
	if manifestFile != "" {
		if in.m, err = manifest.Load(manifestFile); err != nil {
			return nil, err
		}
	}
	paths, err := listDir(dir)
	if err != nil {
		return nil, err
	}
	var prefixes []string
	for _, p := range only {
		prefixes = append(prefixes, path.Clean(filepath.ToSlash(p)))
	}
	for _, p := range paths {
		if len(prefixes) > 0 && !underAny(p, prefixes) {
			continue
		}
		if in.m != nil {
			switch in.m.Classify(p).Class {
			case manifest.Internal:
				continue
			case manifest.Unclassified:
				in.unclassified = append(in.unclassified, p)
				continue
			}
		}
		full := filepath.Join(dir, filepath.FromSlash(p))
		fi, err := os.Lstat(full)
		if errors.Is(err, fs.ErrNotExist) {
			continue // tracked, deleted in the work tree
		}
		if err != nil {
			return nil, err
		}
		f := scan.File{Path: p, Mode: gitobj.ModeFile}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			t, err := os.Readlink(full)
			if err != nil {
				return nil, err
			}
			f.Mode, f.Data = gitobj.ModeSymlink, []byte(filepath.ToSlash(t))
		case fi.IsDir():
			continue // a submodule
		default:
			if fi.Mode()&0o111 != 0 {
				f.Mode = gitobj.ModeExecutable
			}
			if f.Data, err = os.ReadFile(full); err != nil {
				return nil, err
			}
		}
		in.files = append(in.files, f)
	}
	return in, nil
}

func listDir(dir string) ([]string, error) {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree")
	if out, err := cmd.Output(); err == nil && strings.TrimSpace(string(out)) == "true" {
		out, err := exec.Command("git", "-C", dir, "ls-files", "-z", "--cached", "--others", "--exclude-standard").Output()
		if err != nil {
			return nil, fmt.Errorf("git ls-files in %s: %w", dir, err)
		}
		seen := map[string]bool{}
		var ps []string
		for _, p := range strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00") {
			if p != "" && !seen[p] {
				seen[p] = true
				ps = append(ps, p)
			}
		}
		return ps, nil
	}
	var ps []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		ps = append(ps, filepath.ToSlash(rel))
		return nil
	})
	return ps, err
}

// checkHistory scans every blob, message and identity a range introduces,
// judged by the manifest at the range's end.
func checkHistory(r *gitobj.Repo, dl *scan.Denylist, spec string, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintln(stderr, dl.Mask("pubmirror check: "+err.Error()))
		return exitCannot
	}
	from, to, isRange := strings.Cut(spec, "..")
	if !isRange {
		from, to = "", spec
	}
	if to == "" {
		to = "HEAD"
	}
	data, ok, err := r.FileAt(to, manifest.File)
	if err != nil {
		return fail(err)
	}
	if !ok {
		return fail(fmt.Errorf("%s carries no %s", to, manifest.File))
	}
	m, err := manifest.Parse(data)
	if err != nil {
		return fail(fmt.Errorf("%s at %s: %w", manifest.File, to, err))
	}
	revs := []string{to}
	if from != "" {
		revs = append(revs, "^"+from)
	}
	return judgeHistory(r, dl, m, revs, nil, "history "+spec, stdout, stderr)
}

// judgeHistory scans every blob, message and identity the commits revs select
// introduce, plus extra (tag objects). One gitleaks run serves them all; each
// file is then judged on its own so a finding names the commit that introduced
// it, as rev:path.
func judgeHistory(r *gitobj.Repo, dl *scan.Denylist, m *manifest.Manifest, revs []string, extra []scan.Commit, label string, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintln(stderr, dl.Mask("pubmirror check: "+err.Error()))
		return exitCannot
	}
	gf, gc, err := r.Introduced(revs...)
	if err != nil {
		return fail(err)
	}
	var files []scan.File
	for _, f := range gf {
		if m.Classify(f.Path).Class != manifest.Internal {
			files = append(files, scan.File(f))
		}
	}
	var commits []scan.Commit
	for _, c := range gc {
		commits = append(commits, scan.Commit{
			ID:        c.Hash,
			Author:    fmt.Sprintf("%s <%s>", c.AuthorName, c.AuthorEmail),
			Committer: fmt.Sprintf("%s <%s>", c.CommitterName, c.CommitterEmail),
			Message:   c.Message,
		})
	}
	commits = append(commits, extra...)

	cfg := config(dl, m, "")
	tokens, err := scan.Gitleaks{}.Prescan(files)
	if err != nil {
		return fail(err)
	}
	var all scan.Report
	allowed := map[scan.Allow]int{}
	merge := func(rep scan.Report) {
		all.Findings = append(all.Findings, rep.Findings...)
		for _, u := range rep.Allowed {
			allowed[u.Allow] += u.Count
		}
	}
	for _, f := range files {
		c := cfg
		c.Tokens = tokens
		rep, err := scan.Scan(c, []scan.File{f}, nil)
		if err != nil {
			return fail(err)
		}
		if len(rep.Findings) > 0 {
			rev, err := introducedIn(r, f, revs)
			if err != nil {
				return fail(err)
			}
			for i := range rep.Findings {
				rep.Findings[i].Path = rev + ":" + rep.Findings[i].Path
			}
		}
		merge(rep)
	}
	if len(commits) > 0 {
		rep, err := scan.Scan(cfg, nil, commits)
		if err != nil {
			return fail(err)
		}
		merge(rep)
	}
	for _, a := range cfg.Allow {
		if n := allowed[a]; n > 0 {
			all.Allowed = append(all.Allowed, scan.AllowUse{Allow: a, Count: n})
			delete(allowed, a)
		}
	}
	what := fmt.Sprintf("%s (%d commits)", label, len(gc))
	return report(dl, what, len(files), nil, all, stdout)
}

// introducedIn names the oldest commit revs select that adds f's blob.
func introducedIn(r *gitobj.Repo, f scan.File, revs []string) (string, error) {
	oid, err := r.RunInput(bytes.NewReader(f.Data), "hash-object", "--stdin")
	if err != nil {
		return "", err
	}
	args := append([]string{"log", "--format=%H", "--reverse", "--find-object=" + strings.TrimSpace(string(oid))}, revs...)
	out, err := r.Run(append(args, "--")...)
	if err != nil {
		return "", err
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	if first == "" {
		return "?", nil
	}
	return short(first), nil
}

func toScan(gf []gitobj.File) []scan.File {
	out := make([]scan.File, len(gf))
	for i, f := range gf {
		out[i] = scan.File(f)
	}
	return out
}

func underAny(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		if pre == "." || p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
