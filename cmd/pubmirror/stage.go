package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/caoer/pubmirror/internal/gitobj"
	"github.com/caoer/pubmirror/internal/publish"
	"github.com/caoer/pubmirror/internal/scan"
	"github.com/caoer/pubmirror/internal/stage"
)

func init() {
	register("stage", "build the public tree of a commit and print its approval X:H:D", runStage)
}

var canonicalTrailer = regexp.MustCompile(`(?m)^Canonical-Commit: ([0-9a-f]{40})$`)

func runStage(args []string) int {
	fs := flag.NewFlagSet("stage", flag.ContinueOnError)
	commit := fs.String("commit", "", "the canonical commit X to stage (required)")
	out := fs.String("out", "", "write the public files into this directory for review")
	repoDir := fs.String("repo", ".", "the canonical repository")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *commit == "" {
		fmt.Fprintln(os.Stderr, "usage: pubmirror stage --commit X [--out DIR] [--repo DIR]")
		return exitCannot
	}
	r, err := gitobj.Open(*repoDir)
	if err != nil {
		return exitFor("stage", err)
	}
	st, err := stage.Build(r, *commit)
	if err != nil {
		return exitFor("stage", err)
	}
	if len(st.Unclassified) > 0 {
		fmt.Printf("%d unclassified paths at %s:\n", len(st.Unclassified), st.Commit)
		for _, p := range st.Unclassified {
			fmt.Println("  " + p)
		}
		return exitFindings
	}
	dl, err := coreDenylist()
	if err != nil {
		return exitFor("stage", err)
	}
	files, err := st.Files(r)
	if err != nil {
		return exitFor("stage", err)
	}
	sfiles := make([]scan.File, len(files))
	for i, f := range files {
		sfiles[i] = scan.File(f)
	}
	rep, err := scan.Scan(publish.ScanConfig(st.Manifest, dl, scan.Gitleaks{}), sfiles, nil)
	if err != nil {
		return exitFor("stage", err)
	}
	for _, u := range rep.Allowed {
		fmt.Printf("allowed: %s %q in %s (%s), %d times\n", u.Allow.Rule, u.Allow.Match, u.Allow.Path, u.Allow.Reason, u.Count)
	}
	if len(rep.Findings) > 0 {
		fmt.Printf("%d findings in the public tree of %s:\n", len(rep.Findings), st.Commit)
		for _, f := range rep.Findings {
			fmt.Println("  " + f.String())
		}
		return exitFindings
	}

	fmt.Printf("commit    %s\ntree      %s\ndenylist  %s\nmode      %s\npublic    %d files, internal %d\n",
		st.Commit, st.Tree, dl.Hash(), st.Manifest.Mode, len(st.Public), len(st.Internal))
	lastTree := gitobj.EmptyTree
	switch tip, err := r.RemoteRef(st.Manifest.Public.Remote, "refs/heads/main"); {
	case err != nil:
		fmt.Printf("last published: unknown, %v\n", err)
	case tip == "":
		fmt.Println("last published: none, the public repository has no main")
	default:
		if _, err := r.Fetch(st.Manifest.Public.Remote, "refs/heads/main", "refs/pubmirror/public-main"); err != nil {
			fmt.Printf("last published: unknown, %v\n", err)
			break
		}
		c, err := r.ReadCommit(tip)
		if err != nil {
			return exitFor("stage", err)
		}
		carried := "no Canonical-Commit"
		if ms := canonicalTrailer.FindAllStringSubmatch(c.Message, -1); len(ms) > 0 {
			carried = "canonical " + ms[len(ms)-1][1]
		}
		fmt.Printf("last published: %s (%s)\n", tip, carried)
		lastTree = c.Tree
	}
	changes, err := r.Diff(lastTree, st.Tree)
	if err != nil {
		return exitFor("stage", err)
	}
	fmt.Printf("changes against the last published tree: %d\n", len(changes))
	for _, c := range changes {
		fmt.Printf("  %c %s\n", c.Status, c.Path)
	}
	if *out != "" {
		if err := stage.Export(r, st, *out); err != nil {
			return exitFor("stage", err)
		}
		fmt.Printf("public files written to %s\n", *out)
	}
	fmt.Printf("approve   %s:%s:%s\n", st.Commit, st.Tree, dl.Hash())
	return exitClean
}
