// Package gitobj reads files, blobs and commits from git objects — a named
// commit or the index, never the working tree — and writes trees and commits.
// It runs the git binary.
package gitobj

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Git file modes.
const (
	ModeFile       = 0o100644
	ModeExecutable = 0o100755
	ModeSymlink    = 0o120000
	ModeGitlink    = 0o160000
)

// EmptyTree is the hash of the empty tree (SHA-1 object format).
const EmptyTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

// Entry is one path of a tree or the index. Object is the blob hash, or the
// commit hash for a gitlink.
type Entry struct {
	Path   string
	Mode   uint32
	Object string
}

// File is an entry with its content. Data is nil for a gitlink.
type File struct {
	Path string
	Mode uint32
	Data []byte
}

// Repo is a git repository: a working clone, a worktree or a bare repository.
type Repo struct {
	Dir string
	Env []string // extra environment for every git call
}

// Open returns the repository containing dir.
func Open(dir string) (*Repo, error) {
	r := &Repo{Dir: dir}
	if _, err := r.Run("rev-parse", "--git-dir"); err != nil {
		return nil, err
	}
	return r, nil
}

// Error is a failed git invocation.
type Error struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *Error) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		msg = e.Err.Error()
	}
	return fmt.Sprintf("git %s: %s", strings.Join(e.Args, " "), msg)
}

func (e *Error) Unwrap() error { return e.Err }

// SSHCommand is a GIT_SSH_COMMAND whose only identity is the key file at
// identity, or no key at all when identity is empty. It reads no ssh config
// file and asks no agent, so an IdentityFile the host's ~/.ssh/config sets for
// the remote host is never offered: a dev host authenticates as the image
// does. Host keys are checked against the default known-hosts files.
func SSHCommand(identity string) string {
	id := "none"
	if identity != "" {
		id = "'" + strings.ReplaceAll(identity, "'", `'\''`) + "'"
	}
	return "ssh -F /dev/null -o IdentityAgent=none -o IdentitiesOnly=yes -o IdentityFile=" + id + " -o StrictHostKeyChecking=yes"
}

func (r *Repo) cmd(args ...string) *exec.Cmd {
	c := exec.Command("git", append([]string{"-c", "core.quotepath=off"}, args...)...)
	c.Dir = r.Dir
	c.Env = append(os.Environ(), r.Env...)
	return c
}

// Run runs git with args and returns its standard output.
func (r *Repo) Run(args ...string) ([]byte, error) {
	return r.RunInput(nil, args...)
}

// RunInput runs git with stdin and returns its standard output.
func (r *Repo) RunInput(stdin io.Reader, args ...string) ([]byte, error) {
	return r.RunEnv(nil, stdin, args...)
}

// RunEnv runs git with extra environment and stdin.
func (r *Repo) RunEnv(env []string, stdin io.Reader, args ...string) ([]byte, error) {
	c := r.cmd(args...)
	c.Env = append(c.Env, env...)
	c.Stdin = stdin
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		return out.Bytes(), &Error{Args: args, Stderr: errb.String(), Err: err}
	}
	return out.Bytes(), nil
}

func (r *Repo) line(args ...string) (string, error) {
	out, err := r.Run(args...)
	return strings.TrimSpace(string(out)), err
}

// ResolveCommit returns the full hash of the commit rev names.
func (r *Repo) ResolveCommit(rev string) (string, error) {
	return r.line("rev-parse", "--verify", "--end-of-options", rev+"^{commit}")
}

// Exists reports whether rev resolves to a commit in this repository.
func (r *Repo) Exists(rev string) bool {
	_, err := r.ResolveCommit(rev)
	return err == nil
}

// GitDir returns the absolute git directory, and CommonDir the directory shared
// by every worktree.
func (r *Repo) GitDir() (string, error)    { return r.absPath("--git-dir") }
func (r *Repo) CommonDir() (string, error) { return r.absPath("--git-common-dir") }

func (r *Repo) absPath(flag string) (string, error) {
	p, err := r.line("rev-parse", flag)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(r.Dir, p)
	}
	return filepath.Clean(p), nil
}

// Tree lists every path of a commit or tree, recursively, in git order.
func (r *Repo) Tree(rev string) ([]Entry, error) {
	out, err := r.Run("ls-tree", "-r", "-z", "--full-tree", "--end-of-options", rev)
	if err != nil {
		return nil, err
	}
	var es []Entry
	for rec := range strings.SplitSeq(strings.TrimSuffix(string(out), "\x00"), "\x00") {
		if rec == "" {
			continue
		}
		// <mode> SP <type> SP <object> TAB <path>
		meta, p, ok := strings.Cut(rec, "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 {
			return nil, fmt.Errorf("gitobj: unexpected ls-tree record %q", rec)
		}
		mode, err := strconv.ParseUint(f[0], 8, 32)
		if err != nil {
			return nil, fmt.Errorf("gitobj: mode in %q: %w", rec, err)
		}
		es = append(es, Entry{Path: p, Mode: uint32(mode), Object: f[2]})
	}
	return es, nil
}

// Index lists the stage-0 entries of the index. A path with unresolved
// conflict stages is an error. GIT_INDEX_FILE is honored.
func (r *Repo) Index() ([]Entry, error) {
	out, err := r.Run("ls-files", "--stage", "-z")
	if err != nil {
		return nil, err
	}
	var es []Entry
	for rec := range strings.SplitSeq(strings.TrimSuffix(string(out), "\x00"), "\x00") {
		if rec == "" {
			continue
		}
		// <mode> SP <object> SP <stage> TAB <path>
		meta, p, ok := strings.Cut(rec, "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 {
			return nil, fmt.Errorf("gitobj: unexpected ls-files record %q", rec)
		}
		if f[2] != "0" {
			return nil, fmt.Errorf("gitobj: %s has an unresolved conflict", p)
		}
		mode, err := strconv.ParseUint(f[0], 8, 32)
		if err != nil {
			return nil, fmt.Errorf("gitobj: mode in %q: %w", rec, err)
		}
		es = append(es, Entry{Path: p, Mode: uint32(mode), Object: f[1]})
	}
	return es, nil
}

// Blobs reads the named objects' contents in one git process.
func (r *Repo) Blobs(objects []string) (map[string][]byte, error) {
	out := map[string][]byte{}
	var want []string
	for _, o := range objects {
		if _, dup := out[o]; !dup {
			out[o] = nil
			want = append(want, o)
		}
	}
	if len(want) == 0 {
		return out, nil
	}
	c := r.cmd("cat-file", "--batch")
	c.Stdin = strings.NewReader(strings.Join(want, "\n") + "\n")
	var errb bytes.Buffer
	c.Stderr = &errb
	stdout, err := c.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := c.Start(); err != nil {
		return nil, err
	}
	rd := bufio.NewReader(stdout)
	var readErr error
	for _, o := range want {
		hdr, err := rd.ReadString('\n')
		if err != nil {
			readErr = fmt.Errorf("gitobj: cat-file: %w", err)
			break
		}
		f := strings.Fields(hdr)
		if len(f) == 2 && f[1] == "missing" {
			readErr = fmt.Errorf("gitobj: object %s is missing", o)
			break
		}
		if len(f) != 3 || f[1] != "blob" {
			readErr = fmt.Errorf("gitobj: object %s is not a blob: %q", o, strings.TrimSpace(hdr))
			break
		}
		n, err := strconv.Atoi(f[2])
		if err != nil {
			readErr = fmt.Errorf("gitobj: cat-file header %q", hdr)
			break
		}
		data := make([]byte, n+1) // content and the trailing newline
		if _, err := io.ReadFull(rd, data); err != nil {
			readErr = fmt.Errorf("gitobj: reading %s: %w", o, err)
			break
		}
		out[o] = data[:n]
	}
	if readErr != nil {
		_ = c.Process.Kill()
		_ = c.Wait()
		return nil, readErr
	}
	if err := c.Wait(); err != nil {
		return nil, &Error{Args: []string{"cat-file", "--batch"}, Stderr: errb.String(), Err: err}
	}
	return out, nil
}

// Files reads the content of each entry. A gitlink gets nil Data.
func (r *Repo) Files(es []Entry) ([]File, error) {
	var objs []string
	for _, e := range es {
		if e.Mode != ModeGitlink {
			objs = append(objs, e.Object)
		}
	}
	blobs, err := r.Blobs(objs)
	if err != nil {
		return nil, err
	}
	fs := make([]File, len(es))
	for i, e := range es {
		fs[i] = File{Path: e.Path, Mode: e.Mode}
		if e.Mode != ModeGitlink {
			fs[i].Data = blobs[e.Object]
		}
	}
	return fs, nil
}

// FileAt reads one path of a commit. ok is false when the path is absent.
func (r *Repo) FileAt(rev, path string) (data []byte, ok bool, err error) {
	out, err := r.Run("ls-tree", "-z", "--full-tree", "--end-of-options", rev, "--", path)
	if err != nil {
		return nil, false, err
	}
	rec := strings.TrimSuffix(string(out), "\x00")
	if rec == "" {
		return nil, false, nil
	}
	meta, _, _ := strings.Cut(rec, "\t")
	f := strings.Fields(meta)
	if len(f) != 3 || f[1] != "blob" {
		return nil, false, fmt.Errorf("gitobj: %s at %s is not a file", path, rev)
	}
	blobs, err := r.Blobs([]string{f[2]})
	if err != nil {
		return nil, false, err
	}
	return blobs[f[2]], true, nil
}

// WriteTree writes a tree holding exactly the given entries and returns its
// hash. It uses a throwaway index; the repository's index is not touched.
func (r *Repo) WriteTree(es []Entry) (string, error) {
	if len(es) == 0 {
		return r.line("hash-object", "-t", "tree", "-w", os.DevNull)
	}
	tmp, err := os.MkdirTemp("", "pubmirror-index-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	env := []string{"GIT_INDEX_FILE=" + filepath.Join(tmp, "index")}
	var in bytes.Buffer
	for _, e := range es {
		fmt.Fprintf(&in, "%06o %s\t%s\x00", e.Mode, e.Object, e.Path)
	}
	if _, err := r.RunEnv(env, &in, "update-index", "--add", "-z", "--index-info"); err != nil {
		return "", err
	}
	out, err := r.RunEnv(env, nil, "write-tree")
	return strings.TrimSpace(string(out)), err
}

// Commit is a commit's metadata.
type Commit struct {
	Hash           string
	Tree           string
	Parents        []string
	AuthorName     string
	AuthorEmail    string
	CommitterName  string
	CommitterEmail string
	Message        string
}

// ReadCommit reads one commit's metadata and full message.
func (r *Repo) ReadCommit(rev string) (*Commit, error) {
	out, err := r.Run("show", "-s", "--no-show-signature", "--format=%H%x00%T%x00%P%x00%an%x00%ae%x00%cn%x00%ce%x00%B", "--end-of-options", rev)
	if err != nil {
		return nil, err
	}
	f := strings.SplitN(string(out), "\x00", 8)
	if len(f) != 8 {
		return nil, fmt.Errorf("gitobj: unexpected commit format for %s", rev)
	}
	return &Commit{
		Hash: f[0], Tree: f[1], Parents: strings.Fields(f[2]),
		AuthorName: f[3], AuthorEmail: f[4], CommitterName: f[5], CommitterEmail: f[6],
		Message: strings.TrimRight(f[7], "\n"),
	}, nil
}

// Tag is one annotated tag object.
type Tag struct {
	Hash       string
	Object     string // what it tags
	Type       string // the tagged object's type: commit, tag, tree or blob
	Name       string
	TaggerName string
	TaggerMail string
	Message    string
}

// Type returns an object's type: commit, tag, tree or blob.
func (r *Repo) Type(oid string) (string, error) {
	return r.line("cat-file", "-t", oid)
}

// ReadTag reads an annotated tag object.
func (r *Repo) ReadTag(oid string) (*Tag, error) {
	out, err := r.Run("cat-file", "tag", oid)
	if err != nil {
		return nil, err
	}
	head, msg, _ := strings.Cut(string(out), "\n\n")
	t := &Tag{Hash: oid, Message: strings.TrimRight(msg, "\n")}
	for line := range strings.SplitSeq(head, "\n") {
		k, v, _ := strings.Cut(line, " ")
		switch k {
		case "object":
			t.Object = v
		case "type":
			t.Type = v
		case "tag":
			t.Name = v
		case "tagger":
			// Name <address> <seconds> <zone>
			if lt, gt := strings.Index(v, "<"), strings.LastIndex(v, ">"); lt >= 0 && gt > lt {
				t.TaggerName = strings.TrimSpace(v[:lt])
				t.TaggerMail = v[lt+1 : gt]
			}
		}
	}
	return t, nil
}

// RevList lists the commits of a range expression, newest first.
func (r *Repo) RevList(args ...string) ([]string, error) {
	out, err := r.Run(append([]string{"rev-list"}, args...)...)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// IsAncestor reports whether a is an ancestor of b (or equal to it).
func (r *Repo) IsAncestor(a, b string) (bool, error) {
	_, err := r.Run("merge-base", "--is-ancestor", a, b)
	if err == nil {
		return true, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

// Signature is a commit identity with a date in git's internal format
// ("<unix seconds> +0000").
type Signature struct {
	Name, Email, Date string
}

// CommitTree writes a commit object and returns its hash.
func (r *Repo) CommitTree(tree string, parents []string, message string, author, committer Signature) (string, error) {
	args := []string{"commit-tree", "--no-gpg-sign", tree}
	for _, p := range parents {
		args = append(args, "-p", p)
	}
	env := []string{
		"GIT_AUTHOR_NAME=" + author.Name, "GIT_AUTHOR_EMAIL=" + author.Email, "GIT_AUTHOR_DATE=" + author.Date,
		"GIT_COMMITTER_NAME=" + committer.Name, "GIT_COMMITTER_EMAIL=" + committer.Email, "GIT_COMMITTER_DATE=" + committer.Date,
	}
	out, err := r.RunEnv(env, strings.NewReader(message), args...)
	return strings.TrimSpace(string(out)), err
}

// Range returns every file the commits of from..to introduce — each blob a
// commit adds or modifies, compared with every parent, at each path it lands
// on — and those commits, newest first. from "" means all history of to.
// Gitlinks are skipped.
func (r *Repo) Range(from, to string) ([]File, []*Commit, error) {
	spec := []string{to}
	if from != "" {
		spec = []string{"^" + from, to}
	}
	return r.Introduced(spec...)
}

// Introduced is Range over the commits a rev-list expression selects, such as
// {tip, "--not", "--all"}: the commits a push brings into a repository.
func (r *Repo) Introduced(revs ...string) ([]File, []*Commit, error) {
	ids, err := r.RevList(append(revs, "--")...)
	if err != nil {
		return nil, nil, err
	}
	var es []Entry
	seen := map[Entry]bool{}
	var commits []*Commit
	for _, id := range ids {
		c, err := r.ReadCommit(id)
		if err != nil {
			return nil, nil, err
		}
		commits = append(commits, c)
		out, err := r.Run("diff-tree", "-r", "-z", "-m", "--root", "--no-renames", "--no-commit-id", "--no-abbrev", id)
		if err != nil {
			return nil, nil, err
		}
		f := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
		for i := 0; i+1 < len(f); i += 2 {
			// :<old mode> <new mode> <old object> <new object> <status>, then the path
			meta := strings.Fields(strings.TrimPrefix(f[i], ":"))
			if len(meta) != 5 {
				return nil, nil, fmt.Errorf("gitobj: unexpected diff-tree record %q", f[i])
			}
			if meta[4] == "D" {
				continue
			}
			mode, err := strconv.ParseUint(meta[1], 8, 32)
			if err != nil {
				return nil, nil, fmt.Errorf("gitobj: mode in %q: %w", f[i], err)
			}
			e := Entry{Path: f[i+1], Mode: uint32(mode), Object: meta[3]}
			if e.Mode == ModeGitlink || seen[e] {
				continue
			}
			seen[e] = true
			es = append(es, e)
		}
	}
	files, err := r.Files(es)
	if err != nil {
		return nil, nil, err
	}
	return files, commits, nil
}

// RemoteRef returns the commit a remote's ref points to, or "" when the remote
// has no such ref.
func (r *Repo) RemoteRef(remote, ref string) (string, error) {
	out, err := r.Run("ls-remote", "--end-of-options", remote, ref)
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		if hash, name, ok := strings.Cut(line, "\t"); ok && name == ref {
			return hash, nil
		}
	}
	return "", nil
}

// Fetch fetches one ref of a remote into the local ref dst, overwriting it,
// without tags, and returns the fetched commit.
func (r *Repo) Fetch(remote, ref, dst string) (string, error) {
	if _, err := r.Run("fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--end-of-options", remote, "+"+ref+":"+dst); err != nil {
		return "", err
	}
	return r.ResolveCommit(dst)
}

// Unshallow completes the history of a shallow clone from remote; a full
// clone is left alone. Ancestry checks need the whole history.
func (r *Repo) Unshallow(remote string) error {
	s, err := r.line("rev-parse", "--is-shallow-repository")
	if err != nil || s != "true" {
		return err
	}
	_, err = r.Run("fetch", "--quiet", "--no-tags", "--unshallow", "--end-of-options", remote)
	return err
}

// Change is one path that differs between two trees, with a status letter:
// A added, D deleted, M modified, T type changed.
type Change struct {
	Status byte
	Path   string
}

// Diff compares two trees without rename detection.
func (r *Repo) Diff(from, to string) ([]Change, error) {
	out, err := r.Run("diff-tree", "-r", "-z", "--no-renames", "--name-status", from, to)
	if err != nil {
		return nil, err
	}
	f := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	var cs []Change
	for i := 0; i+1 < len(f); i += 2 {
		cs = append(cs, Change{Status: f[i][0], Path: f[i+1]})
	}
	return cs, nil
}
