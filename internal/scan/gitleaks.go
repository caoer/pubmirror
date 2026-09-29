package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Gitleaks runs the gitleaks binary over a set of files. The files are written
// to a temporary directory outside any checkout, one numbered subdirectory
// each, so a scanned repository's .gitleaks.toml or .gitleaksignore never
// configures the scan. The verdict is read from the report file: a crash and a
// finding both exit 1, and only the report tells them apart.
type Gitleaks struct {
	Bin string // empty: $PUBMIRROR_GITLEAKS, else gitleaks on PATH
}

// ErrScanner reports a token scanner that could not run.
var ErrScanner = errors.New("gitleaks could not run")

func (g Gitleaks) bin() (string, error) {
	b := g.Bin
	if b == "" {
		b = os.Getenv("PUBMIRROR_GITLEAKS")
	}
	if b == "" {
		b = "gitleaks"
	}
	p, err := exec.LookPath(b)
	if err != nil {
		return "", fmt.Errorf("%w: %s not found (install gitleaks or set PUBMIRROR_GITLEAKS)", ErrScanner, b)
	}
	return p, nil
}

type gitleaksFinding struct {
	RuleID    string
	File      string
	StartLine int
}

// ScanTokens implements TokenScanner.
func (g Gitleaks) ScanTokens(files []File) ([]Finding, error) {
	each, err := g.scanEach(files)
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, fs := range each {
		out = append(out, fs...)
	}
	return out, nil
}

// scanEach returns the findings of each file, by its index in files.
func (g Gitleaks) scanEach(files []File) ([][]Finding, error) {
	bin, err := g.bin()
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "pubmirror-gitleaks-")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrScanner, err)
	}
	defer os.RemoveAll(tmp)
	src := filepath.Join(tmp, "src")
	for i, f := range files {
		rel := filepath.FromSlash(f.Path)
		if !filepath.IsLocal(rel) {
			rel = "file"
		}
		p := filepath.Join(src, strconv.Itoa(i), rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrScanner, err)
		}
		if err := os.WriteFile(p, f.Data, 0o600); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrScanner, err)
		}
	}
	cfg := filepath.Join(tmp, "gitleaks.toml")
	if err := os.WriteFile(cfg, []byte("[extend]\nuseDefault = true\n"), 0o600); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrScanner, err)
	}
	report := filepath.Join(tmp, "report.json")
	cmd := exec.Command(bin, "dir", "--no-banner", "--redact", "--log-level", "error",
		"--config", cfg, "--report-format", "json", "--report-path", report,
		"--exit-code", "1", src)
	cmd.Dir = tmp
	cmd.Env = cleanEnv()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	runErr := cmd.Run()
	rc := 0
	if runErr != nil {
		var ee *exec.ExitError
		if !errors.As(runErr, &ee) {
			return nil, fmt.Errorf("%w: %v", ErrScanner, runErr)
		}
		rc = ee.ExitCode()
	}
	data, err := os.ReadFile(report)
	if err != nil {
		return nil, fmt.Errorf("%w: exit %d and no report written: %s", ErrScanner, rc, lastLine(stderr.String()))
	}
	var gf []gitleaksFinding
	if err := json.Unmarshal(data, &gf); err != nil {
		return nil, fmt.Errorf("%w: exit %d and an unreadable report: %v", ErrScanner, rc, err)
	}
	out := make([][]Finding, len(files))
	switch {
	case rc == 0 && len(gf) == 0:
		return out, nil
	case rc == 1 && len(gf) > 0:
	default:
		return nil, fmt.Errorf("%w: exit %d with %d findings in its report: %s", ErrScanner, rc, len(gf), lastLine(stderr.String()))
	}
	for _, f := range gf {
		rel, err := filepath.Rel(src, f.File)
		if err != nil {
			return nil, fmt.Errorf("%w: a finding outside the scanned set", ErrScanner)
		}
		idx, _, _ := strings.Cut(filepath.ToSlash(rel), "/")
		i, err := strconv.Atoi(idx)
		if err != nil || i < 0 || i >= len(files) {
			return nil, fmt.Errorf("%w: a finding outside the scanned set", ErrScanner)
		}
		out[i] = append(out[i], Finding{files[i].Path, f.StartLine, RuleToken, f.RuleID})
	}
	return out, nil
}

// Prescan runs g once over files and returns a TokenScanner that answers from
// those results, keyed by path and content, and runs g for anything else. A
// history check scans each commit on its own for attribution, and one gitleaks
// run serves them all.
func (g Gitleaks) Prescan(files []File) (TokenScanner, error) {
	each, err := g.scanEach(files)
	if err != nil {
		return nil, err
	}
	c := cachedTokens{found: map[string][]Finding{}, next: g}
	for i, f := range files {
		c.found[fileKey(f)] = each[i]
	}
	return c, nil
}

type cachedTokens struct {
	found map[string][]Finding // a key present with no findings was scanned clean
	next  TokenScanner
}

func (c cachedTokens) ScanTokens(files []File) ([]Finding, error) {
	var out []Finding
	var miss []File
	for _, f := range files {
		fs, ok := c.found[fileKey(f)]
		if !ok {
			miss = append(miss, f)
			continue
		}
		out = append(out, fs...)
	}
	if len(miss) > 0 {
		more, err := c.next.ScanTokens(miss)
		if err != nil {
			return nil, err
		}
		out = append(out, more...)
	}
	return out, nil
}

func fileKey(f File) string {
	sum := sha256.Sum256(f.Data)
	return f.Path + "\x00" + string(sum[:])
}

// cleanEnv drops variables that would reconfigure gitleaks or make its inner
// git calls noisy.
func cleanEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "GITLEAKS_CONFIG" || k == "GITLEAKS_CONFIG_TOML" || strings.HasPrefix(k, "GIT_TRACE") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if s == "" {
		return "no output"
	}
	return s
}
