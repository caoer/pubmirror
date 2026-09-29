package scan

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// plantedKey is a generic-api-key shape assembled at run time, so this file
// carries no secret-shaped span of its own.
func plantedKey() string {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	var b strings.Builder
	for i := 0; i < 32; i++ {
		b.WriteByte(alphabet[(i*37+11)%len(alphabet)])
	}
	return "api" + "_key = \"" + b.String() + "\"\n"
}

func needGitleaks(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not installed")
	}
}

func TestGitleaksFinds(t *testing.T) {
	needGitleaks(t)
	files := []File{
		text("cfg/app.go", "package cfg\n\n"+plantedKey()),
		text("clean.go", "package clean\n"),
		// A scanned repository's own gitleaks files never configure the scan.
		text(".gitleaks.toml", "[allowlist]\npaths = ['''.*''']\n"),
		text(".gitleaksignore", "cfg/app.go:generic-api-key:3\n"),
	}
	got, err := Gitleaks{}.ScanTokens(files)
	if err != nil {
		t.Fatal(err)
	}
	want := Finding{"cfg/app.go", 3, RuleToken, "generic-api-key"}
	if !has(got, want) || len(got) != 1 {
		t.Fatalf("want exactly %v, got %v", want, got)
	}

	c := cfg(t)
	c.Tokens = Gitleaks{}
	c.Allow = []Allow{{RuleToken, "generic-api-key", "cfg/", "test"}}
	rep := run(t, c, files[:2])
	if len(rep.Findings) != 0 {
		t.Fatalf("allowed token still fired: %v", rep.Findings)
	}
}

func TestGitleaksClean(t *testing.T) {
	needGitleaks(t)
	got, err := Gitleaks{}.ScanTokens([]File{text("a.go", "package a\n")})
	if err != nil || len(got) != 0 {
		t.Fatalf("clean set: %v %v", got, err)
	}
}

func TestGitleaksMissing(t *testing.T) {
	_, err := Gitleaks{Bin: filepath.Join(t.TempDir(), "no-such-gitleaks")}.ScanTokens([]File{text("a", "x")})
	if !errors.Is(err, ErrScanner) || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing binary: %v", err)
	}
}

// A gitleaks that exits 1 without a report is a crash, never a finding.
func TestGitleaksCrash(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "gitleaks")
	os.WriteFile(bin, []byte("#!/bin/sh\necho 'FTL unable to load gitleaks config' >&2\nexit 1\n"), 0o700)
	_, err := Gitleaks{Bin: bin}.ScanTokens([]File{text("a", "x")})
	if !errors.Is(err, ErrScanner) || !strings.Contains(err.Error(), "no report written") || !strings.Contains(err.Error(), "unable to load") {
		t.Fatalf("crash: %v", err)
	}
	c := cfg(t)
	c.Tokens = Gitleaks{Bin: bin}
	if _, err := Scan(c, []File{text("a", "x")}, nil); !errors.Is(err, ErrScanner) {
		t.Fatalf("scan over a crashing gitleaks: %v", err)
	}
}

func TestPrescan(t *testing.T) {
	needGitleaks(t)
	a := text("x/k.go", plantedKey())
	b := text("x/k.go", "package x\n")
	ts, err := Gitleaks{}.Prescan([]File{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := ts.ScanTokens([]File{b}); len(got) != 0 {
		t.Fatalf("the clean version of a path must stay clean: %v", got)
	}
	if got, _ := ts.ScanTokens([]File{a}); len(got) != 1 {
		t.Fatalf("the planted version must fire once: %v", got)
	}
}
