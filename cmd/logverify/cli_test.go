package main

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syncplify/logverify/internal/corpus"
)

// buildTool compiles the command once per run. Exercising the real binary is the point: the exit codes are
// this tool's contract with whatever script is checking a fleet of machines, and they cannot be tested by
// calling the functions, which exit the process.
func buildTool(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "logverify")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build the tool: %v\n%s", err, out)
	}
	return bin
}

// run returns the exit code and the combined output.
func run(t *testing.T, bin string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return code, string(out)
}

// fixture lays down a chain with its identity, the way an operator would hand it over.
func fixture(t *testing.T, segments, lines int) *corpus.Chain {
	t.Helper()
	c, err := corpus.Build(corpus.BuildOptions{
		Dir: t.TempDir(), Seed: 21, Segments: segments, LinesPerSegment: lines,
		Symlink: true, WriteIdentity: true,
	})
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return c
}

func TestVerifyExitsZeroOnACleanChain(t *testing.T) {
	bin := buildTool(t)
	c := fixture(t, 3, 4)

	code, out := run(t, bin, "verify", "-dir", c.Dir, "-identity", c.Dir)
	if code != 0 {
		t.Fatalf("a clean chain exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "one unbroken chain") {
		t.Fatalf("the directory pass did not report the chain check:\n%s", out)
	}
}

func TestVerifyExitsOneWhenEvidenceIsAltered(t *testing.T) {
	bin := buildTool(t)
	c := fixture(t, 2, 4)

	lines, err := corpus.ReadLines(c.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	lines[2] = strings.Replace(lines[2], "segment 0 line 1", "segment 0 line !", 1)
	if err := corpus.WriteLines(c.Files[0], lines); err != nil {
		t.Fatal(err)
	}

	code, out := run(t, bin, "verify", "-dir", c.Dir, "-identity", c.Dir)
	if code != 1 {
		t.Fatalf("altered evidence exited %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(out, "FAIL") {
		t.Fatalf("the output does not say it failed:\n%s", out)
	}
}

// Exit 2 is a script visible distinction from exit 1: "this evidence is bad" and "I could not read this
// evidence" must never be conflated, because a monitor that treats them alike will eventually report a
// broken path as a clean log, or as a tampered one.
func TestBadArgumentsAndUnreadableEvidenceExitTwo(t *testing.T) {
	bin := buildTool(t)
	c := fixture(t, 1, 2)

	cases := [][]string{
		{"verify"},                // no target
		{"verify", "-dir", c.Dir}, // no key source
		{"verify", "-dir", filepath.Join(c.Dir, "nope"), "-identity", c.Dir}, // unreadable
		{"verify", "-dir", c.Dir, "-identity", t.TempDir()},                  // no identity there
		{"anchor", "-dir", c.Dir},                                            // missing required flags
	}
	for _, args := range cases {
		if code, out := run(t, bin, args...); code != 2 {
			t.Fatalf("%v exited %d, want 2:\n%s", args, code, out)
		}
	}
}

// The identity flag must never mint. Pointing it at the wrong directory is an ordinary mistake, and a tool
// that answers it by writing a key into that directory has modified evidence.
func TestTheToolNeverWritesIntoADirectoryItWasPointedAt(t *testing.T) {
	bin := buildTool(t)
	c := fixture(t, 1, 2)
	empty := t.TempDir()

	if code, _ := run(t, bin, "verify", "-dir", c.Dir, "-identity", empty); code != 2 {
		t.Fatal("pointing -identity at a directory with no identity should be an error")
	}
	entries, err := os.ReadDir(empty)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the tool wrote into the directory it was pointed at: %v", entries)
	}
}

func TestAnchorCheckPassesAndThenCatchesARewrite(t *testing.T) {
	bin := buildTool(t)
	c := fixture(t, 1, 3)

	anchorPath := filepath.Join(t.TempDir(), "anchor.json")
	if err := corpus.WriteAnchor(anchorPath, c.Anchors[0]); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(t.TempDir(), "producer.pub")
	if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(c.Producer.Pub)), 0o644); err != nil {
		t.Fatal(err)
	}

	code, out := run(t, bin, "anchor", "-dir", c.Dir, "-anchor", anchorPath, "-pubkey", "@"+pubPath, "-identity", c.Dir)
	if code != 0 {
		t.Fatalf("the honest log did not match its own anchor, exit %d:\n%s", code, out)
	}

	// The owner rewrites and re-MACs correctly. Same identity, same chain, same file number, same key.
	rewriter := corpus.New(21, c.Producer.Service, c.Producer.ChainID)
	var b strings.Builder
	b.WriteString(rewriter.StartSegment() + "\n")
	for i := 0; i < 3; i++ {
		b.WriteString(rewriter.Line("a tidier version of events") + "\n")
	}
	if err := os.WriteFile(c.Files[0], []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	// Local verification still passes, and should: that is the honest limit of a MAC.
	if code, out := run(t, bin, "verify", "-dir", c.Dir, "-identity", c.Dir); code != 0 {
		t.Fatalf("the re-MACed log should still pass local verification, exit %d:\n%s", code, out)
	}
	// The anchor is what catches it.
	code, out = run(t, bin, "anchor", "-dir", c.Dir, "-anchor", anchorPath, "-pubkey", "@"+pubPath, "-identity", c.Dir)
	if code != 1 {
		t.Fatalf("a rewritten log passed the anchor check, exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "altered since the anchor was signed") {
		t.Fatalf("the failure does not explain itself:\n%s", out)
	}
}
