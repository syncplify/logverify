package chain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syncplify/logverify/internal/corpus"
)

// build lays down a chain and returns it along with a key function derived the way a verifier would.
func build(t *testing.T, o corpus.BuildOptions) (*corpus.Chain, KeyFunc) {
	t.Helper()
	o.Dir = t.TempDir()
	c, err := corpus.Build(o)
	if err != nil {
		t.Fatalf("build the fixture: %v", err)
	}
	return c, func(chainID string, seq uint64) []byte {
		p := corpus.New(o.Seed, c.Producer.Service, chainID)
		for p.Seq() < seq {
			p.Rotate()
		}
		return p.ChainKey()
	}
}

func TestACleanSingleFileChainVerifies(t *testing.T) {
	c, keyFor := build(t, corpus.BuildOptions{Segments: 1, LinesPerSegment: 6})

	res, err := VerifyFile(c.Files[0], keyFor, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a clean file did not verify: %v", res.Issues)
	}
	if res.LineCount != 7 { // the start line counts
		t.Fatalf("counted %d lines, want 7", res.LineCount)
	}
	if len(res.Segments) != 1 || res.Segments[0].ChainV != "2" {
		t.Fatalf("segments: %+v", res.Segments)
	}
}

func TestACleanMultiFileChainVerifiesIncludingCompressedSegments(t *testing.T) {
	c, keyFor := build(t, corpus.BuildOptions{
		Segments: 4, LinesPerSegment: 3,
		GzipSegments: map[int]bool{1: true, 2: true},
		Symlink:      true,
	})

	res, err := VerifyDir(c.Dir, keyFor, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a clean chain did not verify: %v", res.Issues)
	}
	if len(res.Segments) != 4 {
		t.Fatalf("found %d segments, want 4", len(res.Segments))
	}
}

// The live symlink that every real producer keeps. Following it reads the current segment twice and reports
// a chain that restarts in the middle of its own run: a false alarm on a healthy log, which is the fastest
// way to teach people to ignore the tool.
func TestTheLiveSymlinkIsNotReadTwice(t *testing.T) {
	c, keyFor := build(t, corpus.BuildOptions{Segments: 2, LinesPerSegment: 2, Symlink: true})

	if _, err := os.Lstat(filepath.Join(c.Dir, "sc-test.jsonl")); err != nil {
		t.Fatalf("the fixture has no symlink to skip: %v", err)
	}
	res, err := VerifyDir(c.Dir, keyFor, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("the live symlink produced a false alarm: %v", res.Issues)
	}
	if len(res.Segments) != 2 {
		t.Fatalf("the symlinked file was counted again: %d segments", len(res.Segments))
	}
}

func TestAnEditedLineIsCaught(t *testing.T) {
	c, keyFor := build(t, corpus.BuildOptions{Segments: 1, LinesPerSegment: 6})

	lines, err := corpus.ReadLines(c.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	lines[3] = strings.Replace(lines[3], "segment 0 line 2", "segment 0 line X", 1)
	if err := corpus.WriteLines(c.Files[0], lines); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyFile(c.Files[0], keyFor, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("an edited line verified")
	}
	// One edited line implicates one line. A verifier that cascaded would condemn every line after it and
	// tell an investigator nothing about where to look.
	if len(res.Issues) != 1 || res.Issues[0].Line != 4 {
		t.Fatalf("expected exactly one issue on line 4, got %v", res.Issues)
	}
}

func TestADeletedLineIsCaught(t *testing.T) {
	c, keyFor := build(t, corpus.BuildOptions{Segments: 1, LinesPerSegment: 6})

	lines, err := corpus.ReadLines(c.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := corpus.WriteLines(c.Files[0], append(lines[:3], lines[4:]...)); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyFile(c.Files[0], keyFor, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a deleted line went unnoticed")
	}
}

// The cheapest attack on a log, and the one that a per file check cannot see: every remaining file verifies
// perfectly and the set is simply missing history.
func TestAnEntireDeletedSegmentIsCaught(t *testing.T) {
	c, keyFor := build(t, corpus.BuildOptions{Segments: 4, LinesPerSegment: 3})

	if err := os.Remove(c.Files[2]); err != nil {
		t.Fatal(err)
	}

	// Each surviving file is still individually perfect, which is exactly why the set level check exists.
	for _, f := range []string{c.Files[0], c.Files[1], c.Files[3]} {
		res, err := VerifyFile(f, keyFor, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if !res.OK() {
			t.Fatalf("%s should still verify on its own: %v", filepath.Base(f), res.Issues)
		}
	}

	res, err := VerifyDir(c.Dir, keyFor, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a whole deleted segment went unnoticed by the directory pass")
	}
	joined := issueText(res.Issues)
	if !strings.Contains(joined, "missing") {
		t.Fatalf("the report does not say a file is missing: %s", joined)
	}
}

// Stopping at the first violation must never manufacture a SECOND, worse finding.
//
// A partly replayed segment has no closing MAC to compare against its successor's claim. If the cross file
// checks run anyway, that segment is missing or incomplete in the set, so one edited line reports as a
// deleted file and an investigator goes hunting for a deletion that never happened. A false accusation that
// evidence was destroyed is the worst thing this tool could produce, and it is worse than reporting
// nothing.
func TestStoppingEarlyNeverInventsAMissingFile(t *testing.T) {
	c, keyFor := build(t, corpus.BuildOptions{Segments: 3, LinesPerSegment: 5})

	lines, err := corpus.ReadLines(c.Files[1])
	if err != nil {
		t.Fatal(err)
	}
	lines[3] = strings.Replace(lines[3], "segment 1 line 2", "segment 1 line X", 1)
	if err := corpus.WriteLines(c.Files[1], lines); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyDir(c.Dir, keyFor, Options{StopOnFirst: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("the edit was not caught at all")
	}
	if !res.Truncated {
		t.Fatal("the result does not report that it stopped early, so a caller cannot tell the continuity check was skipped")
	}
	for _, iss := range res.Issues {
		if strings.Contains(iss.Reason, "missing") || strings.Contains(iss.Reason, "claims a predecessor") {
			t.Fatalf("stopping early invented a continuity finding: %s", iss.String())
		}
	}

	// Reporting everything, which is what the tool does by default, gives the one honest finding and runs
	// the continuity checks for real.
	full, err := VerifyDir(c.Dir, keyFor, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if full.Truncated {
		t.Fatal("a full pass reported itself as truncated")
	}
	if len(full.Issues) != 1 {
		t.Fatalf("expected exactly one finding for one edited line, got %v", full.Issues)
	}
}

// Ordering is carried by the segment headers, not by file names, so presenting the files out of order must
// verify cleanly. An implementation that trusted directory order would report a healthy log as broken.
func TestSegmentsPresentedOutOfOrderStillVerify(t *testing.T) {
	c, keyFor := build(t, corpus.BuildOptions{Segments: 3, LinesPerSegment: 2})

	// Swap the names of the first and last segments so that lexicographic order contradicts chain order.
	a, b := c.Files[0], c.Files[2]
	tmp := filepath.Join(c.Dir, "swap.tmp")
	for _, step := range [][2]string{{a, tmp}, {b, a}, {tmp, b}} {
		if err := os.Rename(step[0], step[1]); err != nil {
			t.Fatal(err)
		}
	}

	res, err := VerifyDir(c.Dir, keyFor, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("renaming files broke verification, so the chain is trusting file order: %v", res.Issues)
	}
}

// The frozen version 1 format. These files exist on disks nobody controls, they name the per line value
// "sig", and they carry no continuity fields. They must verify, and they must produce NO continuity
// findings: reporting a break in a log that never claimed to link would be a false accusation.
func TestAFrozenVersion1FileStillVerifies(t *testing.T) {
	dir := t.TempDir()
	p := corpus.New(3, "sc-legacy", "ignored-in-v1")

	var b strings.Builder
	b.WriteString(p.V1Line("", true))
	b.WriteString("\n")
	for i := 0; i < 4; i++ {
		b.WriteString(p.V1Line("legacy line", false))
		b.WriteString("\n")
	}
	path := filepath.Join(dir, "legacy.0000.jsonl")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	keyFor := StaticKey(p.ChainKey())
	res, err := VerifyDir(dir, keyFor, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("a frozen version 1 file did not verify: %v", res.Issues)
	}
	if len(res.Segments) != 1 || res.Segments[0].ChainV != "" {
		t.Fatalf("the version 1 segment was misread: %+v", res.Segments)
	}
}

// An unsigned line in a log that is supposed to be signed is the most interesting line in the file, so it
// is a violation by default rather than something to skip quietly.
func TestAnUnsignedLineIsAViolationUnlessAllowed(t *testing.T) {
	c, keyFor := build(t, corpus.BuildOptions{Segments: 1, LinesPerSegment: 3})

	lines, err := corpus.ReadLines(c.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	lines = append(lines, `{"time":"2026-08-15 09:00:00.000","level":"info","message":"slipped in"}`)
	if err := corpus.WriteLines(c.Files[0], lines); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyFile(c.Files[0], keyFor, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("an unsigned line was accepted by default")
	}

	res, err = VerifyFile(c.Files[0], keyFor, Options{AllowUnsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("allow-unsigned did not downgrade the finding: %v", res.Issues)
	}
}

// Removing the head of a file leaves lines whose chain begins somewhere the reader was never given. That
// must be reported rather than replayed from a guessed starting point.
func TestSignedLinesBeforeAnyChainStartAreReported(t *testing.T) {
	c, keyFor := build(t, corpus.BuildOptions{Segments: 1, LinesPerSegment: 4})

	lines, err := corpus.ReadLines(c.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := corpus.WriteLines(c.Files[0], lines[1:]); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyFile(c.Files[0], keyFor, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a beheaded file verified")
	}
	if !strings.Contains(issueText(res.Issues), "beginning of the file is missing") {
		t.Fatalf("the report does not name the real problem: %v", res.Issues)
	}
}

// A segment nobody can supply a key for must be reported, never silently treated as fine.
func TestASegmentWithNoKeyIsReported(t *testing.T) {
	c, _ := build(t, corpus.BuildOptions{Segments: 1, LinesPerSegment: 2})

	res, err := VerifyFile(c.Files[0], func(string, uint64) []byte { return nil }, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() {
		t.Fatal("a segment with no key reported clean")
	}
}

func issueText(issues []Issue) string {
	var parts []string
	for _, i := range issues {
		parts = append(parts, i.String())
	}
	return strings.Join(parts, "; ")
}
