// Package conformance holds the end to end scenarios that need more than one layer of the format at once.
package conformance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syncplify/logverify/anchor"
	"github.com/syncplify/logverify/chain"
	"github.com/syncplify/logverify/internal/corpus"
)

func toAnchor(sa corpus.SignedAnchor) anchor.SignedAnchor {
	return anchor.SignedAnchor{
		Anchor: anchor.Anchor{
			Service: sa.Service, KeyFP: sa.KeyFP, ChainID: sa.ChainID,
			Seq: sa.Seq, LineCount: sa.LineCount, ChainMAC: sa.ChainMAC,
			First: sa.First, Last: sa.Last, Final: sa.Final,
			AnchorSeq: sa.AnchorSeq, PrevAnchor: sa.PrevAnchor, SignedAt: sa.SignedAt,
		},
		Signature: sa.Signature,
	}
}

// macAtLine replays a file and returns the chain MAC reached at the anchored line.
func macAtLine(t *testing.T, path string, keyFor chain.KeyFunc, sa anchor.SignedAnchor) (string, bool, *chain.Result) {
	t.Helper()
	var reached string
	var found bool
	res, err := chain.VerifyFile(path, keyFor, chain.Options{
		OnLine: func(chainID string, seq, line uint64, mac string) {
			if chainID == sa.ChainID && seq == sa.Seq && line == sa.LineCount {
				reached, found = mac, true
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return reached, found, res
}

// THE SCENARIO THE WHOLE DESIGN EXISTS FOR.
//
// The machine owner holds the log, the chain key and the identity. They rewrite their own history and
// re-MAC every line correctly, which they are perfectly able to do. Local verification therefore passes,
// and it SHOULD pass: the chain only ever claimed that nobody without the key altered the file.
//
// The anchor is what catches it, and only because it was signed before the rewrite and, in the real system,
// handed to somebody else at a time that has already passed. If this test ever goes green on the anchor
// check, the product's central claim is false.
func TestARewrittenAndCorrectlyReMACedLogIsCaughtOnlyByTheAnchor(t *testing.T) {
	dir := t.TempDir()
	const seed, service, chainID = 5, "sc-conn", "a1b2c3d4e5f60718293a4b5c6d7e8f90"

	// The honest log, and the anchor signed over it.
	original := corpus.New(seed, service, chainID)
	var honest strings.Builder
	honest.WriteString(original.StartSegment() + "\n")
	for _, msg := range []string{"user alice logged in", "DELETE /finance/q3.xlsx by alice", "user alice logged out"} {
		honest.WriteString(original.Line(msg) + "\n")
	}
	sa := toAnchor(original.Anchor(true))

	path := filepath.Join(dir, "sc-conn.0000.jsonl")
	if err := os.WriteFile(path, []byte(honest.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	keyFor := func(cid string, seq uint64) []byte {
		return corpus.New(seed, service, cid).ChainKey()
	}

	// The anchor is authentic and the honest log matches it.
	if err := anchor.Verify(original.Pub, sa); err != nil {
		t.Fatalf("the anchor did not verify: %v", err)
	}
	reached, found, res := macAtLine(t, path, keyFor, sa)
	if !found || !res.OK() || reached != sa.ChainMAC {
		t.Fatalf("the honest log did not match its own anchor: found=%v ok=%v issues=%v", found, res.OK(), res.Issues)
	}

	// Now the owner rewrites history. Same identity, same chain, same file number, so the same derived key:
	// every MAC below is recomputed correctly and the file is internally perfect.
	rewriter := corpus.New(seed, service, chainID)
	var rewritten strings.Builder
	rewritten.WriteString(rewriter.StartSegment() + "\n")
	for _, msg := range []string{"user alice logged in", "user alice logged out", "nothing to see here"} {
		rewritten.WriteString(rewriter.Line(msg) + "\n")
	}
	if err := os.WriteFile(path, []byte(rewritten.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	// Layer 1 is satisfied, and that is not a bug. It is the precise limit of what a MAC can say.
	res2, err := chain.VerifyFile(path, keyFor, chain.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.OK() {
		t.Fatalf("the rewritten log should still pass LOCAL verification, since the owner holds the key: %v", res2.Issues)
	}

	// Layer 2 catches it. The anchor still verifies, because it is authentic; what it commits to is no
	// longer what the file contains.
	if err := anchor.Verify(original.Pub, sa); err != nil {
		t.Fatalf("the anchor stopped verifying, which would mean the evidence was destroyed rather than the log: %v", err)
	}
	reached2, found2, _ := macAtLine(t, path, keyFor, sa)
	if !found2 {
		t.Fatal("the rewritten log does not even reach the anchored line")
	}
	if reached2 == sa.ChainMAC {
		t.Fatal("a rewritten log matched the anchor signed over the original; the central claim of the format is broken")
	}
}

// The other half of the same claim: an owner who rewrites the log and signs a FRESH anchor over the new
// content produces something entirely self consistent. Nothing local can tell the difference. Only the
// copy of the old anchor held by somebody else can, which is why the witness layer exists and why the
// tool's help text tells people to check anchors against a copy they did not get from the producer.
func TestARewrittenLogWithAFreshAnchorIsSelfConsistent(t *testing.T) {
	dir := t.TempDir()
	const seed, service, chainID = 9, "sc-conn", "b1b2c3d4e5f60718293a4b5c6d7e8f90"

	rewriter := corpus.New(seed, service, chainID)
	var b strings.Builder
	b.WriteString(rewriter.StartSegment() + "\n")
	b.WriteString(rewriter.Line("a tidier version of events") + "\n")
	fresh := toAnchor(rewriter.Anchor(true))

	path := filepath.Join(dir, "sc-conn.0000.jsonl")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	keyFor := func(cid string, seq uint64) []byte {
		return corpus.New(seed, service, cid).ChainKey()
	}
	if err := anchor.Verify(rewriter.Pub, fresh); err != nil {
		t.Fatalf("verify: %v", err)
	}
	reached, found, res := macAtLine(t, path, keyFor, fresh)
	if !found || !res.OK() || reached != fresh.ChainMAC {
		t.Fatal("a self consistent rewrite failed its own anchor, which would make this test meaningless")
	}
	// Stated as an assertion so that nobody reads the pass above as a security property.
	if fresh.AnchorSeq != 1 {
		t.Fatalf("the fresh anchor restarted the counter at %d; a restarted counter is exactly what a witness treats as a replay", fresh.AnchorSeq)
	}
}
