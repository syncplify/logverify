package anchor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/syncplify/logverify/internal/corpus"
)

func toAnchor(sa corpus.SignedAnchor) SignedAnchor {
	return SignedAnchor{
		Anchor: Anchor{
			Service: sa.Service, KeyFP: sa.KeyFP, ChainID: sa.ChainID,
			Seq: sa.Seq, LineCount: sa.LineCount, ChainMAC: sa.ChainMAC,
			First: sa.First, Last: sa.Last, Final: sa.Final,
			AnchorSeq: sa.AnchorSeq, PrevAnchor: sa.PrevAnchor, SignedAt: sa.SignedAt,
		},
		Signature: sa.Signature,
	}
}

// The cross implementation check that gives the corpus its value. If these two encoders can disagree, then
// every other test in this package is only checking that the verifier agrees with itself.
//
// The awkward cases are deliberate: an empty PrevAnchor (the first anchor of an identity), a zero time
// (whose Unix nanosecond count is a large NEGATIVE number that has to survive the conversion to unsigned),
// and multi byte characters (where a length prefix counting runes instead of bytes would diverge).
func TestTheCanonicalEncodingMatchesAnIndependentImplementation(t *testing.T) {
	base := time.Date(2026, 8, 15, 9, 23, 13, 205538975, time.UTC)
	cases := map[string]corpus.SignedAnchor{
		"ordinary": {
			Service: "sc-conn", KeyFP: strings.Repeat("a", 64), ChainID: strings.Repeat("b", 32),
			Seq: 3, LineCount: 1284, ChainMAC: strings.Repeat("c", 64),
			First: base, Last: base.Add(time.Hour), Final: true,
			AnchorSeq: 42, PrevAnchor: strings.Repeat("d", 64), SignedAt: base.Add(2 * time.Hour),
		},
		"first anchor, no predecessor": {
			Service: "sc-head", KeyFP: strings.Repeat("e", 64), ChainID: "f0",
			Seq: 0, LineCount: 1, ChainMAC: strings.Repeat("0", 64),
			First: base, Last: base, Final: false,
			AnchorSeq: 1, PrevAnchor: "", SignedAt: base,
		},
		"zero times, negative unix nanoseconds": {
			Service: "sc-portal", KeyFP: "ab", ChainID: "cd",
			Seq: 0, LineCount: 7, ChainMAC: "ef",
			First: time.Time{}, Last: time.Time{}, Final: false,
			AnchorSeq: 0, PrevAnchor: "", SignedAt: time.Time{},
		},
		"multi byte characters": {
			Service: "sc-conn éü中", KeyFP: "é", ChainID: "中文",
			Seq: 1, LineCount: 2, ChainMAC: "aa",
			First: base, Last: base, Final: true,
			AnchorSeq: 9, PrevAnchor: "ü", SignedAt: base,
		},
	}

	for name, sa := range cases {
		t.Run(name, func(t *testing.T) {
			mine := toAnchor(sa).Anchor.CanonicalBytes()
			theirs := corpus.CanonicalBytes(sa)
			if !bytes.Equal(mine, theirs) {
				t.Fatalf("the two encoders disagree\n  verifier: %s\n  corpus:   %s", hex.EncodeToString(mine), hex.EncodeToString(theirs))
			}
		})
	}
}

// A signature is only as good as the uniqueness of what it covers. Without length prefixes, moving a
// character across a field boundary would produce identical signing input, and whoever controls one field
// could forge a claim about the next.
func TestAdjacentFieldsCannotBeSlidAcrossTheirBoundary(t *testing.T) {
	a := Anchor{Service: "s", KeyFP: "k", ChainID: "ab", ChainMAC: "", LineCount: 1}
	b := Anchor{Service: "s", KeyFP: "k", ChainID: "a", ChainMAC: "b", LineCount: 1}
	if bytes.Equal(a.CanonicalBytes(), b.CanonicalBytes()) {
		t.Fatal("two different anchors produced identical signing input")
	}
}

func buildAnchor(t *testing.T) (corpus.SignedAnchor, ed25519.PublicKey) {
	t.Helper()
	p := corpus.New(7, "sc-conn", "a1b2c3d4e5f60718293a4b5c6d7e8f90")
	p.StartSegment()
	p.Line("one")
	p.Line("two")
	return p.Anchor(true), p.Pub
}

func TestAValidAnchorVerifies(t *testing.T) {
	sa, pub := buildAnchor(t)
	if err := Verify(pub, toAnchor(sa)); err != nil {
		t.Fatalf("a freshly signed anchor did not verify: %v", err)
	}
}

// Every field is covered by the signature, so touching any of them must break it. The chain MAC is the one
// that matters most: it is the actual claim about what the log contained.
func TestEveryFieldIsCoveredBySignature(t *testing.T) {
	sa, pub := buildAnchor(t)

	mutations := map[string]func(*SignedAnchor){
		"chain mac":  func(a *SignedAnchor) { a.ChainMAC = strings.Repeat("9", 64) },
		"line count": func(a *SignedAnchor) { a.LineCount++ },
		"seq":        func(a *SignedAnchor) { a.Seq++ },
		"service":    func(a *SignedAnchor) { a.Service = "sc-head" },
		"chain id":   func(a *SignedAnchor) { a.ChainID = strings.Repeat("0", 32) },
		"final":      func(a *SignedAnchor) { a.Final = !a.Final },
		"anchor seq": func(a *SignedAnchor) { a.AnchorSeq++ },
		"prev":       func(a *SignedAnchor) { a.PrevAnchor = strings.Repeat("1", 64) },
		"first":      func(a *SignedAnchor) { a.First = a.First.Add(time.Nanosecond) },
		"last":       func(a *SignedAnchor) { a.Last = a.Last.Add(time.Nanosecond) },
		"signed at":  func(a *SignedAnchor) { a.SignedAt = a.SignedAt.Add(time.Nanosecond) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			bad := toAnchor(sa)
			mutate(&bad)
			if err := Verify(pub, bad); err == nil {
				t.Fatalf("an anchor with an altered %s still verified", name)
			}
		})
	}
}

// A record verified under a key it does not name is a record whose provenance a reader has to reconstruct
// by guessing, so naming the wrong key is a refusal even when the signature itself would check out.
func TestAnAnchorMustNameTheKeyItIsCheckedAgainst(t *testing.T) {
	sa, pub := buildAnchor(t)
	bad := toAnchor(sa)
	bad.KeyFP = strings.Repeat("f", 64)
	if err := Verify(pub, bad); err == nil {
		t.Fatal("an anchor naming a different key was accepted")
	}
}

// A valid signature over nonsense is still nonsense. Refusing beats putting an identity's name on a claim
// that cannot be checked against anything.
func TestAnchorsThatDescribeNothingAreRefusedBeforeTheSignatureIsChecked(t *testing.T) {
	_, pub := buildAnchor(t)
	cases := map[string]Anchor{
		"no service":     {ChainID: "c", LineCount: 1, ChainMAC: strings.Repeat("a", 64)},
		"no chain":       {Service: "s", LineCount: 1, ChainMAC: strings.Repeat("a", 64)},
		"no lines":       {Service: "s", ChainID: "c", LineCount: 0, ChainMAC: strings.Repeat("a", 64)},
		"short mac":      {Service: "s", ChainID: "c", LineCount: 1, ChainMAC: "aa"},
		"mac is not hex": {Service: "s", ChainID: "c", LineCount: 1, ChainMAC: strings.Repeat("z", 64)},
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Verify(pub, SignedAnchor{Anchor: a}); err == nil {
				t.Fatal("an anchor that commits to nothing was accepted")
			}
		})
	}
}

// The digest covers the hexadecimal signature TEXT, not the raw signature bytes. Reaching for the raw bytes
// is the instinctive choice and yields a different value, so this pins the one that is normative.
func TestTheDigestCoversTheHexTextOfTheSignature(t *testing.T) {
	sa, _ := buildAnchor(t)
	a := toAnchor(sa)

	rawSig, err := hex.DecodeString(a.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() == hexSHA256(rawSig) {
		t.Fatal("the digest was taken over the raw signature bytes rather than the hex text")
	}
	if a.Digest() != hexSHA256([]byte(a.Signature)) {
		t.Fatal("the digest does not cover the hex signature text")
	}
}

// Withholding is the attack the anchor chain exists to expose: a relay cannot forge an anchor, but it can
// drop one, and dropping one must be visible rather than silent.
func TestADroppedAnchorBreaksTheSuccession(t *testing.T) {
	p := corpus.New(11, "sc-conn", "aa")
	p.StartSegment()
	p.Line("one")
	first := toAnchor(p.Anchor(false))
	p.Line("two")
	second := toAnchor(p.Anchor(false))
	p.Line("three")
	third := toAnchor(p.Anchor(true))

	if !second.FollowsFrom(first) {
		t.Fatal("consecutive anchors did not chain")
	}
	if third.FollowsFrom(first) {
		t.Fatal("an anchor with one withheld between it and its predecessor was accepted as consecutive")
	}
}

// The anchor JSON is a published contract: a customer's evidence export carries these names, and anything
// automated against them breaks silently if they move.
func TestTheAnchorJSONFieldNamesAreTheContract(t *testing.T) {
	sa, _ := buildAnchor(t)
	raw, err := json.Marshal(toAnchor(sa))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		`"service"`, `"keyFp"`, `"chainId"`, `"seq"`, `"lineCount"`, `"chainMac"`,
		`"first"`, `"last"`, `"final"`, `"anchorSeq"`, `"signedAt"`, `"signature"`,
	} {
		if !strings.Contains(string(raw), name) {
			t.Fatalf("the published anchor lost the field %s: %s", name, raw)
		}
	}
	// The value is a MAC and the format says so. "sig" was the version 1 name for a MAC and must never
	// reappear on an anchor, where a real signature also lives and the two would be confusable.
	if strings.Contains(string(raw), `"sig"`) {
		t.Fatalf("an anchor field is named sig: %s", raw)
	}
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
