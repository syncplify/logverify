package observation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/syncplify/logverify/identity"
)

// Every case here is a way a signature could look sound and cover something other than what it appears to.
//
// The signer below exists only in this test file, deliberately. The package itself holds no code that can
// produce a batch, for the same reason the anchor package holds none: a verifier that can also sign is a
// worse thing to hand somebody who has stopped trusting the producer. A test needs to make one in order to
// check that it verifies, so it makes one here, in four lines, where nothing ships it.

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

// sign is the producer side, present only in this test.
func sign(t *testing.T, priv ed25519.PrivateKey, b Batch) SignedBatch {
	t.Helper()
	b.KeyFP = identity.Fingerprint(priv.Public().(ed25519.PublicKey))
	b.Canonicalize()
	if err := b.Validate(); err != nil {
		t.Fatalf("the fixture batch is invalid: %v", err)
	}
	return SignedBatch{Batch: b, Signature: hex.EncodeToString(ed25519.Sign(priv, b.CanonicalBytes()))}
}

func sampleBatch() Batch {
	return Batch{
		Monitor:  "mon-aws-use1",
		Seq:      1,
		SignedAt: time.Date(2026, 8, 19, 4, 5, 6, 0, time.UTC),
		Entries: []Entry{
			{Target: "head-1", Service: "sftp", Day: "2026-08-19", Probed: "AAEC", Down: "AAAA"},
			{Target: "head-1", Service: "https", Day: "2026-08-19", Probed: "AAEC", Down: "AAEA"},
		},
	}
}

// TestARoundTripVerifies, so nothing below is passing because everything fails.
func TestARoundTripVerifies(t *testing.T) {
	pub, priv := keys(t)
	sb := sign(t, priv, sampleBatch())
	if err := Verify(pub, &sb); err != nil {
		t.Fatalf("a freshly signed batch did not verify: %v", err)
	}
	if len(sb.Digest()) != 64 {
		t.Fatalf("digest %q", sb.Digest())
	}
}

// TestAnotherMonitorsKeyDoesNotVerify. The whole measurement plane rests on this: testimony is attributable.
func TestAnotherMonitorsKeyDoesNotVerify(t *testing.T) {
	_, priv := keys(t)
	otherPub, _ := keys(t)
	sb := sign(t, priv, sampleBatch())
	if Verify(otherPub, &sb) == nil {
		t.Fatal("a batch verified against a key that did not sign it")
	}
}

// TestABatchMustNameTheKeyItIsCheckedAgainst. A record verified under a key it does not name leaves a
// reader reconstructing its provenance by guessing, which in a dispute is the reader doing the producer's
// job for them.
func TestABatchMustNameTheKeyItIsCheckedAgainst(t *testing.T) {
	pub, priv := keys(t)
	sb := sign(t, priv, sampleBatch())
	sb.KeyFP = strings.Repeat("ab", 32)
	if err := Verify(pub, &sb); err == nil {
		t.Fatal("a batch naming a different key verified")
	}
}

// TestEveryFieldIsCovered walks each field, changes it, and requires the signature to fail. A field left
// out of the canonical bytes is a field an intermediary can rewrite freely, and here that means rewriting
// which service was down, on which day, for how many minutes.
func TestEveryFieldIsCovered(t *testing.T) {
	pub, priv := keys(t)
	sb := sign(t, priv, sampleBatch())
	fp := sb.KeyFP

	mutations := map[string]func(*Batch){
		"monitor":          func(b *Batch) { b.Monitor = "mon-somebody-else" },
		"sequence":         func(b *Batch) { b.Seq = 2; b.PrevBatch = strings.Repeat("cd", 32) },
		"signed at":        func(b *Batch) { b.SignedAt = b.SignedAt.Add(time.Second) },
		"target":           func(b *Batch) { b.Entries[0].Target = "head-2" },
		"service":          func(b *Batch) { b.Entries[0].Service = "ftps-implicit" },
		"day":              func(b *Batch) { b.Entries[0].Day = "2026-08-18" },
		"probed minutes":   func(b *Batch) { b.Entries[0].Probed = "AAED" },
		"down minutes":     func(b *Batch) { b.Entries[1].Down = "AAAA" },
		"an entry dropped": func(b *Batch) { b.Entries = b.Entries[:1] },
		"an entry added": func(b *Batch) {
			b.Entries = append(b.Entries, Entry{Target: "head-9", Service: "sftp", Day: "2026-08-19", Probed: "AA", Down: "AA"})
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			tampered := SignedBatch{Batch: sampleBatch(), Signature: sb.Signature}
			tampered.KeyFP = fp
			mutate(&tampered.Batch)
			if Verify(pub, &tampered) == nil {
				t.Fatalf("changing the %s did not break the signature; it is not covered by the canonical bytes", name)
			}
		})
	}
}

// TestThePreviousBatchLinkIsCovered separately, because it is the chain link: an intermediary able to
// rewrite it could re-parent a batch and hide the hole its own withheld batch left.
func TestThePreviousBatchLinkIsCovered(t *testing.T) {
	pub, priv := keys(t)
	b := sampleBatch()
	b.Seq = 2
	b.PrevBatch = strings.Repeat("ab", 32)
	sb := sign(t, priv, b)
	if err := Verify(pub, &sb); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	sb.PrevBatch = strings.Repeat("cd", 32)
	if Verify(pub, &sb) == nil {
		t.Fatal("the previous batch link is not covered; a batch could be re-parented to hide a gap")
	}
}

// TestFieldsCannotSlideAcrossTheirBoundary is what the length prefixes are for. Without them
// {Target:"head", Service:"1sftp"} and {Target:"head1", Service:"sftp"} would sign identical bytes, and a
// party controlling one field could forge a claim about the other.
func TestFieldsCannotSlideAcrossTheirBoundary(t *testing.T) {
	a := Batch{Monitor: "mon-1", Seq: 1, SignedAt: time.Unix(0, 1).UTC(),
		Entries: []Entry{{Target: "head", Service: "1sftp", Day: "2026-08-19"}}}
	b := Batch{Monitor: "mon-1", Seq: 1, SignedAt: time.Unix(0, 1).UTC(),
		Entries: []Entry{{Target: "head1", Service: "sftp", Day: "2026-08-19"}}}
	if string(a.CanonicalBytes()) == string(b.CanonicalBytes()) {
		t.Fatal("two different batches produce the same canonical bytes; the fields are not length prefixed")
	}
}

// TestEntryOrderDoesNotChangeTheSignature. The order carries no meaning, so leaving it to whatever a map
// iteration produced would make verification fail at random on perfectly honest records.
func TestEntryOrderDoesNotChangeTheSignature(t *testing.T) {
	pub, priv := keys(t)
	sb := sign(t, priv, sampleBatch())

	shuffled := SignedBatch{Batch: sampleBatch(), Signature: sb.Signature}
	shuffled.KeyFP = sb.KeyFP
	shuffled.Entries[0], shuffled.Entries[1] = shuffled.Entries[1], shuffled.Entries[0]
	if err := Verify(pub, &shuffled); err != nil {
		t.Fatalf("reordering the entries broke verification: %v", err)
	}
	if shuffled.Digest() != sb.Digest() {
		t.Fatal("reordering the entries changed the digest, so a chain would fork on presentation order alone")
	}
}

// TestTheDigestCoversTheSignatureText pins the note implementers most often get wrong: the hash is over
// the hexadecimal signature TEXT, not the raw bytes.
func TestTheDigestCoversTheSignatureText(t *testing.T) {
	sb := SignedBatch{Signature: "aa"}
	other := SignedBatch{Signature: "bb"}
	if sb.Digest() == other.Digest() {
		t.Fatal("the digest ignores the signature")
	}
	// Spelled out so a reimplementer can check their own against a literal.
	want := "961b6dd3ede3cb8ecbaacbd68de040cd78eb2ed5889130cceb4c49268ea4d506"
	if got := (SignedBatch{Signature: "aa"}).Digest(); got != want {
		t.Fatalf("Digest over the text \"aa\" is %s, want %s (are you hashing the raw bytes?)", got, want)
	}
}

// TestAValidBatchIsNotConfusedWithNonsense covers the refusals, each of which describes a record that
// could not have come from an honest producer.
func TestAValidBatchIsNotConfusedWithNonsense(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	cases := map[string]Batch{
		"no monitor":          {KeyFP: fp, Seq: 1, SignedAt: time.Now(), Entries: sampleBatch().Entries},
		"no key fingerprint":  {Monitor: "m", Seq: 1, SignedAt: time.Now(), Entries: sampleBatch().Entries},
		"short fingerprint":   {Monitor: "m", KeyFP: "abcd", Seq: 1, SignedAt: time.Now(), Entries: sampleBatch().Entries},
		"sequence zero":       {Monitor: "m", KeyFP: fp, Seq: 0, SignedAt: time.Now(), Entries: sampleBatch().Entries},
		"no entries":          {Monitor: "m", KeyFP: fp, Seq: 1, SignedAt: time.Now()},
		"no signing time":     {Monitor: "m", KeyFP: fp, Seq: 1, Entries: sampleBatch().Entries},
		"unchained after one": {Monitor: "m", KeyFP: fp, Seq: 2, SignedAt: time.Now(), Entries: sampleBatch().Entries},
		"chained at the top":  {Monitor: "m", KeyFP: fp, Seq: 1, PrevBatch: fp, SignedAt: time.Now(), Entries: sampleBatch().Entries},
		"bad prev digest":     {Monitor: "m", KeyFP: fp, Seq: 2, PrevBatch: "not-a-digest", SignedAt: time.Now(), Entries: sampleBatch().Entries},
		"duplicate entry": {Monitor: "m", KeyFP: fp, Seq: 1, SignedAt: time.Now(), Entries: []Entry{
			{Target: "h", Service: "sftp", Day: "2026-08-19"},
			{Target: "h", Service: "sftp", Day: "2026-08-19"},
		}},
		"not a day": {Monitor: "m", KeyFP: fp, Seq: 1, SignedAt: time.Now(), Entries: []Entry{
			{Target: "h", Service: "sftp", Day: "yesterday"},
		}},
		"oversized bitmap": {Monitor: "m", KeyFP: fp, Seq: 1, SignedAt: time.Now(), Entries: []Entry{
			{Target: "h", Service: "sftp", Day: "2026-08-19", Probed: strings.Repeat("A", MaxBitmapChars+1)},
		}},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			b.Canonicalize()
			if err := b.Validate(); err == nil {
				t.Fatal("an impossible batch validated")
			}
		})
	}
}

// TestAnOversizedBatchIsRefused, because entry count is the one dimension a producer controls freely and a
// receiver does per entry work.
func TestAnOversizedBatchIsRefused(t *testing.T) {
	b := Batch{Monitor: "m", KeyFP: strings.Repeat("ab", 32), Seq: 1, SignedAt: time.Now()}
	day := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i <= MaxEntriesPerBatch; i++ {
		b.Entries = append(b.Entries, Entry{
			Target: "head", Service: "sftp", Day: day.AddDate(0, 0, i).Format(DayLayout),
		})
	}
	if err := b.Validate(); err == nil {
		t.Fatal("a batch above the entry cap was accepted")
	}
}

// TestTheDomainSeparatesThisFormat. Bytes signed for another purpose must not be replayable here, and a
// batch must not be replayable as anything else. In particular a monitor also signs log anchors.
func TestTheDomainSeparatesThisFormat(t *testing.T) {
	b := sampleBatch()
	if !strings.HasPrefix(string(b.CanonicalBytes()), Domain) {
		t.Fatal("the canonical bytes are not domain separated")
	}
	if !strings.Contains(Domain, "/v1") {
		t.Fatal("the domain carries no version, so a format change would be an ambiguity rather than a new domain")
	}
}

// TestAWithheldBatchIsVisible is the property the chain exists for: a party in the path can drop what it
// cannot forge, and cannot hide the drop.
func TestAWithheldBatchIsVisible(t *testing.T) {
	pub, priv := keys(t)

	first := sign(t, priv, sampleBatch())

	second := sampleBatch()
	second.Seq = 2
	second.PrevBatch = first.Digest()
	second.Entries[0].Probed = "AAED"
	sb2 := sign(t, priv, second)

	third := sampleBatch()
	third.Seq = 3
	third.PrevBatch = sb2.Digest()
	third.Entries[0].Probed = "AAEE"
	sb3 := sign(t, priv, third)

	if idx, err := VerifyChain(pub, []SignedBatch{first, sb2, sb3}); err != nil {
		t.Fatalf("a complete run failed at %d: %v", idx, err)
	}

	// The middle batch is withheld. Both survivors are perfectly signed and neither can be forged.
	idx, err := VerifyChain(pub, []SignedBatch{first, sb3})
	if err == nil {
		t.Fatal("a run with a withheld batch verified; a dropped batch would be invisible")
	}
	if idx != 1 {
		t.Fatalf("the break was reported at index %d, want 1", idx)
	}
}

// TestASuccessorIsRecognizedOnlyFromItsOwnPredecessor, so FollowsFrom cannot be satisfied by any batch
// that merely happens to be adjacent.
func TestASuccessorIsRecognizedOnlyFromItsOwnPredecessor(t *testing.T) {
	_, priv := keys(t)
	_, otherPriv := keys(t)

	first := sign(t, priv, sampleBatch())

	next := sampleBatch()
	next.Seq = 2
	next.PrevBatch = first.Digest()
	good := sign(t, priv, next)
	if !good.FollowsFrom(first) {
		t.Fatal("a correctly chained successor was not recognized")
	}

	// Right sequence, right link, wrong signer.
	fromElsewhere := sign(t, otherPriv, next)
	if fromElsewhere.FollowsFrom(first) {
		t.Fatal("a batch from a different key was accepted as a successor")
	}

	// Right signer, wrong link.
	forked := sampleBatch()
	forked.Seq = 2
	forked.PrevBatch = strings.Repeat("cd", 32)
	if sign(t, priv, forked).FollowsFrom(first) {
		t.Fatal("a batch chained onto something else was accepted as a successor")
	}
}
