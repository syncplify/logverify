// Package observation implements the signed availability observations that SFTP.cloud's independent
// monitors publish, and the chain that makes a withheld one visible.
//
// It sits beside the log format in this module because it answers the same question for a different kind
// of evidence. The logs say what a machine DID; observations say what an outside witness SAW, minute by
// minute, about whether the service was reachable. Both end up in a dispute, and in a dispute the useful
// property is identical: the party that produced the record is cryptographically bound to what it said at
// the time and cannot revise it afterwards.
//
// The reason it is published at all is the reason the rest of this module is. SFTP.cloud's service level
// agreement settles disputes on what a majority of the available monitors observed, and the arithmetic is
// performed by SFTP.cloud. A customer who wants to check that arithmetic needs the monitors' public keys,
// the signed batches, and an encoder they can run themselves. Handing over the first two and asking them
// to take our word for the third would leave the evidence checkable only by the party being checked.
//
// This package VERIFIES. Like the anchor package, it deliberately cannot sign and holds no code that
// could. Signing belongs to the monitor that made the observation, and a verifier that could also produce
// observations would be a strictly worse thing to hand somebody who has stopped trusting the producer.
//
// See SPEC.md section 10 for the format implemented here.
package observation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/syncplify/logverify/identity"
)

// Domain prefixes every byte string this format signs.
//
// Domain separation is not decoration. It makes bytes signed for some other purpose unreplayable as an
// observation batch, and a batch unreplayable as anything else, even if some future code shares a key by
// mistake. In particular it is what stops a monitor's signature over its own log anchors being presented
// as testimony about a service, and the reverse. The version inside the string means a future format
// change becomes a different domain rather than an ambiguity.
const Domain = "sftp.cloud/sla-observation/v1\x00"

// DayLayout is how a UTC day is written throughout this format.
const DayLayout = "2006-01-02"

// MaxEntriesPerBatch bounds one batch. A monitor watches a fleet across a handful of protocols, so a few
// hundred entries is a large deployment; a few thousand is not a deployment, it is a fault or an attempt
// to make the receiver do unbounded work.
const MaxEntriesPerBatch = 2048

// MaxBitmapChars bounds one base64 minute bitmap. A UTC day holds 1440 minutes, so 180 bytes, so 240
// base64 characters. The allowance above that is slack for padding and encoding variants, not room to
// grow.
const MaxBitmapChars = 512

// Entry is one target's minute outcomes for one UTC day, from one monitor's vantage point.
//
// Probed and Down are base64 minute bitmaps over the UTC day, bit n being minute n from 00:00. They are
// CUMULATIVE for the day and are republished in full by each batch that touches that day, which is what
// makes a batch idempotent and a lost batch self healing: the next one carries everything the lost one
// did.
//
// A minute present in Probed and absent from Down is a minute the monitor looked and saw the service
// answer. A minute absent from Probed is NEITHER up nor down: it is a minute with no evidence, and any
// honest arithmetic over these records must leave it out of the numerator and the denominator together.
// Treating an unprobed minute as an up minute is the single easiest way to read these records too kindly.
type Entry struct {
	// Target names what was observed. For SFTP.cloud these are Head identifiers and the platform's own
	// front door; the format attaches no meaning to the string beyond identity.
	Target string `json:"target"`
	// Service names the protocol observed on that target, for example "sftp" or "https".
	Service string `json:"service"`
	// Day is the UTC day, YYYY-MM-DD.
	Day string `json:"day"`
	// Probed and Down are base64 minute bitmaps. Down is a subset of Probed in any honest record.
	Probed string `json:"probed"`
	Down   string `json:"down"`
}

// Batch is one monitor's signed statement about what it observed.
//
// Seq and PrevBatch are the chain, and they exist so that a batch WITHHELD in transit leaves a hole that
// names itself. Anyone in the path can drop what they cannot forge; the chain is what stops them hiding
// the drop.
type Batch struct {
	// Monitor is the vantage point that made these observations. It is inside the signed bytes on purpose:
	// without it, a batch lifted off one connection and replayed on another would silently become somebody
	// else's testimony, and a quorum is a count of DISTINCT vantage points.
	Monitor string `json:"monitor"`
	// KeyFP is the fingerprint of the signing identity: which key to verify with. A batch that did not name
	// its key would leave a reader reconstructing its provenance by guessing.
	KeyFP string `json:"keyFp"`
	// Seq is monotonic from 1 across every batch this monitor has ever published. A counter that restarts
	// looks exactly like a replay, so it never restarts.
	Seq uint64 `json:"seq"`
	// PrevBatch is the Digest of the previous SignedBatch from this monitor, empty for the very first.
	PrevBatch string `json:"prevBatch,omitempty"`
	// SignedAt is when the signature was produced, which is not when the minutes were observed.
	SignedAt time.Time `json:"signedAt"`
	Entries  []Entry   `json:"entries"`
}

// SignedBatch is a Batch plus the monitor's signature over its canonical bytes.
type SignedBatch struct {
	Batch
	// Signature is the hex Ed25519 signature over CanonicalBytes.
	Signature string `json:"signature"`
}

// Canonicalize normalizes a batch in place so that two honest producers stating the same testimony produce
// the same bytes. It never returns an error; Validate is what refuses.
//
// The entry ORDER is normalized because it carries no meaning. A batch is a set of per day per target
// statements, and leaving the order to whatever a map iteration produced would make the signature depend
// on something neither side intends, which shows up as verification failing at random.
func (b *Batch) Canonicalize() {
	b.Monitor = strings.TrimSpace(b.Monitor)
	b.KeyFP = strings.ToLower(strings.TrimSpace(b.KeyFP))
	b.PrevBatch = strings.ToLower(strings.TrimSpace(b.PrevBatch))
	b.SignedAt = b.SignedAt.UTC()
	for i := range b.Entries {
		e := &b.Entries[i]
		e.Target = strings.TrimSpace(e.Target)
		e.Service = strings.ToLower(strings.TrimSpace(e.Service))
		e.Day = strings.TrimSpace(e.Day)
		e.Probed = strings.TrimSpace(e.Probed)
		e.Down = strings.TrimSpace(e.Down)
	}
	sort.SliceStable(b.Entries, func(i, j int) bool {
		x, y := b.Entries[i], b.Entries[j]
		if x.Day != y.Day {
			return x.Day < y.Day
		}
		if x.Target != y.Target {
			return x.Target < y.Target
		}
		return x.Service < y.Service
	})
}

// CanonicalBytes renders the batch deterministically for signing and verification.
//
// Hand rolled rather than JSON because a signature is only as good as the uniqueness of what it covers,
// and JSON offers several ways to write the same value. Every string is length prefixed so that no pair of
// adjacent fields can be slid across the boundary between them: without that, {Target:"head", Service:"1"}
// and {Target:"head1", Service:""} would sign identical bytes, and a party controlling one field could
// forge a claim about another.
//
// It is exported because this is a published format: an implementer comparing their encoder against this
// one should not have to reach into the package to do it.
func (b Batch) CanonicalBytes() []byte {
	var buf bytes.Buffer
	buf.WriteString(Domain)
	writeLenPrefixed(&buf, b.Monitor)
	writeLenPrefixed(&buf, b.KeyFP)
	writeUint64(&buf, b.Seq)
	writeLenPrefixed(&buf, b.PrevBatch)
	writeUint64(&buf, uint64(b.SignedAt.UTC().UnixNano()))
	// The entry COUNT is signed as well as the entries. Without it a suffix could be truncated and the
	// remaining bytes would still parse as a shorter, perfectly valid batch.
	writeUint64(&buf, uint64(len(b.Entries)))
	for _, e := range b.Entries {
		writeLenPrefixed(&buf, e.Target)
		writeLenPrefixed(&buf, e.Service)
		writeLenPrefixed(&buf, e.Day)
		writeLenPrefixed(&buf, e.Probed)
		writeLenPrefixed(&buf, e.Down)
	}
	return buf.Bytes()
}

func writeLenPrefixed(b *bytes.Buffer, s string) {
	writeUint64(b, uint64(len(s)))
	b.WriteString(s)
}

func writeUint64(b *bytes.Buffer, v uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], v)
	b.Write(raw[:])
}

// Validate rejects a batch that could not describe real testimony.
//
// It runs BEFORE any signature check. A valid signature over nonsense is still nonsense, and accepting it
// would put a monitor's name on a claim that cannot be checked against anything.
func (b Batch) Validate() error {
	if b.Monitor == "" {
		return errors.New("an observation batch must name the monitor that produced it")
	}
	if len(b.KeyFP) != 64 {
		return fmt.Errorf("a key fingerprint is 64 hex characters, got %d", len(b.KeyFP))
	}
	if _, err := hex.DecodeString(b.KeyFP); err != nil {
		return fmt.Errorf("the key fingerprint is not hex: %w", err)
	}
	if b.Seq == 0 {
		// Sequences start at 1 so that a zero value, which is what an absent field decodes to, can never
		// pass for a position in the chain.
		return errors.New("an observation batch sequence starts at 1")
	}
	if b.Seq > 1 && b.PrevBatch == "" {
		return errors.New("every observation batch after the first must name the digest of the one before it")
	}
	if b.Seq == 1 && b.PrevBatch != "" {
		return errors.New("the first observation batch has nothing before it to chain onto")
	}
	if b.PrevBatch != "" {
		if len(b.PrevBatch) != 64 {
			return fmt.Errorf("a batch digest is 64 hex characters, got %d", len(b.PrevBatch))
		}
		if _, err := hex.DecodeString(b.PrevBatch); err != nil {
			return fmt.Errorf("the previous batch digest is not hex: %w", err)
		}
	}
	if b.SignedAt.IsZero() {
		return errors.New("an observation batch must say when it was signed")
	}
	if len(b.Entries) == 0 {
		return errors.New("an observation batch with no entries says nothing")
	}
	if len(b.Entries) > MaxEntriesPerBatch {
		return fmt.Errorf("an observation batch carries %d entries, more than the %d allowed",
			len(b.Entries), MaxEntriesPerBatch)
	}
	seen := make(map[string]bool, len(b.Entries))
	for i, e := range b.Entries {
		if e.Target == "" || e.Service == "" {
			return fmt.Errorf("entries[%d] must name a target and a service", i)
		}
		if _, err := time.Parse(DayLayout, e.Day); err != nil {
			return fmt.Errorf("entries[%d] day %q is not a date", i, e.Day)
		}
		if len(e.Probed) > MaxBitmapChars || len(e.Down) > MaxBitmapChars {
			return fmt.Errorf("entries[%d] carries a bitmap longer than a day", i)
		}
		// Two entries for one (target, service, day) would fold into one row wherever they are stored and
		// silently overwrite each other, so the second statement would be signed, accepted, and discarded.
		key := e.Day + "|" + e.Target + "|" + e.Service
		if seen[key] {
			return fmt.Errorf("entries[%d]: %s appears twice in one batch", i, key)
		}
		seen[key] = true
	}
	return nil
}

// ErrSignature is returned when the Ed25519 signature does not verify.
var ErrSignature = errors.New("the observation batch signature is not valid")

// Verify checks sb against pub.
//
// It returns nil only when the signature is valid AND the batch names pub as its signer. A record verified
// under a key it does not name is a record whose provenance a reader would have to reconstruct by
// guessing.
//
// The batch is canonicalized first, which is safe only because canonicalization is deterministic and
// lossless: it trims and reorders, and a producer that signed anything else simply fails the check.
func Verify(pub ed25519.PublicKey, sb *SignedBatch) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key size")
	}
	if sb == nil {
		return errors.New("no observation batch to verify")
	}
	sb.Batch.Canonicalize()
	if err := sb.Batch.Validate(); err != nil {
		return err
	}
	if fp := identity.Fingerprint(pub); sb.KeyFP != fp {
		return fmt.Errorf("the batch names key %s but was checked against %s",
			identity.Short(sb.KeyFP), identity.Short(fp))
	}
	raw, err := hex.DecodeString(strings.TrimSpace(sb.Signature))
	if err != nil {
		return fmt.Errorf("the batch signature is not hex: %w", err)
	}
	if !ed25519.Verify(pub, sb.Batch.CanonicalBytes(), raw) {
		return ErrSignature
	}
	return nil
}

// Digest identifies this signed batch to its successor, which names it in PrevBatch.
//
// It is taken over the SIGNATURE rather than the record, matching the anchor format in this module and for
// the same reason: the signature already commits to every field, which makes this both shorter and
// impossible to collide without breaking Ed25519 first.
//
// Note for implementers: the hash covers the hexadecimal signature TEXT, not the raw signature bytes.
// Reaching for the raw bytes is the instinctive choice and produces a different digest.
func (sb SignedBatch) Digest() string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(sb.Signature))))
	return hex.EncodeToString(sum[:])
}

// FollowsFrom reports whether sb is the immediate successor of prev from the same monitor.
//
// This is what makes WITHHOLDING visible rather than merely tampering: a relay can drop a batch it cannot
// forge, and the gap in Seq plus the broken PrevBatch link names precisely what went missing.
func (sb SignedBatch) FollowsFrom(prev SignedBatch) bool {
	return sb.KeyFP == prev.KeyFP &&
		sb.Monitor == prev.Monitor &&
		sb.Seq == prev.Seq+1 &&
		sb.PrevBatch == prev.Digest()
}

// VerifyChain checks a run of batches from one monitor: every signature valid, every link intact, and no
// hole in the sequence. It returns the index of the first batch that fails and why.
//
// A hole is reported rather than tolerated, and that is the whole point of holding a run rather than a
// single batch. A monitor's testimony is only as good as the certainty that none of it was quietly
// removed between the monitor and the reader.
func VerifyChain(pub ed25519.PublicKey, run []SignedBatch) (int, error) {
	for i := range run {
		if err := Verify(pub, &run[i]); err != nil {
			return i, err
		}
		if i == 0 {
			continue
		}
		if !run[i].FollowsFrom(run[i-1]) {
			return i, fmt.Errorf("batch %d does not follow batch %d: expected sequence %d chained onto %s",
				run[i].Seq, run[i-1].Seq, run[i-1].Seq+1, run[i-1].Digest())
		}
	}
	return -1, nil
}
