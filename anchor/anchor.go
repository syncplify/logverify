// Package anchor implements the signed commitments that make a log chain mean something to a third party.
//
// A chained HMAC proves a log was not edited by anyone lacking its key, and stops there, because whoever
// can verify a MAC can also forge one. On hardware its owner controls, that makes the log a diary. An
// anchor is a small ASYMMETRIC signature over a claim about what the log contained: anyone holding the
// public key can check it and nobody but the holder of the private key can produce it.
//
// This package verifies. It deliberately cannot sign, and holds no code that could: signing belongs to the
// machine that owns the log, and a verifier that could also produce anchors would be a strictly worse
// thing to hand somebody who has stopped trusting the producer.
//
// See SPEC.md section 5 for the format implemented here.
package anchor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/syncplify/logverify/identity"
)

// Domain prefixes every byte string this format signs.
//
// Domain separation is not decoration. It makes bytes signed for some other purpose unreplayable as an
// anchor, and an anchor unreplayable as anything else, even if some future code shares the key by mistake.
// The version inside the string means a future format change becomes a different domain rather than an
// ambiguity.
const Domain = "sftp.cloud/log-anchor/v1\x00"

// Anchor is a signed commitment to a PREFIX of one log chain segment: lines 1 through LineCount of the
// file at position Seq in chain ChainID produce the chain MAC ChainMAC.
type Anchor struct {
	// Service names the component that produced the log.
	Service string `json:"service"`
	// KeyFP is the fingerprint of the signing identity: which key to verify with.
	KeyFP string `json:"keyFp"`
	// ChainID, Seq, LineCount and ChainMAC describe the commitment.
	ChainID   string `json:"chainId"`
	Seq       uint64 `json:"seq"`
	LineCount uint64 `json:"lineCount"`
	// ChainMAC is the log chain's HMAC value at the committed line. The name is deliberate: this value is a
	// MAC, not a signature, and an evidence artifact that labels symmetric key material "sig" invites
	// exactly the challenge this format exists to survive. The asymmetric signature over the whole record
	// is SignedAnchor.Signature, and it is the only thing here called a signature.
	ChainMAC string `json:"chainMac"`
	// First and Last bound the covered lines in time, always UTC.
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	// Final reports that the segment is closed and will gain no further lines.
	Final bool `json:"final"`
	// AnchorSeq is monotonic across every anchor this identity has ever produced, ACROSS chains. A counter
	// that restarts looks exactly like a replay.
	AnchorSeq uint64 `json:"anchorSeq"`
	// PrevAnchor is the Digest of the previous SignedAnchor from this identity, empty for the very first.
	PrevAnchor string `json:"prevAnchor,omitempty"`
	// SignedAt is when the signature was produced, which is not when the lines were written.
	SignedAt time.Time `json:"signedAt"`
}

// SignedAnchor is an Anchor plus the identity's signature over its canonical bytes.
type SignedAnchor struct {
	Anchor
	// Signature is the hex Ed25519 signature over CanonicalBytes.
	Signature string `json:"signature"`
}

// CanonicalBytes renders the anchor deterministically for signing and verification.
//
// Hand rolled rather than JSON because a signature is only as good as the uniqueness of what it covers,
// and JSON offers several ways to write the same value. Every string is length prefixed so that no pair of
// adjacent fields can be slid across the boundary between them: without that, {ChainID:"a", ChainMAC:"b"}
// and {ChainID:"ab", ChainMAC:""} would sign identical bytes, and an attacker controlling one field could
// forge a claim about another.
//
// It is exported because this is a published format: an implementer comparing their encoder against this
// one should not have to reach into the package to do it.
func (a Anchor) CanonicalBytes() []byte {
	var b bytes.Buffer
	b.WriteString(Domain)
	writeLenPrefixed(&b, a.Service)
	writeLenPrefixed(&b, a.KeyFP)
	writeLenPrefixed(&b, a.ChainID)
	writeUint64(&b, a.Seq)
	writeUint64(&b, a.LineCount)
	writeLenPrefixed(&b, a.ChainMAC)
	writeUint64(&b, uint64(a.First.UTC().UnixNano()))
	writeUint64(&b, uint64(a.Last.UTC().UnixNano()))
	if a.Final {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	writeUint64(&b, a.AnchorSeq)
	writeLenPrefixed(&b, a.PrevAnchor)
	writeUint64(&b, uint64(a.SignedAt.UTC().UnixNano()))
	return b.Bytes()
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

// Validate rejects an anchor that could not describe a real chain segment.
//
// It runs BEFORE any signature check. A valid signature over nonsense is still nonsense, and accepting it
// would put an identity's name on a claim that cannot be checked against anything.
func (a Anchor) Validate() error {
	if a.Service == "" {
		return errors.New("an anchor must name its service")
	}
	if a.ChainID == "" {
		return errors.New("an anchor must name its chain")
	}
	if a.LineCount == 0 {
		return errors.New("an anchor covering no lines commits to nothing")
	}
	if len(a.ChainMAC) != 64 {
		return fmt.Errorf("a chain MAC is 64 hex characters, got %d", len(a.ChainMAC))
	}
	if _, err := hex.DecodeString(a.ChainMAC); err != nil {
		return fmt.Errorf("the chain MAC is not hex: %w", err)
	}
	return nil
}

// ErrSignature is returned when the Ed25519 signature does not verify.
var ErrSignature = errors.New("the anchor signature is not valid")

// Verify checks sa against pub.
//
// It returns nil only when the signature is valid AND the anchor names pub as its signer. A record
// verified under a key it does not name is a record whose provenance a reader would have to reconstruct
// by guessing.
func Verify(pub ed25519.PublicKey, sa SignedAnchor) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid public key size")
	}
	if err := sa.Anchor.Validate(); err != nil {
		return err
	}
	if fp := identity.Fingerprint(pub); sa.KeyFP != fp {
		return fmt.Errorf("the anchor names key %s but was checked against %s", identity.Short(sa.KeyFP), identity.Short(fp))
	}
	raw, err := hex.DecodeString(sa.Signature)
	if err != nil {
		return fmt.Errorf("the anchor signature is not hex: %w", err)
	}
	if !ed25519.Verify(pub, sa.Anchor.CanonicalBytes(), raw) {
		return ErrSignature
	}
	return nil
}

// Digest identifies this signed anchor to its successor, which names it in PrevAnchor.
//
// It is taken over the SIGNATURE rather than the record, because the signature already commits to every
// field, which makes this both shorter and impossible to collide without breaking Ed25519 first.
//
// Note for implementers: the hash covers the hexadecimal signature TEXT, not the raw signature bytes.
// Reaching for the raw bytes is the instinctive choice and produces a different digest.
func (sa SignedAnchor) Digest() string {
	sum := sha256.Sum256([]byte(sa.Signature))
	return hex.EncodeToString(sum[:])
}

// FollowsFrom reports whether sa is the immediate successor of prev from the same identity.
//
// This is what makes WITHHOLDING visible rather than merely tampering: a relay can drop an anchor it
// cannot forge, and the gap in AnchorSeq plus the broken PrevAnchor link names precisely what went
// missing.
func (sa SignedAnchor) FollowsFrom(prev SignedAnchor) bool {
	return sa.KeyFP == prev.KeyFP &&
		sa.AnchorSeq == prev.AnchorSeq+1 &&
		sa.PrevAnchor == prev.Digest()
}
