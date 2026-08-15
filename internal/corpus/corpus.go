// Package corpus builds signed log fixtures for tests.
//
// It is TEST ONLY and is never linked into the tool. It exists for two reasons, and the second matters
// more than the first.
//
// The obvious reason is that the verifier needs evidence to verify, including deliberately damaged
// evidence, and committing real signed logs plus a real identity file to a public repository would put key
// material into git history and into every secret scanner that looks at it. So the fixtures are generated
// deterministically from a fixed seed at test time, and nothing secret is ever committed.
//
// The better reason is that this is a SECOND IMPLEMENTATION of the format, written from SPEC.md rather
// than from the verifier's source. Its line construction, its key derivation and its anchor canonical
// encoding are written out here in full rather than being borrowed from the packages under test. A fixture
// generator that called into the code it is testing would agree with that code by construction and would
// prove nothing about either; this one can disagree, and the tests check that it does not.
package corpus

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// SignedAnchor mirrors the published anchor JSON. Declared here rather than imported so that a change to
// the verifier's struct tags cannot silently propagate into the fixtures that are supposed to catch it.
type SignedAnchor struct {
	Service    string    `json:"service"`
	KeyFP      string    `json:"keyFp"`
	ChainID    string    `json:"chainId"`
	Seq        uint64    `json:"seq"`
	LineCount  uint64    `json:"lineCount"`
	ChainMAC   string    `json:"chainMac"`
	First      time.Time `json:"first"`
	Last       time.Time `json:"last"`
	Final      bool      `json:"final"`
	AnchorSeq  uint64    `json:"anchorSeq"`
	PrevAnchor string    `json:"prevAnchor,omitempty"`
	SignedAt   time.Time `json:"signedAt"`
	Signature  string    `json:"signature"`
}

// Producer writes one chain, exactly as SPEC.md sections 3 and 5 describe it.
type Producer struct {
	Service string
	ChainID string
	Priv    ed25519.PrivateKey
	Pub     ed25519.PublicKey

	seq         uint64
	prevMAC     []byte
	prevFileMAC []byte
	lineCount   uint64
	first       time.Time
	last        time.Time

	anchorSeq  uint64
	prevAnchor string

	clock time.Time
}

// New builds a producer with a throwaway identity derived from seed. The identity is deterministic and
// worthless outside the tests.
func New(seed byte, service, chainID string) *Producer {
	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	priv := ed25519.NewKeyFromSeed(raw)
	return &Producer{
		Service: service,
		ChainID: chainID,
		Priv:    priv,
		Pub:     priv.Public().(ed25519.PublicKey),
		prevMAC: make([]byte, 32),
		clock:   time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC),
	}
}

// KeyFP is the identity's fingerprint: hex SHA-256 of the public key.
func (p *Producer) KeyFP() string {
	sum := sha256.Sum256(p.Pub)
	return hex.EncodeToString(sum[:])
}

// Seq is the current file number within the chain.
func (p *Producer) Seq() uint64 { return p.seq }

// ChainKey derives the current file's HMAC key: HKDF-SHA256 over the identity private key, salted with the
// chain id and the big endian file number, under the chain key purpose string.
func (p *Producer) ChainKey() []byte {
	var seqRaw [8]byte
	binary.BigEndian.PutUint64(seqRaw[:], p.seq)
	salt := append([]byte(p.ChainID), seqRaw[:]...)
	key, err := hkdf.Key(sha256.New, p.Priv, salt, "sftp.cloud/log-chain-key/v1", 32)
	if err != nil {
		panic(err)
	}
	return key
}

func (p *Producer) tick() time.Time {
	p.clock = p.clock.Add(1500 * time.Millisecond)
	return p.clock
}

// mac computes HMAC-SHA256(key, signable || prevMAC) and advances the chain.
func (p *Producer) mac(signable string) string {
	m := hmac.New(sha256.New, p.ChainKey())
	m.Write([]byte(signable))
	m.Write(p.prevMAC)
	sum := m.Sum(nil)
	p.prevMAC = sum
	return hex.EncodeToString(sum)
}

// StartSegment returns the start line of the current file. It resets the running chain to 32 zero bytes,
// names the predecessor when there is one, and counts itself as line 1.
func (p *Producer) StartSegment() string {
	p.prevMAC = make([]byte, 32)
	t := p.tick()
	signable := `{"time":"` + t.Format("2006-01-02 15:04:05.000") + `","level":"info","service":"` + p.Service +
		`","chain_init":"1","chain_v":"2","chain_id":"` + p.ChainID +
		`","chain_seq":"` + fmt.Sprint(p.seq) + `"`
	// Omitted, not zeroed, for the first file: "this chain starts here" and "the file before this one ended
	// in zeros" must not look the same to a verifier.
	if len(p.prevFileMAC) > 0 {
		signable += `,"prev_mac":"` + hex.EncodeToString(p.prevFileMAC) + `"`
	}
	line := signable + `,"mac":"` + p.mac(signable) + `"}`
	p.lineCount = 1
	p.first, p.last = t, t
	return line
}

// Line returns one ordinary signed log line.
func (p *Producer) Line(message string) string {
	t := p.tick()
	signable := `{"time":"` + t.Format("2006-01-02 15:04:05.000") + `","level":"info","service":"` + p.Service +
		`","message":"` + message + `"`
	line := signable + `,"mac":"` + p.mac(signable) + `"}`
	p.lineCount++
	p.last = t
	return line
}

// Rotate closes the current file and moves to the next, carrying the closing MAC forward.
func (p *Producer) Rotate() {
	p.prevFileMAC = p.prevMAC
	p.seq++
}

// Anchor signs a commitment to everything written in the current segment so far.
func (p *Producer) Anchor(final bool) SignedAnchor {
	p.anchorSeq++
	sa := SignedAnchor{
		Service:    p.Service,
		KeyFP:      p.KeyFP(),
		ChainID:    p.ChainID,
		Seq:        p.seq,
		LineCount:  p.lineCount,
		ChainMAC:   hex.EncodeToString(p.prevMAC),
		First:      p.first.UTC(),
		Last:       p.last.UTC(),
		Final:      final,
		AnchorSeq:  p.anchorSeq,
		PrevAnchor: p.prevAnchor,
		SignedAt:   p.tick().UTC(),
	}
	sa.Signature = hex.EncodeToString(ed25519.Sign(p.Priv, CanonicalBytes(sa)))
	sum := sha256.Sum256([]byte(sa.Signature))
	p.prevAnchor = hex.EncodeToString(sum[:])
	return sa
}

// CanonicalBytes is this package's own rendering of the anchor signing input, written out from SPEC.md
// section 5.3. The whole value of writing it twice is that a test can compare the two.
func CanonicalBytes(sa SignedAnchor) []byte {
	var b strings.Builder
	b.WriteString("sftp.cloud/log-anchor/v1\x00")
	lp := func(s string) {
		var raw [8]byte
		binary.BigEndian.PutUint64(raw[:], uint64(len(s)))
		b.Write(raw[:])
		b.WriteString(s)
	}
	u64 := func(v uint64) {
		var raw [8]byte
		binary.BigEndian.PutUint64(raw[:], v)
		b.Write(raw[:])
	}
	lp(sa.Service)
	lp(sa.KeyFP)
	lp(sa.ChainID)
	u64(sa.Seq)
	u64(sa.LineCount)
	lp(sa.ChainMAC)
	u64(uint64(sa.First.UTC().UnixNano()))
	u64(uint64(sa.Last.UTC().UnixNano()))
	if sa.Final {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	u64(sa.AnchorSeq)
	lp(sa.PrevAnchor)
	u64(uint64(sa.SignedAt.UTC().UnixNano()))
	return []byte(b.String())
}

// V1Line returns a line in the frozen chain format version 1: the value is named "sig", and the start line
// carries no continuity fields at all.
func (p *Producer) V1Line(message string, start bool) string {
	t := p.tick()
	var signable string
	if start {
		p.prevMAC = make([]byte, 32)
		signable = `{"time":"` + t.Format("2006-01-02 15:04:05.000") + `","level":"info","service":"` + p.Service + `","chain_init":"1"`
	} else {
		signable = `{"time":"` + t.Format("2006-01-02 15:04:05.000") + `","level":"info","service":"` + p.Service +
			`","message":"` + message + `"`
	}
	return signable + `,"sig":"` + p.mac(signable) + `"}`
}
