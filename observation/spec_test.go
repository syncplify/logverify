package observation

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The specification, checked against the code.
//
// SPEC.md section 10 claims this format can be reimplemented from the document alone. That claim is only
// worth something if the document and the code are the same format, and the way they drift is that
// somebody changes the code. So this file re-derives the canonical bytes by following the SPEC's
// pseudocode literally, field by field, and requires the result to equal what the package produces.
//
// It is deliberately a SECOND implementation rather than a call into the first. A test that asked the
// encoder to check itself would pass forever.

// specCanonicalBytes builds the byte string exactly as SPEC.md section 10.4 writes it.
func specCanonicalBytes(b Batch) []byte {
	var out []byte
	putStr := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		out = append(out, n[:]...)
		out = append(out, s...)
	}
	putU64 := func(v uint64) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], v)
		out = append(out, n[:]...)
	}

	out = append(out, "sftp.cloud/sla-observation/v1\x00"...)
	putStr(b.Monitor)
	putStr(b.KeyFP)
	putU64(b.Seq)
	putStr(b.PrevBatch)
	putU64(uint64(b.SignedAt.UTC().UnixNano()))
	putU64(uint64(len(b.Entries)))
	for _, e := range b.Entries {
		putStr(e.Target)
		putStr(e.Service)
		putStr(e.Day)
		putStr(e.Probed)
		putStr(e.Down)
	}
	return out
}

// TestTheCodeEncodesWhatTheSpecDescribes. If this fails, one of the two moved, and every batch signed
// under the other is unverifiable by anyone who implemented from the document.
func TestTheCodeEncodesWhatTheSpecDescribes(t *testing.T) {
	b := Batch{
		Monitor:   "mon-aws-use1",
		KeyFP:     strings.Repeat("ab", 32),
		Seq:       7,
		PrevBatch: strings.Repeat("cd", 32),
		SignedAt:  time.Date(2026, 8, 19, 4, 5, 6, 7, time.UTC),
		Entries: []Entry{
			{Target: "head-3", Service: "sftp", Day: "2026-08-19", Probed: "AAEC", Down: "AAAA"},
			{Target: "head-3", Service: "https", Day: "2026-08-19", Probed: "AAEC", Down: "AAEA"},
			{Target: "head-1", Service: "sftp", Day: "2026-08-18", Probed: "//8=", Down: "AAAA"},
		},
	}
	b.Canonicalize()

	if got, want := b.CanonicalBytes(), specCanonicalBytes(b); string(got) != string(want) {
		t.Fatalf("the encoder and SPEC.md section 10.4 disagree\n code: %s\n spec: %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

// TestTheCanonicalOrderIsTheOneTheSpecStates: day, then target, then service, all as byte comparisons.
func TestTheCanonicalOrderIsTheOneTheSpecStates(t *testing.T) {
	b := Batch{
		Monitor: "m", KeyFP: strings.Repeat("ab", 32), Seq: 1, SignedAt: time.Unix(0, 1).UTC(),
		Entries: []Entry{
			{Target: "b", Service: "sftp", Day: "2026-08-19"},
			{Target: "a", Service: "https", Day: "2026-08-19"},
			{Target: "a", Service: "sftp", Day: "2026-08-19"},
			{Target: "z", Service: "sftp", Day: "2026-08-18"},
		},
	}
	b.Canonicalize()

	want := []string{
		"2026-08-18|z|sftp",
		"2026-08-19|a|https",
		"2026-08-19|a|sftp",
		"2026-08-19|b|sftp",
	}
	for i, e := range b.Entries {
		if got := e.Day + "|" + e.Target + "|" + e.Service; got != want[i] {
			t.Fatalf("entry %d is %s, want %s", i, got, want[i])
		}
	}
}

// TestTheJSONShapeMatchesTheSpec. The document prints a batch as JSON with named fields, so a
// reimplementer will read those names off the page. A struct tag renamed here would silently make every
// published batch unreadable by their parser.
func TestTheJSONShapeMatchesTheSpec(t *testing.T) {
	sb := SignedBatch{
		Batch: Batch{
			Monitor: "mon-aws-use1", KeyFP: strings.Repeat("ab", 32), Seq: 7,
			PrevBatch: strings.Repeat("cd", 32), SignedAt: time.Unix(0, 1).UTC(),
			Entries: []Entry{{Target: "head-3", Service: "sftp", Day: "2026-08-19", Probed: "AAEC", Down: "AAAA"}},
		},
		Signature: strings.Repeat("ef", 64),
	}
	raw, err := json.Marshal(sb)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"monitor", "keyFp", "seq", "prevBatch", "signedAt", "entries", "signature"} {
		if _, ok := doc[field]; !ok {
			t.Fatalf("SPEC.md section 10.2 names a field %q that the JSON does not carry: %s", field, raw)
		}
	}
	entry, ok := doc["entries"].([]any)
	if !ok || len(entry) != 1 {
		t.Fatalf("entries: %s", raw)
	}
	e, _ := entry[0].(map[string]any)
	for _, field := range []string{"target", "service", "day", "probed", "down"} {
		if _, ok := e[field]; !ok {
			t.Fatalf("SPEC.md section 10.2 names an entry field %q that the JSON does not carry: %s", field, raw)
		}
	}
}

// TestTheSpecBoundsAreTheCodeBounds, because SPEC.md quotes both numbers and a reimplementer will enforce
// exactly what it says.
func TestTheSpecBoundsAreTheCodeBounds(t *testing.T) {
	if MaxEntriesPerBatch != 2048 {
		t.Fatalf("SPEC.md section 10.2 says at most 2048 entries; the code allows %d", MaxEntriesPerBatch)
	}
	if MaxBitmapChars != 512 {
		t.Fatalf("SPEC.md section 10.2 says at most 512 base64 characters; the code allows %d", MaxBitmapChars)
	}
	if Domain != "sftp.cloud/sla-observation/v1\x00" {
		t.Fatalf("SPEC.md section 10.4 states a different domain string than %q", Domain)
	}
}

// TestTheDomainCannotCollideWithTheAnchorDomain, which is what stops a monitor's anchor signature being
// presented as testimony about a service, and the reverse. Both are signed by the same key.
func TestTheDomainCannotCollideWithTheAnchorDomain(t *testing.T) {
	const anchorDomain = "sftp.cloud/log-anchor/v1\x00"
	if Domain == anchorDomain {
		t.Fatal("the observation and anchor domains are identical")
	}
	if strings.HasPrefix(Domain, strings.TrimSuffix(anchorDomain, "\x00")) ||
		strings.HasPrefix(anchorDomain, strings.TrimSuffix(Domain, "\x00")) {
		t.Fatal("one domain is a prefix of the other, so a signature over one could be read as the other")
	}
}

// TestVerificationRefusesBeforeItChecksTheSignature, which SPEC.md section 10.6 states as an ordering
// requirement rather than an implementation detail. A valid signature over an impossible batch is still
// impossible, and a reimplementer that checked the signature first would accept records we refuse.
func TestVerificationRefusesBeforeItChecksTheSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// A batch with no entries: genuinely signed, and saying nothing.
	b := Batch{Monitor: "m", KeyFP: "", Seq: 1, SignedAt: time.Now().UTC()}
	sb := SignedBatch{Batch: b, Signature: hex.EncodeToString(ed25519.Sign(priv, b.CanonicalBytes()))}

	err = Verify(pub, &sb)
	if err == nil {
		t.Fatal("a correctly signed but impossible batch verified")
	}
	if err == ErrSignature {
		t.Fatal("the refusal came from the signature check; the well formedness check must run first")
	}
}
