# SFTP.cloud signed evidence formats

Chain format version 2. Anchor format v1. Observation batch format v1. Draft, 2026-08-19.

This document specifies the formats of the signed evidence SFTP.cloud publishes about itself, and the
exact procedures for verifying them. It is written so that an independent implementation can be built
from this document alone, without reading our code.

Sections 1 through 9 cover the tamper evident LOGS the components produce: what a machine did.
Section 10 covers the availability OBSERVATIONS the independent monitors produce: what an outside
witness saw. They are separate formats with separate domain strings and no shared bytes, specified
together because they answer the same question about different evidence, and because in a dispute a
reader is likely to hold both.

## 0. What this format proves, and what it does not

Read this section before quoting any result produced by a verifier.

The format has three layers, and they prove different things to different people.

1. **The per line chain** is an HMAC. It proves that nobody **who did not hold the chain key**
   altered, inserted, removed or reordered a line. It proves nothing whatsoever against whoever holds
   that key, because with a MAC the ability to verify and the ability to forge are the same ability.
   On a machine its owner controls, this layer alone makes the log a diary.

2. **Anchors** are Ed25519 signatures over small commitments to what the log contained. They are
   asymmetric, so anyone holding the public key can check them and nobody but the holder of the
   private key can produce them. This layer is third party checkable. It still does not stop the
   holder of the private key from rewriting old history and re-signing all of it.

3. **Witnessing** is the layer that carries the claim. An anchor that was delivered to and retained by
   an independent party at a time that has already passed cannot be revised afterwards. Matching a
   witnessed anchor means the log has not been rewritten since that moment, not even by the party who
   owns the machine and holds every key on it.

The honest claim, and the sentence a verifier's output supports: **the producer is cryptographically
bound to its contemporaneous record, and cannot alter it later.** Cryptography cannot say whether what
was written was true when it was written. It can say that nobody rewrote it afterwards.

## 1. Terminology

- **MAC**: a symmetric authentication tag. In this format, always HMAC-SHA256, always rendered as 64
  lowercase hexadecimal characters. A MAC is never called a signature, in this document, in the wire
  format, or in any output. Chain format version 1 named this field `sig`; that was wrong, it is frozen
  on disks nobody controls, and section 3.6 says what to do about it.
- **Signature**: an Ed25519 signature, rendered as 128 lowercase hexadecimal characters. Only anchors
  carry one.
- **Chain**: a sequence of log files produced by one logger instance, linked so that removing a whole
  file is detectable.
- **Segment**: the portion of a chain contained in one file. In an unrotated file, the segment is the
  whole file.
- **BE64(n)**: the 8 byte big endian encoding of the unsigned 64 bit integer n.

Hexadecimal output is lowercase everywhere. Hexadecimal input should be compared case insensitively only
if an implementation chooses to be lenient; the reference implementation compares exact strings.

## 2. Layout

A signed log directory contains one or more files:

```
sc-conn-audit.2026-08-15T09-00-00.jsonl        a segment
sc-conn-audit.2026-08-14T09-00-00.jsonl.gz     an older segment, compressed
sc-conn-audit.jsonl                            a SYMLINK to the current segment
anchors/                                       the producer's anchor spool (not part of this format)
```

Each `.jsonl` file holds one JSON object per line, UTF-8, newline terminated.

## 3. Layer 1: the signed log file

### 3.1 Line shape

Every signed line is a complete JSON object on one line, ending with `}`, followed by `\n`. The chain
MAC is always the **last field** of the object:

```json
{"time":"2026-08-15 09:23:13.205","level":"info","service":"sc-conn","message":"...","mac":"3f0a...9c"}
```

### 3.2 The signable region

Given one raw line `L` with the trailing newline removed:

1. `L` must end with `}`. Let `W = L` with that final byte removed.
2. Find the **last** occurrence in `W` of the byte string `,"mac":"`. Call its offset `i` and its length
   `f` (8 bytes). If it is absent, look for `,"sig":"` instead, which is the frozen version 1 name;
   `f` is then the length of the constant that actually matched.
3. The remainder `W[i+f:]` must be exactly 65 bytes: 64 hexadecimal characters followed by `"`. The
   first 64 are the **stated MAC** of this line.
4. The **signable region** is `W[:i]`, taken as raw bytes.

The last occurrence rule matters: a log message may legitimately contain the text `,"mac":"`, and the
authentic field is always the final one.

Implementations **must** treat the signable region as opaque bytes. Decoding the line as JSON and
re-serializing it would verify one thing and report another.

### 3.3 The chain MAC

Let `K` be the segment's chain key (section 4) and let `P` be the previous line's MAC as **32 raw
bytes**, not as text. For the first line of a segment, `P` is 32 zero bytes.

```
MAC_i = HMAC-SHA256(K, signable_i || P_i)
P_(i+1) = MAC_i
```

The stated MAC on the line must equal `hex(MAC_i)`.

**On a mismatch**, a verifier reports the line and then continues the chain from the value **stated on
disk**, not from the value it computed. This is deliberate: continuing from the computed value would
cascade a single edited line into a report condemning every line after it, which tells an investigator
nothing about where to look. Detection is unaffected, because an insertion or a deletion still breaks
the very next link either way. An independent implementation that continues from the computed value
will produce different reports for the same evidence, so this rule is normative.

### 3.4 The segment start line

The first line of every segment is a self describing start line, recognised by the field `chain_init`
with the value `"1"`. In chain format version 2 it is constructed exactly as follows, with the fields in
this order:

```
{"time":"<ts>","level":"info","service":"<service>","chain_init":"1","chain_v":"2","chain_id":"<id>","chain_seq":"<n>"[,"prev_mac":"<64 hex>"],"mac":"<64 hex>"}
```

- `<ts>` is `YYYY-MM-DD HH:MM:SS.mmm`. The producer decides whether it is UTC or local; audit logs use
  UTC. The timestamp is covered by the MAC but is not used in any structural check.
- `chain_v` is `"2"`.
- `chain_id` is 128 bits of randomness as 32 hexadecimal characters. It only has to be unique. It is
  neither secret nor required to be unpredictable.
- `chain_seq` is the segment's position in the chain as a decimal string, `"0"` for the first.
- `prev_mac` is the **final MAC of the preceding segment**. It is **omitted entirely** for the first
  segment of a chain. Omission and a value of 64 zeros are different claims: "this chain starts here"
  must not look like "the file before this one ended in zeros".

The continuity fields sit inside the signable region, before the trailing MAC, so they are covered by
it. A file cannot be renumbered or repointed at a different predecessor without invalidating the very
line that makes the claim.

The start line is **line 1 of its segment**. Line counting, including the `lineCount` an anchor commits
to, begins here.

### 3.5 Files, rotation and discovery

A rotation ends a segment and begins the next one in a new file. The producer captures the closing MAC
of the old segment, increments `chain_seq`, derives a new chain key for the new file (section 4.1), and
writes the new start line naming the old segment's closing MAC in `prev_mac`.

When verifying a directory:

- consider only files whose name ends in `.jsonl` or `.jsonl.gz`, case insensitively;
- decompress `.gz` transparently;
- **skip symlinks.** Producers keep a stable name such as `sc-conn-audit.jsonl` as a symlink to the
  current file. A verifier that follows it reads the live segment twice and reports a chain that
  restarts in the middle of its own run: a false alarm on a healthy log, which is the fastest way to
  teach people to ignore the tool;
- sort the remaining paths lexicographically, then verify each in turn and accumulate the segments.

### 3.6 Chain format version 1, frozen

Version 1 files carry no `chain_v`, `chain_id`, `chain_seq` or `prev_mac`, reset the chain to 32 zero
bytes at every rotation, and name the per line value `sig` rather than `mac`.

A version 2 verifier **must** read them: absence of `chain_v` identifies a version 1 segment, the `sig`
field name is accepted, and the cross file continuity checks of section 7.4 are **skipped** for those
segments. Reporting a continuity break in a log that never claimed to link would be a false accusation.

No new file is ever written in version 1, and no existing file is ever rewritten to change its
vocabulary. Version 1 files exist on disks nobody controls, so this fallback is permanent.

## 4. Chain keys

### 4.1 Derived per file keys

Producers that hold a log identity (section 4.3) derive a fresh key for every file. The root key never
enters the logger and a leaked key costs exactly one file.

```
salt = utf8(chain_id) || BE64(chain_seq)
info = utf8("sftp.cloud/log-chain-key/v1")
K    = HKDF-SHA256(secret = <identity private key, 64 bytes>, salt, info, L = 32)
```

HKDF is RFC 5869 extract then expand with SHA-256. The secret is the **full 64 byte Ed25519 private
key** as Go represents it, that is the 32 byte seed followed by the 32 byte public key, exactly as
stored in the identity file.

Both inputs come from the file's own start line, so any holder of the identity can re-derive any file's
key with nothing escrowed, stored beside the log, or transported.

### 4.2 Passphrase keys

A log signed with a passphrase rather than an identity uses one key for every file:

```
K = SHA-256(utf8(passphrase))
```

Raw 32 byte key material may also be supplied directly, in which case it is used as the HMAC key
exactly as given, with no hashing.

### 4.3 The identity key file

The log identity lives in the producer's data directory as `logid.key`, mode 0600 (and an owner only
ACL on Windows). It is JSON:

```json
{
  "comment": "sftp.cloud log signing identity; back this up, and never copy it to another machine",
  "private_key": "<base64, 64 bytes>",
  "public_key": "<base64, 32 bytes>"
}
```

Both key fields are standard base64. The stored public key can disagree with the private key in a hand
edited file, so a reader **must** check that the public half derives from the private half and reject
the file if it does not.

A **verifier must never create this file.** Minting an identity is a producer action. A verifier
pointed at the wrong directory must fail with a diagnostic and must leave nothing behind: writing into
an evidence tree is not acceptable behaviour for a forensic tool.

## 5. Layer 2: anchors

An anchor is a signed commitment to a **prefix** of one segment: lines 1 through `lineCount` of the file
at position `seq` in chain `chainId` produce the chain MAC `chainMac`.

Anchors are produced when a segment closes (a rotation, or the logger shutting down) and on a timer, so
that a slowly rotating log is not a long stretch of unwitnessed history.

### 5.1 JSON shape

```json
{
  "service": "sc-conn",
  "keyFp": "<64 hex>",
  "chainId": "<32 hex>",
  "seq": 0,
  "lineCount": 128,
  "chainMac": "<64 hex>",
  "first": "2026-08-15T09:00:00.000000000Z",
  "last": "2026-08-15T09:23:13.205538975Z",
  "final": false,
  "anchorSeq": 7,
  "prevAnchor": "<64 hex>",
  "signedAt": "2026-08-15T09:23:14.001002003Z",
  "signature": "<128 hex>"
}
```

- `service` names the producing component: `sc-conn`, `sc-head`, `sc-portal`.
- `keyFp` names the signing identity (section 5.4).
- `chainMac` is the value of the log chain's MAC at line `lineCount`. It is a MAC, and only the
  `signature` field is a signature.
- `first`, `last` and `signedAt` are RFC 3339 with nanoseconds and are **always UTC**. A local zone
  offset inside signed evidence reads as sloppiness at best and manipulation at worst.
- `final` reports that the segment is closed and will gain no further lines.
- `anchorSeq` is monotonic across every anchor this identity has ever produced, **across chains**. The
  producer owns it and must persist it: a counter that restarts looks exactly like a replay.
- `prevAnchor` is the digest of this identity's previous signed anchor (section 5.5), omitted for the
  very first.

### 5.2 Validity

Before its signature is checked, an anchor must satisfy all of:

- `service` is not empty;
- `chainId` is not empty;
- `lineCount` is greater than zero, since an anchor covering no lines commits to nothing;
- `chainMac` is exactly 64 characters and decodes as hexadecimal.

An anchor failing any of these is rejected without checking the signature. A valid signature over
nonsense is still nonsense, and would put an identity's name on a claim that cannot be checked against
anything.

### 5.3 Canonical encoding and signature

The signature covers a hand rolled, length prefixed byte string, not the JSON. JSON offers several ways
to write the same value, and a signature is only as good as the uniqueness of what it covers.

Let `LP(s) = BE64(byte length of s) || utf8(s)`.

```
canonical =
    "sftp.cloud/log-anchor/v1\x00"          25 bytes: 24 ASCII characters and one NUL
 || LP(service)
 || LP(keyFp)
 || LP(chainId)
 || BE64(seq)
 || BE64(lineCount)
 || LP(chainMac)
 || BE64(uint64(first  as Unix nanoseconds))
 || BE64(uint64(last   as Unix nanoseconds))
 || (final ? 0x01 : 0x00)
 || BE64(anchorSeq)
 || LP(prevAnchor)
 || BE64(uint64(signedAt as Unix nanoseconds))
```

Notes for implementers:

- The domain prefix is not decoration. It makes bytes signed for any other purpose unreplayable as an
  anchor, and an anchor unreplayable as anything else, even if some future code shares the key by
  mistake. The `v1` in the string means a future format change becomes a different domain rather than
  an ambiguity.
- Every string is length prefixed so that no pair of adjacent fields can be slid across the boundary
  between them. Without it, `{chainId:"a", chainMac:"b"}` and `{chainId:"ab", chainMac:""}` would sign
  identical bytes.
- Unix nanoseconds are a signed 64 bit count converted to unsigned by two's complement. Times are
  converted to UTC first; this does not change the value, and is stated so that no implementation
  believes the offset matters.
- `signature = hex(Ed25519-Sign(private key, canonical))`, 128 lowercase hexadecimal characters.

### 5.4 Key fingerprint

```
keyFp = hex(SHA-256(public key, 32 raw bytes))
```

The public key remains the authority; the fingerprint is only how it is named in records and on the
wire. The first 16 characters are used as a human comparable short form and must never be used as an
identifier.

Verification **must** additionally require that the anchor's `keyFp` equals the fingerprint of the key
being verified against. A record verified under a key it does not name is a record whose provenance a
reader has to reconstruct by guessing.

Public keys are transported as standard base64 of the 32 raw bytes.

### 5.5 Anchor digest and the anchor chain

```
digest = hex(SHA-256( ASCII of the anchor's hexadecimal signature string ))
```

Note carefully: the hash is taken over the **128 character hex text** of the signature, not over the 64
raw signature bytes. This is the single most likely place for an independent implementation to diverge.

The signature already commits to every field, so hashing it is both shorter than hashing the record and
impossible to collide without breaking Ed25519 first.

Anchor `B` is the immediate successor of anchor `A` from the same identity when all of:

```
B.keyFp      == A.keyFp
B.anchorSeq  == A.anchorSeq + 1
B.prevAnchor == digest(A)
```

This is what makes **withholding** visible rather than merely tampering. A relay can drop an anchor it
cannot forge; the gap in `anchorSeq` plus the broken `prevAnchor` link names precisely what went
missing.

## 6. Layer 3: witnessing (informative)

Not part of the on disk format, and stated so that a verifier's output is not over read.

Producers deliver their anchors to an independent party which stores them append only, refuses a
contradicting anchor for an already witnessed `(keyFp, anchorSeq)` pair, records identity rotations
explicitly, and reports gaps. An anchor that has been witnessed is one the producer can no longer
revise.

The SFTP.cloud Portal witnesses Connector and Head anchors, and publishes its own anchor heads at an
unauthenticated endpoint so that third parties can pin them independently. Self witnessing is a circle
and proves nothing on its own; what has adversarial value is a retrieval that the retrieving party can
timestamp. If nobody pins a published head, publishing it changes nothing.

## 7. Verification procedures

### 7.1 Verify a chain

For each file, in the discovery order of section 3.5: read lines, and for each non blank line apply
section 3.2 to obtain the signable region and the stated MAC. On a line carrying `chain_init":"1"`,
close the current segment, start a new one, record `chain_v`, `chain_id`, `chain_seq` and `prev_mac`,
reset the running MAC to 32 zero bytes, and obtain the segment's key (section 4). Then apply section 3.3
to every line, including the start line itself.

Report, and do not resolve:

- a line whose stated MAC does not match;
- a line with no MAC field at all, which in a log that is supposed to be signed is the most interesting
  line in the file;
- a malformed MAC field;
- a signed line appearing before any segment start, which usually means the head of the file was
  removed;
- a segment for which no key is available.

Field values are read by scanning the raw bytes for `"name":"` and taking up to the next `"`, for the
same reason the signable region is opaque: the line is signed as bytes and must be read as bytes.

### 7.2 Verify an anchor

Check validity (section 5.2), check that `keyFp` matches the public key being used (section 5.4), then
verify the Ed25519 signature over the canonical bytes (section 5.3). No log file is required.

### 7.3 Verify a log against an anchor

**Always verify the anchor's signature first.** Checking a log against an unverified claim answers a
question nobody asked, since any attacker can write an anchor matching the log they just rewrote.

Then replay the chain (section 7.1) and capture the running MAC at exactly line `lineCount` of the
segment identified by `(chainId, seq)`. Three outcomes:

- the segment never reaches that line: the anchored history is not all present;
- the captured MAC differs from `chainMac`: the log has been altered since the anchor was signed;
- the captured MAC equals `chainMac`: the anchored prefix is intact, and if the anchor was witnessed at
  a moment already past, the log has not been rewritten since that moment.

Problems found elsewhere in the file set do not invalidate the anchored prefix, and must be reported
separately rather than folded into the anchor verdict.

### 7.4 Verify continuity across files

These checks require that **every segment was replayed to its end**. A verifier that stopped early, for
example at the first violation, does not have the true closing MAC of the segment it abandoned, and
**must skip these checks and say that it skipped them** rather than run them on incomplete data.

This is normative because the failure is not a missing finding but an invented one: the abandoned segment
is absent or incomplete in the set, so a single edited line reports as a **deleted file**, and an
investigator goes looking for a deletion that never happened. A false accusation that evidence was
destroyed is worse than no report at all.

Using the segments accumulated in section 7.1, ignoring any with no `chain_v`:

1. group by `chain_id` and sort each group by `chain_seq`;
2. for the lowest numbered segment of a chain, if its `chain_seq` is not 0 and it names no `prev_mac`,
   report that earlier files are missing;
3. for each subsequent segment, report a gap when `chain_seq` is not exactly one more than its
   predecessor's, naming how many files are absent;
4. for each subsequent segment, report a break when its `prev_mac` does not equal the predecessor
   segment's closing MAC, meaning a file has been altered, replaced or reordered.

This is the check that makes deleting a **whole file** visible. Every individual file can verify
perfectly while the set is missing a week of history, which is exactly what an attacker with file access
attempts first.

## 8. Conformance corpus

A conforming implementation must reproduce the reference results for the corpus, which is generated
deterministically from a fixed seed rather than committed, so that no key material ever enters a public
repository. The reference generator is a second implementation of this document, written from it rather
than from the verifier, so that the two can disagree.

Cases, with the expected verdict for each:

1. a clean single file chain: verifies;
2. a clean multi file chain including gzipped segments and the producer's live symlink: verifies, and the
   symlinked file is **not** counted twice;
3. one edited line: fails, naming **exactly that line** and no others;
4. one deleted line: fails;
5. an entire middle segment deleted: every surviving file still verifies **on its own**, and the directory
   pass fails naming the missing file;
6. segments renamed so that file order contradicts chain order: **verifies**, because ordering is carried
   by the segment headers rather than by file names;
7. a chain rewritten and correctly re-MACed with the producer's own identity: **passes** chain
   verification, and fails against an anchor signed over the original. This is the case the whole design
   exists for, and case 7a is its shadow: the same rewrite with a **fresh** anchor is entirely self
   consistent, and nothing local can tell the difference;
8. a frozen version 1 file: verifies, and produces **no** continuity findings;
9. an unsigned line appended: fails by default, and is downgraded only when unsigned lines are explicitly
   allowed;
10. a file with its head removed: fails, naming the missing beginning rather than replaying from a guessed
    starting point;
11. a segment for which no key is available: reported, never treated as clean;
12. anchors: a valid one verifies; one with any single field altered fails; one naming a different key
    fails even though its signature is intact; one that commits to nothing is refused before its signature
    is checked; and one with a predecessor withheld does not follow from it;
13. an identity file whose public half does not belong to its private half: refused.

Every fixture key is derived from a fixed test seed and is worthless outside the corpus.

## 9. Compatibility rules

- Chain format version 1 is frozen and read forever. Its `sig` field name is never revived and never
  rewritten.
- New fields may be added to the log line before the trailing MAC field; a verifier that does not
  recognise them still verifies the line, because the signable region is opaque bytes.
- The anchor canonical encoding is **positional**. A new field can only be added by defining a new
  domain string, which makes it a different signature domain and therefore a different format version.
  Nothing may be inserted into, removed from, or reordered within the version 1 encoding.
- The observation batch canonical encoding is **positional** under the same rule, and its domain string
  is distinct from the anchor's, so neither can ever be replayed as the other.
- The format version and the tool version are versioned separately. The tool will move faster than the
  format, and it must be possible to say which format a file is in without reference to which tool
  wrote it.

## 10. Observation batches

An observation batch is a signed statement by one independent monitor about what it saw, minute by
minute, on a set of targets over a set of UTC days.

It is specified here because SFTP.cloud's service level agreement settles disputes on what a **majority
of the available monitors** observed, and SFTP.cloud performs that arithmetic. A customer checking a
service credit therefore needs three things: the monitors' public keys, the signed batches, and an
encoder they can run themselves. Publishing the first two while keeping the third private would leave
the evidence checkable only by the party being checked.

### 10.1 What a batch proves, and what it does not

A valid signature proves that the named monitor made exactly this statement, and that nobody has
altered it since. It does not prove the statement is TRUE: a monitor could report an outage that did
not happen, or miss one that did.

That is why no single monitor's testimony decides anything. The fleet is placed so that no one hosting
provider holds a majority of the vote and the provider hosting the measured service holds the minority,
and a minute is resolved only when at least three monitors reported on it. What this format gives you
is the ability to check each witness's statement individually, and to see whether any of them went
missing on the way to you.

**A minute absent from `probed` is neither up nor down.** It is a minute with no evidence, and any
honest arithmetic over these records must leave it out of the numerator and the denominator together.
Treating an unprobed minute as an up minute is the single easiest way to read these records too kindly,
and it is the error that flatters the service provider.

### 10.2 JSON shape

```json
{
  "monitor": "mon-aws-use1",
  "keyFp": "<64 hex>",
  "seq": 7,
  "prevBatch": "<64 hex>",
  "signedAt": "2026-08-19T04:05:06.000000000Z",
  "entries": [
    {
      "target": "head-3",
      "service": "sftp",
      "day": "2026-08-19",
      "probed": "<base64>",
      "down": "<base64>"
    }
  ],
  "signature": "<128 hex>"
}
```

- `monitor` names the vantage point. It is inside the signed bytes deliberately: without it, a batch
  lifted off one transport and replayed on another would silently become another monitor's testimony,
  and a quorum is a count of DISTINCT vantage points.
- `keyFp` is the hex SHA-256 of the signing public key, exactly as in section 5.4. A verifier MUST
  refuse a batch whose `keyFp` is not the fingerprint of the key it was handed.
- `seq` is monotonic from 1 across every batch this monitor has ever published, and never restarts. A
  counter that restarts is indistinguishable from a replay.
- `prevBatch` is the digest (section 10.5) of the previous batch from this monitor. It is absent or
  empty only for `seq` 1.
- `signedAt` is when the signature was produced, which is not when the minutes were observed.
- `target` and `service` identify what was observed. This format attaches no meaning to either string
  beyond identity; for SFTP.cloud they are a Head identifier and a protocol name such as `sftp`,
  `ftpes-explicit`, `ftps-implicit` or `https`.
- `day` is the UTC day, `YYYY-MM-DD`.
- `probed` and `down` are minute bitmaps for that UTC day (section 10.3).
- `signature` is the Ed25519 signature over the canonical bytes of section 10.4.

Batches are bounded: at most 2048 entries, and each bitmap at most 512 base64 characters. A verifier
MAY refuse a batch that exceeds either.

### 10.3 Minute bitmaps

A UTC day holds 1440 minutes. A bitmap is those 1440 bits, most significant bit first within each byte,
packed into 180 bytes and then standard base64 encoded. Bit *n* is minute *n* counting from 00:00 UTC.

A bitmap MAY be shorter than 180 bytes once decoded, in which case every minute beyond its length is
absent. Trailing zero bytes carry no meaning and a producer MAY trim them.

`probed` marks the minutes the monitor looked. `down` marks the minutes it looked and did not get a
usable answer. In any honest record `down` is a subset of `probed`.

Both are **cumulative for the day** and are republished in full by every batch that touches that day.
That is what makes a batch idempotent and a lost batch self healing: the next one carries everything
the lost one did. It also means the newest batch mentioning a given `(target, service, day)` supersedes
every earlier one for that triple.

Within one batch, a `(target, service, day)` triple MUST NOT appear twice. Two statements about one
triple would fold into one row wherever they are stored, silently discarding one of them.

### 10.4 Canonical bytes

The signature covers the following byte string, and nothing else. Every field is written in this order,
positionally; there is no self description and no field is optional.

```
"sftp.cloud/sla-observation/v1\x00"
len(monitor)      as uint64 big endian, then monitor
len(keyFp)        as uint64 big endian, then keyFp
seq               as uint64 big endian
len(prevBatch)    as uint64 big endian, then prevBatch
signedAt          as uint64 big endian, UNIX NANOSECONDS in UTC
len(entries)      as uint64 big endian
  for each entry, in canonical order:
    len(target)   as uint64 big endian, then target
    len(service)  as uint64 big endian, then service
    len(day)      as uint64 big endian, then day
    len(probed)   as uint64 big endian, then probed
    len(down)     as uint64 big endian, then down
```

Three details are load bearing and each has a failure it prevents:

- **The domain prefix.** It makes bytes signed for another purpose unreplayable as an observation batch
  and a batch unreplayable as anything else, even if a future implementation shares a key by mistake.
  In particular a monitor also signs log anchors, and the two domains keep those apart.
- **Every string is length prefixed.** Without it, adjacent fields slide across the boundary between
  them: `{target:"head", service:"1"}` and `{target:"head1", service:""}` would produce identical bytes,
  and a party controlling one field could forge a claim about another.
- **The entry count is signed.** Without it a suffix of entries could be truncated and the remaining
  bytes would still parse as a shorter, perfectly valid batch.

**Canonical order.** Before signing or verifying, entries are sorted by `day`, then `target`, then
`service`, all as byte comparisons; the sort is stable. `monitor`, `target`, `service`, `day`, `probed`
and `down` are trimmed of leading and trailing whitespace; `service`, `keyFp` and `prevBatch` are
lowercased; `signedAt` is converted to UTC. Entry order carries no meaning, so leaving it to the
producer would make verification fail at random on honest records.

### 10.5 Batch digest

```
digest = hex( SHA-256( ascii( signature ) ) )
```

The hash covers the hexadecimal signature TEXT, not the raw signature bytes. This is the same
construction as the anchor digest in section 5, and the same note applies: reaching for the raw bytes is
the instinctive choice and produces a different digest.

Taking the digest over the signature rather than the record is deliberate. The signature already commits
to every field, which makes the digest both shorter and impossible to collide without breaking Ed25519
first.

### 10.6 Verifying a batch

1. Apply the canonical ordering of section 10.4.
2. Check the batch is well formed: `monitor` non empty; `keyFp` 64 hex characters; `seq` at least 1;
   `prevBatch` empty exactly when `seq` is 1 and 64 hex characters otherwise; `signedAt` non zero; at
   least one entry and no more than 2048; every `day` a valid date; no repeated
   `(target, service, day)`. **Do this before checking the signature.** A valid signature over an
   impossible batch is still impossible, and accepting it puts a monitor's name on a claim that cannot
   be checked against anything.
3. Check `keyFp` equals the SHA-256 fingerprint of the public key you are verifying with. A record
   verified under a key it does not name leaves its provenance to be reconstructed by guessing.
4. Check the Ed25519 signature over the canonical bytes.

### 10.7 Verifying a run, and what a gap means

Given several batches from one monitor, ordered by `seq`:

1. Verify each batch as in section 10.6.
2. For each adjacent pair, check that the later one has the same `keyFp` and `monitor`, a `seq` exactly
   one greater, and a `prevBatch` equal to the digest of the earlier one.

A break at step 2 is the finding this chain exists to produce. **Anyone in the path can drop a batch
they cannot forge; the chain is what stops them hiding the drop.** A missing `seq` with an unmatched
`prevBatch` names precisely what went missing, and no amount of subsequent well formed traffic closes
it: continuity is measured from the last position with no hole below it, not from the newest batch.

The same applies to a party holding the batches on the monitor's behalf, including SFTP.cloud. If you
were given a run by SFTP.cloud and it verifies with no gaps, that establishes that nothing was removed
from it after the monitor signed it. It does not establish that the monitor sent nothing else. For that,
compare against a copy you did not get from us, which is the same advice section 6 gives for anchors and
for the same reason.
