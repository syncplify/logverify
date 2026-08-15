# logverify

Verifies the tamper evident logs produced by [SFTP.cloud](https://sftp.cloud) components: the on premises
Storage Connector, the protocol Heads, and the Portal.

It is published so that the logs can be checked by people who have no reason to trust the party that
produced them, including us. A verification tool that only its author can run is not a control, it is a
claim.

- No dependencies outside the Go standard library.
- Reads only. It never writes to the evidence it is given, never creates a key, and never repairs a file
  mode.
- The format is specified in [SPEC.md](SPEC.md), in enough detail to be reimplemented without reading this
  code. If you would rather write your own verifier than run ours, that is a reasonable thing to want, and
  the specification exists for exactly that.

MIT licensed.

## What a verification result actually proves

Read this before quoting an output anywhere it matters.

The logs have three layers, and only the third carries the claim that matters in a dispute.

**The per line chain is an HMAC.** It proves that nobody **without the key** altered, inserted, removed or
reordered a line. It proves nothing at all against whoever holds that key, because verifying a MAC and
forging one are the same capability. The key lives on the machine that writes the log. So a passing
`logverify verify` says the file was not tampered with by an outsider. It does not say the log is honest.

**Anchors are Ed25519 signatures** over small commitments to what the log contained. Anyone with the public
key can check one and nobody without the private key can produce one. But the producer holds the private
key, and can rewrite old history and re-sign all of it.

**Witnessing is what closes that.** An anchor that an independent party received and retained at a time
that has already passed cannot be revised afterwards. Matching such an anchor means the log has not been
rewritten since that moment, not even by whoever owns the machine and holds every key on it.

Which is why the practical advice is one sentence: **check anchors against a copy you did not get from the
producer.**

The honest claim, and the only one this tool supports: the producer is cryptographically bound to its
contemporaneous record and cannot alter it later. Cryptography cannot say whether what was written was true
when it was written. It can say that nobody rewrote it afterwards.

## Install

```
go install github.com/syncplify/logverify/cmd/logverify@latest
```

Or build it yourself, which is the point:

```
git clone https://github.com/syncplify/logverify
cd logverify
go build ./cmd/logverify
```

There is nothing to download beyond the Go toolchain, so the build works on an air gapped machine and
there is no dependency tree to audit before you believe the result.

## Use

**Check a directory of logs.** This checks more than checking the files one at a time: every file can be
individually perfect while the set is missing a week of history, so the directory pass also verifies that
the files form one unbroken chain.

```
logverify verify -dir /opt/Syncplify/sc-conn/audit -identity /opt/Syncplify/sc-conn
```

`-identity` points at the data directory of the machine that **produced** the log. The per file keys are
derived from the identity there, using values each file states about itself, so nothing has to be stored
beside the log or shipped with it.

For a log signed with a passphrase rather than a machine identity:

```
logverify verify -dir ./logs -key-file ./key.txt
printf %s "$KEY" | logverify verify -dir ./logs -key-file -
```

There is deliberately no `-secret` flag. A key on the command line is readable by every process on the
machine and is kept in your shell history, and this particular key lets its holder rewrite the log and
re-MAC it perfectly.

**Check a log against a signed anchor**, which is the check that means something to a third party:

```
logverify anchor -dir ./logs -anchor ./anchor.json -pubkey @./producer.pub -identity ./producer-data-dir
```

The anchor's signature is verified first, always. Checking a log against an unverified claim answers a
question nobody asked, since anyone can write an anchor matching a log they have just rewritten.

## Exit codes

```
0  verified
1  did not verify
2  bad arguments, or the evidence could not be read
```

`1` and `2` are kept apart on purpose: "this evidence is bad" and "I could not read this evidence" are
different findings, and a script that conflates them will eventually report the second as the first.

## Contributing

Bug reports about the verifier, and about the specification, are both welcome. A case where this tool and
the specification disagree is a bug in at least one of them and we want to know either way.

The format itself changes rarely and cautiously. Chain format version 1 is frozen and read forever, and the
anchor canonical encoding is positional, so a new field means a new signature domain rather than an
insertion. See section 9 of [SPEC.md](SPEC.md).
