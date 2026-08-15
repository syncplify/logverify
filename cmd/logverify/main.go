// Command logverify checks SFTP.cloud tamper evident logs.
//
// It is deliberately small, deliberately dependency free, and deliberately read only. It is meant to be
// run by people who have no reason to trust the party that produced the log, including against that
// party's own machines, so every property that makes it auditable is worth more than any convenience.
//
// Output is plain deterministic text with no colour and no cursor tricks, because the useful thing to do
// with a verification result is paste it into a report.
//
// Exit codes are the contract:
//
//	0  everything checked out
//	1  something did not verify
//	2  bad arguments, or the evidence could not be read
package main

import (
	"fmt"
	"os"
)

// Version is the tool's version. The FORMAT is versioned separately and on purpose: the tool moves faster
// than the format, and it must be possible to say which format a file is in without reference to which
// tool wrote it. See SPEC.md.
//
// It starts at 0.x because the Go API has not yet been consumed by a caller other than this command. The
// on disk format it implements is not provisional in the slightest, and does not move with this number.
const Version = "0.1.0"

const usage = `logverify checks SFTP.cloud tamper evident logs.

  logverify verify   replay a log's HMAC chain and check the files form one unbroken chain
  logverify anchor   check a log against a signed anchor, which needs no HMAC key
  logverify version  print the tool and format versions

Run any command with -h for its options. The format these commands implement is
specified in SPEC.md, which is written so that this tool can be reimplemented
without reading its source.

WHAT A PASS MEANS. The per line chain is an HMAC, so it proves only that nobody
WITHOUT the key altered the log; whoever holds the key can rewrite it and re-MAC
it perfectly. An anchor is an Ed25519 signature, so it cannot be forged by
someone holding only the public key, but the producer holds the private key and
can re-sign old history. What rules that out is an anchor that a third party
received and retained at a time already past. Check anchors against a copy you
did not get from the producer.

Exit codes: 0 verified, 1 not verified, 2 bad arguments or unreadable evidence.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "verify":
		runVerify(os.Args[2:])
	case "anchor":
		runAnchor(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Printf("logverify %s\n", Version)
		fmt.Printf("chain format 2 (reads 1), anchor format v1\n")
	case "help", "-h", "-help", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// fail2 reports a problem with the invocation or with reading the evidence, which is a different thing
// from evidence that failed to verify and gets a different exit code so that scripts can tell them apart.
func fail2(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error  "+format+"\n", args...)
	os.Exit(2)
}
