package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/syncplify/logverify/anchor"
	"github.com/syncplify/logverify/chain"
	"github.com/syncplify/logverify/identity"
)

const anchorUsage = `logverify anchor checks a signed log against a signed anchor.

An anchor states that lines 1 through N of one file reach a particular chain MAC.
That claim is signed with the producer's Ed25519 key, so anyone holding the
public key can check it and nobody holding only the public key can forge it.

Where the anchor has ALSO been received and retained by a third party at a time
already past, matching it means the log has not been rewritten since that
moment, not even by whoever owns the machine and holds every key on it. That is
the only configuration in which a log is evidence rather than a diary, so check
anchors against a copy you did not obtain from the producer.

Options:
`

func runAnchor(args []string) {
	fs := flag.NewFlagSet("anchor", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, anchorUsage)
		fs.PrintDefaults()
	}
	var (
		file       = fs.String("file", "", "the signed log file the anchor refers to")
		dir        = fs.String("dir", "", "a directory of signed log files, one of which the anchor refers to")
		anchorPath = fs.String("anchor", "", "path to the signed anchor, as JSON (required)")
		pubKey     = fs.String("pubkey", "", "the producer's public key as base64, or @path to a file holding it (required)")
		idPath     = fs.String("identity", "", "data directory (or logid.key) of the producing machine, to derive its per file keys")
		keyFile    = fs.String("key-file", "", "file holding the key for a passphrase signed log; \"-\" reads standard input")
	)
	_ = fs.Parse(args)

	if *anchorPath == "" || *pubKey == "" {
		fail2("both -anchor and -pubkey are required")
	}
	if (*file == "") == (*dir == "") {
		fail2("give either -file or -dir")
	}

	raw, err := os.ReadFile(*anchorPath)
	if err != nil {
		fail2("read the anchor: %s", err)
	}
	var sa anchor.SignedAnchor
	if err := json.Unmarshal(raw, &sa); err != nil {
		fail2("parse the anchor: %s", err)
	}
	pub, err := loadPublicKey(*pubKey)
	if err != nil {
		fail2("%s", err)
	}

	// The signature FIRST, always. Checking a log against an unverified claim answers a question nobody
	// asked, because any attacker can write an anchor that matches the log they have just rewritten.
	if err := anchor.Verify(pub, sa); err != nil {
		fmt.Printf("FAIL      the anchor did not verify: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("ok        anchor signed by %s\n", identity.Short(sa.KeyFP))
	fmt.Printf("          service %s, chain %s, file %d, lines 1 to %d\n\n",
		sa.Service, shortID(sa.ChainID), sa.Seq, sa.LineCount)

	keyFor, err := keySource(*idPath, *keyFile)
	if err != nil {
		fail2("%s", err)
	}

	// Capture the chain MAC at exactly the line the anchor commits to.
	var reached string
	var found bool
	opt := chain.Options{
		OnLine: func(chainID string, seq, line uint64, mac string) {
			if chainID == sa.ChainID && seq == sa.Seq && line == sa.LineCount {
				reached, found = mac, true
			}
		},
	}

	var res *chain.Result
	if *dir != "" {
		res, err = chain.VerifyDir(*dir, keyFor, opt)
	} else {
		res, err = chain.VerifyFile(*file, keyFor, opt)
	}
	if err != nil {
		fail2("%s", err)
	}

	if !found {
		fmt.Printf("FAIL      the log does not reach line %d of file %d in chain %s; the anchored history is not all here\n",
			sa.LineCount, sa.Seq, shortID(sa.ChainID))
		os.Exit(1)
	}
	if reached != sa.ChainMAC {
		fmt.Printf("FAIL      the log does NOT match the anchor: it has been altered since the anchor was signed\n")
		fmt.Printf("          anchor commits to  %s\n", sa.ChainMAC)
		fmt.Printf("          the log reaches    %s\n", reached)
		os.Exit(1)
	}

	if len(res.Issues) > 0 {
		// The anchor matched, so the anchored prefix is intact. Anything else wrong is elsewhere in the set
		// and is worth naming rather than swallowing, but it must not be folded into the anchor verdict.
		fmt.Printf("ok        %d line(s) match the signed anchor exactly\n\n", sa.LineCount)
		for _, iss := range res.Issues {
			fmt.Printf("FAIL      %s\n", iss.String())
		}
		fmt.Printf("\nFAIL      the anchored prefix matches, but %d other problem(s) were found\n", len(res.Issues))
		os.Exit(1)
	}

	fmt.Printf("ok        %d line(s) match the signed anchor exactly\n", sa.LineCount)
}

// loadPublicKey accepts the key inline as base64 or, with a leading @, as a path to a file holding it.
// A public key is not secret, so unlike the HMAC key it is allowed on the command line.
func loadPublicKey(spec string) (ed25519.PublicKey, error) {
	text := spec
	if strings.HasPrefix(spec, "@") {
		raw, err := os.ReadFile(strings.TrimPrefix(spec, "@"))
		if err != nil {
			return nil, fmt.Errorf("read the public key: %w", err)
		}
		text = string(raw)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return nil, fmt.Errorf("decode the public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("a public key is %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
