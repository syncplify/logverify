package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/syncplify/logverify/chain"
)

const verifyUsage = `logverify verify replays the HMAC chain in signed log files.

Verifying a DIRECTORY checks more than verifying its files one at a time. Every
file can be individually perfect while the set is missing a week of history, so
the directory pass also checks that the files form one unbroken chain: numbered
consecutively, each naming the closing MAC of the one before it. Deleting a
whole file is the cheapest attack on a log, and a per file check cannot see it.

A pass here means nobody WITHOUT the key altered these files. It says nothing
about whoever holds the key. For that, use "logverify anchor".

Options:
`

func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, verifyUsage)
		fs.PrintDefaults()
	}
	var (
		file      = fs.String("file", "", "one signed log file (.jsonl or .jsonl.gz)")
		dir       = fs.String("dir", "", "a directory of signed log files; also checks they form one unbroken chain")
		idPath    = fs.String("identity", "", "data directory (or logid.key) of the machine that PRODUCED the log, to derive its per file keys")
		keyFile   = fs.String("key-file", "", "file holding the key for a passphrase signed log; \"-\" reads standard input")
		verbose   = fs.Bool("verbose", false, "print each chain segment as it is verified")
		unsigned  = fs.Bool("allow-unsigned", false, "treat lines with no chain mac as skipped rather than as violations")
		stopFirst = fs.Bool("stop-on-first", false, "stop at the first violation; the cross file checks are then SKIPPED, because a partly replayed segment has no closing mac to compare")
	)
	_ = fs.Parse(args)

	if (*file == "") == (*dir == "") {
		fail2("give either -file or -dir")
	}

	keyFor, err := keySource(*idPath, *keyFile)
	if err != nil {
		fail2("%s", err)
	}

	target := *file
	if *dir != "" {
		target = *dir
	}
	fmt.Printf("target    %s\n\n", target)

	// Reporting everything is the default. Stopping at the first violation answers a yes or no question
	// quickly, but it leaves the cross file checks unrunnable, and an investigator wants the whole picture
	// rather than the first line that happened to be wrong.
	opt := chain.Options{
		AllowUnsigned: *unsigned,
		StopOnFirst:   *stopFirst,
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

	if *verbose {
		for _, s := range res.Segments {
			label := fmt.Sprintf("%s file %d", shortID(s.ChainID), s.Seq)
			if s.ChainV == "" {
				label += " (format 1, not linked)"
			}
			fmt.Printf("segment   %-40s %6d lines  %s\n", label, s.LineCount, filepath.Base(s.Source))
		}
		fmt.Println()
	}

	if len(res.Issues) > 0 {
		for _, iss := range res.Issues {
			fmt.Printf("FAIL      %s\n", iss.String())
		}
		fmt.Printf("\nFAIL      %d violation(s) across %d line(s) in %d file(s)\n",
			len(res.Issues), res.LineCount, len(res.Files))
		if res.Truncated {
			// Never let a partial pass read as a complete one.
			fmt.Println("          stopped at the first violation, so the files were NOT checked for continuity;")
			fmt.Println("          re-run without -stop-on-first for the full picture")
		}
		os.Exit(1)
	}

	fmt.Printf("ok        %d line(s) in %d file(s), %d chain segment(s) verified",
		res.LineCount, len(res.Files), len(res.Segments))
	if *dir != "" && !res.Truncated {
		fmt.Print(", and the files form one unbroken chain")
	}
	fmt.Println()
}

func shortID(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}
