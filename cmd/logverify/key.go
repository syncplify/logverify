package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/syncplify/logverify/chain"
	"github.com/syncplify/logverify/identity"
)

// How the verification key reaches this tool, and why there is no --secret flag.
//
// A value passed as a command line flag is readable by every process on the machine for as long as the
// command runs, and it lands in shell history besides. For most flags that is irrelevant; for the key that
// authenticates an audit log it is the whole ballgame, because anyone who reads it can rewrite the log and
// re-MAC it perfectly. So the key arrives from a file, or from standard input, and never from argv.
//
// There is also no interactive no echo prompt. It would cost a dependency and buy little: the workflows
// that matter here are scripted, and "-key-file -" reads standard input, which a human can drive with a
// here document and a pipeline can drive with anything.

// keySource turns the flags describing where the verification key comes from into the per segment key
// function the verifier wants.
//
// Two shapes exist because two kinds of log exist. A log signed with one passphrase has one key for every
// file. A log signed by a machine identity has a DERIVED key per file, reproducible by anyone holding that
// identity from the chain id and the file number that the file states about itself, which is why nothing
// has to be stored alongside the log or shipped with it.
func keySource(identityPath, keyFile string) (chain.KeyFunc, error) {
	switch {
	case identityPath != "" && keyFile != "":
		return nil, fmt.Errorf("give either -identity or -key-file, not both")

	case identityPath != "":
		id, err := identity.Open(identityPath)
		if err != nil {
			return nil, err
		}
		return chain.KeyFunc(id.ChainKeys()), nil

	case keyFile != "":
		raw, err := readKeyMaterial(keyFile)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(raw) == "" {
			return nil, fmt.Errorf("the key source held nothing")
		}
		return chain.StaticKey(identity.InterpretKeyMaterial(raw)), nil

	default:
		return nil, fmt.Errorf("no verification key was supplied; use -identity for a machine signed log, or -key-file for a passphrase signed one")
	}
}

// readKeyMaterial reads the key from a file, or from standard input when the path is "-".
//
// Surrounding whitespace is trimmed by the interpreter, since a trailing newline is what every editor and
// every "echo > file" adds and nobody means to include it.
func readKeyMaterial(path string) (string, error) {
	if path == "-" {
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<16))
		if err != nil {
			return "", fmt.Errorf("read the key from standard input: %w", err)
		}
		return string(raw), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read the key file: %w", err)
	}
	return string(raw), nil
}
