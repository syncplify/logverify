package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// testSeed produces a throwaway identity deterministically. It is worthless outside this test.
func testSeed() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// The key derivation is the one place where this verifier and the producer must agree byte for byte, and
// where a disagreement is silent: every line of every file would simply report as tampered, with nothing
// pointing at the key.
//
// This vector was produced by the PRODUCER's implementation, which derives through
// golang.org/x/crypto/hkdf, and is pinned here so that the standard library's crypto/hkdf can never drift
// from it unnoticed. It is a cross implementation vector, not a copy of this package's own output.
func TestChainKeyDerivationMatchesTheProducersVector(t *testing.T) {
	const (
		chainID = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
		seq     = 3
		want    = "b755070f2f9e8e2741963e357ce118089b3f95e96a206f3748570a5be5cc4d17"
	)
	got, err := DeriveChainKey(testSeed(), chainID, seq)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("the derived chain key does not match the producer:\n got  %s\n want %s", hex.EncodeToString(got), want)
	}
}

// Each file gets its own key, and that is the entire point of deriving per file: a leaked key must cost one
// file rather than the whole history.
func TestEveryFileGetsADifferentKey(t *testing.T) {
	priv := testSeed()
	a, _ := DeriveChainKey(priv, "chain-a", 0)
	b, _ := DeriveChainKey(priv, "chain-a", 1)
	c, _ := DeriveChainKey(priv, "chain-b", 0)
	if hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Fatal("two files of one chain derived the same key, so a leaked key exposes the whole chain")
	}
	if hex.EncodeToString(a) == hex.EncodeToString(c) {
		t.Fatal("two chains derived the same key")
	}
}

func writeIdentity(t *testing.T, dir string, priv ed25519.PrivateKey, pub ed25519.PublicKey) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"comment":     "test identity",
		"private_key": priv,
		"public_key":  pub,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, KeyFileName)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpenReadsADirectoryOrTheKeyFileItself(t *testing.T) {
	dir := t.TempDir()
	priv := testSeed()
	path := writeIdentity(t, dir, priv, priv.Public().(ed25519.PublicKey))

	for _, target := range []string{dir, path} {
		id, err := Open(target)
		if err != nil {
			t.Fatalf("open %s: %v", target, err)
		}
		if id.PublicKeyBase64() != base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)) {
			t.Fatal("the wrong public key came back")
		}
	}
}

// The property that makes this tool safe to point at evidence. A verifier that mints a key has written to
// the tree it was asked to examine, and "what it wrote was harmless" is not something anyone can establish
// afterwards without taking the tool author's word for it.
func TestOpenNeverCreatesAnything(t *testing.T) {
	dir := t.TempDir()

	if _, err := Open(dir); err == nil {
		t.Fatal("opening a directory with no identity succeeded; it must refuse, never mint")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("the verifier wrote into the evidence directory: %v", names)
	}
}

// A hand edited file can hold two keys that have nothing to do with each other. Deriving from one while
// telling the world to verify with the other produces a log nobody can check.
func TestAnIdentityWhosePublicHalfDoesNotMatchIsRefused(t *testing.T) {
	dir := t.TempDir()
	priv := testSeed()

	otherSeed := make([]byte, ed25519.SeedSize)
	for i := range otherSeed {
		otherSeed[i] = byte(200 - i)
	}
	other := ed25519.NewKeyFromSeed(otherSeed)

	writeIdentity(t, dir, priv, other.Public().(ed25519.PublicKey))

	if _, err := Open(dir); err == nil {
		t.Fatal("an inconsistent identity was accepted")
	}
}

func TestKeyMaterialIsInterpretedByShape(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i * 7)
	}
	if got := InterpretKeyMaterial(hex.EncodeToString(raw)); hex.EncodeToString(got) != hex.EncodeToString(raw) {
		t.Fatal("64 hex characters were not read as a raw key")
	}
	if got := InterpretKeyMaterial(base64.StdEncoding.EncodeToString(raw)); hex.EncodeToString(got) != hex.EncodeToString(raw) {
		t.Fatal("base64 of 32 bytes was not read as a raw key")
	}
	// Anything else is a passphrase, hashed the way the producer hashes one.
	if got := InterpretKeyMaterial("  correct horse battery staple  "); len(got) != 32 {
		t.Fatalf("a passphrase produced %d key bytes", len(got))
	}
	if hex.EncodeToString(InterpretKeyMaterial("hunter2")) == hex.EncodeToString(InterpretKeyMaterial("hunter3")) {
		t.Fatal("two different passphrases produced the same key")
	}
}
