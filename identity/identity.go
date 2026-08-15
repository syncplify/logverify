// Package identity reads a log producer's identity and derives the per file chain keys it implies.
//
// Everything here is strictly READ ONLY, and that is a security property rather than a convenience. This
// code runs against evidence: a directory that somebody may later have to defend as unmodified. A verifier
// that mints a missing key file, or quietly repairs a file mode, has written to the evidence tree, and
// "what it wrote was harmless" is not something anyone can establish afterwards without taking the tool
// author's word for it. So this package opens files, reads them, and changes nothing.
//
// See SPEC.md section 4 for the formats implemented here.
package identity

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyFileName is the identity's name inside a producer's data directory.
const KeyFileName = "logid.key"

// chainKeyInfo is the HKDF purpose string for log chain keys. Any other use of an identity must pick a
// different one, so that two purposes can never derive the same bytes.
const chainKeyInfo = "sftp.cloud/log-chain-key/v1"

// chainKeyLen matches the HMAC-SHA256 key the log chain uses.
const chainKeyLen = 32

// Identity is a producer's log signing identity, as read from disk.
//
// The private key is held unexported and never returned. A verifier needs it only to re-derive chain
// keys, which is what the methods below do; handing the raw key back to callers would invite it into
// logs, error messages and crash dumps for no gain.
type Identity struct {
	// Public is the verifying key.
	Public ed25519.PublicKey
	// Path is the file this identity was read from.
	Path string

	private ed25519.PrivateKey
}

// keyFile is the on disk shape. The two key fields are standard base64, which is what Go's encoding/json
// produces for a []byte.
type keyFile struct {
	Comment    string `json:"comment"`
	PrivateKey []byte `json:"private_key"`
	PublicKey  []byte `json:"public_key"`
}

// Open reads the identity at path, which may name either the data directory or the key file itself,
// because people type both.
//
// It NEVER creates anything. A directory holding no identity is an error, not an invitation to mint one:
// every key a fresh identity would derive is unrelated to the log being checked, so the alternative to
// this error is a confident report that every line has been tampered with.
func Open(path string) (*Identity, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("no identity path was given")
	}
	file := path
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		file = filepath.Join(path, KeyFileName)
	}

	raw, err := os.ReadFile(file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no log identity at %s; this must point at the data directory of the machine that PRODUCED the log", file)
		}
		return nil, fmt.Errorf("read the log identity: %w", err)
	}

	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("parse the log identity at %s: %w", file, err)
	}
	if len(kf.PrivateKey) != ed25519.PrivateKeySize || len(kf.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the log identity at %s holds %d/%d bytes of key material, want %d/%d",
			file, len(kf.PrivateKey), len(kf.PublicKey), ed25519.PrivateKeySize, ed25519.PublicKeySize)
	}

	priv := ed25519.PrivateKey(kf.PrivateKey)
	// The public half is stored beside the private one, so a hand edited file can hold two keys that have
	// nothing to do with each other. Trust the private key and check: deriving from one while telling the
	// world to verify with the other produces a log nobody can check.
	if !priv.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(kf.PublicKey)) {
		return nil, fmt.Errorf("the log identity at %s is inconsistent: the stored public key does not belong to the stored private key", file)
	}

	return &Identity{Public: ed25519.PublicKey(kf.PublicKey), Path: file, private: priv}, nil
}

// Fingerprint is the hex SHA-256 of a public key: the identity's stable name in anchors and in control
// plane records. The public key itself remains the authority; this is only how it is referred to.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// Fingerprint is Fingerprint(i.Public).
func (i *Identity) Fingerprint() string { return Fingerprint(i.Public) }

// PublicKeyBase64 renders the public key the way it travels: standard base64 of the 32 raw bytes.
func (i *Identity) PublicKeyBase64() string { return base64.StdEncoding.EncodeToString(i.Public) }

// Short is the first 16 characters of a fingerprint, for places a human compares two values by eye. It is
// a label and must never be used as an identifier.
func Short(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16]
}

// DeriveChainKey derives the HMAC key for one log file: chain chainID, file number seq.
//
// It is deterministic, which is what makes verification possible at all. Both inputs are stated by the
// file's own first line, so anyone holding the identity can re-derive any file's key with nothing
// escrowed, stored beside the log, or transported.
func DeriveChainKey(priv ed25519.PrivateKey, chainID string, seq uint64) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}
	if chainID == "" {
		return nil, errors.New("the chain id cannot be empty")
	}
	// The salt binds the key to this chain AND this file. Without the file number every file in a chain
	// would share one key, and the per file scoping would be a comment rather than a property.
	salt := make([]byte, 0, len(chainID)+8)
	salt = append(salt, chainID...)
	var seqRaw [8]byte
	binary.BigEndian.PutUint64(seqRaw[:], seq)
	salt = append(salt, seqRaw[:]...)

	return hkdf.Key(sha256.New, priv, salt, chainKeyInfo, chainKeyLen)
}

// ChainKey derives the key for one file of one chain under this identity.
func (i *Identity) ChainKey(chainID string, seq uint64) ([]byte, error) {
	if i == nil {
		return nil, errors.New("no identity")
	}
	return DeriveChainKey(i.private, chainID, seq)
}

// ChainKeys is shaped for the chain package's key function, so a whole directory can be verified from one
// identity. A derivation failure yields no key, which the verifier reports as a segment it could not
// check rather than silently accepting.
func (i *Identity) ChainKeys() func(chainID string, seq uint64) []byte {
	return func(chainID string, seq uint64) []byte {
		key, err := i.ChainKey(chainID, seq)
		if err != nil {
			return nil
		}
		return key
	}
}

// PassphraseKey turns a passphrase into the 32 byte HMAC key a passphrase signed log uses.
func PassphraseKey(passphrase string) []byte {
	sum := sha256.Sum256([]byte(passphrase))
	return sum[:]
}

// InterpretKeyMaterial turns whatever an operator supplied into HMAC key bytes: 64 hex characters or
// base64 of exactly 32 bytes are decoded as a raw key, and anything else is treated as a passphrase.
//
// The ambiguity is deliberate and bounded: a 32 byte key has exactly two conventional text encodings and
// a passphrase that happens to be valid base64 of exactly 32 bytes is not a passphrase anyone types.
func InterpretKeyMaterial(s string) []byte {
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		if raw, err := hex.DecodeString(s); err == nil {
			return raw
		}
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && len(raw) == chainKeyLen {
		return raw
	}
	return PassphraseKey(s)
}
