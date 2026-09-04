// Package sign signs and verifies incident.json with ed25519.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Set at build time:
//   -ldflags "-X github.com/dfirtnt/DFIRMedic/internal/sign.embeddedPubKeyHex=<64 hex chars>"
var embeddedPubKeyHex string

func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func WritePrivateKey(path string, priv ed25519.PrivateKey) error {
	return os.WriteFile(path, []byte(hexOf(priv)+"\n"), 0o600)
}

func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s: not a valid ed25519 private key", path)
	}
	return ed25519.PrivateKey(raw), nil
}

func Sign(priv ed25519.PrivateKey, payload []byte) []byte {
	return ed25519.Sign(priv, payload)
}

func Verify(pub ed25519.PublicKey, payload, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, payload, sig)
}

func EmbeddedPublicKey() (ed25519.PublicKey, error) {
	if embeddedPubKeyHex == "" {
		return nil, errors.New("no responder public key embedded in this binary; build with -ldflags -X ...sign.embeddedPubKeyHex=")
	}
	raw, err := hex.DecodeString(embeddedPubKeyHex)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("embedded public key is malformed")
	}
	return ed25519.PublicKey(raw), nil
}

func WriteSig(path string, sig []byte) error {
	return os.WriteFile(path, []byte(hexOf(sig)+"\n"), 0o644)
}

func ReadSig(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(b)))
}
