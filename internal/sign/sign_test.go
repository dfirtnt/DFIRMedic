package sign

import (
	"path/filepath"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"case_id":"X"}`)
	sig := Sign(priv, msg)
	if !Verify(pub, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if Verify(pub, append(msg, '\n'), sig) {
		t.Fatal("modified payload accepted")
	}
	pub2, _, _ := GenerateKeypair()
	if Verify(pub2, msg, sig) {
		t.Fatal("wrong key accepted")
	}
}

func TestPrivateKeyFileRoundTrip(t *testing.T) {
	_, priv, _ := GenerateKeypair()
	p := filepath.Join(t.TempDir(), "responder.key")
	if err := WritePrivateKey(p, priv); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPrivateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(priv) {
		t.Fatal("key mismatch after round trip")
	}
}

func TestSigFileRoundTrip(t *testing.T) {
	_, priv, _ := GenerateKeypair()
	sig := Sign(priv, []byte("x"))
	p := filepath.Join(t.TempDir(), "incident.json.sig")
	if err := WriteSig(p, sig); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSig(p)
	if err != nil || string(got) != string(sig) {
		t.Fatalf("sig round trip failed: %v", err)
	}
}

func TestEmbeddedPublicKey(t *testing.T) {
	pub, _, _ := GenerateKeypair()
	old := embeddedPubKeyHex
	t.Cleanup(func() { embeddedPubKeyHex = old })
	embeddedPubKeyHex = ""
	if _, err := EmbeddedPublicKey(); err == nil {
		t.Fatal("empty embedded key must error")
	}
	embeddedPubKeyHex = hexOf(pub)
	got, err := EmbeddedPublicKey()
	if err != nil || string(got) != string(pub) {
		t.Fatal("embedded key not decoded")
	}
}
