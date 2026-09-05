package velo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
)

// testCAPEM and otherCAPEM are real self-signed CA certificates. The
// fixtures used to carry a fake `AAAA` body, which meant nothing checked
// that the pinned CA is actually a certificate: a client config with a
// PEM-shaped but non-certificate ca_certificate built and shipped happily,
// and only failed on the victim, ten minutes later, as an E50.
const testCAPEM = `-----BEGIN CERTIFICATE-----
MIIBazCCARGgAwIBAgIBATAKBggqhkjOPQQDAjAcMRowGAYDVQQDExFERklSTWVk
aWMgVGVzdCBDQTAgFw0yMDAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowHDEa
MBgGA1UEAxMRREZJUk1lZGljIFRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAAQ0VadvyKRtY034nyXHgOvhAmYhcyP05/TRHMvnyND4eSspprUn4Bpcnnqo
3zl3JZj1Rg2eIgU6CWzDlO2KNMxno0IwQDAOBgNVHQ8BAf8EBAMCAoQwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUEx30H3MgsQ/gsIm4ZW8qV84sadAwCgYIKoZI
zj0EAwIDSAAwRQIhAPYvQ+VMiWEcdW2P2EByp8HoxtAY5CTQPHfIp79XY8ybAiA4
bYDmgS7eArLPZlqmoHGKLAvkIdcsXHITekEY+v+4Fw==
-----END CERTIFICATE-----
`

const otherCAPEM = `-----BEGIN CERTIFICATE-----
MIIBdzCCAR2gAwIBAgIBAjAKBggqhkjOPQQDAjAiMSAwHgYDVQQDExdERklSTWVk
aWMgT3RoZXIgVGVzdCBDQTAgFw0yMDAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAw
MFowIjEgMB4GA1UEAxMXREZJUk1lZGljIE90aGVyIFRlc3QgQ0EwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAARtD0RHzUhoBvwO46NFJYoEDMgBbWmC8JGQZyviclUP
TYRSh92fpNJ4YiRWtaIiqY9ef7nfArCZ8dsdcKP8IEoLo0IwQDAOBgNVHQ8BAf8E
BAMCAoQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUSPOXwpLn/uQwnSvEDoJf
DXCeOIkwCgYIKoZIzj0EAwIDSAAwRQIgDv0dNUEAcv890py9mNOzObDiKtgKAS4g
vX8c3iYJWtACIQD5xqFx6JX1TxmONHAUHbW+O+rvfFjLL0kpcToPSx65cA==
-----END CERTIFICATE-----
`

// indented returns caPEM indented to sit under `ca_certificate: |`.
func indented(caPEM string) string {
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimRight(caPEM, "\n"), "\n") {
		b.WriteString("    " + l + "\n")
	}
	return b.String()
}

var sampleClientYAML = `version:
  name: velociraptor
Client:
  server_urls:
  - https://203.0.113.10:443/
  ca_certificate: |
` + indented(testCAPEM) + `  nonce: abc
  windows_installer:
    service_name: Velociraptor
    install_path: $ProgramFiles\Velociraptor\Velociraptor.exe
    service_description: Velociraptor service
  darwin_installer:
    service_name: com.velocidex.velociraptor
    install_path: /usr/local/bin/velociraptor
`

func TestExtractCAReturnsDedentedPEM(t *testing.T) {
	got, err := ExtractCA([]byte(sampleClientYAML))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != testCAPEM {
		t.Fatalf("got %q want %q", got, testCAPEM)
	}
}

func TestExtractCAMissing(t *testing.T) {
	if _, err := ExtractCA([]byte("Client:\n  server_urls:\n  - x\n")); err == nil {
		t.Fatal("expected error for missing ca_certificate")
	}
}

func TestCAFingerprintHashesDER(t *testing.T) {
	got, err := CAFingerprint([]byte(testCAPEM))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(testCAPEM))
	sum := sha256.Sum256(block.Bytes)
	if got != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("got %s", got)
	}
	other, err := CAFingerprint([]byte(otherCAPEM))
	if err != nil {
		t.Fatal(err)
	}
	if other == got {
		t.Fatal("two different CAs must not share a fingerprint")
	}
	if _, err := CAFingerprint([]byte("not pem")); err == nil {
		t.Fatal("expected error for non-PEM input")
	}
}

// TestCAFingerprintRejectsNonCertificateDER: a CERTIFICATE-labelled block
// whose body is not a certificate must fail here, at build time on the
// responder's Mac, rather than as a ten-minute E50 on the victim host.
func TestCAFingerprintRejectsNonCertificateDER(t *testing.T) {
	fake := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	if _, err := CAFingerprint([]byte(fake)); err == nil {
		t.Fatal("a PEM block that is not a certificate must be rejected")
	}
}

func TestExtractInstallPathUsesWindowsBlockOnly(t *testing.T) {
	got, err := ExtractInstallPath([]byte(sampleClientYAML))
	if err != nil {
		t.Fatal(err)
	}
	if got != `C:\Program Files\Velociraptor\Velociraptor.exe` {
		t.Fatalf("got %q", got)
	}
	if strings.Contains(got, "$ProgramFiles") {
		t.Fatal("$ProgramFiles must be expanded")
	}
	// The darwin block also has install_path; it must not be picked up.
	noWin := strings.Replace(sampleClientYAML, "  windows_installer:\n    service_name: Velociraptor\n    install_path: $ProgramFiles\\Velociraptor\\Velociraptor.exe\n    service_description: Velociraptor service\n", "", 1)
	if _, err := ExtractInstallPath([]byte(noWin)); err == nil {
		t.Fatal("expected error when windows_installer block is absent")
	}
}
