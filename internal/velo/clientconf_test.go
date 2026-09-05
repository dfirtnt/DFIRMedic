package velo

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const sampleClientYAML = `version:
  name: velociraptor
Client:
  server_urls:
  - https://203.0.113.10:443/
  ca_certificate: |
    -----BEGIN CERTIFICATE-----
    AAAA
    -----END CERTIFICATE-----
  nonce: abc
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
	want := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestExtractCAMissing(t *testing.T) {
	if _, err := ExtractCA([]byte("Client:\n  server_urls:\n  - x\n")); err == nil {
		t.Fatal("expected error for missing ca_certificate")
	}
}

func TestCAFingerprintHashesDER(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	got, err := CAFingerprint([]byte(pem))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte{0, 0, 0}) // base64 "AAAA" decodes to three zero bytes
	if got != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("got %s", got)
	}
	if _, err := CAFingerprint([]byte("not pem")); err == nil {
		t.Fatal("expected error for non-PEM input")
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
