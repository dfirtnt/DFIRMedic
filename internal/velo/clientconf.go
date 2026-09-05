package velo

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// The client config is YAML, but the kit needs exactly two values from it
// and must not carry a YAML parser onto the victim. Both are read with
// indentation-aware line scanning, which is enough for the file
// `velociraptor config client` emits.

func indent(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }

// ExtractCA returns the PEM block under `Client.ca_certificate: |`.
func ExtractCA(yaml []byte) ([]byte, error) {
	lines := strings.Split(string(yaml), "\n")
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t != "ca_certificate: |" && t != "ca_certificate: |-" {
			continue
		}
		keyIndent := indent(l)
		var out []string
		for _, b := range lines[i+1:] {
			if strings.TrimSpace(b) == "" {
				continue
			}
			if indent(b) <= keyIndent {
				break
			}
			out = append(out, strings.TrimSpace(b))
		}
		p := strings.Join(out, "\n") + "\n"
		if !strings.HasPrefix(p, "-----BEGIN CERTIFICATE-----") {
			return nil, errors.New("ca_certificate is not a PEM certificate")
		}
		return []byte(p), nil
	}
	return nil, errors.New("ca_certificate not found in client config")
}

// CAFingerprint is "sha256:<hex>" over the DER bytes of the first
// CERTIFICATE block, matching incident.json server.ca_sha256. The DER is
// parsed, not just hashed: a PEM-shaped block that is not a certificate
// would otherwise fingerprint cleanly at build time and fail only on the
// victim host, as a ten-minute E50 with the network already up.
func CAFingerprint(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("no CERTIFICATE block in ca_certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", fmt.Errorf("ca_certificate is not a valid certificate: %w", err)
	}
	sum := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ExtractInstallPath returns Client.windows_installer.install_path, the
// path `velociraptor service install` copies the binary to and registers
// the service against. The firewall egress rule must name this path.
func ExtractInstallPath(yaml []byte) (string, error) {
	lines := strings.Split(string(yaml), "\n")
	inBlock := false
	blockIndent := -1
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		ind := indent(l)
		if t == "windows_installer:" {
			inBlock, blockIndent = true, ind
			continue
		}
		if !inBlock {
			continue
		}
		if ind <= blockIndent {
			inBlock = false
			continue
		}
		if v, ok := strings.CutPrefix(t, "install_path:"); ok {
			return ExpandProgramFiles(strings.Trim(strings.TrimSpace(v), `"'`)), nil
		}
	}
	return "", errors.New("windows_installer.install_path not found in client config")
}

// ExpandProgramFiles turns Velociraptor's `$ProgramFiles` (and the
// Windows-style `%ProgramFiles%`) into the literal path the firewall and
// `sc qc` will report. The kit only ships to 64-bit Windows, so this is
// always C:\Program Files.
func ExpandProgramFiles(p string) string {
	return strings.NewReplacer("$ProgramFiles", `C:\Program Files`, "%ProgramFiles%", `C:\Program Files`).Replace(p)
}
