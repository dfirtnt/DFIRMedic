# Direct Velociraptor Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove Tailscale from the victim host. The kit installs only the Velociraptor client, which reaches a fixed public IP on one TCP port; the quarantine allows exactly that and DHCP/ND, with no DNS.

**Architecture:** `incident.json` moves to schema 2 with a `server` block (IP, port, pinned CA fingerprint) and an explicit Velociraptor `install_path`. A new `internal/probe` package does a TLS handshake against the server and verifies the leaf chains to the CA shipped in the client config; `connect` uses it as the "responder online" gate and heartbeat instead of `tailscale status`. Quarantine rules become nine: three single-destination program rules (installed Velociraptor, payload Velociraptor, orchestrator) plus DHCP and IPv6 ND. The `internal/tailscale` package is deleted.

**Tech Stack:** Go 1.22 standard library only (`crypto/tls`, `crypto/x509`, `net/url`). No new dependencies. Windows built-ins via the existing `runner` chokepoint.

**Spec:** `docs/superpowers/specs/2026-09-05-direct-velociraptor-design.md` (supersedes sections of `docs/superpowers/specs/2026-09-04-dfirmedic-design.md` listed in its §9).

## Global Constraints

- `CGO_ENABLED=0`; `GOOS=windows GOARCH=amd64` for the victim binary; standard library only (go.mod: `golang.org/x/sys` is the sole dependency and stays).
- Every host-changing action goes through `runner.Runner` so it lands in the audit log. The one exception, by spec §7, is `internal/probe` (a TLS dial); it must contain no other network code.
- Error codes keep their numbers. New codes: **E18** (client config CA does not match signed `incident.json`), **E41** (Velociraptor service installed to an unexpected path).
- `incident.json` schema is **2**. `Validate` rejects any other schema.
- Public port default **443**. `server.ip` must be an IP literal; hostnames are rejected at `build`.
- Firewall rule group stays `DFIRMedic-<case_id>`. Rule names: `velociraptor-egress`, `velociraptor-egress-payload`, `orchestrator-probe`, `dhcp-out`, `dhcp-in`, `dhcpv6-out`, `dhcpv6-in`, `nd-out`, `nd-in`, plus `dns-dhcp-udp`/`dns-dhcp-tcp` only when `firewall.dns_fallback_to_dhcp` is true.
- The Windows exe must be rebuilt with `make build-windows LDFLAGS="-X github.com/dfirtnt/DFIRMedic/internal/sign.embeddedPubKeyHex=98a7e595f1e05f0134293f5d421a858604ba1b9c3b459834c5ef41562bdb642e"` after the code changes; `go-winres` lives in `~/go/bin` (`export PATH="$HOME/go/bin:$PATH"`).
- Commit messages end with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- **Compile order matters.** Tasks 1–4 are additive and keep `go build ./...` green. Task 5 changes `config` and breaks every consumer until Tasks 6–11 land; during that window run only the named package's tests. Task 12 restores `make check`.

---

## File Structure

| Path | Responsibility |
|---|---|
| `internal/velo/clientconf.go` (new) | Read two values out of the Velociraptor client YAML without a YAML parser: the CA PEM block and `windows_installer.install_path`. Fingerprint the CA. |
| `internal/probe/probe.go` (new) | `Prober` interface and `TLS` implementation: dial, handshake, verify chain against a pinned CA, return leaf fingerprint. Only network code in the kit. |
| `internal/velo/velo.go` | Add `InstalledBinaryPath` (parses `sc qc`). |
| `internal/win/firewall.go` | `ServerRules` (three program rules, one destination); `QuarantineRules(dnsFallbackDHCP bool)` (DHCP, ND, optional DHCP-resolver DNS). Remove `TailscaledPath`. |
| `internal/win/system.go` | Remove `IsHomeEdition`, `EnableRDP`. Add `RemoveDirIfExists`. |
| `internal/config/config.go` | Schema 2: `Server`, `Velo{ConfigFile, InstallPath, ServiceName}`, `Firewall{DNSFallbackToDHCP}`. Remove `Tailscale`. |
| `internal/build/build.go` | Derive `Server` from `--server-url`; read CA + install path from the client YAML; reject hostname URLs and stale YAML. |
| `internal/stage/stage.go` | Preflight E18; quarantine uses `ServerRules`; install drops MSI/`tailscale up`, adds E41 path check; no RDP/edition logic. |
| `internal/connect/connect.go` | `Deps.Probe probe.Prober` replaces `Deps.TS`; `server_verified` audit event. |
| `internal/teardown/teardown.go` | Drop Tailscale steps; add "delete Velociraptor install directory". |
| `cmd/dfirmedic/cmds.go`, `main.go` | Flags, wiring, usage text. |
| `internal/tailscale/` | **Deleted.** |
| `docs/responder-setup.md`, `docs/integration-tests.md`, `README.md`, `payload/README.md`, old spec | Updated per spec §9/§12. |

---

### Task 1: Client config extraction (`internal/velo/clientconf.go`)

**Files:**
- Create: `internal/velo/clientconf.go`
- Test: `internal/velo/clientconf_test.go`

**Interfaces:**
- Produces:
  - `func ExtractCA(yaml []byte) ([]byte, error)` — PEM bytes of `Client.ca_certificate`.
  - `func CAFingerprint(pemBytes []byte) (string, error)` — `"sha256:<hex>"` of the DER of the first CERTIFICATE block.
  - `func ExtractInstallPath(yaml []byte) (string, error)` — `Client.windows_installer.install_path` with `$ProgramFiles` expanded.
  - `func ExpandProgramFiles(p string) string`.

- [ ] **Step 1: Write the failing tests**

```go
// internal/velo/clientconf_test.go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/velo/ -run 'TestExtractCA|TestCAFingerprint|TestExtractInstallPath' 2>&1 | head`
Expected: FAIL — `undefined: ExtractCA`, `undefined: CAFingerprint`, `undefined: ExtractInstallPath`

- [ ] **Step 3: Write the implementation**

```go
// internal/velo/clientconf.go
package velo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
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
// CERTIFICATE block, matching incident.json server.ca_sha256.
func CAFingerprint(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("no CERTIFICATE block in ca_certificate")
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/velo/ 2>&1 | tail -3`
Expected: `ok  github.com/dfirtnt/DFIRMedic/internal/velo`

- [ ] **Step 5: Commit**

```bash
git add internal/velo/clientconf.go internal/velo/clientconf_test.go
git commit -m "velo: extract CA and install_path from the client config without a YAML parser

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: TLS probe with pinned CA (`internal/probe`)

**Files:**
- Create: `internal/probe/probe.go`
- Test: `internal/probe/probe_test.go`

**Interfaces:**
- Produces:
  - `type Prober interface { Verify(ctx context.Context) (leafFingerprint string, err error) }`
  - `type TLS struct { IP string; Port int; CAPEM []byte; Timeout time.Duration }` implementing `Prober`.
  - Success means: TCP connect, TLS handshake, and the leaf certificate chains to a root pool containing only `CAPEM`. No HTTP is sent.

- [ ] **Step 1: Write the failing tests**

```go
// internal/probe/probe_test.go
package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newCA returns a self-signed CA certificate and key.
func newCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// leafSignedBy returns a tls.Certificate for a server leaf signed by ca.
// No SAN on purpose: Velociraptor's internal CA issues certs the default
// verifier would reject on name, and the probe must not care.
func leafSignedBy(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "VelociraptorServer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serve starts a TLS listener presenting cert and returns ip, port.
func serve(t *testing.T, cert tls.Certificate) (string, int) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				c.Close()
			}(c)
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func TestVerifyAcceptsLeafSignedByPinnedCA(t *testing.T) {
	ca, caKey, caPEM := newCA(t, "Velociraptor CA")
	ip, port := serve(t, leafSignedBy(t, ca, caKey))
	fp, err := TLS{IP: ip, Port: port, CAPEM: caPEM, Timeout: 5 * time.Second}.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(fp) != 64 {
		t.Fatalf("leaf fingerprint should be 64 hex chars, got %q", fp)
	}
}

func TestVerifyRejectsLeafFromOtherCA(t *testing.T) {
	_, _, pinnedPEM := newCA(t, "Pinned CA")
	otherCA, otherKey, _ := newCA(t, "Other CA")
	ip, port := serve(t, leafSignedBy(t, otherCA, otherKey))
	_, err := TLS{IP: ip, Port: port, CAPEM: pinnedPEM, Timeout: 5 * time.Second}.Verify(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pinned CA") {
		t.Fatalf("expected pinned-CA failure, got %v", err)
	}
}

func TestVerifyRejectsPlainTCPListener(t *testing.T) {
	_, _, caPEM := newCA(t, "CA")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")) // a captive portal, roughly
			c.Close()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	if _, err := (TLS{IP: host, Port: port, CAPEM: caPEM, Timeout: 5 * time.Second}).Verify(context.Background()); err == nil {
		t.Fatal("plain TCP must not verify")
	}
}

func TestVerifyTimesOutOnSilentPeer(t *testing.T) {
	_, _, caPEM := newCA(t, "CA")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { time.Sleep(10 * time.Second); c.Close() }(c) // never handshakes
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	start := time.Now()
	_, err := TLS{IP: host, Port: port, CAPEM: caPEM, Timeout: 500 * time.Millisecond}.Verify(context.Background())
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("probe did not honor its timeout: %v", time.Since(start))
	}
}

func TestVerifyRejectsUnusableCA(t *testing.T) {
	if _, err := (TLS{IP: "127.0.0.1", Port: 1, CAPEM: []byte("garbage")}).Verify(context.Background()); err == nil {
		t.Fatal("expected error for unusable CA")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/probe/ 2>&1 | head -5`
Expected: FAIL — `undefined: TLS`

- [ ] **Step 3: Write the implementation**

```go
// Package probe answers one question for the victim host: is the thing at
// server_ip:port *our* Velociraptor server? It dials, completes a TLS
// handshake, and verifies the presented certificate chains to the CA shipped
// in the client config. It is the only in-process network code in the kit
// (spec 2026-09-05 §7) and speaks no protocol above TLS.
package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

type Prober interface {
	Verify(ctx context.Context) (leafFingerprint string, err error)
}

type TLS struct {
	IP      string
	Port    int
	CAPEM   []byte
	Timeout time.Duration // default 10s
}

func (p TLS) Verify(ctx context.Context) (string, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(p.CAPEM) {
		return "", errors.New("probe: no usable CA certificate")
	}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(p.IP, strconv.Itoa(p.Port)))
	if err != nil {
		return "", fmt.Errorf("probe: %w", err)
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}

	var leafFP string
	cfg := &tls.Config{
		// Velociraptor's internal CA issues server certs without a SAN for the
		// bare IP, so Go's default verifier would fail on the name check.
		// InsecureSkipVerify disables ONLY that; the chain check below is
		// mandatory and aborts the handshake on failure.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no certificate presented")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			inter := x509.NewCertPool()
			for _, rc := range rawCerts[1:] {
				if c, err := x509.ParseCertificate(rc); err == nil {
					inter.AddCert(c)
				}
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				return fmt.Errorf("certificate not signed by the pinned CA: %w", err)
			}
			sum := sha256.Sum256(rawCerts[0])
			leafFP = hex.EncodeToString(sum[:])
			return nil
		},
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("probe: %w", err)
	}
	_ = tc.Close()
	return leafFP, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/probe/ -v 2>&1 | grep -E "^(=== RUN|--- |ok|FAIL)"`
Expected: all five PASS, `ok`

- [ ] **Step 5: Commit**

```bash
git add internal/probe/
git commit -m "probe: TLS handshake verified against the pinned Velociraptor CA

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Read the installed service path (`velo.InstalledBinaryPath`)

**Files:**
- Modify: `internal/velo/velo.go`
- Test: `internal/velo/velo_test.go`

**Interfaces:**
- Produces:
  - `func (c Client) InstalledBinaryPath(ctx context.Context) (string, error)` — runs `sc.exe qc Velociraptor`.
  - `func ParseBinaryPath(scqc string) (string, error)` — pure parser.

- [ ] **Step 1: Write the failing tests** (append to `internal/velo/velo_test.go`)

```go
func TestParseBinaryPathQuoted(t *testing.T) {
	out := "[SC] QueryServiceConfig SUCCESS\r\n\r\nSERVICE_NAME: Velociraptor\r\n        TYPE               : 10  WIN32_OWN_PROCESS\r\n        BINARY_PATH_NAME   : \"C:\\Program Files\\Velociraptor\\Velociraptor.exe\" --config \"C:\\Program Files\\Velociraptor\\client.config.yaml\" service run\r\n        DISPLAY_NAME       : Velociraptor\r\n"
	got, err := ParseBinaryPath(out)
	if err != nil {
		t.Fatal(err)
	}
	if got != `C:\Program Files\Velociraptor\Velociraptor.exe` {
		t.Fatalf("got %q", got)
	}
}

func TestParseBinaryPathUnquoted(t *testing.T) {
	got, err := ParseBinaryPath("        BINARY_PATH_NAME   : C:\\Velo\\Velociraptor.exe --config c.yaml service run\r\n")
	if err != nil || got != `C:\Velo\Velociraptor.exe` {
		t.Fatalf("got %q err %v", got, err)
	}
	if _, err := ParseBinaryPath("SERVICE_NAME: x\r\n"); err == nil {
		t.Fatal("expected error when BINARY_PATH_NAME absent")
	}
}

func TestInstalledBinaryPathRunsScQc(t *testing.T) {
	f := runner.NewFake()
	f.Responses[f.Key("sc.exe", "qc", "Velociraptor")] = runner.Result{Stdout: "        BINARY_PATH_NAME   : \"C:\\P\\Velociraptor.exe\" service run\r\n"}
	got, err := Client{R: f}.InstalledBinaryPath(context.Background())
	if err != nil || got != `C:\P\Velociraptor.exe` {
		t.Fatalf("got %q err %v", got, err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/velo/ -run 'TestParseBinaryPath|TestInstalledBinaryPath' 2>&1 | head -5`
Expected: FAIL — `undefined: ParseBinaryPath`, `InstalledBinaryPath`

- [ ] **Step 3: Write the implementation** (append to `internal/velo/velo.go`; add `"strings"` to imports)

```go
// InstalledBinaryPath returns the executable the Velociraptor service is
// registered to run from. `service install` copies the binary to the client
// config's install_path and registers *that*; the firewall egress rule must
// name the same path or the client is silently blocked (seen 2026-09-05).
func (c Client) InstalledBinaryPath(ctx context.Context) (string, error) {
	res, err := c.R.Run(ctx, "sc.exe", "qc", ServiceName)
	if err != nil {
		return "", err
	}
	return ParseBinaryPath(res.Stdout)
}

// ParseBinaryPath pulls the executable out of `sc qc` output. The value is
// either "quoted path" args... or an unquoted path followed by " --args".
func ParseBinaryPath(scqc string) (string, error) {
	for _, l := range strings.Split(scqc, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(k) != "BINARY_PATH_NAME" {
			continue
		}
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, `"`) {
			if end := strings.Index(v[1:], `"`); end >= 0 {
				return v[1 : end+1], nil
			}
			return "", errors.New("unterminated quoted BINARY_PATH_NAME")
		}
		if i := strings.Index(v, " --"); i >= 0 {
			return v[:i], nil
		}
		return v, nil
	}
	return "", errors.New("BINARY_PATH_NAME not found in sc qc output")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/velo/ 2>&1 | tail -2`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add internal/velo/velo.go internal/velo/velo_test.go
git commit -m "velo: read the registered service binary path from sc qc

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Server egress rules and directory removal (`internal/win`, additive)

**Files:**
- Modify: `internal/win/firewall.go` (add `ServerRules`; leave `QuarantineRules` untouched until Task 7)
- Modify: `internal/win/system.go` (add `RemoveDirIfExists`)
- Test: `internal/win/firewall_test.go`, `internal/win/system_test.go`

**Interfaces:**
- Produces:
  - `func ServerRules(installPath, payloadExe, orchestratorExe, serverIP string, serverPort int) []Rule`
  - `func (s Sys) RemoveDirIfExists(ctx context.Context, dir string) error` — `cmd.exe /c if exist <dir> rmdir /s /q <dir>`

- [ ] **Step 1: Write the failing tests** (append)

```go
// internal/win/firewall_test.go
func TestServerRulesArePinnedToOneDestination(t *testing.T) {
	rules := ServerRules(`C:\Program Files\Velociraptor\Velociraptor.exe`, `C:\w\payload\velociraptor.exe`, `C:\w\dfirmedic.exe`, "203.0.113.10", 443)
	if len(rules) != 3 {
		t.Fatalf("want 3 rules, got %d", len(rules))
	}
	want := map[string]string{
		"velociraptor-egress":         `C:\Program Files\Velociraptor\Velociraptor.exe`,
		"velociraptor-egress-payload": `C:\w\payload\velociraptor.exe`,
		"orchestrator-probe":          `C:\w\dfirmedic.exe`,
	}
	for _, r := range rules {
		if want[r.Name] != r.Program {
			t.Fatalf("rule %s program %q", r.Name, r.Program)
		}
		if r.Direction != "Outbound" || r.Protocol != "TCP" || r.RemotePort != "443" || r.RemoteAddress != "203.0.113.10" {
			t.Fatalf("rule %s not pinned: %+v", r.Name, r)
		}
		if r.LocalPort != "" || r.Service != "" || r.IcmpType != "" {
			t.Fatalf("rule %s has unexpected scope: %+v", r.Name, r)
		}
	}
}
```

```go
// internal/win/system_test.go
func TestRemoveDirIfExists(t *testing.T) {
	f := runner.NewFake()
	if err := (Sys{R: f}).RemoveDirIfExists(context.Background(), `C:\Program Files\Velociraptor`); err != nil {
		t.Fatal(err)
	}
	if !f.Called("cmd.exe", "/c", "if", "exist", `C:\Program Files\Velociraptor`, "rmdir", "/s", "/q", `C:\Program Files\Velociraptor`) {
		t.Fatalf("unexpected argv: %v", f.Calls)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/win/ -run 'TestServerRules|TestRemoveDirIfExists' 2>&1 | head -5`
Expected: FAIL — `undefined: ServerRules`, `RemoveDirIfExists`

- [ ] **Step 3: Write the implementation**

```go
// internal/win/firewall.go — add near QuarantineRules; add "strconv" import
// ServerRules are the only outbound program rules in the quarantine (spec
// 2026-09-05 §6.3). Each names one program and one fixed destination: the
// installed Velociraptor service, the payload copy `service install` runs
// once, and the orchestrator for its TLS probe.
func ServerRules(installPath, payloadExe, orchestratorExe, serverIP string, serverPort int) []Rule {
	port := strconv.Itoa(serverPort)
	r := func(name, prog string) Rule {
		return Rule{Name: name, Direction: "Outbound", Program: prog, Protocol: "TCP", RemotePort: port, RemoteAddress: serverIP}
	}
	return []Rule{
		r("velociraptor-egress", installPath),
		r("velociraptor-egress-payload", payloadExe),
		r("orchestrator-probe", orchestratorExe),
	}
}
```

```go
// internal/win/system.go — append
// RemoveDirIfExists deletes dir and everything under it, and is a no-op when
// it is absent. Used by teardown to remove the Velociraptor install directory
// that `service remove` leaves behind. Goes through cmd.exe so it is audited
// like every other host change.
func (s Sys) RemoveDirIfExists(ctx context.Context, dir string) error {
	_, err := s.R.Run(ctx, "cmd.exe", "/c", "if", "exist", dir, "rmdir", "/s", "/q", dir)
	return err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/win/ 2>&1 | tail -2`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add internal/win/firewall.go internal/win/firewall_test.go internal/win/system.go internal/win/system_test.go
git commit -m "win: single-destination server egress rules; RemoveDirIfExists

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: `incident.json` schema 2 (`internal/config`)

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces (used by every later task):
  ```go
  type Incident struct {
      Schema int; CaseID string; CreatedUTC, ExpiresUTC time.Time
      Server Server; Velociraptor Velo; Firewall Firewall; Watchdog Watchdog; Contact Contact
      BreakglassCodeHash, PayloadManifestSHA256 string
  }
  type Server struct { URL string `json:"url"`; IP string `json:"ip"`; Port int `json:"port"`; CASHA256 string `json:"ca_sha256"` }
  type Velo struct { ConfigFile string `json:"config_file"`; InstallPath string `json:"install_path"`; ServiceName string `json:"service_name"` }
  type Firewall struct { DNSFallbackToDHCP bool `json:"dns_fallback_to_dhcp"` }
  ```
  `Tailscale` is removed. `Validate` requires `Schema == 2`.
- **After this task `go build ./...` is red until Task 11.** Run only `go test ./internal/config/`.

- [ ] **Step 1: Replace the sample and add tests** in `internal/config/config_test.go`

Replace the `sample` constant:

```go
const sample = `{
  "schema": 2,
  "case_id": "CASE-2026-0042",
  "created_utc": "2026-09-04T22:15:00Z",
  "expires_utc": "2026-09-05T22:15:00Z",
  "server": {"url":"https://203.0.113.10:443/","ip":"203.0.113.10","port":443,"ca_sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},
  "velociraptor": {"config_file":"payload/velociraptor.client.yaml","install_path":"C:\\Program Files\\Velociraptor\\Velociraptor.exe","service_name":"Velociraptor"},
  "firewall": {"dns_fallback_to_dhcp":false},
  "watchdog": {"tunnel_timeout_sec":600,"heartbeat_grace_sec":300},
  "contact": {"phone":"+15555550100","name":"Responder"},
  "breakglass_code_hash": "sha256:0000",
  "payload_manifest_sha256": "sha256:placeholder"
}`
```

Update `TestValidateRejectsMissingFields` (whatever fields it blanks today, it must now blank `server`, `velociraptor`, and check the messages) and add:

```go
func TestValidateRejectsSchema1(t *testing.T) {
	inc, _, _ := Load(write(t, strings.Replace(sample, `"schema": 2`, `"schema": 1`, 1)))
	err := inc.Validate(time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "schema 1 unsupported") {
		t.Fatalf("want schema error, got %v", err)
	}
}

func TestValidateRejectsBadServer(t *testing.T) {
	cases := map[string]string{
		"hostname ip":  strings.Replace(sample, `"ip":"203.0.113.10"`, `"ip":"velo.example.com"`, 1),
		"port zero":    strings.Replace(sample, `"port":443`, `"port":0`, 1),
		"bad ca hash":  strings.Replace(sample, `"ca_sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"`, `"ca_sha256":"abc"`, 1),
		"no install":   strings.Replace(sample, `"install_path":"C:\\Program Files\\Velociraptor\\Velociraptor.exe"`, `"install_path":""`, 1),
		"no service":   strings.Replace(sample, `"service_name":"Velociraptor"`, `"service_name":""`, 1),
	}
	for name, js := range cases {
		inc, _, err := Load(write(t, js))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if inc.Validate(time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)) == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}
}
```

(Add `"strings"` to the test imports.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ 2>&1 | head -8`
Expected: FAIL — schema 2 sample rejected ("schema 2 unsupported"), unknown fields ignored, `TestValidateRejectsBadServer` fails.

- [ ] **Step 3: Rewrite `internal/config/config.go`**

```go
// Package config loads and validates the per-incident incident.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

// Schema is the incident.json format this kit understands. Schema 1 carried a
// Tailscale block; schema 2 (spec 2026-09-05) talks to a fixed server IP.
const Schema = 2

type Incident struct {
	Schema                int       `json:"schema"`
	CaseID                string    `json:"case_id"`
	CreatedUTC            time.Time `json:"created_utc"`
	ExpiresUTC            time.Time `json:"expires_utc"`
	Server                Server    `json:"server"`
	Velociraptor          Velo      `json:"velociraptor"`
	Firewall              Firewall  `json:"firewall"`
	Watchdog              Watchdog  `json:"watchdog"`
	Contact               Contact   `json:"contact"`
	BreakglassCodeHash    string    `json:"breakglass_code_hash"`
	PayloadManifestSHA256 string    `json:"payload_manifest_sha256"`
}

// Server is the one destination the victim may reach.
type Server struct {
	URL      string `json:"url"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	CASHA256 string `json:"ca_sha256"` // fingerprint of Client.ca_certificate in the shipped client config
}

type Velo struct {
	ConfigFile  string `json:"config_file"`
	InstallPath string `json:"install_path"` // where `service install` puts the binary; the egress rule names it
	ServiceName string `json:"service_name"`
}

type Firewall struct {
	DNSFallbackToDHCP bool `json:"dns_fallback_to_dhcp"`
}

type Watchdog struct {
	TunnelTimeoutSec  int `json:"tunnel_timeout_sec"`
	HeartbeatGraceSec int `json:"heartbeat_grace_sec"`
}

type Contact struct {
	Phone string `json:"phone"`
	Name  string `json:"name"`
}

var (
	caseIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	sha256Re = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Load reads and parses path. The raw bytes are returned so the caller can
// verify the detached signature over exactly what was on disk.
func Load(path string) (*Incident, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var inc Incident
	if err := json.Unmarshal(raw, &inc); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &inc, raw, nil
}

func (i *Incident) Validate(now time.Time) error {
	var errs []error
	if i.Schema != Schema {
		errs = append(errs, fmt.Errorf("schema %d unsupported (this kit requires schema %d)", i.Schema, Schema))
	}
	if !caseIDRe.MatchString(i.CaseID) {
		errs = append(errs, errors.New("case_id must be 1-64 chars of [A-Za-z0-9._-]"))
	}
	if i.ExpiresUTC.IsZero() || !now.Before(i.ExpiresUTC) {
		errs = append(errs, fmt.Errorf("incident config expired at %s", i.ExpiresUTC.Format(time.RFC3339)))
	}
	if i.Server.URL == "" {
		errs = append(errs, errors.New("server.url required"))
	}
	if net.ParseIP(i.Server.IP) == nil {
		errs = append(errs, fmt.Errorf("server.ip must be an IP literal, got %q", i.Server.IP))
	}
	if i.Server.Port < 1 || i.Server.Port > 65535 {
		errs = append(errs, fmt.Errorf("server.port out of range: %d", i.Server.Port))
	}
	if !sha256Re.MatchString(i.Server.CASHA256) {
		errs = append(errs, errors.New("server.ca_sha256 must be sha256:<64 hex>"))
	}
	if i.Velociraptor.ConfigFile == "" {
		errs = append(errs, errors.New("velociraptor.config_file required"))
	}
	if i.Velociraptor.InstallPath == "" || !strings.Contains(i.Velociraptor.InstallPath, `:\`) {
		errs = append(errs, errors.New("velociraptor.install_path must be an absolute Windows path"))
	}
	if i.Velociraptor.ServiceName == "" {
		errs = append(errs, errors.New("velociraptor.service_name required"))
	}
	if i.Watchdog.TunnelTimeoutSec <= 0 || i.Watchdog.HeartbeatGraceSec <= 0 {
		errs = append(errs, errors.New("watchdog timeouts must be > 0"))
	}
	if i.Contact.Phone == "" {
		errs = append(errs, errors.New("contact.phone required"))
	}
	if i.BreakglassCodeHash == "" {
		errs = append(errs, errors.New("breakglass_code_hash required"))
	}
	if i.PayloadManifestSHA256 == "" {
		errs = append(errs, errors.New("payload_manifest_sha256 required"))
	}
	return errors.Join(errs...)
}

func (i *Incident) RuleGroup() string { return "DFIRMedic-" + i.CaseID }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ 2>&1 | tail -2`
Expected: `ok`. (`go build ./...` will fail elsewhere; that is expected until Task 11.)

- [ ] **Step 5: Commit**

```bash
git add internal/config/
git commit -m "config: incident.json schema 2 — server block replaces tailscale

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: `build` derives the server block from the client config (`internal/build`)

**Files:**
- Modify: `internal/build/build.go`
- Test: `internal/build/build_test.go`

**Interfaces:**
- Consumes: `config.Server`, `config.Velo` (Task 5); `velo.ExtractCA`, `velo.CAFingerprint`, `velo.ExtractInstallPath` (Task 1); `velo.ServiceName`.
- Produces:
  ```go
  type Options struct {
      CaseID, ServerURL string
      DNSFallbackDHCP bool
      TunnelTimeoutSec, HeartbeatGraceSec int
      ContactName, ContactPhone, BreakglassCode string
      TTL time.Duration
      PayloadDir, ExePath, FieldCardPath, OutDir, PrivKeyPath string
      Now func() time.Time
  }
  func ServerFromURL(u string) (config.Server, error) // IP + port (default 443); rejects hostnames and non-https
  ```

- [ ] **Step 1: Update the fixture and add tests**

In `fixture` (build_test.go), replace the payload files and Options:

```go
const fixtureClientYAML = `Client:
  server_urls:
  - https://203.0.113.10:443/
  ca_certificate: |
    -----BEGIN CERTIFICATE-----
    AAAA
    -----END CERTIFICATE-----
  windows_installer:
    service_name: Velociraptor
    install_path: $ProgramFiles\Velociraptor\Velociraptor.exe
`
```

```go
	os.WriteFile(filepath.Join(payload, "velociraptor.exe"), []byte("v"), 0o755)
	os.WriteFile(filepath.Join(payload, "velociraptor.client.yaml"), []byte(fixtureClientYAML), 0o644)
	os.WriteFile(filepath.Join(payload, "tools", "thor-lite.exe"), []byte("t"), 0o755)
	// ...
	return Options{
		CaseID: "CASE-1", ServerURL: "https://203.0.113.10:443/",
		ContactName: "Alex", ContactPhone: "+1555", BreakglassCode: "hunter2",
		PayloadDir: payload, ExePath: filepath.Join(src, "dfirmedic.exe"), FieldCardPath: filepath.Join(src, "FIELD-CARD.md"),
		OutDir: filepath.Join(t.TempDir(), "usb"), PrivKeyPath: keyPath,
		Now: func() time.Time { return time.Date(2026, 9, 4, 22, 0, 0, 0, time.UTC) },
	}, pub
```

Add tests:

```go
func TestBuildWritesServerBlockFromClientConfig(t *testing.T) {
	o, pub := fixture(t)
	if _, err := Build(o); err != nil {
		t.Fatal(err)
	}
	inc, err := Verify(o.OutDir, pub, o.Now())
	if err != nil {
		t.Fatal(err)
	}
	if inc.Schema != 2 || inc.Server.IP != "203.0.113.10" || inc.Server.Port != 443 || inc.Server.URL != o.ServerURL {
		t.Fatalf("server block: %+v", inc.Server)
	}
	sum := sha256.Sum256([]byte{0, 0, 0}) // "AAAA"
	if inc.Server.CASHA256 != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("ca_sha256 = %s", inc.Server.CASHA256)
	}
	if inc.Velociraptor.InstallPath != `C:\Program Files\Velociraptor\Velociraptor.exe` || inc.Velociraptor.ServiceName != "Velociraptor" {
		t.Fatalf("velociraptor block: %+v", inc.Velociraptor)
	}
}

func TestServerFromURL(t *testing.T) {
	s, err := ServerFromURL("https://203.0.113.10/")
	if err != nil || s.IP != "203.0.113.10" || s.Port != 443 {
		t.Fatalf("default port: %+v %v", s, err)
	}
	s, err = ServerFromURL("https://203.0.113.10:8000/")
	if err != nil || s.Port != 8000 {
		t.Fatalf("explicit port: %+v %v", s, err)
	}
	for _, bad := range []string{"https://velo.example.com/", "http://203.0.113.10/", "203.0.113.10", "https://[fe80::1]:443/x"} {
		if _, err := ServerFromURL(bad); err == nil && bad != "https://[fe80::1]:443/x" {
			t.Fatalf("expected rejection for %q", bad)
		}
	}
}

func TestBuildRejectsClientConfigThatDoesNotListServerURL(t *testing.T) {
	o, _ := fixture(t)
	o.ServerURL = "https://198.51.100.5:443/" // not in server_urls
	if _, err := Build(o); err == nil || !strings.Contains(err.Error(), "server_urls") {
		t.Fatalf("expected server_urls mismatch error, got %v", err)
	}
}
```

(Add `"crypto/sha256"`, `"encoding/hex"` to test imports.) Fix `TestBuildRejectsMissingInputs` to blank `ServerURL` instead of removed fields.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/build/ 2>&1 | head -8`
Expected: compile errors (`o.AuthKey undefined`, `ServerFromURL` undefined).

- [ ] **Step 3: Update `internal/build/build.go`**

Replace `Options`, `defaults`, `incident`, and the start of `Build`:

```go
import (
	// existing imports plus:
	"net"
	"net/url"
	"strconv"

	"github.com/dfirtnt/DFIRMedic/internal/velo"
)

type Options struct {
	CaseID, ServerURL                                       string
	DNSFallbackDHCP                                         bool
	TunnelTimeoutSec, HeartbeatGraceSec                     int
	ContactName, ContactPhone, BreakglassCode               string
	TTL                                                     time.Duration
	PayloadDir, ExePath, FieldCardPath, OutDir, PrivKeyPath string
	Now                                                     func() time.Time
}

func (o *Options) defaults() {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.TunnelTimeoutSec == 0 {
		o.TunnelTimeoutSec = 600
	}
	if o.HeartbeatGraceSec == 0 {
		o.HeartbeatGraceSec = 300
	}
	if o.TTL == 0 {
		o.TTL = 24 * time.Hour
	}
}

// ServerFromURL derives the pinned destination from --server-url. The host
// must be an IP literal: the victim has no DNS (spec 2026-09-05 §3).
func ServerFromURL(u string) (config.Server, error) {
	p, err := url.Parse(u)
	if err != nil {
		return config.Server{}, fmt.Errorf("--server-url: %w", err)
	}
	if p.Scheme != "https" {
		return config.Server{}, errors.New("--server-url must be https://")
	}
	host := p.Hostname()
	if net.ParseIP(host) == nil {
		return config.Server{}, fmt.Errorf("--server-url host must be an IP literal (the victim has no DNS), got %q", host)
	}
	port := 443
	if ps := p.Port(); ps != "" {
		if port, err = strconv.Atoi(ps); err != nil || port < 1 || port > 65535 {
			return config.Server{}, fmt.Errorf("--server-url port %q invalid", ps)
		}
	}
	return config.Server{URL: u, IP: host, Port: port}, nil
}

// clientConfigFacts reads what incident.json must agree with from the shipped
// client config: the CA fingerprint and the service install path. It also
// refuses a client config that does not list --server-url, which is the
// "stale yaml from the old server" mistake.
func clientConfigFacts(payloadDir, serverURL string) (caSHA256, installPath string, err error) {
	raw, err := os.ReadFile(filepath.Join(payloadDir, "velociraptor.client.yaml"))
	if err != nil {
		return "", "", fmt.Errorf("client config: %w", err)
	}
	if !strings.Contains(string(raw), "- "+serverURL) {
		return "", "", fmt.Errorf("client config server_urls does not contain %s — regenerate it from the server that owns that address", serverURL)
	}
	caPEM, err := velo.ExtractCA(raw)
	if err != nil {
		return "", "", fmt.Errorf("client config: %w", err)
	}
	if caSHA256, err = velo.CAFingerprint(caPEM); err != nil {
		return "", "", fmt.Errorf("client config: %w", err)
	}
	if installPath, err = velo.ExtractInstallPath(raw); err != nil {
		return "", "", fmt.Errorf("client config: %w", err)
	}
	return caSHA256, installPath, nil
}

func (o Options) incident(srv config.Server, installPath, payloadManifestSHA256 string) *config.Incident {
	now := o.Now().UTC()
	return &config.Incident{
		Schema: config.Schema, CaseID: o.CaseID, CreatedUTC: now, ExpiresUTC: now.Add(o.TTL),
		Server:                srv,
		Velociraptor:          config.Velo{ConfigFile: "payload/velociraptor.client.yaml", InstallPath: installPath, ServiceName: velo.ServiceName},
		Firewall:              config.Firewall{DNSFallbackToDHCP: o.DNSFallbackDHCP},
		Watchdog:              config.Watchdog{TunnelTimeoutSec: o.TunnelTimeoutSec, HeartbeatGraceSec: o.HeartbeatGraceSec},
		Contact:               config.Contact{Name: o.ContactName, Phone: o.ContactPhone},
		BreakglassCodeHash:    teardown.CodeHash(o.BreakglassCode),
		PayloadManifestSHA256: "sha256:" + payloadManifestSHA256,
	}
}

func Build(o Options) (*Result, error) {
	o.defaults()
	if o.BreakglassCode == "" {
		return nil, errors.New("break-glass code required")
	}
	if st, err := os.Stat(o.PayloadDir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("payload dir %s: not a directory", o.PayloadDir)
	}
	srv, err := ServerFromURL(o.ServerURL)
	if err != nil {
		return nil, err
	}
	caSHA256, installPath, err := clientConfigFacts(o.PayloadDir, o.ServerURL)
	if err != nil {
		return nil, err
	}
	srv.CASHA256 = caSHA256
	// ... existing key read, mkdir, payload copy, manifest write, manifestHash ...
	inc := o.incident(srv, installPath, manifestHash)
	// ... rest unchanged ...
}
```

Keep every other line of `Build`/`Verify`/`copyFile`/`copyTree` as it is; only the `incident(...)` call site changes.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/build/ 2>&1 | tail -2`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add internal/build/
git commit -m "build: derive server block and install_path from --server-url and the client config

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: Quarantine rules without DNS/RDP/tailscaled (`internal/win`)

**Files:**
- Modify: `internal/win/firewall.go` (`QuarantineRules` signature; delete `TailscaledPath`)
- Modify: `internal/win/system.go` (delete `IsHomeEdition`, `EnableRDP`)
- Test: `internal/win/firewall_test.go`, `internal/win/system_test.go`

**Interfaces:**
- Produces: `func QuarantineRules(dnsFallbackDHCP bool) []Rule` — `dhcp-out`, `dhcp-in`, `dhcpv6-out`, `dhcpv6-in`, `nd-out`, `nd-in`, plus `dns-dhcp-udp`/`dns-dhcp-tcp` when the flag is true.

- [ ] **Step 1: Rewrite the rule tests**

Delete `TestQuarantineRulesAllowOnlyWhatSpecRequires`, `TestQuarantineRulesRDPAndDHCPFallback`, `TestQuarantineRulesScopeDNSToDnscache`, and any `system_test.go` test of `IsHomeEdition`/`EnableRDP`. Update `TestQuarantineRulesIncludeDHCPClient`, `TestQuarantineRulesIncludeIPv6NeighborDiscovery`, `TestQuarantineRulesNoInboundBeyondDHCPAndNDWithoutRDP` to call `QuarantineRules(false)`. Add:

```go
func TestQuarantineRulesHaveNoDNSUnlessDHCPFallback(t *testing.T) {
	for _, r := range QuarantineRules(false) {
		if r.RemotePort == "53" || strings.HasPrefix(r.Name, "dns") {
			t.Fatalf("no DNS rule allowed by default: %+v", r)
		}
		if r.Program != "" && r.Program != SvchostPath {
			t.Fatalf("only svchost may appear in the base quarantine set: %+v", r)
		}
	}
	if n := len(QuarantineRules(false)); n != 6 {
		t.Fatalf("base set must be dhcp x4 + nd x2 = 6, got %d", n)
	}
	withDHCP := QuarantineRules(true)
	if n := len(withDHCP); n != 8 {
		t.Fatalf("dhcp fallback adds exactly two DNS rules, got %d", n)
	}
	for _, r := range withDHCP[6:] {
		if r.Service != "Dnscache" || r.RemotePort != "53" || r.RemoteAddress != "" {
			t.Fatalf("dhcp-fallback DNS rule must be Dnscache-scoped, port 53, any address: %+v", r)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/win/ 2>&1 | head -5`
Expected: compile error — `QuarantineRules` called with 1 arg, defined with 3.

- [ ] **Step 3: Change the implementation**

In `firewall.go`: delete `const TailscaledPath`; replace `QuarantineRules`:

```go
// QuarantineRules are the non-server rules of the quarantine: the DHCP
// client (v4/v6) so the host gets an address on reconnect, IPv6 neighbor
// discovery, and — only when the responder opted in — DNS to the DHCP
// resolver scoped to the Dnscache service. There is deliberately no DNS by
// default: the victim reaches its server by IP (spec 2026-09-05 §3), and a
// resolver rule is a covert channel for any process on the host.
func QuarantineRules(dnsFallbackDHCP bool) []Rule {
	rules := []Rule{
		{Name: "dhcp-out", Direction: "Outbound", Program: SvchostPath, Service: "Dhcp", Protocol: "UDP", LocalPort: "68", RemotePort: "67"},
		{Name: "dhcp-in", Direction: "Inbound", Program: SvchostPath, Service: "Dhcp", Protocol: "UDP", LocalPort: "68", RemotePort: "67"},
		{Name: "dhcpv6-out", Direction: "Outbound", Program: SvchostPath, Service: "Dhcp", Protocol: "UDP", LocalPort: "546", RemotePort: "547"},
		{Name: "dhcpv6-in", Direction: "Inbound", Program: SvchostPath, Service: "Dhcp", Protocol: "UDP", LocalPort: "546", RemotePort: "547"},
		{Name: "nd-out", Direction: "Outbound", Protocol: "ICMPv6", IcmpType: "133,135,136"},
		{Name: "nd-in", Direction: "Inbound", Protocol: "ICMPv6", IcmpType: "134,135,136"},
	}
	if dnsFallbackDHCP {
		dns := func(name, proto string) Rule {
			return Rule{Name: name, Direction: "Outbound", Program: SvchostPath, Service: "Dnscache", Protocol: proto, RemotePort: "53"}
		}
		rules = append(rules, dns("dns-dhcp-udp", "UDP"), dns("dns-dhcp-tcp", "TCP"))
	}
	return rules
}
```

In `system.go`: delete `IsHomeEdition` and `EnableRDP`. Keep `EditionID` (baseline records it).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/win/ 2>&1 | tail -2`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add internal/win/
git commit -m "win: quarantine rules drop tailscaled, pinned DNS, and RDP

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 8: Staging — E18, server rules, no MSI, E41 (`internal/stage`)

**Files:**
- Modify: `internal/stage/stage.go`
- Test: `internal/stage/stage_test.go`

**Interfaces:**
- Consumes: `config.Incident` schema 2; `win.QuarantineRules(bool)`, `win.ServerRules(...)`; `velo.ExtractCA`, `velo.CAFingerprint`, `velo.Client.InstalledBinaryPath`.
- Produces: `stage.Deps` without `TS`. Error codes E18 (preflight), E41 (install).

- [ ] **Step 1: Update the test harness and add tests**

In `stage_test.go`: remove the `tailscale` import and `TS:` line from `deps`; replace `incJSON` with schema 2 (same shape as the config sample in Task 5 but `"case_id":"C1"`, `"server":{"url":"https://203.0.113.10:443/","ip":"203.0.113.10","port":443,"ca_sha256":"__CA_HASH_PLACEHOLDER__"}`, `"velociraptor":{"config_file":"payload/velociraptor.client.yaml","install_path":"C:\\Program Files\\Velociraptor\\Velociraptor.exe","service_name":"Velociraptor"}`, `"firewall":{"dns_fallback_to_dhcp":false}`); write the Task 6 `fixtureClientYAML` content as `payload/velociraptor.client.yaml` in `deps` (instead of `"cfg"`); delete the `tailscale-setup.msi` write; replace `__CA_HASH_PLACEHOLDER__` with `velo.CAFingerprint` of the fixture's PEM (`sha256:` + hex of sha256 of `{0,0,0}`). In `happyFake` add:

```go
	f.Responses[f.Key("sc.exe", "qc", "Velociraptor")] = runner.Result{Stdout: "        BINARY_PATH_NAME   : \"C:\\Program Files\\Velociraptor\\Velociraptor.exe\" --config \"C:\\Program Files\\Velociraptor\\client.config.yaml\" service run\r\n"}
```

Remove `f.Responses[f.Key("sc.exe","query","Tailscale")]`. Delete `TestPreflightRefusesHomeEditionWithRDP`. In `TestPreflightRefusesExistingInstall` keep only the Velociraptor case. In `TestRunHappyPath`: drop `iMSI`/`iUp` and the order assertion involving them (new order: rules → profile flip → `service install` → `schtasks`); expect `len(d.Man.Rules) == 9`; replace the tailscaled-vs-velociraptor egress comment/assertions with:

```go
	for _, want := range []string{
		"-DisplayName 'DFIRMedic-C1: velociraptor-egress' -Direction 'Outbound' -Action Allow -Program 'C:\\Program Files\\Velociraptor\\Velociraptor.exe' -Protocol 'TCP' -RemotePort '443' -RemoteAddress '203.0.113.10'",
		"-DisplayName 'DFIRMedic-C1: velociraptor-egress-payload' -Direction 'Outbound' -Action Allow -Program '" + filepath.Join(d.WorkDir, "payload", "velociraptor.exe") + "' -Protocol 'TCP' -RemotePort '443' -RemoteAddress '203.0.113.10'",
		"-DisplayName 'DFIRMedic-C1: orchestrator-probe' -Direction 'Outbound' -Action Allow -Program '" + filepath.Join(d.WorkDir, "dfirmedic.exe") + "' -Protocol 'TCP' -RemotePort '443' -RemoteAddress '203.0.113.10'",
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing rule %s in:\n%s", want, all)
		}
	}
	if strings.Contains(all, "msiexec") || strings.Contains(all, "tailscale") || strings.Contains(all, "-RemotePort '53'") {
		t.Fatalf("no Tailscale or DNS in the new design:\n%s", all)
	}
	if !f.Called("sc.exe", "qc", "Velociraptor") {
		t.Fatal("install must verify the registered service path (E41 check)")
	}
```

Remove the `payload/tools/thor-lite.exe` expectation only if it was tied to the MSI (it is not; keep it). Add:

```go
func TestPreflightRefusesClientConfigFromAnotherServer(t *testing.T) {
	f := happyFake()
	d := deps(t, f, incJSON)
	other := strings.Replace(fixtureClientYAML, "AAAA", "BBBB", 1) // different CA DER
	os.WriteFile(filepath.Join(d.KitDir, "payload", "velociraptor.client.yaml"), []byte(other), 0o644)
	manifest.Write(filepath.Join(d.KitDir, "payload")) // keep E13/E17 out of the way
	// re-sign: incident.json's manifest hash changed
	d = resign(t, d)
	err := Preflight(context.Background(), d)
	if err == nil || !strings.HasPrefix(err.Error(), "E18") {
		t.Fatalf("want E18, got %v", err)
	}
}

func TestInstallRefusesUnexpectedServicePath(t *testing.T) {
	f := happyFake()
	f.Responses[f.Key("sc.exe", "qc", "Velociraptor")] = runner.Result{Stdout: "        BINARY_PATH_NAME   : \"C:\\Elsewhere\\Velociraptor.exe\" service run\r\n"}
	d := deps(t, f, incJSON)
	err := Install(context.Background(), d)
	if err == nil || !strings.HasPrefix(err.Error(), "E41") {
		t.Fatalf("want E41, got %v", err)
	}
}
```

`resign` is a small test helper: recompute the manifest hash, rewrite `incident.json` with it, sign, and return updated `Deps` (mirror the body of `deps` from the manifest-hash step onward). `fixtureClientYAML` is declared in this test file too (copy the constant from Task 6; packages do not share test code).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/stage/ 2>&1 | head -8`
Expected: compile errors (`d.TS`, `Inc.Tailscale`, `QuarantineRules` arity).

- [ ] **Step 3: Change `stage.go`**

- Remove the `tailscale` import and `TS tailscale.Client` from `Deps`.
- `Preflight`: delete the RDP/edition block; change the service loop to only `velo.ServiceName`; after the E13 payload verification add:

```go
	rawCfg, err := os.ReadFile(filepath.Join(d.KitDir, filepath.FromSlash(d.Inc.Velociraptor.ConfigFile)))
	if err != nil {
		return code("E18", "read client config", err)
	}
	caPEM, err := velo.ExtractCA(rawCfg)
	if err != nil {
		return code("E18", "client config", err)
	}
	caFP, err := velo.CAFingerprint(caPEM)
	if err != nil {
		return code("E18", "client config", err)
	}
	if caFP != d.Inc.Server.CASHA256 {
		return code("E18", "client config CA does not match signed incident.json — kit was assembled from a different server", nil)
	}
```

- `Quarantine`: delete `rdpFrom`; replace the rule loop and the hand-built `veloRule` block with:

```go
	rules := append(
		win.QuarantineRules(d.Inc.Firewall.DNSFallbackToDHCP),
		win.ServerRules(
			d.Inc.Velociraptor.InstallPath,
			filepath.Join(d.WorkDir, "payload", "velociraptor.exe"),
			filepath.Join(d.WorkDir, "dfirmedic.exe"),
			d.Inc.Server.IP, d.Inc.Server.Port,
		)...,
	)
	for _, r := range rules {
		txt, err := d.FW.AddRule(ctx, group, r)
		if err != nil {
			return rollback(fmt.Errorf("rule %s: %w", r.Name, err))
		}
		d.Man.Rules = append(d.Man.Rules, txt)
	}
```

(Windows Firewall matches program paths at process launch, so the not-yet-existing paths are fine, as the old comment said.)

- `Install`: delete the `InstallMSI`/`Up` calls and the RDP block; after `d.Velo.InstallService` add:

```go
	got, err := d.Velo.InstalledBinaryPath(ctx)
	if err != nil {
		return code("E41", "read Velociraptor service path", err)
	}
	if !strings.EqualFold(got, d.Inc.Velociraptor.InstallPath) {
		return code("E41", fmt.Sprintf("Velociraptor service runs from %q but the firewall allows %q", got, d.Inc.Velociraptor.InstallPath), nil)
	}
	_ = d.Log.Record("velociraptor_path_verified", map[string]string{"path": got})
```

Add `"strings"` to imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/stage/ 2>&1 | tail -3`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add internal/stage/
git commit -m "stage: pin client config CA (E18), server egress rules, verify service path (E41), no Tailscale

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: Connect gates on the TLS probe (`internal/connect`)

**Files:**
- Modify: `internal/connect/connect.go`
- Test: `internal/connect/connect_test.go`

**Interfaces:**
- Consumes: `probe.Prober` (Task 2).
- Produces: `connect.Deps.Probe probe.Prober` (replaces `TS`). Audit event `server_verified{leaf_sha256}` on first success.

- [ ] **Step 1: Update the harness and tests**

In `connect_test.go`: drop the `tailscale` import and the `st*` constants; add a scripted prober and use it in `deps`:

```go
// fakeProbe returns scripted results in order, repeating the last one.
type fakeProbe struct {
	errs []error
	i    int
	n    int
}

func (p *fakeProbe) Verify(context.Context) (string, error) {
	p.n++
	i := p.i
	if i >= len(p.errs) {
		i = len(p.errs) - 1
	}
	p.i++
	if err := p.errs[i]; err != nil {
		return "", err
	}
	return "leaf0", nil
}

var errDown = errors.New("probe: dial tcp: i/o timeout")
```

`deps` takes `pr probe.Prober` instead of scripting `tailscale status`; the incident becomes:

```go
	inc := &config.Incident{
		CaseID:   "C1",
		Server:   config.Server{IP: "203.0.113.10", Port: 443},
		Watchdog: config.Watchdog{TunnelTimeoutSec: 600, HeartbeatGraceSec: 300},
		Contact:  config.Contact{Name: "Alex", Phone: "+1555"},
	}
	// ... Probe: pr, no TS
```

Rewrite the scenario tests to script the probe instead of `tailscale status`:
- `TestRunConnectsThenStartsVelociraptorThenHeartbeats`: `&fakeProbe{errs: []error{errDown, errDown, nil}}` → after connect, `sc.exe start Velociraptor` called once, phase `CONNECTED` present, audit contains `server_verified`, heartbeat keeps probing (probe `n` grows) until the clock cancels.
- `TestTunnelTimeoutFailsClosed`: `&fakeProbe{errs: []error{errDown}}` → `E50`, adapters disabled.
- `TestHeartbeatLossFailsClosed`: `[]error{nil, errDown}` with the clock stepping past the grace → `E51`.
- `TestHeartbeatToleratesBriefBlip`: `[]error{nil, errDown, nil}` → no fail-closed before cancel.
- `TestVelociraptorStartFailure`: probe `nil`, fake `sc.exe start` errors → `E52`.
- Others (`FailClosed…`, `WaitLinkUp…`, `DepsDefaults…`) unchanged apart from the harness.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/connect/ 2>&1 | head -5`
Expected: compile errors (`Deps.TS`, `Deps.Probe`).

- [ ] **Step 3: Change `connect.go`**

- Replace the `tailscale` import with `"github.com/dfirtnt/DFIRMedic/internal/probe"`; in `Deps` replace `TS tailscale.Client` with `Probe probe.Prober`.
- Replace `responderOnline`:

```go
// serverVerified is the tunnel-verified condition from spec 2026-09-05 §7:
// a TLS handshake with server_ip:port whose certificate chains to the CA in
// the shipped client config. A captive portal or a stranger on that IP
// cannot pass it.
func (d Deps) serverVerified(ctx context.Context) (string, bool) {
	if d.Probe == nil {
		return "", false
	}
	fp, err := d.Probe.Verify(ctx)
	if err != nil {
		return "", false
	}
	return fp, true
}
```

- In `Run`, the gate loop becomes:

```go
	deadline := d.Now().Add(time.Duration(d.Inc.Watchdog.TunnelTimeoutSec) * time.Second)
	var leaf string
	for {
		var ok bool
		if leaf, ok = d.serverVerified(ctx); ok {
			break
		}
		if !d.Now().Before(deadline) {
			return FailClosed(ctx, d, "E50 server not verified in time")
		}
		if err := d.Sleep(ctx, d.Poll); err != nil {
			d.Beacon.Set(ui.Error, fmt.Sprintf("server verification interrupted: %v", err))
			return err
		}
	}
	_ = d.Log.Record("server_verified", map[string]string{"server": d.Inc.Server.IP, "leaf_sha256": leaf})
```

- In the heartbeat loop replace `if d.responderOnline(ctx)` with `if _, ok := d.serverVerified(ctx); ok`, and the E51 text with `"E51 server unreachable"`.
- Update the package comment: "verify the server is ours via a pinned-CA TLS probe".

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/connect/ 2>&1 | tail -3`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add internal/connect/
git commit -m "connect: gate and heartbeat on the pinned-CA TLS probe instead of tailscale status

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 10: Teardown without Tailscale, with install-dir cleanup (`internal/teardown`)

**Files:**
- Modify: `internal/teardown/teardown.go`
- Test: `internal/teardown/teardown_test.go`

**Interfaces:**
- Consumes: `win.Sys.RemoveDirIfExists` (Task 4); `config.Velo.InstallPath`.
- Produces: `teardown.Deps` without `TS`. Step order: stop Velociraptor → remove service → delete install directory → delete startup task → remove rule group → import original policy → re-enable adapters → restore profiles.

- [ ] **Step 1: Update harness and tests**

In `deps`: remove the `tailscale` import and `TS:` line; set `inc.Velociraptor = config.Velo{InstallPath: "C:\\Program Files\\Velociraptor\\Velociraptor.exe"}`. Update `TestRunOrder` expected sequence to the order above, asserting the new step's argv:

```go
	iRemove := strings.Index(out, "service remove")
	iDir := strings.Index(out, `cmd.exe /c if exist C:\Program Files\Velociraptor rmdir /s /q C:\Program Files\Velociraptor`)
	iTask := strings.Index(out, "schtasks.exe /Delete")
	if !(iRemove < iDir && iDir < iTask) {
		t.Fatalf("install dir must be removed after the service and before the task:\n%s", out)
	}
	if strings.Contains(out, "tailscale") || strings.Contains(out, "msiexec") {
		t.Fatalf("no Tailscale steps:\n%s", out)
	}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/teardown/ 2>&1 | head -5`
Expected: compile error (`Deps.TS`).

- [ ] **Step 3: Change `teardown.go`**

Remove the `tailscale` import and `TS` field. Replace the two Tailscale steps; insert the directory step after "remove Velociraptor service":

```go
	step("stop Velociraptor", func() error { return d.Velo.Stop(ctx) })
	step("remove Velociraptor service", func() error { return d.Velo.RemoveService(ctx) })
	step("delete Velociraptor install directory", func() error {
		return d.Sys.RemoveDirIfExists(ctx, filepath.Dir(d.Inc.Velociraptor.InstallPath))
	})
	step("delete startup task", func() error { return d.Sys.DeleteStartupTask(ctx, stage.TaskNamePrefix+d.Inc.CaseID) })
	step("remove firewall rule group", func() error { return d.FW.RemoveGroup(ctx, d.Inc.RuleGroup()) })
```

Update the package comment to drop "logs out and uninstalls Tailscale".

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/teardown/ 2>&1 | tail -3`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add internal/teardown/
git commit -m "teardown: drop Tailscale steps, remove the Velociraptor install directory

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 11: CLI wiring and flags (`cmd/dfirmedic`)

**Files:**
- Modify: `cmd/dfirmedic/cmds.go`, `cmd/dfirmedic/main.go`
- Test: `cmd/dfirmedic/cmds_test.go`

**Interfaces:**
- Consumes: `build.Options` (Task 6), `connect.Deps.Probe` (Task 9), `probe.TLS` (Task 2), `velo.ExtractCA` (Task 1).
- Produces: `build` flags `--case --server-url --name --phone --breakglass-code --out [--dns-dhcp-fallback --tunnel-timeout --heartbeat-grace --ttl --payload --exe --card --key]`.

- [ ] **Step 1: Update tests**

`TestParseBuildRequiresCore`: required set is now `--case --server-url --phone --name --breakglass-code --out`; assert `--authkey` is rejected as an unknown flag:

```go
func TestParseBuildRejectsRemovedFlags(t *testing.T) {
	if _, err := parseBuild([]string{"--case", "C", "--authkey", "x"}); err == nil {
		t.Fatal("--authkey must no longer exist")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/dfirmedic/ 2>&1 | head -5`
Expected: compile errors (`tailscale` package, `o.AuthKey`).

- [ ] **Step 3: Change the CLI**

In `cmds.go`:
- Imports: remove `tailscale`; add `"github.com/dfirtnt/DFIRMedic/internal/probe"`.
- `parseBuild`: delete the `authkey`, `hostname`, `responder-node-key`, `responder-ip`, `dns`, `rdp` flags and the `dns` split loop; `server-url` help becomes `"Velociraptor server URL, https://<public-ip>[:port]/ (IP literal; default port 443)"`; required map becomes `{"case","server-url","phone","name","breakglass-code","out"}`.
- `host`: remove `ts`; add `caPEM []byte`.
- `openHost`: after computing `payload`, read the CA (tolerate absence so `stage` on a kit dir still opens; preflight reports E18 with a clear message if it is missing):

```go
	caPEM, _ := func() ([]byte, error) {
		raw, err := os.ReadFile(filepath.Join(dir, "payload", "velociraptor.client.yaml"))
		if err != nil {
			return nil, err
		}
		return velo.ExtractCA(raw)
	}()
```

  and drop the `ts:` field from the returned struct; set `caPEM: caPEM`.
- `runConnect`: build the prober:

```go
	d := connect.Deps{
		Inc: h.inc, WorkDir: workDir, R: h.r, Log: h.log, Man: h.man, Beacon: h.beacon,
		Net: h.net, Velo: h.velo,
		Probe: probe.TLS{IP: h.inc.Server.IP, Port: h.inc.Server.Port, CAPEM: h.caPEM, Timeout: 10 * time.Second},
	}
```

- `teardownDeps`: drop `TS: h.ts`.
- `cmdStage`'s `stage.Deps` literal: drop `TS: h.ts`.

In `main.go` usage text: `build        assemble and sign a per-incident kit onto a USB (no Tailscale key needed)`. Nothing else.

- [ ] **Step 4: Run tests and the full build**

Run: `go build ./... && go vet ./... && go test ./cmd/dfirmedic/ 2>&1 | tail -3`
Expected: build clean; `ok`. (`internal/tailscale` still compiles on its own; it is deleted next.)

- [ ] **Step 5: Commit**

```bash
git add cmd/dfirmedic/
git commit -m "cli: build without Tailscale flags; wire the TLS probe into connect

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 12: Delete the Tailscale package; full check

**Files:**
- Delete: `internal/tailscale/tailscale.go`, `internal/tailscale/tailscale_test.go`
- Modify: `payload/README.md` (drop the MSI line)
- Delete (local, untracked): `payload/tailscale-setup.msi`

- [ ] **Step 1: Prove nothing imports it**

Run: `grep -rn "internal/tailscale" --include=*.go . ; echo "exit=$?"`
Expected: no matches, `exit=1`.

- [ ] **Step 2: Delete and run the full check**

```bash
git rm -r internal/tailscale
rm -f payload/tailscale-setup.msi
sed -i '' '/tailscale-setup.msi/d' payload/README.md
export PATH="$HOME/go/bin:$PATH"
gofmt -l cmd internal ; make check
```

Expected: `gofmt -l` prints nothing for changed files (three pre-existing unformatted files are a separate task); `make check` ends with the Windows build line and exit 0.

- [ ] **Step 3: Commit**

```bash
git add payload/README.md
git commit -m "Remove internal/tailscale and the MSI from the payload

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 13: Documentation

**Files:**
- Modify: `docs/responder-setup.md`, `docs/integration-tests.md`, `README.md`, `docs/superpowers/specs/2026-09-04-dfirmedic-design.md`

- [ ] **Step 1: Responder guide**

Replace §1–§4 of `docs/responder-setup.md` with the following (keep §5 signing key, renumber §6–§8 to follow):

````markdown
# Responder-side setup

One-time setup on your side. Everything the victim host does is in the specs
(`docs/superpowers/specs/`). The victim reaches exactly one thing: your Velociraptor
frontend at a fixed public IP. It never runs Tailscale and never resolves a name.

## 1. Velociraptor server on a VPS

A small Linux VPS with a **static public IPv4**, nothing else on it. On it:

```bash
# as root
useradd --system --home /opt/velociraptor --shell /usr/sbin/nologin velociraptor
mkdir -p /opt/velociraptor /var/lib/velociraptor && chown velociraptor: /opt/velociraptor /var/lib/velociraptor
# install the same release as payload/velociraptor.exe (currently 0.77.2)
curl -fsSL -o /opt/velociraptor/velociraptor https://github.com/Velocidex/velociraptor/releases/download/v0.77.2/velociraptor-v0.77.2-linux-amd64
chmod 0755 /opt/velociraptor/velociraptor
# join the tailnet so you can reach the GUI; the victim never uses this
curl -fsSL https://tailscale.com/install.sh | sh && tailscale up
TAILNET_IP=$(tailscale ip -4)
PUBLIC_IP=$(curl -fsS https://api.ipify.org)
/opt/velociraptor/velociraptor config generate --merge "{
  \"Frontend\": {\"hostname\": \"$PUBLIC_IP\", \"bind_address\": \"0.0.0.0\", \"bind_port\": 443},
  \"GUI\": {\"bind_address\": \"$TAILNET_IP\", \"bind_port\": 8889, \"public_url\": \"https://$TAILNET_IP:8889/app/index.html\"},
  \"API\": {\"bind_address\": \"127.0.0.1\"}, \"Monitoring\": {\"bind_address\": \"127.0.0.1\"},
  \"Datastore\": {\"location\": \"/var/lib/velociraptor\", \"filestore_directory\": \"/var/lib/velociraptor\"},
  \"Client\": {\"server_urls\": [\"https://$PUBLIC_IP:443/\"]}
}" > /opt/velociraptor/server.config.yaml
chown velociraptor: /opt/velociraptor/server.config.yaml && chmod 0600 /opt/velociraptor/server.config.yaml
/opt/velociraptor/velociraptor --config /opt/velociraptor/server.config.yaml user add admin --role administrator
/opt/velociraptor/velociraptor --config /opt/velociraptor/server.config.yaml service install   # systemd unit
# host firewall: only 443 public; SSH and GUI over the tailnet
ufw default deny incoming && ufw allow 443/tcp && ufw allow in on tailscale0 && ufw enable
```

Binding to port 443 as a non-root user needs `setcap cap_net_bind_service=+ep /opt/velociraptor/velociraptor`
or `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the unit.

Confirm `Client.server_urls` in the generated config is `https://<public-ip>:443/` — an IP,
never a hostname — then export the client config the kit ships:

```bash
/opt/velociraptor/velociraptor --config /opt/velociraptor/server.config.yaml config client > velociraptor.client.yaml
```

Copy that file to `payload/velociraptor.client.yaml` on your Mac. `dfirmedic build` reads the
CA and `install_path` out of it and refuses a client config whose `server_urls` does not
list your `--server-url`. **If the VPS IP ever changes, every kit built against it is dead.**

Put the datastore on an encrypted volume; the VPS holds evidence.

## 2. Tailnet

Only you and the VPS. No victim tags, no victim grants, no RDP. The default
`autogroup:member → autogroup:member` grant is enough. Keep device approval on.

## 3. Tool cache

Artifacts with a tool dependency (Autoruns) fetch the binary from **your server**, never
the internet. Seed it once: GUI → View Artifacts → `Windows.Sysinternals.Autoruns` → Tools →
Upload `payload/tools/autorunsc64.exe`, or from the VPS
`velociraptor --config server.config.yaml tools upload --name Autorun_amd64 autorunsc64.exe`
followed by a service restart. Memory acquisition needs nothing: WinPmem is built into the client.

## 4. Sanity check from the responder side

```bash
openssl s_client -connect <public-ip>:443 </dev/null 2>/dev/null | openssl x509 -noout -issuer
```

The issuer must be your Velociraptor CA. The kit does the same check on the victim
(spec 2026-09-05 §7); if this fails here it will fail there.
````

§6 "Per incident" build example becomes:

```bash
./dist/dfirmedic build \
  --case CASE-2026-0042 \
  --server-url https://<public-ip>:443/ \
  --name "Your Name" --phone "+1..." \
  --breakglass-code "$(openssl rand -hex 4)" \
  --out /Volumes/DFIRMEDIC
```

and step 1 (mint an auth key) is deleted. In §7 "First-connect collection", item 1's path is unchanged. In §8 "After the engagement", delete "then delete the node in the admin console".

- [ ] **Step 2: Integration runbook**

In `docs/integration-tests.md`: Setup paragraph → "a Velociraptor server reachable at a public IP (or, for a lab, any IP the VM can route to) and a kit built with `--ttl 2h`". Row 1 expected: replace "Velociraptor client appears" with "`audit.jsonl` has `server_verified` with a `leaf_sha256`; client appears in the GUI within 60 s; `netstat -ano` on the VM shows ESTABLISHED to `<ip>:443` from `Velociraptor.exe`". Row 3/4: "Stop the responder workstation's tailscaled" → "Stop the Velociraptor service on the server". Row 5 → `| 5 | Proxy-only egress | On the VM host, block outbound TCP 443 from the VM. Stage, reconnect. | After ~600 s: ERROR E50, adapters Disabled, firewall still default-deny. |`. Row 6: "tailscaled reconnects" → "the startup task re-runs the probe". Delete row 8. Add:

```
| 12 | Client config from another server | Replace `payload\velociraptor.client.yaml` on the stick with one from a different Velociraptor server, then regenerate `manifest.sha256`. Stage. | ERROR E17 (manifest hash no longer matches signed incident.json). If `incident.json` is also re-signed with a stolen key, E18 (CA mismatch) — the two checks are independent. |
| 13 | Impostor on the server IP | Stand up a second Velociraptor with a fresh CA on the same IP:port (or any TLS server). Stage, reconnect. | Never CONNECTED; `audit.jsonl` shows repeated probe failures naming "pinned CA"; E50 at the timeout. |
| 14 | Service path check | Edit `payload\velociraptor.client.yaml` on the stick so `install_path` differs from the one in `incident.json` (and regenerate the manifest; E17 will fire first — so instead pre-install Velociraptor to `C:\Elsewhere` before staging and rely on E16). | E16 (service exists). To exercise E41 directly, run `stage` with a fake `sc.exe qc` in a unit test; E41 has no clean integration trigger. |
```

- [ ] **Step 3: README and old spec**

`README.md` "Use" paragraph: add "The victim reaches only your Velociraptor server's public IP; Tailscale is used on the responder side only." Old spec: insert directly under the title:

```markdown
> **Superseded in part on 2026-09-05** by `2026-09-05-direct-velociraptor-design.md`, which
> removes Tailscale from the victim. Its §9 lists which sections below no longer apply.
> Sections not listed there remain authoritative.
```

- [ ] **Step 4: Verify no stale references**

Run: `grep -rn -i "tailscale\|authkey\|responder-node-key\|1\.1\.1\.1" README.md FIELD-CARD.md docs/responder-setup.md docs/integration-tests.md payload/README.md`
Expected: only the deliberate mentions in responder-setup §1–§2 ("join the tailnet", "Tailnet") and the README sentence above. Anything else is stale; fix it.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/responder-setup.md docs/integration-tests.md docs/superpowers/specs/2026-09-04-dfirmedic-design.md
git commit -m "docs: VPS-hosted Velociraptor, no victim-side Tailscale

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 14: Rebuild binaries and prove the pipeline end to end

**Files:** none in git (`dist/` and a scratch kit).

- [ ] **Step 1: Rebuild both binaries**

```bash
export PATH="$HOME/go/bin:$PATH"
make build-darwin && make build-windows LDFLAGS="-X github.com/dfirtnt/DFIRMedic/internal/sign.embeddedPubKeyHex=98a7e595f1e05f0134293f5d421a858604ba1b9c3b459834c5ef41562bdb642e"
strings dist/dfirmedic.exe | grep -c requireAdministrator   # expect 1
```

- [ ] **Step 2: Trial build against the current client config**

The Mac's current `payload/velociraptor.client.yaml` lists `https://100.117.50.126:8000/`, an IP literal, so it exercises the new path even before the VPS exists:

```bash
K=$(mktemp -d)/kit
./dist/dfirmedic build --case TEST-DIRECT --server-url https://100.117.50.126:8000/ \
  --name "Test" --phone "555" --breakglass-code deadbeef --out "$K" && ./dist/dfirmedic verify --kit "$K"
jq '.schema, .server, .velociraptor' "$K/incident.json"
```

Expected: `OK: case TEST-DIRECT …`; `schema` 2; `server.ip` `100.117.50.126`, `port` 8000, `ca_sha256` present; `install_path` `C:\Program Files\Velociraptor\Velociraptor.exe`. Then:

```bash
./dist/dfirmedic build --case X --server-url https://velo.example.com/ --name a --phone b --breakglass-code c --out "$K-2" ; echo "exit=$?"
```

Expected: non-zero exit, message "host must be an IP literal".

- [ ] **Step 3: Probe the live Mac server with the new binary's logic**

There is no CLI wrapper for the probe; confirm the pinned CA relationship with OpenSSL instead:

```bash
openssl s_client -connect 100.117.50.126:8000 </dev/null 2>/dev/null | openssl x509 -noout -issuer
```

Expected: issuer is the Velociraptor CA from `~/.dfirmedic/velociraptor/server.config.yaml`.

- [ ] **Step 4: Update Todoist** (project DFIRMedic; responder-side, do it if the connector is available, otherwise list it in the final report)

Complete as superseded: "Set pinned DNS resolvers on adapters…", "Install Tailscale silently…", "`build` rejects auth keys that are not tagged…", "Velociraptor egress rule must allow the service's real install path" (delivered by Task 8), "Decide where the Velociraptor server lives" (VPS). Add one task: "Provision the Velociraptor VPS per docs/responder-setup.md §1 and regenerate payload/velociraptor.client.yaml", reasoning-medium, blocking "Second real-host test".

- [ ] **Step 5: Closeout**

Run the LG closeout (the user's `lg` skill) to push the commits from Tasks 1–13 together with whatever was already uncommitted from 2026-09-05.

---

## Self-review

**Spec coverage.** §3 decisions → Tasks 5–8, 11. §4.1 server → Task 13 §1. §4.1 `build` derivation → Task 6. §5 schema 2 → Task 5; `ca_sha256` semantics → Tasks 1, 6, 8. §6.1 E18 → Task 8; drop Tailscale/edition checks → Task 8. §6.3 nine rules → Tasks 4, 7, 8. §6.4 no MSI, E41 → Tasks 3, 8. §7 probe → Tasks 2, 9, 11. §8 failure table → Task 9 (E50/E51 text), Task 13 (runbook rows 5, 12, 13). Teardown install-dir removal → Tasks 4, 10. §9 old-spec dispositions → Task 13 banner. §11 unit tests → Tasks 2, 5, 7, 8, 10; integration rows → Task 13. §12 deletions → Tasks 7, 11, 12, 13; additions → Tasks 1–11; Todoist → Task 14.

**Placeholder scan.** No TBD/TODO. Task 8 Step 1 references a `resign` helper and asks the implementer to mirror the existing `deps` body; that is a concrete instruction, not a placeholder, and the surrounding `deps` code is in the file.

**Type consistency.** `probe.Prober.Verify(ctx) (string, error)` — same in Tasks 2, 9, 11. `velo.ExtractCA([]byte) ([]byte, error)`, `velo.CAFingerprint([]byte) (string, error)`, `velo.ExtractInstallPath([]byte) (string, error)` — same in Tasks 1, 6, 8, 11. `win.ServerRules(installPath, payloadExe, orchestratorExe, serverIP string, serverPort int)` — Tasks 4, 8. `win.QuarantineRules(bool)` — Tasks 7, 8. `config.Server{URL, IP, Port, CASHA256}`, `config.Velo{ConfigFile, InstallPath, ServiceName}` — Tasks 5, 6, 8, 9, 10. `Sys.RemoveDirIfExists(ctx, dir)` — Tasks 4, 10. `build.ServerFromURL(string) (config.Server, error)` — Task 6 only.
