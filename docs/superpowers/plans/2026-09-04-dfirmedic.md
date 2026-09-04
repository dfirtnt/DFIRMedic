# DFIRMedic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `dfirmedic`, a Go orchestrator that stages a compromised Windows host offline (baseline, firewall quarantine, Tailscale, Velociraptor), signals READY, verifies the tunnel to the responder on reconnect, and can tear everything down — plus the responder-side `build` command that produces the signed USB kit.

**Architecture:** One Go module, two binaries from the same code: `dfirmedic.exe` (Windows, runs on the victim) and `dfirmedic` (macOS, runs `build`/`keygen`/`verify` on the responder's Mac). Every host-changing action is a shell-out to a Microsoft- or vendor-signed binary through a single `Runner` interface, so all logic is unit-testable on macOS with a fake runner and every executed command lands in a hash-chained audit log. A sequential state machine drives staging; a watchdog fails closed by disabling adapters.

**Tech Stack:** Go 1.22+, stdlib + `golang.org/x/sys/windows` (elevation check, console VT mode) + `github.com/tc-hib/go-winres` (embed `requireAdministrator` manifest). `CGO_ENABLED=0`. Windows tools invoked: `netsh.exe`, `powershell.exe` (NetSecurity cmdlets), `msiexec.exe`, `sc.exe`, `schtasks.exe`, `reg.exe`, `tailscale.exe`, `velociraptor.exe`.

**Spec:** `docs/superpowers/specs/2026-09-04-dfirmedic-design.md`

## Global Constraints

- Module path `github.com/dfirtnt/DFIRMedic`; Go `1.22` minimum.
- `CGO_ENABLED=0` for every build. No cgo, no GUI toolkit.
- The orchestrator never modifies, repacks, or wraps `velociraptor.exe` or `tailscale-setup.msi`. Config is passed via `--config`.
- Every host-changing command goes through `runner.Runner` and is written to the audit log. No `os/exec` outside `internal/runner`.
- Firewall rule group name is exactly `DFIRMedic-<case_id>` and contains **allow rules only**.
- Windows-only code lives in files with `//go:build windows`; a `//go:build !windows` stub must exist so `go test ./...` passes on macOS.
- Commit after every task with the message shown. Sign-off line: `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Run `make check` (macOS tests + Windows cross-compile) before every commit.

## File Structure

```
go.mod / go.sum
Makefile                              build-darwin, build-windows, test, check
winres/winres.json                    go-winres source: requireAdministrator manifest
cmd/dfirmedic/main.go                 subcommand dispatch only
internal/config/config.go             Incident struct, Load, Validate
internal/sign/sign.go                 ed25519 keygen/sign/verify; embedded pubkey
internal/manifest/manifest.go         payload manifest.sha256 write/verify
internal/audit/audit.go               hash-chained audit.jsonl + manifest.json
internal/runner/runner.go             Runner interface, Exec, DryRun, Fake
internal/win/firewall.go              export/import, profiles, rule group, baseline
internal/win/adapter.go               adapter status, disable
internal/win/system.go                edition, RDP enable, startup task, elevation
internal/win/elevated_windows.go      IsElevated via x/sys/windows
internal/win/elevated_other.go        stub
internal/tailscale/tailscale.go       install, up, status, logout, uninstall
internal/velo/velo.go                 service install/start/stop/remove
internal/ui/beacon.go                 console beacon (STAGING/READY/CONNECTED/ERROR)
internal/ui/vt_windows.go             enable VT processing
internal/ui/vt_other.go               stub
internal/stage/stage.go               Preflight → Baseline → Quarantine → Install → Ready
internal/connect/connect.go           link-up wait, tunnel verify, start Velociraptor
internal/connect/watchdog.go          timeout + heartbeat, fail closed
internal/teardown/teardown.go         teardown + breakglass
internal/build/build.go               responder-side kit builder
docs/responder-setup.md               server, ACL, exit node, key minting
docs/integration-tests.md             Windows VM test matrix runbook
payload/README.md                     what goes in payload/ (binaries not committed)
FIELD-CARD.md                         template copied to USB as FIELD-CARD.txt
```

Each `internal/*` package has a `*_test.go` beside it. Tests never touch the real OS: they use `runner.Fake`.

---

### Task 1: Module scaffold, Makefile, admin manifest

**Files:**
- Create: `go.mod`, `Makefile`, `winres/winres.json`, `cmd/dfirmedic/main.go`, `.gitignore`, `payload/README.md`

**Interfaces:**
- Produces: `make check` (runs `go vet`, `go test ./...` on macOS, then `GOOS=windows GOARCH=amd64 go build`), `make build-windows` → `dist/dfirmedic.exe`, `make build-darwin` → `dist/dfirmedic`.

- [ ] **Step 1: Initialise the module and dependencies**

```bash
go mod init github.com/dfirtnt/DFIRMedic
go get golang.org/x/sys@latest
go install github.com/tc-hib/go-winres@latest
```

- [ ] **Step 2: Write `cmd/dfirmedic/main.go` with a usage stub**

```go
package main

import (
	"fmt"
	"os"
)

//go:generate go-winres make --in ../../winres/winres.json --out rsrc

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: dfirmedic <command> [flags]

commands (victim host, Windows):
  stage        stage the host offline; ends at READY
  connect      wait for link-up, verify tunnel, start Velociraptor
  teardown     remove everything and restore the firewall baseline
  breakglass   local emergency rollback; requires the break-glass code

commands (responder workstation):
  keygen       create the responder ed25519 signing keypair
  build        assemble and sign a per-incident kit onto a USB
  verify       verify a kit's signature and payload hashes`)
}
```

- [ ] **Step 3: Write `winres/winres.json`**

```json
{
  "RT_MANIFEST": {
    "#1": {
      "0409": {
        "identity": { "name": "dfirmedic", "version": "0.1.0.0" },
        "description": "DFIRMedic host orchestrator",
        "execution-level": "requireAdministrator",
        "ui-access": false,
        "dpi-awareness": "system"
      }
    }
  }
}
```

- [ ] **Step 4: Write the `Makefile`**

```make
LDFLAGS ?=
export CGO_ENABLED=0

.PHONY: test vet check build-windows build-darwin generate clean

test:
	go test ./...

vet:
	go vet ./...

generate:
	cd cmd/dfirmedic && go generate

build-windows: generate
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/dfirmedic.exe ./cmd/dfirmedic

build-darwin:
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/dfirmedic ./cmd/dfirmedic

check: vet test
	GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd/dfirmedic

clean:
	rm -rf dist cmd/dfirmedic/rsrc_windows_*.syso
```

- [ ] **Step 5: Write `.gitignore` and `payload/README.md`**

`.gitignore`:
```
dist/
cmd/dfirmedic/rsrc_windows_*.syso
payload/*
!payload/README.md
*.key
```

`payload/README.md`:
```markdown
# payload/

Not committed. Populate before `dfirmedic build`:

- `tailscale-setup.msi` — from https://tailscale.com/download/windows, unmodified
- `velociraptor.exe` — Windows amd64 release from https://github.com/Velocidex/velociraptor/releases, unmodified
- `velociraptor.client.yaml` — client config generated by your server (`velociraptor config client`)
- `tools/autorunsc64.exe`, `tools/procexp64.exe`, `tools/pslist64.exe` — Sysinternals
- `tools/thor-lite.exe`, `tools/thor-lite.lic`, `tools/signatures/` — THOR Lite

`dfirmedic build` regenerates `manifest.sha256` from whatever is here.
```

- [ ] **Step 6: Verify the scaffold builds on both targets**

Run: `make check && make build-windows && ls -la dist/`
Expected: no errors; `dist/dfirmedic.exe` exists; `cmd/dfirmedic/rsrc_windows_amd64.syso` was generated.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "Scaffold module, Makefile, admin manifest

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: `internal/config` — Incident config

**Files:**
- Create: `internal/config/config.go`, `internal/config/config_test.go`

**Interfaces:**
- Produces:
  ```go
  type Incident struct {
      Schema      int       `json:"schema"`
      CaseID      string    `json:"case_id"`
      CreatedUTC  time.Time `json:"created_utc"`
      ExpiresUTC  time.Time `json:"expires_utc"`
      Tailscale   Tailscale `json:"tailscale"`
      Velociraptor Velo     `json:"velociraptor"`
      Firewall    Firewall  `json:"firewall"`
      Watchdog    Watchdog  `json:"watchdog"`
      Contact     Contact   `json:"contact"`
      BreakglassCodeHash string `json:"breakglass_code_hash"`
  }
  type Tailscale struct { AuthKey, Hostname, ResponderNodeKey, ResponderTailnetIP string }
  type Velo struct { ServerURL, ConfigFile string }
  type Firewall struct { DNSResolvers []string; AllowRDPFromResponder, DNSFallbackToDHCP bool }
  type Watchdog struct { TunnelTimeoutSec, HeartbeatGraceSec int }
  type Contact struct { Phone, Name string }
  func Load(path string) (*Incident, []byte, error)   // returns parsed struct and raw bytes (for signature verification)
  func (i *Incident) Validate(now time.Time) error
  func (i *Incident) RuleGroup() string               // "DFIRMedic-" + CaseID
  ```

- [ ] **Step 1: Write the failing tests**

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sample = `{
  "schema": 1,
  "case_id": "CASE-2026-0042",
  "created_utc": "2026-09-04T22:15:00Z",
  "expires_utc": "2026-09-05T22:15:00Z",
  "tailscale": {"authkey":"tskey-auth-x","hostname":"ir-CASE-2026-0042","responder_node_key":"nodekey:abc","responder_tailnet_ip":"100.64.0.1"},
  "velociraptor": {"server_url":"https://100.64.0.1:8000/","config_file":"payload/velociraptor.client.yaml"},
  "firewall": {"dns_resolvers":["1.1.1.1","9.9.9.9"],"allow_rdp_from_responder":false,"dns_fallback_to_dhcp":false},
  "watchdog": {"tunnel_timeout_sec":600,"heartbeat_grace_sec":300},
  "contact": {"phone":"+15555550100","name":"Responder"},
  "breakglass_code_hash": "sha256:0000"
}`

func write(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "incident.json")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadParsesAndReturnsRaw(t *testing.T) {
	inc, raw, err := Load(write(t, sample))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != sample {
		t.Fatal("raw bytes must be returned verbatim")
	}
	if inc.CaseID != "CASE-2026-0042" || inc.Tailscale.ResponderNodeKey != "nodekey:abc" {
		t.Fatalf("bad parse: %+v", inc)
	}
	if inc.RuleGroup() != "DFIRMedic-CASE-2026-0042" {
		t.Fatal(inc.RuleGroup())
	}
}

func TestValidateRejectsExpired(t *testing.T) {
	inc, _, _ := Load(write(t, sample))
	err := inc.Validate(time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestValidateRejectsMissingFields(t *testing.T) {
	inc, _, _ := Load(write(t, sample))
	inc.Tailscale.AuthKey = ""
	if err := inc.Validate(inc.CreatedUTC); err == nil {
		t.Fatal("expected missing authkey error")
	}
	inc, _, _ = Load(write(t, sample))
	inc.CaseID = "bad case id with spaces"
	if err := inc.Validate(inc.CreatedUTC); err == nil {
		t.Fatal("expected case id error")
	}
	inc, _, _ = Load(write(t, sample))
	inc.Watchdog.TunnelTimeoutSec = 0
	if err := inc.Validate(inc.CreatedUTC); err == nil {
		t.Fatal("expected watchdog error")
	}
}

func TestValidateAcceptsSample(t *testing.T) {
	inc, _, _ := Load(write(t, sample))
	if err := inc.Validate(inc.CreatedUTC.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -v`
Expected: FAIL — `undefined: Load`

- [ ] **Step 3: Implement `config.go`**

```go
// Package config loads and validates the per-incident incident.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"
)

type Incident struct {
	Schema             int       `json:"schema"`
	CaseID             string    `json:"case_id"`
	CreatedUTC         time.Time `json:"created_utc"`
	ExpiresUTC         time.Time `json:"expires_utc"`
	Tailscale          Tailscale `json:"tailscale"`
	Velociraptor       Velo      `json:"velociraptor"`
	Firewall           Firewall  `json:"firewall"`
	Watchdog           Watchdog  `json:"watchdog"`
	Contact            Contact   `json:"contact"`
	BreakglassCodeHash string    `json:"breakglass_code_hash"`
}

type Tailscale struct {
	AuthKey            string `json:"authkey"`
	Hostname           string `json:"hostname"`
	ResponderNodeKey   string `json:"responder_node_key"`
	ResponderTailnetIP string `json:"responder_tailnet_ip"`
}

type Velo struct {
	ServerURL  string `json:"server_url"`
	ConfigFile string `json:"config_file"`
}

type Firewall struct {
	DNSResolvers          []string `json:"dns_resolvers"`
	AllowRDPFromResponder bool     `json:"allow_rdp_from_responder"`
	DNSFallbackToDHCP     bool     `json:"dns_fallback_to_dhcp"`
}

type Watchdog struct {
	TunnelTimeoutSec  int `json:"tunnel_timeout_sec"`
	HeartbeatGraceSec int `json:"heartbeat_grace_sec"`
}

type Contact struct {
	Phone string `json:"phone"`
	Name  string `json:"name"`
}

var caseIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

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
	if i.Schema != 1 {
		errs = append(errs, fmt.Errorf("schema %d unsupported", i.Schema))
	}
	if !caseIDRe.MatchString(i.CaseID) {
		errs = append(errs, errors.New("case_id must be 1-64 chars of [A-Za-z0-9._-]"))
	}
	if i.ExpiresUTC.IsZero() || !now.Before(i.ExpiresUTC) {
		errs = append(errs, fmt.Errorf("incident config expired at %s", i.ExpiresUTC.Format(time.RFC3339)))
	}
	if i.Tailscale.AuthKey == "" {
		errs = append(errs, errors.New("tailscale.authkey required"))
	}
	if i.Tailscale.Hostname == "" {
		errs = append(errs, errors.New("tailscale.hostname required"))
	}
	if i.Tailscale.ResponderNodeKey == "" {
		errs = append(errs, errors.New("tailscale.responder_node_key required"))
	}
	if i.Tailscale.ResponderTailnetIP == "" {
		errs = append(errs, errors.New("tailscale.responder_tailnet_ip required"))
	}
	if i.Velociraptor.ServerURL == "" || i.Velociraptor.ConfigFile == "" {
		errs = append(errs, errors.New("velociraptor.server_url and config_file required"))
	}
	if len(i.Firewall.DNSResolvers) == 0 && !i.Firewall.DNSFallbackToDHCP {
		errs = append(errs, errors.New("firewall.dns_resolvers required unless dns_fallback_to_dhcp"))
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
	return errors.Join(errs...)
}

func (i *Incident) RuleGroup() string { return "DFIRMedic-" + i.CaseID }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: 4 PASS

- [ ] **Step 5: Commit**

```bash
git add internal/config
git commit -m "Add incident config loading and validation

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: `internal/sign` — ed25519 signing of incident.json

**Files:**
- Create: `internal/sign/sign.go`, `internal/sign/sign_test.go`

**Interfaces:**
- Produces:
  ```go
  func GenerateKeypair() (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error)
  func WritePrivateKey(path string, priv ed25519.PrivateKey) error   // 0600, hex
  func ReadPrivateKey(path string) (ed25519.PrivateKey, error)
  func Sign(priv ed25519.PrivateKey, payload []byte) []byte           // raw 64-byte sig
  func Verify(pub ed25519.PublicKey, payload, sig []byte) bool
  func EmbeddedPublicKey() (ed25519.PublicKey, error)                 // from -ldflags -X embeddedPubKeyHex
  func WriteSig(path string, sig []byte) error / ReadSig(path string) ([]byte, error) // hex text file
  ```
- `embeddedPubKeyHex` is a package-level `var` set via `-ldflags "-X github.com/dfirtnt/DFIRMedic/internal/sign.embeddedPubKeyHex=<hex>"`.

- [ ] **Step 1: Write the failing tests**

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/sign/ -v`
Expected: FAIL — `undefined: GenerateKeypair`

- [ ] **Step 3: Implement `sign.go`**

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sign/ -v`
Expected: 4 PASS

- [ ] **Step 5: Commit**

```bash
git add internal/sign
git commit -m "Add ed25519 signing for incident config

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: `internal/manifest` — payload hash manifest

**Files:**
- Create: `internal/manifest/manifest.go`, `internal/manifest/manifest_test.go`

**Interfaces:**
- Produces:
  ```go
  // Write walks dir, hashes every regular file except manifest.sha256 itself,
  // and writes "<hex>  <relative/path>\n" lines (sha256sum format) to dir/manifest.sha256.
  func Write(dir string) (map[string]string, error)
  // Verify reads dir/manifest.sha256 and checks every listed file exists and matches.
  // Returns the hashes on success; on failure the error lists every mismatch/missing file.
  func Verify(dir string) (map[string]string, error)
  func HashFile(path string) (string, error)   // hex sha256
  ```
- Relative paths always use forward slashes.

- [ ] **Step 1: Write the failing tests**

```go
package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mk(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestWriteThenVerify(t *testing.T) {
	dir := mk(t, map[string]string{"a.exe": "aaa", "tools/b.exe": "bbb"})
	got, err := Write(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["tools/b.exe"] == "" {
		t.Fatalf("bad hashes: %v", got)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if !strings.Contains(string(body), "  tools/b.exe\n") {
		t.Fatalf("manifest format wrong:\n%s", body)
	}
	if _, err := Verify(dir); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyDetectsTamperAndMissing(t *testing.T) {
	dir := mk(t, map[string]string{"a.exe": "aaa", "b.exe": "bbb"})
	if _, err := Write(dir); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "a.exe"), []byte("evil"), 0o644)
	os.Remove(filepath.Join(dir, "b.exe"))
	_, err := Verify(dir)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "a.exe") || !strings.Contains(err.Error(), "b.exe") {
		t.Fatalf("error must name both files: %v", err)
	}
}

func TestVerifyRejectsMalformedLine(t *testing.T) {
	dir := mk(t, map[string]string{"manifest.sha256": "not a manifest\n"})
	if _, err := Verify(dir); err == nil {
		t.Fatal("expected parse error")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/manifest/ -v`
Expected: FAIL — `undefined: Write`

- [ ] **Step 3: Implement `manifest.go`**

```go
// Package manifest writes and verifies payload/manifest.sha256.
package manifest

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const FileName = "manifest.sha256"

func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func Write(dir string) (map[string]string, error) {
	hashes := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if rel == FileName {
			return nil
		}
		h, err := HashFile(p)
		if err != nil {
			return err
		}
		hashes[rel] = h
		return nil
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(hashes))
	for n := range hashes {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", hashes[n], n)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(b.String()), 0o644); err != nil {
		return nil, err
	}
	return hashes, nil
}

func Verify(dir string) (map[string]string, error) {
	f, err := os.Open(filepath.Join(dir, FileName))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	expected := map[string]string{}
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		txt := sc.Text()
		if strings.TrimSpace(txt) == "" {
			continue
		}
		parts := strings.SplitN(txt, "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 {
			return nil, fmt.Errorf("%s line %d: malformed", FileName, line)
		}
		expected[parts[1]] = parts[0]
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	var errs []error
	for rel, want := range expected {
		got, err := HashFile(filepath.Join(dir, filepath.FromSlash(rel)))
		switch {
		case errors.Is(err, os.ErrNotExist):
			errs = append(errs, fmt.Errorf("missing: %s", rel))
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", rel, err))
		case got != want:
			errs = append(errs, fmt.Errorf("hash mismatch: %s", rel))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return expected, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/manifest/ -v`
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add internal/manifest
git commit -m "Add payload hash manifest write/verify

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: `internal/audit` — hash-chained audit log and manifest.json

**Files:**
- Create: `internal/audit/audit.go`, `internal/audit/audit_test.go`

**Interfaces:**
- Produces:
  ```go
  type Entry struct {
      Seq      int             `json:"seq"`
      TSUTC    time.Time       `json:"ts_utc"`
      Event    string          `json:"event"`
      Data     json.RawMessage `json:"data"`
      PrevHash string          `json:"prev_hash"`
      Hash     string          `json:"hash"`
  }
  type Log struct { /* unexported */ }
  func Open(path string, now func() time.Time) (*Log, error)  // creates or resumes; verifies existing chain on resume
  func (l *Log) Record(event string, data any) error            // appends one entry, fsyncs
  func (l *Log) Phase(name string) error                        // Record("phase", {"name":name})
  func VerifyChain(path string) (int, error)                    // returns entry count; error names first bad seq
  type Manifest struct {
      CaseID, KitVersion, OrchestratorSHA256 string
      Phases   map[string]time.Time
      Payload  map[string]string          // rel path -> sha256
      Baseline json.RawMessage
      Rules    []string                   // full text of every firewall rule created
      Commands []Command
  }
  type Command struct { Argv []string; ExitCode int; DurationMS int64; TSUTC time.Time }
  func (m *Manifest) Save(path string) error
  func LoadManifest(path string) (*Manifest, error)
  ```
- Hash = hex(sha256(seq || "\n" || ts RFC3339Nano || "\n" || event || "\n" || data || "\n" || prev_hash)). Genesis `prev_hash` is 64 zeros.

- [ ] **Step 1: Write the failing tests**

```go
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 9, 4, 22, 0, 0, 0, time.UTC)
	return func() time.Time { t = t.Add(time.Second); return t }
}

func TestRecordBuildsChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(p, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Phase("PREFLIGHT"); err != nil {
		t.Fatal(err)
	}
	if err := l.Record("cmd", map[string]any{"argv": []string{"netsh"}}); err != nil {
		t.Fatal(err)
	}
	n, err := VerifyChain(p)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var e0, e1 Entry
	json.Unmarshal([]byte(lines[0]), &e0)
	json.Unmarshal([]byte(lines[1]), &e1)
	if e0.PrevHash != strings.Repeat("0", 64) || e1.PrevHash != e0.Hash || e1.Seq != 2 {
		t.Fatalf("chain wrong: %+v %+v", e0, e1)
	}
}

func TestVerifyChainDetectsTamper(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(p, fixedClock())
	l.Phase("A")
	l.Phase("B")
	l.Phase("C")
	b, _ := os.ReadFile(p)
	tampered := strings.Replace(string(b), `"name":"B"`, `"name":"X"`, 1)
	os.WriteFile(p, []byte(tampered), 0o600)
	_, err := VerifyChain(p)
	if err == nil || !strings.Contains(err.Error(), "seq 2") {
		t.Fatalf("expected tamper at seq 2, got %v", err)
	}
}

func TestOpenResumesExistingChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(p, fixedClock())
	l.Phase("A")
	l2, err := Open(p, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	l2.Phase("B")
	n, err := VerifyChain(p)
	if err != nil || n != 2 {
		t.Fatalf("resume broke chain: n=%d err=%v", n, err)
	}
}

func TestManifestRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "manifest.json")
	m := &Manifest{CaseID: "C", Phases: map[string]time.Time{"READY": time.Now().UTC()}, Payload: map[string]string{"a": "b"}}
	if err := m.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := LoadManifest(p)
	if err != nil || got.CaseID != "C" || got.Payload["a"] != "b" {
		t.Fatalf("round trip failed: %v %+v", err, got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/audit/ -v`
Expected: FAIL — `undefined: Open`

- [ ] **Step 3: Implement `audit.go`**

```go
// Package audit is the append-only, hash-chained evidence log and the
// manifest.json summary. Nothing in this package is ever overwritten.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

type Entry struct {
	Seq      int             `json:"seq"`
	TSUTC    time.Time       `json:"ts_utc"`
	Event    string          `json:"event"`
	Data     json.RawMessage `json:"data"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
}

func (e *Entry) computeHash() string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\n%s\n%s\n%s\n%s", e.Seq, e.TSUTC.UTC().Format(time.RFC3339Nano), e.Event, string(e.Data), e.PrevHash)
	return hex.EncodeToString(h.Sum(nil))
}

type Log struct {
	mu   sync.Mutex
	f    *os.File
	seq  int
	last string
	now  func() time.Time
}

func Open(path string, now func() time.Time) (*Log, error) {
	if now == nil {
		now = time.Now
	}
	l := &Log{now: now, last: genesis}
	if _, err := os.Stat(path); err == nil {
		n, last, err := walk(path)
		if err != nil {
			return nil, fmt.Errorf("existing audit log is corrupt: %w", err)
		}
		l.seq, l.last = n, last
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

func (l *Log) Record(event string, data any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	e := Entry{Seq: l.seq + 1, TSUTC: l.now().UTC(), Event: event, Data: raw, PrevHash: l.last}
	e.Hash = e.computeHash()
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	l.seq, l.last = e.Seq, e.Hash
	return nil
}

func (l *Log) Phase(name string) error {
	return l.Record("phase", map[string]string{"name": name})
}

func (l *Log) Close() error { return l.f.Close() }

// walk validates the chain and returns (count, lastHash).
func walk(path string) (int, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	prev, n := genesis, 0
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return n, prev, fmt.Errorf("seq %d: unparsable: %w", n+1, err)
		}
		if e.Seq != n+1 {
			return n, prev, fmt.Errorf("seq %d: expected seq %d", e.Seq, n+1)
		}
		if e.PrevHash != prev {
			return n, prev, fmt.Errorf("seq %d: prev_hash does not match previous entry", e.Seq)
		}
		if e.computeHash() != e.Hash {
			return n, prev, fmt.Errorf("seq %d: hash mismatch (entry modified)", e.Seq)
		}
		prev, n = e.Hash, e.Seq
	}
	return n, prev, sc.Err()
}

func VerifyChain(path string) (int, error) {
	n, _, err := walk(path)
	return n, err
}

type Command struct {
	Argv       []string  `json:"argv"`
	ExitCode   int       `json:"exit_code"`
	DurationMS int64     `json:"duration_ms"`
	TSUTC      time.Time `json:"ts_utc"`
}

type Manifest struct {
	CaseID             string               `json:"case_id"`
	KitVersion         string               `json:"kit_version"`
	OrchestratorSHA256 string               `json:"orchestrator_sha256"`
	Phases             map[string]time.Time `json:"phases"`
	Payload            map[string]string    `json:"payload"`
	Baseline           json.RawMessage      `json:"baseline,omitempty"`
	Rules              []string             `json:"rules"`
	Commands           []Command            `json:"commands"`
}

func (m *Manifest) Save(path string) error {
	if m.Phases == nil {
		m.Phases = map[string]time.Time{}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func LoadManifest(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/audit/ -v`
Expected: 4 PASS

- [ ] **Step 5: Commit**

```bash
git add internal/audit
git commit -m "Add hash-chained audit log and manifest

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: `internal/runner` — the only place that executes commands

**Files:**
- Create: `internal/runner/runner.go`, `internal/runner/runner_test.go`

**Interfaces:**
- Produces:
  ```go
  type Result struct { Stdout, Stderr string; ExitCode int; Duration time.Duration }
  type Runner interface {
      Run(ctx context.Context, name string, args ...string) (Result, error)
  }
  // Exec runs for real and records every call to the audit log (argv, exit, duration).
  func NewExec(log *audit.Log, manifest *audit.Manifest) Runner
  // DryRun records "would run" to the audit log and returns canned success (empty stdout).
  func NewDryRun(log *audit.Log) Runner
  // Fake is for tests. Calls are recorded; responses are matched by name+args prefix.
  type Fake struct { Calls [][]string; Responses map[string]Result; Errors map[string]error }
  func NewFake() *Fake
  func (f *Fake) Run(ctx, name, args...) (Result, error)
  func (f *Fake) Key(name string, args ...string) string   // "name arg1 arg2" — used as Responses/Errors key
  // PS is a helper: PS(r, ctx, script) == r.Run(ctx, "powershell.exe", "-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command", script)
  func PS(ctx context.Context, r Runner, script string) (Result, error)
  ```
- A non-zero exit is returned as `Result.ExitCode != 0` **and** an `*ExitError{Result}` error, so callers can `errors.As`.
- `Fake.Run` matches the longest key that is a prefix of `"name args..."`; if none, returns `Result{}` with no error.

- [ ] **Step 1: Write the failing tests**

```go
package runner

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
)

func TestFakeRecordsAndMatchesPrefix(t *testing.T) {
	f := NewFake()
	f.Responses[f.Key("tailscale.exe", "status")] = Result{Stdout: `{"BackendState":"Running"}`}
	f.Responses[f.Key("tailscale.exe", "status", "--json")] = Result{Stdout: `{"BackendState":"NeedsLogin"}`}
	r, err := f.Run(context.Background(), "tailscale.exe", "status", "--json")
	if err != nil || r.Stdout != `{"BackendState":"NeedsLogin"}` {
		t.Fatalf("longest prefix should win: %+v %v", r, err)
	}
	if len(f.Calls) != 1 || f.Calls[0][0] != "tailscale.exe" {
		t.Fatalf("call not recorded: %v", f.Calls)
	}
}

func TestFakeReturnsConfiguredError(t *testing.T) {
	f := NewFake()
	f.Errors[f.Key("msiexec.exe")] = errors.New("boom")
	if _, err := f.Run(context.Background(), "msiexec.exe", "/i", "x.msi"); err == nil {
		t.Fatal("expected error")
	}
}

func TestExecRecordsToAudit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	log, _ := audit.Open(p, nil)
	m := &audit.Manifest{}
	r := NewExec(log, m)
	res, err := r.Run(context.Background(), "/bin/sh", "-c", "echo hi; exit 3")
	var ee *ExitError
	if !errors.As(err, &ee) || res.ExitCode != 3 || res.Stdout != "hi\n" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(m.Commands) != 1 || m.Commands[0].ExitCode != 3 {
		t.Fatalf("manifest not updated: %+v", m.Commands)
	}
	if n, err := audit.VerifyChain(p); err != nil || n != 1 {
		t.Fatalf("audit not written: n=%d err=%v", n, err)
	}
}

func TestDryRunNeverExecutes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	log, _ := audit.Open(p, nil)
	r := NewDryRun(log)
	res, err := r.Run(context.Background(), "definitely-not-a-binary", "--x")
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("dry run must succeed without executing: %+v %v", res, err)
	}
	if n, _ := audit.VerifyChain(p); n != 1 {
		t.Fatal("dry run must still audit")
	}
}

func TestPSHelperBuildsArgv(t *testing.T) {
	f := NewFake()
	PS(context.Background(), f, "Get-Date")
	want := []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Get-Date"}
	if len(f.Calls[0]) != len(want) {
		t.Fatalf("argv %v", f.Calls[0])
	}
	for i := range want {
		if f.Calls[0][i] != want[i] {
			t.Fatalf("argv %v", f.Calls[0])
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/runner/ -v`
Expected: FAIL — `undefined: NewFake`

- [ ] **Step 3: Implement `runner.go`**

```go
// Package runner is the single chokepoint for executing external commands.
// Every call — real or dry-run — is written to the audit log.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
)

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

type ExitError struct{ Result Result }

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit %d: %s", e.Result.ExitCode, strings.TrimSpace(e.Result.Stderr))
}

type Runner interface {
	Run(ctx context.Context, name string, args ...string) (Result, error)
}

// ---- real ----

type execRunner struct {
	log *audit.Log
	m   *audit.Manifest
}

func NewExec(log *audit.Log, manifest *audit.Manifest) Runner {
	return &execRunner{log: log, m: manifest}
}

func (r *execRunner) Run(ctx context.Context, name string, args ...string) (Result, error) {
	start := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr := cmd.Run()
	res := Result{Stdout: out.String(), Stderr: errb.String(), Duration: time.Since(start)}
	var ee *exec.ExitError
	switch {
	case runErr == nil:
	case errors.As(runErr, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		res.ExitCode = -1
	}
	argv := append([]string{name}, args...)
	c := audit.Command{Argv: argv, ExitCode: res.ExitCode, DurationMS: res.Duration.Milliseconds(), TSUTC: start.UTC()}
	if r.m != nil {
		r.m.Commands = append(r.m.Commands, c)
	}
	if r.log != nil {
		_ = r.log.Record("cmd", map[string]any{
			"argv": argv, "exit_code": res.ExitCode, "duration_ms": c.DurationMS,
			"stderr": truncate(res.Stderr, 4096),
		})
	}
	if runErr != nil && res.ExitCode == -1 {
		return res, runErr
	}
	if res.ExitCode != 0 {
		return res, &ExitError{res}
	}
	return res, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// ---- dry run ----

type dryRunner struct{ log *audit.Log }

func NewDryRun(log *audit.Log) Runner { return &dryRunner{log: log} }

func (r *dryRunner) Run(_ context.Context, name string, args ...string) (Result, error) {
	if r.log != nil {
		_ = r.log.Record("dryrun", map[string]any{"argv": append([]string{name}, args...)})
	}
	return Result{}, nil
}

// ---- fake ----

type Fake struct {
	Calls     [][]string
	Responses map[string]Result
	Errors    map[string]error
}

func NewFake() *Fake {
	return &Fake{Responses: map[string]Result{}, Errors: map[string]error{}}
}

func (f *Fake) Key(name string, args ...string) string {
	return strings.Join(append([]string{name}, args...), " ")
}

func (f *Fake) Run(_ context.Context, name string, args ...string) (Result, error) {
	argv := append([]string{name}, args...)
	f.Calls = append(f.Calls, argv)
	full := strings.Join(argv, " ")
	best := ""
	for k := range f.Responses {
		if strings.HasPrefix(full, k) && len(k) > len(best) {
			best = k
		}
	}
	for k := range f.Errors {
		if strings.HasPrefix(full, k) && len(k) > len(best) {
			best = k
		}
	}
	if best == "" {
		return Result{}, nil
	}
	if err, ok := f.Errors[best]; ok {
		return f.Responses[best], err
	}
	res := f.Responses[best]
	if res.ExitCode != 0 {
		return res, &ExitError{res}
	}
	return res, nil
}

// Called reports whether any recorded call starts with the given argv prefix.
func (f *Fake) Called(name string, args ...string) bool {
	want := f.Key(name, args...)
	for _, c := range f.Calls {
		if strings.HasPrefix(strings.Join(c, " "), want) {
			return true
		}
	}
	return false
}

// ---- helpers ----

func PS(ctx context.Context, r Runner, script string) (Result, error) {
	return r.Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/runner/ -v`
Expected: 5 PASS

- [ ] **Step 5: Commit**

```bash
git add internal/runner
git commit -m "Add audited command runner with dry-run and fake

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: `internal/win` — firewall

**Files:**
- Create: `internal/win/firewall.go`, `internal/win/firewall_test.go`

**Interfaces:**
- Consumes: `runner.Runner`, `runner.PS`.
- Produces:
  ```go
  type Firewall struct { R runner.Runner }
  type ProfileState struct { Name string; Enabled bool; DefaultInboundAction, DefaultOutboundAction string }
  func (f Firewall) Export(ctx, path string) error                     // netsh advfirewall export
  func (f Firewall) Import(ctx, path string) error                     // netsh advfirewall import
  func (f Firewall) Profiles(ctx) ([]ProfileState, error)              // Get-NetFirewallProfile … | ConvertTo-Json
  func (f Firewall) RulesJSON(ctx) (json.RawMessage, error)            // Get-NetFirewallRule | ConvertTo-Json -Depth 3
  func (f Firewall) SetAllProfiles(ctx, enabled bool, inbound, outbound string) error
  func (f Firewall) RestoreProfiles(ctx, states []ProfileState) error  // per-profile Set-NetFirewallProfile
  type Rule struct { Name, Direction, Program, Protocol, RemotePort, LocalPort, RemoteAddress string }
  func (f Firewall) AddRule(ctx, group string, r Rule) (string, error) // returns the PS command text (for manifest.Rules)
  func (f Firewall) RemoveGroup(ctx, group string) error
  // QuarantineRules is pure: builds the allow-list for a config.
  func QuarantineRules(dnsResolvers []string, dnsFallbackDHCP bool, rdpFrom string) []Rule
  ```
- `Set-NetFirewallProfile` is issued as `-Profile Domain,Private,Public`. Actions are the strings `Block`/`Allow`/`NotConfigured`.
- `AddRule` builds: `New-NetFirewallRule -Group '<group>' -DisplayName '<group>: <Name>' -Direction <Direction> -Action Allow [-Program '<Program>'] [-Protocol <Protocol>] [-RemotePort <RemotePort>] [-LocalPort <LocalPort>] [-RemoteAddress <RemoteAddress>] | Out-Null`. Single quotes in values are doubled.
- The tailscaled path is the constant `TailscaledPath = C:\Program Files\Tailscale\tailscaled.exe`.

- [ ] **Step 1: Write the failing tests**

```go
package win

import (
	"context"
	"strings"
	"testing"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

func TestQuarantineRulesAllowOnlyWhatSpecRequires(t *testing.T) {
	rules := QuarantineRules([]string{"1.1.1.1", "9.9.9.9"}, false, "")
	var names []string
	for _, r := range rules {
		names = append(names, r.Name)
		if r.Direction != "Outbound" {
			t.Fatalf("no inbound rules without RDP: %+v", r)
		}
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"tailscaled", "dns-udp", "dns-tcp"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %s", want, joined)
		}
	}
	for _, r := range rules {
		if r.Name == "dns-udp" && r.RemoteAddress != "1.1.1.1,9.9.9.9" {
			t.Fatalf("dns rule must pin resolvers: %+v", r)
		}
	}
}

func TestQuarantineRulesRDPAndDHCPFallback(t *testing.T) {
	rules := QuarantineRules([]string{"1.1.1.1"}, true, "100.64.0.1")
	var rdp, dhcp bool
	for _, r := range rules {
		if r.Direction == "Inbound" && r.LocalPort == "3389" && r.RemoteAddress == "100.64.0.1" {
			rdp = true
		}
		if strings.HasPrefix(r.Name, "dns-dhcp") && r.RemoteAddress == "" {
			dhcp = true
		}
	}
	if !rdp || !dhcp {
		t.Fatalf("rdp=%v dhcp=%v rules=%+v", rdp, dhcp, rules)
	}
}

func TestAddRuleBuildsCommand(t *testing.T) {
	f := runner.NewFake()
	fw := Firewall{R: f}
	txt, err := fw.AddRule(context.Background(), "DFIRMedic-C1", Rule{
		Name: "tailscaled", Direction: "Outbound", Program: TailscaledPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"New-NetFirewallRule", "-Group 'DFIRMedic-C1'", "-Direction Outbound", "-Action Allow", `-Program 'C:\Program Files\Tailscale\tailscaled.exe'`} {
		if !strings.Contains(txt, want) {
			t.Fatalf("missing %q in %s", want, txt)
		}
	}
	if strings.Contains(txt, "-Protocol") {
		t.Fatal("no protocol should be emitted when empty")
	}
	if !f.Called("powershell.exe") {
		t.Fatal("must run through PS")
	}
}

func TestProfilesParsesJSON(t *testing.T) {
	f := runner.NewFake()
	f.Responses["powershell.exe"] = runner.Result{Stdout: `[
	  {"Name":"Domain","Enabled":1,"DefaultInboundAction":4,"DefaultOutboundAction":2},
	  {"Name":"Private","Enabled":1,"DefaultInboundAction":4,"DefaultOutboundAction":2}]`}
	ps, err := Firewall{R: f}.Profiles(context.Background())
	if err != nil || len(ps) != 2 || ps[0].DefaultInboundAction != "Block" || ps[0].DefaultOutboundAction != "Allow" || !ps[0].Enabled {
		t.Fatalf("%+v %v", ps, err)
	}
}

func TestSetAllProfilesAndRemoveGroup(t *testing.T) {
	f := runner.NewFake()
	fw := Firewall{R: f}
	if err := fw.SetAllProfiles(context.Background(), true, "Block", "Block"); err != nil {
		t.Fatal(err)
	}
	if err := fw.RemoveGroup(context.Background(), "DFIRMedic-C1"); err != nil {
		t.Fatal(err)
	}
	all := ""
	for _, c := range f.Calls {
		all += strings.Join(c, " ") + "\n"
	}
	for _, want := range []string{"Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block", "Remove-NetFirewallRule -Group 'DFIRMedic-C1'"} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing %q in:\n%s", want, all)
		}
	}
}

func TestExportImportUseNetsh(t *testing.T) {
	f := runner.NewFake()
	fw := Firewall{R: f}
	fw.Export(context.Background(), `C:\w\fw.wfw`)
	fw.Import(context.Background(), `C:\w\fw.wfw`)
	if !f.Called("netsh.exe", "advfirewall", "export", `C:\w\fw.wfw`) || !f.Called("netsh.exe", "advfirewall", "import", `C:\w\fw.wfw`) {
		t.Fatalf("%v", f.Calls)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/win/ -v`
Expected: FAIL — `undefined: QuarantineRules`

- [ ] **Step 3: Implement `firewall.go`**

```go
// Package win wraps the Windows tools the orchestrator drives. Every function
// builds a command and hands it to a runner.Runner; nothing here executes
// directly, so all of it is testable with runner.Fake on any OS.
package win

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

const TailscaledPath = `C:\Program Files\Tailscale\tailscaled.exe`

type Firewall struct{ R runner.Runner }

type ProfileState struct {
	Name                  string
	Enabled               bool
	DefaultInboundAction  string
	DefaultOutboundAction string
}

func psq(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func (f Firewall) Export(ctx context.Context, path string) error {
	_, err := f.R.Run(ctx, "netsh.exe", "advfirewall", "export", path)
	return err
}

func (f Firewall) Import(ctx context.Context, path string) error {
	_, err := f.R.Run(ctx, "netsh.exe", "advfirewall", "import", path)
	return err
}

// NetSecurity enums: Enabled 1=True 0=False; actions 2=Allow 4=Block 0=NotConfigured.
func actionName(v int) string {
	switch v {
	case 2:
		return "Allow"
	case 4:
		return "Block"
	default:
		return "NotConfigured"
	}
}

func (f Firewall) Profiles(ctx context.Context) ([]ProfileState, error) {
	res, err := runner.PS(ctx, f.R, "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress")
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Name                  string
		Enabled               int
		DefaultInboundAction  int
		DefaultOutboundAction int
	}
	txt := strings.TrimSpace(res.Stdout)
	if strings.HasPrefix(txt, "{") { // single profile comes back as an object
		txt = "[" + txt + "]"
	}
	if err := json.Unmarshal([]byte(txt), &raw); err != nil {
		return nil, fmt.Errorf("parse Get-NetFirewallProfile: %w", err)
	}
	out := make([]ProfileState, 0, len(raw))
	for _, p := range raw {
		out = append(out, ProfileState{Name: p.Name, Enabled: p.Enabled == 1,
			DefaultInboundAction: actionName(p.DefaultInboundAction), DefaultOutboundAction: actionName(p.DefaultOutboundAction)})
	}
	return out, nil
}

func (f Firewall) RulesJSON(ctx context.Context) (json.RawMessage, error) {
	res, err := runner.PS(ctx, f.R, "Get-NetFirewallRule | Select-Object Name,DisplayName,Group,Enabled,Direction,Action,Profile | ConvertTo-Json -Compress -Depth 3")
	if err != nil {
		return nil, err
	}
	return json.RawMessage(res.Stdout), nil
}

func (f Firewall) SetAllProfiles(ctx context.Context, enabled bool, inbound, outbound string) error {
	en := "False"
	if enabled {
		en = "True"
	}
	_, err := runner.PS(ctx, f.R, fmt.Sprintf("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled %s -DefaultInboundAction %s -DefaultOutboundAction %s", en, inbound, outbound))
	return err
}

func (f Firewall) RestoreProfiles(ctx context.Context, states []ProfileState) error {
	for _, s := range states {
		en := "False"
		if s.Enabled {
			en = "True"
		}
		if _, err := runner.PS(ctx, f.R, fmt.Sprintf("Set-NetFirewallProfile -Profile %s -Enabled %s -DefaultInboundAction %s -DefaultOutboundAction %s", s.Name, en, s.DefaultInboundAction, s.DefaultOutboundAction)); err != nil {
			return err
		}
	}
	return nil
}

type Rule struct {
	Name          string
	Direction     string // Inbound | Outbound
	Program       string
	Protocol      string // TCP | UDP | ""
	RemotePort    string
	LocalPort     string
	RemoteAddress string
}

func (f Firewall) AddRule(ctx context.Context, group string, r Rule) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "New-NetFirewallRule -Group %s -DisplayName %s -Direction %s -Action Allow", psq(group), psq(group+": "+r.Name), r.Direction)
	if r.Program != "" {
		fmt.Fprintf(&b, " -Program %s", psq(r.Program))
	}
	if r.Protocol != "" {
		fmt.Fprintf(&b, " -Protocol %s", r.Protocol)
	}
	if r.RemotePort != "" {
		fmt.Fprintf(&b, " -RemotePort %s", r.RemotePort)
	}
	if r.LocalPort != "" {
		fmt.Fprintf(&b, " -LocalPort %s", r.LocalPort)
	}
	if r.RemoteAddress != "" {
		fmt.Fprintf(&b, " -RemoteAddress %s", r.RemoteAddress)
	}
	b.WriteString(" | Out-Null")
	txt := b.String()
	_, err := runner.PS(ctx, f.R, txt)
	return txt, err
}

func (f Firewall) RemoveGroup(ctx context.Context, group string) error {
	_, err := runner.PS(ctx, f.R, fmt.Sprintf("Remove-NetFirewallRule -Group %s -ErrorAction SilentlyContinue", psq(group)))
	return err
}

// QuarantineRules is the entire allow-list from spec §8.3. Allow rules only.
func QuarantineRules(dnsResolvers []string, dnsFallbackDHCP bool, rdpFrom string) []Rule {
	rules := []Rule{
		{Name: "tailscaled", Direction: "Outbound", Program: TailscaledPath},
	}
	if len(dnsResolvers) > 0 {
		addrs := strings.Join(dnsResolvers, ",")
		rules = append(rules,
			Rule{Name: "dns-udp", Direction: "Outbound", Protocol: "UDP", RemotePort: "53", RemoteAddress: addrs},
			Rule{Name: "dns-tcp", Direction: "Outbound", Protocol: "TCP", RemotePort: "53", RemoteAddress: addrs},
		)
	}
	if dnsFallbackDHCP {
		rules = append(rules,
			Rule{Name: "dns-dhcp-udp", Direction: "Outbound", Protocol: "UDP", RemotePort: "53"},
			Rule{Name: "dns-dhcp-tcp", Direction: "Outbound", Protocol: "TCP", RemotePort: "53"},
		)
	}
	if rdpFrom != "" {
		rules = append(rules, Rule{Name: "rdp-from-responder", Direction: "Inbound", Protocol: "TCP", LocalPort: "3389", RemoteAddress: rdpFrom})
	}
	return rules
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/win/ -v`
Expected: 6 PASS

- [ ] **Step 5: Commit**

```bash
git add internal/win
git commit -m "Add Windows Firewall wrapper and quarantine rule set

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 8: `internal/win` — adapters, edition, RDP, startup task, elevation

**Files:**
- Create: `internal/win/adapter.go`, `internal/win/system.go`, `internal/win/elevated_windows.go`, `internal/win/elevated_other.go`, `internal/win/adapter_test.go`, `internal/win/system_test.go`

**Interfaces:**
- Produces:
  ```go
  type Adapter struct { Name, InterfaceDescription, Status string }
  type Net struct { R runner.Runner }
  func (n Net) PhysicalAdapters(ctx) ([]Adapter, error)         // Get-NetAdapter -Physical
  func (n Net) AnyPhysicalUp(ctx) (bool, []Adapter, error)
  func (n Net) DisableAll(ctx, adapters []Adapter) error         // Disable-NetAdapter -Name X -Confirm:$false
  type Sys struct { R runner.Runner }
  func (s Sys) EditionID(ctx) (string, error)                    // reg query … EditionID
  func IsHomeEdition(editionID string) bool                       // Core, CoreN, CoreSingleLanguage, CoreCountrySpecific
  func (s Sys) EnableRDP(ctx) error                              // reg add fDenyTSConnections 0
  func (s Sys) CreateStartupTask(ctx, name, exe, args string) error   // schtasks /Create /SC ONSTART /RU SYSTEM
  func (s Sys) DeleteStartupTask(ctx, name string) error
  func (s Sys) ServiceExists(ctx, name string) (bool, error)     // sc query <name>
  func IsElevated() bool                                          // windows: token elevation; other: true
  ```

- [ ] **Step 1: Write the failing tests**

`adapter_test.go`:
```go
package win

import (
	"context"
	"testing"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

func TestAnyPhysicalUp(t *testing.T) {
	f := runner.NewFake()
	f.Responses["powershell.exe"] = runner.Result{Stdout: `[{"Name":"Wi-Fi","InterfaceDescription":"Intel","Status":"Up"},{"Name":"Ethernet","InterfaceDescription":"Realtek","Status":"Disconnected"}]`}
	up, ads, err := Net{R: f}.AnyPhysicalUp(context.Background())
	if err != nil || !up || len(ads) != 1 || ads[0].Name != "Wi-Fi" {
		t.Fatalf("up=%v ads=%+v err=%v", up, ads, err)
	}
}

func TestAnyPhysicalUpSingleObject(t *testing.T) {
	f := runner.NewFake()
	f.Responses["powershell.exe"] = runner.Result{Stdout: `{"Name":"Wi-Fi","InterfaceDescription":"Intel","Status":"Disconnected"}`}
	up, _, err := Net{R: f}.AnyPhysicalUp(context.Background())
	if err != nil || up {
		t.Fatalf("up=%v err=%v", up, err)
	}
}

func TestDisableAll(t *testing.T) {
	f := runner.NewFake()
	err := Net{R: f}.DisableAll(context.Background(), []Adapter{{Name: "Wi-Fi"}, {Name: "Ethernet 2"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Calls) != 2 || f.Calls[1][len(f.Calls[1])-1] != "Disable-NetAdapter -Name 'Ethernet 2' -Confirm:$false" {
		t.Fatalf("%v", f.Calls)
	}
}
```

`system_test.go`:
```go
package win

import (
	"context"
	"strings"
	"testing"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

func TestEditionID(t *testing.T) {
	f := runner.NewFake()
	f.Responses["reg.exe"] = runner.Result{Stdout: "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\r\n    EditionID    REG_SZ    Professional\r\n\r\n"}
	id, err := Sys{R: f}.EditionID(context.Background())
	if err != nil || id != "Professional" {
		t.Fatalf("%q %v", id, err)
	}
	if IsHomeEdition("Professional") || !IsHomeEdition("Core") || !IsHomeEdition("CoreSingleLanguage") {
		t.Fatal("home detection wrong")
	}
}

func TestEnableRDPAndTasks(t *testing.T) {
	f := runner.NewFake()
	s := Sys{R: f}
	s.EnableRDP(context.Background())
	s.CreateStartupTask(context.Background(), "DFIRMedic-C1", `C:\w\dfirmedic.exe`, `connect --workdir C:\w`)
	s.DeleteStartupTask(context.Background(), "DFIRMedic-C1")
	all := ""
	for _, c := range f.Calls {
		all += strings.Join(c, " ") + "\n"
	}
	for _, want := range []string{
		`reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 0 /f`,
		`schtasks.exe /Create /TN DFIRMedic-C1 /SC ONSTART /RU SYSTEM /RL HIGHEST /F /TR "C:\w\dfirmedic.exe" connect --workdir C:\w`,
		`schtasks.exe /Delete /TN DFIRMedic-C1 /F`,
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing %q in:\n%s", want, all)
		}
	}
}

func TestServiceExists(t *testing.T) {
	f := runner.NewFake()
	f.Responses[f.Key("sc.exe", "query", "Velociraptor")] = runner.Result{Stdout: "SERVICE_NAME: Velociraptor\r\n        STATE : 1  STOPPED"}
	f.Responses[f.Key("sc.exe", "query", "Nope")] = runner.Result{ExitCode: 1060, Stderr: "The specified service does not exist"}
	s := Sys{R: f}
	if ok, err := s.ServiceExists(context.Background(), "Velociraptor"); err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if ok, err := s.ServiceExists(context.Background(), "Nope"); err != nil || ok {
		t.Fatalf("%v %v", ok, err)
	}
}

func TestIsElevatedCompiles(t *testing.T) { _ = IsElevated() }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/win/ -v`
Expected: FAIL — `undefined: Net`

- [ ] **Step 3: Implement `adapter.go`**

```go
package win

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

type Adapter struct {
	Name                 string
	InterfaceDescription string
	Status               string
}

type Net struct{ R runner.Runner }

func (n Net) PhysicalAdapters(ctx context.Context) ([]Adapter, error) {
	res, err := runner.PS(ctx, n.R, "Get-NetAdapter -Physical | Select-Object Name,InterfaceDescription,Status | ConvertTo-Json -Compress")
	if err != nil {
		return nil, err
	}
	txt := strings.TrimSpace(res.Stdout)
	if txt == "" {
		return nil, nil
	}
	if strings.HasPrefix(txt, "{") {
		txt = "[" + txt + "]"
	}
	var out []Adapter
	if err := json.Unmarshal([]byte(txt), &out); err != nil {
		return nil, fmt.Errorf("parse Get-NetAdapter: %w", err)
	}
	return out, nil
}

// AnyPhysicalUp returns true and the list of adapters whose Status is "Up".
func (n Net) AnyPhysicalUp(ctx context.Context) (bool, []Adapter, error) {
	all, err := n.PhysicalAdapters(ctx)
	if err != nil {
		return false, nil, err
	}
	var up []Adapter
	for _, a := range all {
		if strings.EqualFold(a.Status, "Up") {
			up = append(up, a)
		}
	}
	return len(up) > 0, up, nil
}

func (n Net) DisableAll(ctx context.Context, adapters []Adapter) error {
	for _, a := range adapters {
		if _, err := runner.PS(ctx, n.R, fmt.Sprintf("Disable-NetAdapter -Name %s -Confirm:$false", psq(a.Name))); err != nil {
			return fmt.Errorf("disable %s: %w", a.Name, err)
		}
	}
	return nil
}
```

- [ ] **Step 4: Implement `system.go`**

```go
package win

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

type Sys struct{ R runner.Runner }

func (s Sys) EditionID(ctx context.Context) (string, error) {
	res, err := s.R.Run(ctx, "reg.exe", "query", `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "/v", "EditionID")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "EditionID" {
			return fields[2], nil
		}
	}
	return "", errors.New("EditionID not found in reg output")
}

func IsHomeEdition(editionID string) bool {
	return strings.HasPrefix(editionID, "Core")
}

func (s Sys) EnableRDP(ctx context.Context) error {
	_, err := s.R.Run(ctx, "reg.exe", "add", `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "0", "/f")
	return err
}

func (s Sys) CreateStartupTask(ctx context.Context, name, exe, args string) error {
	_, err := s.R.Run(ctx, "schtasks.exe", "/Create", "/TN", name, "/SC", "ONSTART", "/RU", "SYSTEM", "/RL", "HIGHEST", "/F", "/TR", fmt.Sprintf(`"%s" %s`, exe, args))
	return err
}

func (s Sys) DeleteStartupTask(ctx context.Context, name string) error {
	_, err := s.R.Run(ctx, "schtasks.exe", "/Delete", "/TN", name, "/F")
	return err
}

// ServiceExists: sc query exits 1060 when the service is not installed.
func (s Sys) ServiceExists(ctx context.Context, name string) (bool, error) {
	res, err := s.R.Run(ctx, "sc.exe", "query", name)
	var ee *runner.ExitError
	if errors.As(err, &ee) && res.ExitCode == 1060 {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
```

- [ ] **Step 5: Implement the elevation check**

`elevated_windows.go`:
```go
//go:build windows

package win

import "golang.org/x/sys/windows"

func IsElevated() bool {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return false
	}
	defer tok.Close()
	return tok.IsElevated()
}
```

`elevated_other.go`:
```go
//go:build !windows

package win

// IsElevated is always true off Windows so tests and dry runs proceed.
func IsElevated() bool { return true }
```

- [ ] **Step 6: Run tests and the cross-compile**

Run: `make check`
Expected: all `internal/win` tests PASS; Windows build succeeds.

- [ ] **Step 7: Commit**

```bash
git add internal/win
git commit -m "Add adapter, edition, RDP, task, and elevation helpers

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: `internal/tailscale` — install, up, status, logout, uninstall

**Files:**
- Create: `internal/tailscale/tailscale.go`, `internal/tailscale/tailscale_test.go`

**Interfaces:**
- Consumes: `runner.Runner`.
- Produces:
  ```go
  const ExePath = `C:\Program Files\Tailscale\tailscale.exe`
  type Client struct { R runner.Runner; MSIPath string }
  func (c Client) InstallMSI(ctx) error                 // msiexec.exe /i <msi> /quiet /norestart
  func (c Client) Up(ctx, authkey, hostname string) error
      // tailscale.exe up --authkey=… --hostname=… --accept-routes=false --accept-dns=false --timeout=15s
      // A timeout exit while offline is NOT an error (prefs are stored; daemon retries once the NIC is up).
  type Status struct { BackendState string; Self Peer; Peers []Peer }
  type Peer struct { PublicKey, HostName string; Online bool; TailscaleIPs []string }
  func (c Client) Status(ctx) (Status, error)            // tailscale.exe status --json
  func ParseStatus(jsonText string) (Status, error)      // pure
  func (s Status) ResponderOnline(nodeKey string) bool   // BackendState=="Running" && a peer with PublicKey==nodeKey && Online
  func (c Client) Logout(ctx) error                      // tailscale.exe logout
  func (c Client) UninstallMSI(ctx) error                // msiexec.exe /x <msi> /quiet /norestart
  ```
- `tailscale status --json` shape used: `{"BackendState":"Running","Self":{"PublicKey":"nodekey:…","HostName":"…","Online":true,"TailscaleIPs":["100.…"]},"Peer":{"nodekey:…":{"PublicKey":"nodekey:…","HostName":"…","Online":true,"TailscaleIPs":[…]}}}`.

- [ ] **Step 1: Write the failing tests**

```go
package tailscale

import (
	"context"
	"strings"
	"testing"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

const statusJSON = `{
 "BackendState":"Running",
 "Self":{"PublicKey":"nodekey:self","HostName":"ir-C1","Online":true,"TailscaleIPs":["100.64.0.9"]},
 "Peer":{
   "nodekey:resp":{"PublicKey":"nodekey:resp","HostName":"analyst","Online":true,"TailscaleIPs":["100.64.0.1"]},
   "nodekey:other":{"PublicKey":"nodekey:other","HostName":"nas","Online":false,"TailscaleIPs":["100.64.0.2"]}
 }}`

func TestParseStatusAndResponderOnline(t *testing.T) {
	s, err := ParseStatus(statusJSON)
	if err != nil {
		t.Fatal(err)
	}
	if s.BackendState != "Running" || s.Self.HostName != "ir-C1" || len(s.Peers) != 2 {
		t.Fatalf("%+v", s)
	}
	if !s.ResponderOnline("nodekey:resp") {
		t.Fatal("responder should be online")
	}
	if s.ResponderOnline("nodekey:other") {
		t.Fatal("offline peer must not count")
	}
	if s.ResponderOnline("nodekey:missing") {
		t.Fatal("unknown peer must not count")
	}
	s.BackendState = "NeedsLogin"
	if s.ResponderOnline("nodekey:resp") {
		t.Fatal("must require Running")
	}
}

func TestUpTreatsTimeoutAsSuccess(t *testing.T) {
	f := runner.NewFake()
	f.Responses[ExePath+" up"] = runner.Result{ExitCode: 1, Stderr: "timeout waiting for Tailscale service to enter state Running"}
	c := Client{R: f}
	if err := c.Up(context.Background(), "tskey-x", "ir-C1"); err != nil {
		t.Fatalf("offline timeout must not be fatal: %v", err)
	}
	argv := strings.Join(f.Calls[0], " ")
	for _, want := range []string{"--authkey=tskey-x", "--hostname=ir-C1", "--accept-routes=false", "--accept-dns=false", "--timeout=15s"} {
		if !strings.Contains(argv, want) {
			t.Fatalf("missing %s in %s", want, argv)
		}
	}
}

func TestUpPropagatesRealErrors(t *testing.T) {
	f := runner.NewFake()
	f.Responses[ExePath+" up"] = runner.Result{ExitCode: 1, Stderr: "invalid key: key expired"}
	if err := (Client{R: f}).Up(context.Background(), "tskey-x", "ir-C1"); err == nil {
		t.Fatal("expired key must be fatal")
	}
}

func TestInstallAndUninstallMSI(t *testing.T) {
	f := runner.NewFake()
	c := Client{R: f, MSIPath: `C:\w\payload\tailscale-setup.msi`}
	c.InstallMSI(context.Background())
	c.UninstallMSI(context.Background())
	if !f.Called("msiexec.exe", "/i", c.MSIPath, "/quiet", "/norestart") || !f.Called("msiexec.exe", "/x", c.MSIPath, "/quiet", "/norestart") {
		t.Fatalf("%v", f.Calls)
	}
}

func TestStatusUsesJSONFlag(t *testing.T) {
	f := runner.NewFake()
	f.Responses[ExePath+" status --json"] = runner.Result{Stdout: statusJSON}
	s, err := (Client{R: f}).Status(context.Background())
	if err != nil || s.BackendState != "Running" {
		t.Fatalf("%+v %v", s, err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/tailscale/ -v`
Expected: FAIL — `undefined: ParseStatus`

- [ ] **Step 3: Implement `tailscale.go`**

```go
// Package tailscale drives the stock Tailscale Windows install through its CLI.
package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

const ExePath = `C:\Program Files\Tailscale\tailscale.exe`

type Client struct {
	R       runner.Runner
	MSIPath string
}

func (c Client) InstallMSI(ctx context.Context) error {
	_, err := c.R.Run(ctx, "msiexec.exe", "/i", c.MSIPath, "/quiet", "/norestart")
	return err
}

func (c Client) UninstallMSI(ctx context.Context) error {
	_, err := c.R.Run(ctx, "msiexec.exe", "/x", c.MSIPath, "/quiet", "/norestart")
	return err
}

// Up applies prefs and the auth key. While the host is offline the daemon
// cannot reach the control plane, so the CLI exits with a timeout; the prefs
// are persisted and the daemon will connect once a link is up. Any other
// failure (bad key, expired key) is fatal.
func (c Client) Up(ctx context.Context, authkey, hostname string) error {
	res, err := c.R.Run(ctx, ExePath, "up",
		"--authkey="+authkey, "--hostname="+hostname,
		"--accept-routes=false", "--accept-dns=false", "--timeout=15s")
	if err == nil {
		return nil
	}
	var ee *runner.ExitError
	if errors.As(err, &ee) && strings.Contains(strings.ToLower(res.Stderr), "timeout") {
		return nil
	}
	return fmt.Errorf("tailscale up: %w", err)
}

type Peer struct {
	PublicKey    string   `json:"PublicKey"`
	HostName     string   `json:"HostName"`
	Online       bool     `json:"Online"`
	TailscaleIPs []string `json:"TailscaleIPs"`
}

type Status struct {
	BackendState string
	Self         Peer
	Peers        []Peer
}

func ParseStatus(jsonText string) (Status, error) {
	var raw struct {
		BackendState string          `json:"BackendState"`
		Self         Peer            `json:"Self"`
		Peer         map[string]Peer `json:"Peer"`
	}
	if err := json.Unmarshal([]byte(jsonText), &raw); err != nil {
		return Status{}, fmt.Errorf("parse tailscale status: %w", err)
	}
	s := Status{BackendState: raw.BackendState, Self: raw.Self}
	for _, p := range raw.Peer {
		s.Peers = append(s.Peers, p)
	}
	return s, nil
}

func (c Client) Status(ctx context.Context) (Status, error) {
	res, err := c.R.Run(ctx, ExePath, "status", "--json")
	if err != nil {
		return Status{}, err
	}
	return ParseStatus(res.Stdout)
}

// ResponderOnline is the tunnel-verified condition from spec §9 step 3.
func (s Status) ResponderOnline(nodeKey string) bool {
	if s.BackendState != "Running" {
		return false
	}
	for _, p := range s.Peers {
		if p.PublicKey == nodeKey && p.Online {
			return true
		}
	}
	return false
}

func (c Client) Logout(ctx context.Context) error {
	_, err := c.R.Run(ctx, ExePath, "logout")
	return err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/tailscale/ -v`
Expected: 5 PASS

- [ ] **Step 5: Commit**

```bash
git add internal/tailscale
git commit -m "Add Tailscale CLI wrapper with responder verification

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 10: `internal/velo` — Velociraptor service lifecycle

**Files:**
- Create: `internal/velo/velo.go`, `internal/velo/velo_test.go`

**Interfaces:**
- Consumes: `runner.Runner`, `win.Sys.ServiceExists`.
- Produces:
  ```go
  const ServiceName = "Velociraptor"
  type Client struct { R runner.Runner; ExePath, ConfigPath string }
  func (c Client) InstallService(ctx) error   // velociraptor.exe --config <cfg> service install ; then sc.exe stop ; sc.exe config start= demand
  func (c Client) Start(ctx) error            // sc.exe start Velociraptor
  func (c Client) Stop(ctx) error             // sc.exe stop Velociraptor (exit 1062 "not started" is not an error)
  func (c Client) RemoveService(ctx) error    // velociraptor.exe --config <cfg> service remove
  ```
- `service install` starts the service immediately. The spec requires Manual start and not-running until the tunnel is verified, so `InstallService` stops it and sets `start= demand` in the same call.

- [ ] **Step 1: Write the failing tests**

```go
package velo

import (
	"context"
	"strings"
	"testing"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

func joined(f *runner.Fake) string {
	var b strings.Builder
	for _, c := range f.Calls {
		b.WriteString(strings.Join(c, " ") + "\n")
	}
	return b.String()
}

func TestInstallServiceStopsAndSetsManual(t *testing.T) {
	f := runner.NewFake()
	c := Client{R: f, ExePath: `C:\w\payload\velociraptor.exe`, ConfigPath: `C:\w\payload\velociraptor.client.yaml`}
	if err := c.InstallService(context.Background()); err != nil {
		t.Fatal(err)
	}
	all := joined(f)
	for i, want := range []string{
		`C:\w\payload\velociraptor.exe --config C:\w\payload\velociraptor.client.yaml service install`,
		`sc.exe stop Velociraptor`,
		`sc.exe config Velociraptor start= demand`,
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("step %d missing %q in:\n%s", i, want, all)
		}
	}
	if strings.Index(all, "service install") > strings.Index(all, "sc.exe stop") {
		t.Fatal("must install before stopping")
	}
}

func TestStopToleratesNotRunning(t *testing.T) {
	f := runner.NewFake()
	f.Responses[f.Key("sc.exe", "stop", ServiceName)] = runner.Result{ExitCode: 1062, Stderr: "The service has not been started."}
	if err := (Client{R: f}).Stop(context.Background()); err != nil {
		t.Fatalf("1062 must be tolerated: %v", err)
	}
	f.Responses[f.Key("sc.exe", "stop", ServiceName)] = runner.Result{ExitCode: 5, Stderr: "Access is denied."}
	if err := (Client{R: f}).Stop(context.Background()); err == nil {
		t.Fatal("other errors must propagate")
	}
}

func TestStartAndRemove(t *testing.T) {
	f := runner.NewFake()
	c := Client{R: f, ExePath: "v.exe", ConfigPath: "c.yaml"}
	c.Start(context.Background())
	c.RemoveService(context.Background())
	all := joined(f)
	if !strings.Contains(all, "sc.exe start Velociraptor") || !strings.Contains(all, "v.exe --config c.yaml service remove") {
		t.Fatal(all)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/velo/ -v`
Expected: FAIL — `undefined: Client`

- [ ] **Step 3: Implement `velo.go`**

```go
// Package velo manages the Velociraptor client as a Windows service using
// the stock, unmodified velociraptor.exe and an external config file.
package velo

import (
	"context"
	"errors"
	"fmt"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

const ServiceName = "Velociraptor"

type Client struct {
	R          runner.Runner
	ExePath    string
	ConfigPath string
}

// InstallService registers the service (which also starts it), then stops it
// and sets Manual start so it stays down until the tunnel is verified.
func (c Client) InstallService(ctx context.Context) error {
	if _, err := c.R.Run(ctx, c.ExePath, "--config", c.ConfigPath, "service", "install"); err != nil {
		return fmt.Errorf("velociraptor service install: %w", err)
	}
	if err := c.Stop(ctx); err != nil {
		return err
	}
	if _, err := c.R.Run(ctx, "sc.exe", "config", ServiceName, "start=", "demand"); err != nil {
		return fmt.Errorf("set Velociraptor to manual start: %w", err)
	}
	return nil
}

func (c Client) Start(ctx context.Context) error {
	_, err := c.R.Run(ctx, "sc.exe", "start", ServiceName)
	return err
}

// Stop tolerates 1062 (ERROR_SERVICE_NOT_ACTIVE).
func (c Client) Stop(ctx context.Context) error {
	res, err := c.R.Run(ctx, "sc.exe", "stop", ServiceName)
	var ee *runner.ExitError
	if errors.As(err, &ee) && res.ExitCode == 1062 {
		return nil
	}
	return err
}

func (c Client) RemoveService(ctx context.Context) error {
	_, err := c.R.Run(ctx, c.ExePath, "--config", c.ConfigPath, "service", "remove")
	return err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/velo/ -v`
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add internal/velo
git commit -m "Add Velociraptor service lifecycle wrapper

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 11: `internal/ui` — the status beacon

**Files:**
- Create: `internal/ui/beacon.go`, `internal/ui/font.go`, `internal/ui/vt_windows.go`, `internal/ui/vt_other.go`, `internal/ui/beacon_test.go`

**Interfaces:**
- Consumes: `config.Contact`.
- Produces:
  ```go
  type State int
  const ( Staging State = iota; Ready; Connected; Error )
  type Beacon struct { /* unexported */ }
  func New(w io.Writer, contact config.Contact) *Beacon
  func (b *Beacon) Set(state State, detail string)   // re-renders immediately
  func (b *Beacon) State() State
  func (b *Beacon) Render() string                    // pure; full screen contents
  func BigText(s string) []string                     // 5 rows of block glyphs for A-Z and space
  func EnableVT()                                     // windows: ENABLE_VIRTUAL_TERMINAL_PROCESSING; other: no-op
  ```
- Screen: clear + home, a coloured box, the state word in 5-row block letters, one instruction line, one detail line. `Ready` prints `RECONNECT NETWORK NOW`. `Error` prints `CALL <name> <phone>` and the detail (an error code or short message). Yellow = Staging, green = Ready/Connected, red = Error.

- [ ] **Step 1: Write the failing tests**

```go
package ui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dfirtnt/DFIRMedic/internal/config"
)

func TestBigTextShape(t *testing.T) {
	rows := BigText("READY")
	if len(rows) != 5 {
		t.Fatalf("want 5 rows, got %d", len(rows))
	}
	w := len([]rune(rows[0]))
	for _, r := range rows {
		if len([]rune(r)) != w {
			t.Fatalf("ragged rows:\n%s", strings.Join(rows, "\n"))
		}
	}
	if !strings.Contains(strings.Join(rows, "\n"), "█") {
		t.Fatal("expected block glyphs")
	}
}

func TestBigTextUnknownRuneIsBlank(t *testing.T) {
	rows := BigText("A?")
	if len(rows) != 5 || len([]rune(rows[0])) != 11 { // 5 + 1 gap + 5
		t.Fatalf("%v", rows)
	}
}

func TestRenderStates(t *testing.T) {
	var buf bytes.Buffer
	b := New(&buf, config.Contact{Name: "Alex", Phone: "+15555550100"})
	if b.State() != Staging {
		t.Fatal("initial state must be Staging")
	}
	if !strings.Contains(b.Render(), "STAGING") {
		t.Fatal("staging word missing")
	}
	b.Set(Ready, "")
	out := b.Render()
	if !strings.Contains(out, "RECONNECT NETWORK NOW") || !strings.Contains(out, "\x1b[32m") {
		t.Fatalf("ready screen wrong:\n%s", out)
	}
	b.Set(Error, "E14 tunnel timeout")
	out = b.Render()
	for _, want := range []string{"ERROR", "CALL Alex +15555550100", "E14 tunnel timeout", "\x1b[31m"} {
		if !strings.Contains(out, want) {
			t.Fatalf("error screen missing %q:\n%s", want, out)
		}
	}
	if !strings.HasPrefix(buf.String(), "\x1b[2J\x1b[H") {
		t.Fatal("Set must write a cleared screen to the writer")
	}
}

func TestEnableVTCompiles(t *testing.T) { EnableVT() }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/ui/ -v`
Expected: FAIL — `undefined: BigText`

- [ ] **Step 3: Implement `font.go`**

```go
package ui

import "strings"

// 5x5 glyphs, '#' = filled. Only the letters the beacon needs, plus space.
var font = map[rune][5]string{
	'A': {" ### ", "#   #", "#####", "#   #", "#   #"},
	'C': {" ####", "#    ", "#    ", "#    ", " ####"},
	'D': {"#### ", "#   #", "#   #", "#   #", "#### "},
	'E': {"#####", "#    ", "#### ", "#    ", "#####"},
	'G': {" ####", "#    ", "#  ##", "#   #", " ####"},
	'I': {"#####", "  #  ", "  #  ", "  #  ", "#####"},
	'N': {"#   #", "##  #", "# # #", "#  ##", "#   #"},
	'O': {" ### ", "#   #", "#   #", "#   #", " ### "},
	'R': {"#### ", "#   #", "#### ", "#  # ", "#   #"},
	'S': {" ####", "#    ", " ### ", "    #", "#### "},
	'T': {"#####", "  #  ", "  #  ", "  #  ", "  #  "},
	'Y': {"#   #", " # # ", "  #  ", "  #  ", "  #  "},
	' ': {"     ", "     ", "     ", "     ", "     "},
}

// BigText renders s (uppercased) as five rows of block glyphs separated by one column.
func BigText(s string) []string {
	rows := make([]string, 5)
	for i, r := range strings.ToUpper(s) {
		g, ok := font[r]
		if !ok {
			g = font[' ']
		}
		for row := 0; row < 5; row++ {
			if i > 0 {
				rows[row] += " "
			}
			rows[row] += strings.ReplaceAll(g[row], "#", "█")
		}
	}
	return rows
}
```

- [ ] **Step 4: Implement `beacon.go`**

```go
// Package ui is the single-screen status beacon shown to the on-site person.
// It shows one of four states and nothing else: no logs, no findings.
package ui

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/dfirtnt/DFIRMedic/internal/config"
)

type State int

const (
	Staging State = iota
	Ready
	Connected
	Error
)

const (
	ansiClear  = "\x1b[2J\x1b[H"
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiBold   = "\x1b[1m"
)

type Beacon struct {
	mu      sync.Mutex
	w       io.Writer
	contact config.Contact
	state   State
	detail  string
}

func New(w io.Writer, contact config.Contact) *Beacon {
	return &Beacon{w: w, contact: contact, state: Staging}
}

func (b *Beacon) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

func (b *Beacon) Set(state State, detail string) {
	b.mu.Lock()
	b.state, b.detail = state, detail
	b.mu.Unlock()
	fmt.Fprint(b.w, b.Render())
}

func (b *Beacon) Render() string {
	b.mu.Lock()
	state, detail := b.state, b.detail
	b.mu.Unlock()

	var word, colour, instruction string
	switch state {
	case Staging:
		word, colour, instruction = "STAGING", ansiYellow, "Please wait. Do not touch the computer."
	case Ready:
		word, colour, instruction = "READY", ansiGreen, "RECONNECT NETWORK NOW"
	case Connected:
		word, colour, instruction = "CONNECTED", ansiGreen, "You may leave. Do not turn the computer off."
	case Error:
		word, colour, instruction = "ERROR", ansiRed, fmt.Sprintf("CALL %s %s", b.contact.Name, b.contact.Phone)
	}

	rows := BigText(word)
	width := len([]rune(rows[0])) + 6
	if len(instruction)+6 > width {
		width = len(instruction) + 6
	}
	if len(detail)+6 > width {
		width = len(detail) + 6
	}
	line := strings.Repeat("═", width)
	center := func(s string) string {
		pad := width - len([]rune(s))
		l := pad / 2
		return strings.Repeat(" ", l) + s + strings.Repeat(" ", pad-l)
	}

	var out strings.Builder
	out.WriteString(ansiClear)
	out.WriteString(colour + ansiBold)
	out.WriteString("╔" + line + "╗\n")
	out.WriteString("║" + center("") + "║\n")
	for _, r := range rows {
		out.WriteString("║" + center(r) + "║\n")
	}
	out.WriteString("║" + center("") + "║\n")
	out.WriteString("║" + center(instruction) + "║\n")
	if detail != "" {
		out.WriteString("║" + center(detail) + "║\n")
	}
	out.WriteString("║" + center("") + "║\n")
	out.WriteString("╚" + line + "╝\n")
	out.WriteString(ansiReset)
	out.WriteString("\nDFIRMedic\n")
	return out.String()
}
```

- [ ] **Step 5: Implement the VT enable stubs**

`vt_windows.go`:
```go
//go:build windows

package ui

import "golang.org/x/sys/windows"

// EnableVT turns on ANSI escape processing for the console so colours and
// box-drawing render on Windows 10+.
func EnableVT() {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return
	}
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return
	}
	_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}
```

`vt_other.go`:
```go
//go:build !windows

package ui

func EnableVT() {}
```

- [ ] **Step 6: Run tests and cross-compile**

Run: `make check`
Expected: `internal/ui` 4 PASS; Windows build OK.

- [ ] **Step 7: Commit**

```bash
git add internal/ui
git commit -m "Add status beacon with block-letter states

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 12: `internal/stage` — PREFLIGHT → BASELINE → QUARANTINE → INSTALL → READY

**Files:**
- Create: `internal/stage/stage.go`, `internal/stage/copy.go`, `internal/stage/stage_test.go`

**Interfaces:**
- Consumes: everything from Tasks 2–11.
- Produces:
  ```go
  type Deps struct {
      Inc       *config.Incident
      RawConfig []byte            // exact bytes of incident.json
      Sig       []byte            // from incident.json.sig
      PubKey    ed25519.PublicKey
      KitDir    string            // directory containing dfirmedic.exe, incident.json, payload/
      WorkDir   string            // C:\ProgramData\DFIRMedic\<case_id>
      ExeSHA256 string
      R         runner.Runner
      Log       *audit.Log
      Man       *audit.Manifest
      Beacon    *ui.Beacon
      FW        win.Firewall
      Net       win.Net
      Sys       win.Sys
      TS        tailscale.Client
      Velo      velo.Client
      Now       func() time.Time
      Elevated  func() bool
  }
  type Baseline struct {
      Hostname, EditionID, Timezone string
      TimeUTC  time.Time
      Profiles []win.ProfileState
      Rules    json.RawMessage
      Adapters []win.Adapter
      Services string            // raw `sc query` text
  }
  func Run(ctx, d Deps) error                    // all phases; nil means READY
  func Preflight(ctx, d Deps) error
  func TakeBaseline(ctx, d Deps) (*Baseline, error)
  func Quarantine(ctx, d Deps, base *Baseline) error   // rolls back on any error
  func Install(ctx, d Deps) error
  const TaskNamePrefix = "DFIRMedic-"
  ```
- Files written to `WorkDir`: `audit.jsonl` (opened by caller), `manifest.json`, `baseline.json`, `firewall-original.wfw`, `payload/` (copy of the kit's payload), `dfirmedic.exe`, `incident.json`, `incident.json.sig`.
- The Velociraptor service and the startup task point at the **WorkDir** copies, never the USB.
- Error codes shown on the beacon: `E10` not elevated, `E11` bad signature, `E12` config invalid/expired, `E13` payload hash, `E14` network is up, `E15` Home edition with RDP, `E16` already installed, `E20` baseline, `E30` quarantine, `E40` install.

- [ ] **Step 1: Write the failing tests**

```go
package stage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/manifest"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/sign"
	"github.com/dfirtnt/DFIRMedic/internal/tailscale"
	"github.com/dfirtnt/DFIRMedic/internal/ui"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

const incJSON = `{"schema":1,"case_id":"C1","created_utc":"2026-09-04T22:00:00Z","expires_utc":"2026-09-05T22:00:00Z",
"tailscale":{"authkey":"tskey-x","hostname":"ir-C1","responder_node_key":"nodekey:resp","responder_tailnet_ip":"100.64.0.1"},
"velociraptor":{"server_url":"https://100.64.0.1:8000/","config_file":"payload/velociraptor.client.yaml"},
"firewall":{"dns_resolvers":["1.1.1.1"],"allow_rdp_from_responder":false,"dns_fallback_to_dhcp":false},
"watchdog":{"tunnel_timeout_sec":600,"heartbeat_grace_sec":300},
"contact":{"phone":"+1555","name":"Alex"},"breakglass_code_hash":"sha256:x"}`

func psKey(f *runner.Fake, script string) string {
	return f.Key("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

// happyFake returns a fake whose responses describe an offline, clean host.
func happyFake() *runner.Fake {
	f := runner.NewFake()
	f.Responses[psKey(f, "Get-NetAdapter")] = runner.Result{Stdout: `[{"Name":"Wi-Fi","InterfaceDescription":"Intel","Status":"Disconnected"}]`}
	f.Responses[psKey(f, "Get-NetFirewallProfile")] = runner.Result{Stdout: `[{"Name":"Domain","Enabled":1,"DefaultInboundAction":4,"DefaultOutboundAction":2}]`}
	f.Responses[psKey(f, "Get-NetFirewallRule")] = runner.Result{Stdout: `[{"Name":"r1"}]`}
	f.Responses[f.Key("reg.exe", "query")] = runner.Result{Stdout: "    EditionID    REG_SZ    Professional\r\n"}
	f.Responses[f.Key("sc.exe", "query", "Tailscale")] = runner.Result{ExitCode: 1060}
	f.Responses[f.Key("sc.exe", "query", "Velociraptor")] = runner.Result{ExitCode: 1060}
	f.Responses[f.Key("sc.exe", "query", "type=")] = runner.Result{Stdout: "SERVICE_NAME: Spooler\r\n"}
	return f
}

func deps(t *testing.T, f *runner.Fake, incText string) Deps {
	t.Helper()
	kit := t.TempDir()
	work := filepath.Join(t.TempDir(), "work")
	os.MkdirAll(filepath.Join(kit, "payload", "tools"), 0o755)
	os.WriteFile(filepath.Join(kit, "payload", "velociraptor.exe"), []byte("velo"), 0o755)
	os.WriteFile(filepath.Join(kit, "payload", "velociraptor.client.yaml"), []byte("cfg"), 0o644)
	os.WriteFile(filepath.Join(kit, "payload", "tailscale-setup.msi"), []byte("msi"), 0o644)
	os.WriteFile(filepath.Join(kit, "payload", "tools", "thor-lite.exe"), []byte("thor"), 0o755)
	os.WriteFile(filepath.Join(kit, "dfirmedic.exe"), []byte("exe"), 0o755)
	if _, err := manifest.Write(filepath.Join(kit, "payload")); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := sign.GenerateKeypair()
	os.WriteFile(filepath.Join(kit, "incident.json"), []byte(incText), 0o600)
	inc, raw, err := config.Load(filepath.Join(kit, "incident.json"))
	if err != nil {
		t.Fatal(err)
	}
	sig := sign.Sign(priv, raw)
	sign.WriteSig(filepath.Join(kit, "incident.json.sig"), sig)
	os.MkdirAll(work, 0o700)
	log, _ := audit.Open(filepath.Join(work, "audit.jsonl"), nil)
	man := &audit.Manifest{CaseID: inc.CaseID}
	return Deps{
		Inc: inc, RawConfig: raw, Sig: sig, PubKey: pub, KitDir: kit, WorkDir: work, ExeSHA256: "abc",
		R: f, Log: log, Man: man, Beacon: ui.New(&strings.Builder{}, inc.Contact),
		FW: win.Firewall{R: f}, Net: win.Net{R: f}, Sys: win.Sys{R: f},
		TS: tailscale.Client{R: f, MSIPath: filepath.Join(work, "payload", "tailscale-setup.msi")},
		Velo: velo.Client{R: f, ExePath: filepath.Join(work, "payload", "velociraptor.exe"), ConfigPath: filepath.Join(work, "payload", "velociraptor.client.yaml")},
		Now: func() time.Time { return time.Date(2026, 9, 4, 23, 0, 0, 0, time.UTC) },
		Elevated: func() bool { return true },
	}
}

func TestPreflightRefusesWhenNetworkUp(t *testing.T) {
	f := happyFake()
	f.Responses[psKey(f, "Get-NetAdapter")] = runner.Result{Stdout: `[{"Name":"Wi-Fi","Status":"Up"}]`}
	err := Preflight(context.Background(), deps(t, f, incJSON))
	if err == nil || !strings.Contains(err.Error(), "E14") {
		t.Fatalf("want E14, got %v", err)
	}
}

func TestPreflightRefusesBadSignature(t *testing.T) {
	d := deps(t, happyFake(), incJSON)
	d.Sig[0] ^= 0xff
	if err := Preflight(context.Background(), d); err == nil || !strings.Contains(err.Error(), "E11") {
		t.Fatalf("want E11, got %v", err)
	}
}

func TestPreflightRefusesTamperedPayload(t *testing.T) {
	d := deps(t, happyFake(), incJSON)
	os.WriteFile(filepath.Join(d.KitDir, "payload", "velociraptor.exe"), []byte("evil"), 0o755)
	if err := Preflight(context.Background(), d); err == nil || !strings.Contains(err.Error(), "E13") {
		t.Fatalf("want E13, got %v", err)
	}
}

func TestPreflightRefusesExistingInstall(t *testing.T) {
	f := happyFake()
	f.Responses[f.Key("sc.exe", "query", "Tailscale")] = runner.Result{Stdout: "SERVICE_NAME: Tailscale"}
	if err := Preflight(context.Background(), deps(t, f, incJSON)); err == nil || !strings.Contains(err.Error(), "E16") {
		t.Fatalf("want E16, got %v", err)
	}
}

func TestPreflightRefusesHomeEditionWithRDP(t *testing.T) {
	f := happyFake()
	f.Responses[f.Key("reg.exe", "query")] = runner.Result{Stdout: "    EditionID    REG_SZ    Core\r\n"}
	inc := strings.Replace(incJSON, `"allow_rdp_from_responder":false`, `"allow_rdp_from_responder":true`, 1)
	if err := Preflight(context.Background(), deps(t, f, inc)); err == nil || !strings.Contains(err.Error(), "E15") {
		t.Fatalf("want E15, got %v", err)
	}
}

func TestPreflightNotElevated(t *testing.T) {
	d := deps(t, happyFake(), incJSON)
	d.Elevated = func() bool { return false }
	if err := Preflight(context.Background(), d); err == nil || !strings.Contains(err.Error(), "E10") {
		t.Fatalf("want E10, got %v", err)
	}
}

func TestQuarantineRollsBackOnFailure(t *testing.T) {
	f := happyFake()
	f.Responses[psKey(f, "New-NetFirewallRule -Group 'DFIRMedic-C1' -DisplayName 'DFIRMedic-C1: dns-tcp'")] = runner.Result{ExitCode: 1, Stderr: "nope"}
	d := deps(t, f, incJSON)
	base, err := TakeBaseline(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	err = Quarantine(context.Background(), d, base)
	if err == nil || !strings.Contains(err.Error(), "E30") {
		t.Fatalf("want E30, got %v", err)
	}
	if !f.Called("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Remove-NetFirewallRule -Group 'DFIRMedic-C1'") {
		t.Fatal("rule group must be removed on rollback")
	}
	if !f.Called("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Set-NetFirewallProfile -Profile Domain -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow") {
		t.Fatal("profiles must be restored from baseline on rollback")
	}
}

func TestRunHappyPath(t *testing.T) {
	f := happyFake()
	d := deps(t, f, incJSON)
	if err := Run(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if d.Beacon.State() != ui.Ready {
		t.Fatalf("beacon state %v", d.Beacon.State())
	}
	// phases in order
	n, err := audit.VerifyChain(filepath.Join(d.WorkDir, "audit.jsonl"))
	if err != nil || n < 5 {
		t.Fatalf("audit n=%d err=%v", n, err)
	}
	for _, p := range []string{"PREFLIGHT", "BASELINE", "QUARANTINE", "INSTALL", "READY"} {
		if _, ok := d.Man.Phases[p]; !ok {
			t.Fatalf("manifest missing phase %s", p)
		}
	}
	// order of host changes: rules before profile defaults; install after quarantine
	all := ""
	for _, c := range f.Calls {
		all += strings.Join(c, " ") + "\n"
	}
	iRule := strings.Index(all, "New-NetFirewallRule")
	iProf := strings.Index(all, "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block")
	iMSI := strings.Index(all, "msiexec.exe /i")
	iUp := strings.Index(all, "tailscale.exe up")
	iVelo := strings.Index(all, "service install")
	iTask := strings.Index(all, "schtasks.exe /Create")
	if !(iRule < iProf && iProf < iMSI && iMSI < iUp && iUp < iVelo && iVelo < iTask) {
		t.Fatalf("bad order:\n%s", all)
	}
	if len(d.Man.Rules) != 3 { // tailscaled, dns-udp, dns-tcp
		t.Fatalf("manifest rules: %v", d.Man.Rules)
	}
	// workdir populated, service points at workdir copies
	for _, p := range []string{"manifest.json", "baseline.json", "firewall-original.wfw", "dfirmedic.exe", "incident.json", "incident.json.sig", filepath.Join("payload", "velociraptor.exe"), filepath.Join("payload", "tools", "thor-lite.exe")} {
		if _, err := os.Stat(filepath.Join(d.WorkDir, p)); err != nil {
			t.Fatalf("missing %s in workdir", p)
		}
	}
	if !strings.Contains(all, filepath.Join(d.WorkDir, "payload", "velociraptor.exe")+" --config") {
		t.Fatal("velociraptor must be installed from the workdir copy")
	}
	if strings.Contains(all, "fDenyTSConnections") {
		t.Fatal("RDP must not be enabled when the flag is false")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/stage/ -v`
Expected: FAIL — `undefined: Deps`

- [ ] **Step 3: Implement `copy.go`**

```go
package stage

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(p, target)
	})
}
```

- [ ] **Step 4: Implement `stage.go`**

```go
// Package stage runs the offline staging phases from spec §8. Each phase
// records itself in the audit log and manifest; the first error aborts.
package stage

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/manifest"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/sign"
	"github.com/dfirtnt/DFIRMedic/internal/tailscale"
	"github.com/dfirtnt/DFIRMedic/internal/ui"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

const TaskNamePrefix = "DFIRMedic-"

type Deps struct {
	Inc       *config.Incident
	RawConfig []byte
	Sig       []byte
	PubKey    ed25519.PublicKey
	KitDir    string
	WorkDir   string
	ExeSHA256 string
	R         runner.Runner
	Log       *audit.Log
	Man       *audit.Manifest
	Beacon    *ui.Beacon
	FW        win.Firewall
	Net       win.Net
	Sys       win.Sys
	TS        tailscale.Client
	Velo      velo.Client
	Now       func() time.Time
	Elevated  func() bool
}

type Baseline struct {
	Hostname  string             `json:"hostname"`
	EditionID string             `json:"edition_id"`
	Timezone  string             `json:"timezone"`
	TimeUTC   time.Time          `json:"time_utc"`
	Profiles  []win.ProfileState `json:"profiles"`
	Rules     json.RawMessage    `json:"rules"`
	Adapters  []win.Adapter      `json:"adapters"`
	Services  string             `json:"services"`
}

func code(c, msg string, err error) error {
	if err != nil {
		return fmt.Errorf("%s %s: %w", c, msg, err)
	}
	return fmt.Errorf("%s %s", c, msg)
}

func (d Deps) phase(name string) error {
	if d.Man.Phases == nil {
		d.Man.Phases = map[string]time.Time{}
	}
	d.Man.Phases[name] = d.Now().UTC()
	return d.Log.Phase(name)
}

func (d Deps) saveManifest() error {
	return d.Man.Save(filepath.Join(d.WorkDir, "manifest.json"))
}

func Run(ctx context.Context, d Deps) error {
	if d.Man.Phases == nil {
		d.Man.Phases = map[string]time.Time{}
	}
	d.Man.CaseID = d.Inc.CaseID
	d.Man.OrchestratorSHA256 = d.ExeSHA256
	d.Beacon.Set(ui.Staging, "Checking")
	if err := Preflight(ctx, d); err != nil {
		return err
	}
	d.Beacon.Set(ui.Staging, "Recording baseline")
	base, err := TakeBaseline(ctx, d)
	if err != nil {
		return err
	}
	d.Beacon.Set(ui.Staging, "Locking network")
	if err := Quarantine(ctx, d, base); err != nil {
		return err
	}
	d.Beacon.Set(ui.Staging, "Installing")
	if err := Install(ctx, d); err != nil {
		return err
	}
	if err := d.phase("READY"); err != nil {
		return err
	}
	if err := d.saveManifest(); err != nil {
		return err
	}
	d.Beacon.Set(ui.Ready, "")
	return nil
}

func Preflight(ctx context.Context, d Deps) error {
	if err := d.phase("PREFLIGHT"); err != nil {
		return err
	}
	if !d.Elevated() {
		return code("E10", "not running as Administrator", nil)
	}
	if !sign.Verify(d.PubKey, d.RawConfig, d.Sig) {
		return code("E11", "incident.json signature invalid", nil)
	}
	if err := d.Inc.Validate(d.Now()); err != nil {
		return code("E12", "incident.json invalid", err)
	}
	hashes, err := manifest.Verify(filepath.Join(d.KitDir, "payload"))
	if err != nil {
		return code("E13", "payload verification failed", err)
	}
	d.Man.Payload = hashes
	up, ads, err := d.Net.AnyPhysicalUp(ctx)
	if err != nil {
		return code("E14", "cannot read adapter state", err)
	}
	if up {
		return code("E14", fmt.Sprintf("network is connected (%s); disconnect before staging", ads[0].Name), nil)
	}
	if d.Inc.Firewall.AllowRDPFromResponder {
		ed, err := d.Sys.EditionID(ctx)
		if err != nil {
			return code("E15", "cannot read Windows edition", err)
		}
		if win.IsHomeEdition(ed) {
			return code("E15", "RDP requested but this is a Home edition ("+ed+")", nil)
		}
	}
	for _, svc := range []string{"Tailscale", velo.ServiceName} {
		exists, err := d.Sys.ServiceExists(ctx, svc)
		if err != nil {
			return code("E16", "cannot query service "+svc, err)
		}
		if exists {
			return code("E16", svc+" service already installed on this host", nil)
		}
	}
	return nil
}

func TakeBaseline(ctx context.Context, d Deps) (*Baseline, error) {
	if err := d.phase("BASELINE"); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(d.WorkDir, 0o700); err != nil {
		return nil, code("E20", "create workdir", err)
	}
	if err := d.FW.Export(ctx, filepath.Join(d.WorkDir, "firewall-original.wfw")); err != nil {
		return nil, code("E20", "firewall export", err)
	}
	b := &Baseline{TimeUTC: d.Now().UTC()}
	b.Hostname, _ = os.Hostname()
	b.Timezone, _ = d.Now().Zone()
	var err error
	if b.EditionID, err = d.Sys.EditionID(ctx); err != nil {
		return nil, code("E20", "edition", err)
	}
	if b.Profiles, err = d.FW.Profiles(ctx); err != nil {
		return nil, code("E20", "firewall profiles", err)
	}
	if b.Rules, err = d.FW.RulesJSON(ctx); err != nil {
		return nil, code("E20", "firewall rules", err)
	}
	if b.Adapters, err = d.Net.PhysicalAdapters(ctx); err != nil {
		return nil, code("E20", "adapters", err)
	}
	res, err := d.R.Run(ctx, "sc.exe", "query", "type=", "service", "state=", "all")
	if err != nil {
		return nil, code("E20", "services", err)
	}
	b.Services = res.Stdout
	raw, _ := json.MarshalIndent(b, "", "  ")
	if err := os.WriteFile(filepath.Join(d.WorkDir, "baseline.json"), raw, 0o600); err != nil {
		return nil, code("E20", "write baseline", err)
	}
	d.Man.Baseline = raw
	return b, nil
}

// Quarantine adds the allow-list first (harmless while defaults are still
// Allow), then flips the profile defaults to Block. Any failure removes the
// group and restores the baseline profile settings.
func Quarantine(ctx context.Context, d Deps, base *Baseline) error {
	if err := d.phase("QUARANTINE"); err != nil {
		return err
	}
	group := d.Inc.RuleGroup()
	rdpFrom := ""
	if d.Inc.Firewall.AllowRDPFromResponder {
		rdpFrom = d.Inc.Tailscale.ResponderTailnetIP
	}
	rollback := func(cause error) error {
		_ = d.Log.Record("quarantine_rollback", map[string]string{"cause": cause.Error()})
		_ = d.FW.RemoveGroup(ctx, group)
		_ = d.FW.RestoreProfiles(ctx, base.Profiles)
		return code("E30", "quarantine failed and was rolled back", cause)
	}
	for _, r := range win.QuarantineRules(d.Inc.Firewall.DNSResolvers, d.Inc.Firewall.DNSFallbackToDHCP, rdpFrom) {
		txt, err := d.FW.AddRule(ctx, group, r)
		if err != nil {
			return rollback(fmt.Errorf("rule %s: %w", r.Name, err))
		}
		d.Man.Rules = append(d.Man.Rules, txt)
	}
	if err := d.FW.SetAllProfiles(ctx, true, "Block", "Block"); err != nil {
		return rollback(err)
	}
	return nil
}

func Install(ctx context.Context, d Deps) error {
	if err := d.phase("INSTALL"); err != nil {
		return err
	}
	// Everything the services depend on must survive USB removal.
	if err := copyDir(filepath.Join(d.KitDir, "payload"), filepath.Join(d.WorkDir, "payload")); err != nil {
		return code("E40", "copy payload", err)
	}
	for _, f := range []string{"dfirmedic.exe", "incident.json", "incident.json.sig"} {
		if err := copyFile(filepath.Join(d.KitDir, f), filepath.Join(d.WorkDir, f)); err != nil {
			return code("E40", "copy "+f, err)
		}
	}
	_ = d.Log.Record("copy", map[string]string{"from": d.KitDir, "to": d.WorkDir})

	if err := d.TS.InstallMSI(ctx); err != nil {
		return code("E40", "install Tailscale", err)
	}
	if err := d.TS.Up(ctx, d.Inc.Tailscale.AuthKey, d.Inc.Tailscale.Hostname); err != nil {
		return code("E40", "tailscale up", err)
	}
	if err := d.Velo.InstallService(ctx); err != nil {
		return code("E40", "install Velociraptor", err)
	}
	if d.Inc.Firewall.AllowRDPFromResponder {
		if err := d.Sys.EnableRDP(ctx); err != nil {
			return code("E40", "enable RDP", err)
		}
	}
	exe := filepath.Join(d.WorkDir, "dfirmedic.exe")
	if err := d.Sys.CreateStartupTask(ctx, TaskNamePrefix+d.Inc.CaseID, exe, "connect --workdir "+d.WorkDir); err != nil {
		return code("E40", "startup task", err)
	}
	return nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/stage/ -v`
Expected: 8 PASS

- [ ] **Step 6: Commit**

```bash
git add internal/stage
git commit -m "Add offline staging state machine with rollback

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 13: `internal/connect` — link-up, tunnel verification, watchdog, fail-closed

**Files:**
- Create: `internal/connect/connect.go`, `internal/connect/connect_test.go`

**Interfaces:**
- Consumes: `config`, `audit`, `runner`, `win.Net`, `tailscale.Client`, `velo.Client`, `ui.Beacon`.
- Produces:
  ```go
  type Deps struct {
      Inc     *config.Incident
      WorkDir string
      R       runner.Runner
      Log     *audit.Log
      Man     *audit.Manifest
      Beacon  *ui.Beacon
      Net     win.Net
      TS      tailscale.Client
      Velo    velo.Client
      Now     func() time.Time
      Sleep   func(ctx context.Context, d time.Duration) error   // injectable; must return ctx.Err() when cancelled
      Poll    time.Duration                                      // default 2s
  }
  func Run(ctx, d Deps) error
      // WaitLinkUp → phase CONNECT → poll until TS.Status().ResponderOnline(nodeKey) or timeout
      // → Velo.Start → phase CONNECTED → heartbeat until ctx is cancelled or the tunnel is lost.
      // Returns nil when ctx is cancelled after CONNECTED (normal shutdown); otherwise the fail-closed error.
  func WaitLinkUp(ctx, d Deps) error                 // blocks until any physical adapter is Up
  func FailClosed(ctx, d Deps, reason string) error  // Velo.Stop → Net.DisableAll(all physical) → beacon ERROR → returns error
  ```
- Error codes: `E50` tunnel not verified before `tunnel_timeout_sec`; `E51` tunnel lost for longer than `heartbeat_grace_sec`; `E52` Velociraptor failed to start.
- After a reboot the startup task runs `dfirmedic.exe connect --workdir <dir>`; the NIC is already up so `WaitLinkUp` returns at once and the same verification applies. Velociraptor is Manual-start, so it stays down until this code starts it.

- [ ] **Step 1: Write the failing tests**

```go
package connect

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/tailscale"
	"github.com/dfirtnt/DFIRMedic/internal/ui"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

const (
	stNeedsLogin = `{"BackendState":"NeedsLogin","Peer":{}}`
	stRespOnline = `{"BackendState":"Running","Peer":{"nodekey:resp":{"PublicKey":"nodekey:resp","Online":true}}}`
	stRespOff    = `{"BackendState":"Running","Peer":{"nodekey:resp":{"PublicKey":"nodekey:resp","Online":false}}}`
	adUp         = `[{"Name":"Wi-Fi","Status":"Up"}]`
	adDown       = `[{"Name":"Wi-Fi","Status":"Disconnected"}]`
)

// seq is a Runner that returns scripted responses in order for matching
// argv prefixes (repeating the last one), and delegates everything else to a Fake.
type seq struct {
	f     *runner.Fake
	steps map[string][]runner.Result
	idx   map[string]int
}

func newSeq() *seq {
	return &seq{f: runner.NewFake(), steps: map[string][]runner.Result{}, idx: map[string]int{}}
}

func (s *seq) script(key string, outs ...string) {
	for _, o := range outs {
		s.steps[key] = append(s.steps[key], runner.Result{Stdout: o})
	}
}

func (s *seq) Run(ctx context.Context, name string, args ...string) (runner.Result, error) {
	full := strings.Join(append([]string{name}, args...), " ")
	for k, outs := range s.steps {
		if strings.HasPrefix(full, k) {
			s.f.Calls = append(s.f.Calls, append([]string{name}, args...))
			i := s.idx[k]
			if i >= len(outs) {
				i = len(outs) - 1
			}
			s.idx[k]++
			return outs[i], nil
		}
	}
	return s.f.Run(ctx, name, args...)
}

type clock struct {
	t      time.Time
	step   time.Duration
	sleeps int
	cancel context.CancelFunc
	after  int // cancel ctx after this many sleeps (0 = never)
}

func (c *clock) now() time.Time { return c.t }
func (c *clock) sleep(ctx context.Context, _ time.Duration) error {
	c.sleeps++
	c.t = c.t.Add(c.step)
	if c.after > 0 && c.sleeps >= c.after && c.cancel != nil {
		c.cancel()
	}
	return ctx.Err()
}

func deps(t *testing.T, r runner.Runner, c *clock) Deps {
	t.Helper()
	work := t.TempDir()
	log, _ := audit.Open(filepath.Join(work, "audit.jsonl"), nil)
	inc := &config.Incident{
		CaseID:    "C1",
		Tailscale: config.Tailscale{ResponderNodeKey: "nodekey:resp"},
		Watchdog:  config.Watchdog{TunnelTimeoutSec: 600, HeartbeatGraceSec: 300},
		Contact:   config.Contact{Name: "Alex", Phone: "+1555"},
	}
	return Deps{
		Inc: inc, WorkDir: work, R: r, Log: log, Man: &audit.Manifest{Phases: map[string]time.Time{}},
		Beacon: ui.New(&strings.Builder{}, inc.Contact),
		Net: win.Net{R: r}, TS: tailscale.Client{R: r}, Velo: velo.Client{R: r},
		Now: c.now, Sleep: c.sleep, Poll: 2 * time.Second,
	}
}

func psPrefix(script string) string {
	return "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " + script
}

func TestRunConnectsThenStartsVelociraptorThenHeartbeats(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adDown, adDown, adUp)
	s.script(tailscale.ExePath+" status --json", stNeedsLogin, stRespOnline)
	ctx, cancel := context.WithCancel(context.Background())
	c := &clock{t: time.Unix(1000, 0), step: 2 * time.Second, cancel: cancel, after: 12}
	d := deps(t, s, c)
	err := Run(ctx, d)
	if err != nil {
		t.Fatalf("normal cancel must return nil, got %v", err)
	}
	if !s.f.Called("sc.exe", "start", "Velociraptor") {
		t.Fatal("Velociraptor not started")
	}
	if d.Beacon.State() != ui.Connected {
		t.Fatalf("beacon %v", d.Beacon.State())
	}
	for _, p := range []string{"CONNECT", "CONNECTED"} {
		if _, ok := d.Man.Phases[p]; !ok {
			t.Fatalf("missing phase %s", p)
		}
	}
	if s.f.Called("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Disable-NetAdapter") {
		t.Fatal("must not disable adapters on a clean run")
	}
}

func TestTunnelTimeoutFailsClosed(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	s.script(tailscale.ExePath+" status --json", stNeedsLogin)
	c := &clock{t: time.Unix(1000, 0), step: 30 * time.Second}
	d := deps(t, s, c)
	err := Run(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "E50") {
		t.Fatalf("want E50, got %v", err)
	}
	if !s.f.Called("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Disable-NetAdapter -Name 'Wi-Fi'") {
		t.Fatal("adapters must be disabled on timeout")
	}
	if s.f.Called("sc.exe", "start", "Velociraptor") {
		t.Fatal("Velociraptor must never start without a verified tunnel")
	}
	if d.Beacon.State() != ui.Error || !strings.Contains(d.Beacon.Render(), "E50") {
		t.Fatal("beacon must show E50")
	}
}

func TestHeartbeatLossFailsClosed(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	s.script(tailscale.ExePath+" status --json", stRespOnline, stRespOnline, stRespOff)
	c := &clock{t: time.Unix(1000, 0), step: 100 * time.Second}
	d := deps(t, s, c)
	err := Run(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "E51") {
		t.Fatalf("want E51, got %v", err)
	}
	if !s.f.Called("sc.exe", "stop", "Velociraptor") {
		t.Fatal("Velociraptor must be stopped on fail-closed")
	}
	if !s.f.Called("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Disable-NetAdapter") {
		t.Fatal("adapters must be disabled")
	}
}

func TestHeartbeatToleratesBriefBlip(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	s.script(tailscale.ExePath+" status --json", stRespOnline, stRespOff, stRespOff, stRespOnline)
	ctx, cancel := context.WithCancel(context.Background())
	c := &clock{t: time.Unix(1000, 0), step: 50 * time.Second, cancel: cancel, after: 8}
	d := deps(t, s, c)
	if err := Run(ctx, d); err != nil {
		t.Fatalf("a blip shorter than the grace period must not fail closed: %v", err)
	}
}

func TestVelociraptorStartFailure(t *testing.T) {
	s := newSeq()
	s.script(psPrefix("Get-NetAdapter"), adUp)
	s.script(tailscale.ExePath+" status --json", stRespOnline)
	s.f.Responses[s.f.Key("sc.exe", "start", "Velociraptor")] = runner.Result{ExitCode: 1053, Stderr: "did not respond"}
	c := &clock{t: time.Unix(1000, 0), step: time.Second}
	err := Run(context.Background(), deps(t, s, c))
	if err == nil || !strings.Contains(err.Error(), "E52") {
		t.Fatalf("want E52, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/connect/ -v`
Expected: FAIL — `undefined: Deps`

- [ ] **Step 3: Implement `connect.go`**

```go
// Package connect runs the online half of the workflow (spec §9 and §10):
// wait for a link, verify the tunnel is to the responder, start Velociraptor,
// then watch the tunnel and fail closed if it is lost.
package connect

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/tailscale"
	"github.com/dfirtnt/DFIRMedic/internal/ui"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

type Deps struct {
	Inc     *config.Incident
	WorkDir string
	R       runner.Runner
	Log     *audit.Log
	Man     *audit.Manifest
	Beacon  *ui.Beacon
	Net     win.Net
	TS      tailscale.Client
	Velo    velo.Client
	Now     func() time.Time
	Sleep   func(ctx context.Context, d time.Duration) error
	Poll    time.Duration
}

func defaultSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (d *Deps) defaults() {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Sleep == nil {
		d.Sleep = defaultSleep
	}
	if d.Poll == 0 {
		d.Poll = 2 * time.Second
	}
	if d.Man.Phases == nil {
		d.Man.Phases = map[string]time.Time{}
	}
}

func (d Deps) phase(name string) error {
	d.Man.Phases[name] = d.Now().UTC()
	_ = d.Man.Save(filepath.Join(d.WorkDir, "manifest.json"))
	return d.Log.Phase(name)
}

func WaitLinkUp(ctx context.Context, d Deps) error {
	d.defaults()
	for {
		up, _, err := d.Net.AnyPhysicalUp(ctx)
		if err != nil {
			return err
		}
		if up {
			return d.Log.Record("link_up", map[string]string{"at": d.Now().UTC().Format(time.RFC3339)})
		}
		if err := d.Sleep(ctx, d.Poll); err != nil {
			return err
		}
	}
}

func (d Deps) responderOnline(ctx context.Context) bool {
	st, err := d.TS.Status(ctx)
	if err != nil {
		return false
	}
	return st.ResponderOnline(d.Inc.Tailscale.ResponderNodeKey)
}

func Run(ctx context.Context, d Deps) error {
	d.defaults()
	if err := WaitLinkUp(ctx, d); err != nil {
		return err
	}
	if err := d.phase("CONNECT"); err != nil {
		return err
	}
	d.Beacon.Set(ui.Staging, "Connecting")

	deadline := d.Now().Add(time.Duration(d.Inc.Watchdog.TunnelTimeoutSec) * time.Second)
	for !d.responderOnline(ctx) {
		if !d.Now().Before(deadline) {
			return FailClosed(ctx, d, "E50 tunnel not established in time")
		}
		if err := d.Sleep(ctx, d.Poll); err != nil {
			return err
		}
	}
	_ = d.Log.Record("tunnel_verified", map[string]string{"responder_node_key": d.Inc.Tailscale.ResponderNodeKey})

	if err := d.Velo.Start(ctx); err != nil {
		return FailClosed(ctx, d, "E52 Velociraptor failed to start")
	}
	if err := d.phase("CONNECTED"); err != nil {
		return err
	}
	d.Beacon.Set(ui.Connected, "")

	grace := time.Duration(d.Inc.Watchdog.HeartbeatGraceSec) * time.Second
	lastOK := d.Now()
	for {
		if err := d.Sleep(ctx, d.Poll); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		if d.responderOnline(ctx) {
			lastOK = d.Now()
			continue
		}
		if d.Now().Sub(lastOK) > grace {
			return FailClosed(ctx, d, "E51 tunnel lost")
		}
	}
}

// FailClosed is the watchdog response from spec §10: stop Velociraptor, take
// every physical adapter down, keep the firewall locked, show ERROR.
func FailClosed(ctx context.Context, d Deps, reason string) error {
	d.defaults()
	_ = d.Log.Record("fail_closed", map[string]string{"reason": reason})
	_ = d.Velo.Stop(ctx)
	ads, err := d.Net.PhysicalAdapters(ctx)
	if err == nil {
		_ = d.Net.DisableAll(ctx, ads)
	}
	_ = d.phase("FAILED")
	d.Beacon.Set(ui.Error, reason)
	return fmt.Errorf("%s", reason)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/connect/ -v`
Expected: 5 PASS

- [ ] **Step 5: Commit**

```bash
git add internal/connect
git commit -m "Add connect flow with tunnel verification and fail-closed watchdog

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 14: `internal/teardown` — teardown and break-glass

**Files:**
- Create: `internal/teardown/teardown.go`, `internal/teardown/teardown_test.go`

**Interfaces:**
- Consumes: `config`, `audit`, `runner`, `win.Firewall`, `win.Sys`, `tailscale.Client`, `velo.Client`, `stage.Baseline` (read from `baseline.json`), `stage.TaskNamePrefix`.
- Produces:
  ```go
  type Deps struct {
      Inc     *config.Incident
      WorkDir string
      R       runner.Runner
      Log     *audit.Log
      Man     *audit.Manifest
      FW      win.Firewall
      Sys     win.Sys
      TS      tailscale.Client
      Velo    velo.Client
      Now     func() time.Time
  }
  // Run is best-effort: every step runs even if an earlier one failed; the
  // returned error joins every failure. Order (spec §13):
  //   phase TEARDOWN → Velo.Stop → Velo.RemoveService → Sys.DeleteStartupTask
  //   → TS.Logout → TS.UninstallMSI → FW.RemoveGroup → FW.Import(firewall-original.wfw)
  //   → FW.RestoreProfiles(baseline) → phase TEARDOWN_COMPLETE → Man.Save
  func Run(ctx, d Deps) error
  // Breakglass records the attempt, checks sha256(code) against Inc.BreakglassCodeHash, then calls Run.
  func Breakglass(ctx, d Deps, code string) error   // wrong code → "E60 break-glass code rejected"
  func CodeHash(code string) string                  // "sha256:" + hex(sha256(code))
  ```

- [ ] **Step 1: Write the failing tests**

```go
package teardown

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/tailscale"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

func deps(t *testing.T, f *runner.Fake) Deps {
	t.Helper()
	work := t.TempDir()
	base := map[string]any{"profiles": []map[string]any{{"Name": "Domain", "Enabled": true, "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"}}}
	raw, _ := json.Marshal(base)
	os.WriteFile(filepath.Join(work, "baseline.json"), raw, 0o600)
	os.WriteFile(filepath.Join(work, "firewall-original.wfw"), []byte("wfw"), 0o600)
	log, _ := audit.Open(filepath.Join(work, "audit.jsonl"), nil)
	inc := &config.Incident{CaseID: "C1", BreakglassCodeHash: CodeHash("hunter2")}
	return Deps{
		Inc: inc, WorkDir: work, R: f, Log: log, Man: &audit.Manifest{Phases: map[string]time.Time{}},
		FW: win.Firewall{R: f}, Sys: win.Sys{R: f},
		TS: tailscale.Client{R: f, MSIPath: `C:\w\payload\tailscale-setup.msi`},
		Velo: velo.Client{R: f, ExePath: "v.exe", ConfigPath: "c.yaml"},
		Now: func() time.Time { return time.Unix(2000, 0) },
	}
}

func all(f *runner.Fake) string {
	var b strings.Builder
	for _, c := range f.Calls {
		b.WriteString(strings.Join(c, " ") + "\n")
	}
	return b.String()
}

func TestRunOrder(t *testing.T) {
	f := runner.NewFake()
	d := deps(t, f)
	if err := Run(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	a := all(f)
	order := []string{
		"sc.exe stop Velociraptor",
		"v.exe --config c.yaml service remove",
		"schtasks.exe /Delete /TN DFIRMedic-C1 /F",
		tailscale.ExePath + " logout",
		`msiexec.exe /x C:\w\payload\tailscale-setup.msi /quiet /norestart`,
		"Remove-NetFirewallRule -Group 'DFIRMedic-C1'",
		"netsh.exe advfirewall import " + filepath.Join(d.WorkDir, "firewall-original.wfw"),
		"Set-NetFirewallProfile -Profile Domain -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow",
	}
	last := -1
	for _, want := range order {
		i := strings.Index(a, want)
		if i < 0 {
			t.Fatalf("missing %q in:\n%s", want, a)
		}
		if i < last {
			t.Fatalf("%q out of order in:\n%s", want, a)
		}
		last = i
	}
	for _, p := range []string{"TEARDOWN", "TEARDOWN_COMPLETE"} {
		if _, ok := d.Man.Phases[p]; !ok {
			t.Fatalf("missing phase %s", p)
		}
	}
	if _, err := os.Stat(filepath.Join(d.WorkDir, "manifest.json")); err != nil {
		t.Fatal("manifest must be saved")
	}
}

func TestRunContinuesPastFailures(t *testing.T) {
	f := runner.NewFake()
	f.Responses[f.Key("msiexec.exe", "/x")] = runner.Result{ExitCode: 1603, Stderr: "fatal"}
	d := deps(t, f)
	err := Run(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "uninstall Tailscale") {
		t.Fatalf("expected joined error naming the failed step, got %v", err)
	}
	a := all(f)
	if !strings.Contains(a, "Remove-NetFirewallRule") || !strings.Contains(a, "advfirewall import") {
		t.Fatal("firewall restore must still run after an earlier failure")
	}
}

func TestBreakglassRejectsWrongCode(t *testing.T) {
	f := runner.NewFake()
	d := deps(t, f)
	err := Breakglass(context.Background(), d, "wrong")
	if err == nil || !strings.Contains(err.Error(), "E60") {
		t.Fatalf("want E60, got %v", err)
	}
	if len(f.Calls) != 0 {
		t.Fatal("nothing may run on a rejected code")
	}
	n, _ := audit.VerifyChain(filepath.Join(d.WorkDir, "audit.jsonl"))
	if n != 1 {
		t.Fatal("the rejected attempt must be logged")
	}
}

func TestBreakglassAcceptsRightCode(t *testing.T) {
	f := runner.NewFake()
	d := deps(t, f)
	if err := Breakglass(context.Background(), d, "hunter2"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(all(f), "advfirewall import") {
		t.Fatal("teardown must run")
	}
}

func TestCodeHashFormat(t *testing.T) {
	h := CodeHash("x")
	if !strings.HasPrefix(h, "sha256:") || len(h) != 7+64 {
		t.Fatal(h)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/teardown/ -v`
Expected: FAIL — `undefined: CodeHash`

- [ ] **Step 3: Implement `teardown.go`**

```go
// Package teardown reverses everything staging did (spec §13) and provides
// the local break-glass path (spec §10.1). Best-effort: every step runs.
package teardown

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/stage"
	"github.com/dfirtnt/DFIRMedic/internal/tailscale"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

type Deps struct {
	Inc     *config.Incident
	WorkDir string
	R       runner.Runner
	Log     *audit.Log
	Man     *audit.Manifest
	FW      win.Firewall
	Sys     win.Sys
	TS      tailscale.Client
	Velo    velo.Client
	Now     func() time.Time
}

func CodeHash(code string) string {
	sum := sha256.Sum256([]byte(code))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (d Deps) phase(name string) {
	if d.Man.Phases == nil {
		d.Man.Phases = map[string]time.Time{}
	}
	d.Man.Phases[name] = d.Now().UTC()
	_ = d.Log.Phase(name)
}

func Run(ctx context.Context, d Deps) error {
	if d.Now == nil {
		d.Now = time.Now
	}
	d.phase("TEARDOWN")
	var errs []error
	step := func(name string, fn func() error) {
		if err := fn(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			_ = d.Log.Record("teardown_step_failed", map[string]string{"step": name, "error": err.Error()})
		}
	}
	step("stop Velociraptor", func() error { return d.Velo.Stop(ctx) })
	step("remove Velociraptor service", func() error { return d.Velo.RemoveService(ctx) })
	step("delete startup task", func() error { return d.Sys.DeleteStartupTask(ctx, stage.TaskNamePrefix+d.Inc.CaseID) })
	step("tailscale logout", func() error { return d.TS.Logout(ctx) })
	step("uninstall Tailscale", func() error { return d.TS.UninstallMSI(ctx) })
	step("remove firewall rule group", func() error { return d.FW.RemoveGroup(ctx, d.Inc.RuleGroup()) })
	step("import original firewall policy", func() error {
		return d.FW.Import(ctx, filepath.Join(d.WorkDir, "firewall-original.wfw"))
	})
	step("restore firewall profiles", func() error {
		raw, err := os.ReadFile(filepath.Join(d.WorkDir, "baseline.json"))
		if err != nil {
			return err
		}
		var base stage.Baseline
		if err := json.Unmarshal(raw, &base); err != nil {
			return err
		}
		return d.FW.RestoreProfiles(ctx, base.Profiles)
	})
	d.phase("TEARDOWN_COMPLETE")
	if err := d.Man.Save(filepath.Join(d.WorkDir, "manifest.json")); err != nil {
		errs = append(errs, fmt.Errorf("save manifest: %w", err))
	}
	return errors.Join(errs...)
}

func Breakglass(ctx context.Context, d Deps, code string) error {
	if d.Now == nil {
		d.Now = time.Now
	}
	got, want := CodeHash(code), d.Inc.BreakglassCodeHash
	ok := subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
	_ = d.Log.Record("breakglass_attempt", map[string]any{"accepted": ok, "at": d.Now().UTC()})
	if !ok {
		return errors.New("E60 break-glass code rejected")
	}
	return Run(ctx, d)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/teardown/ -v`
Expected: 5 PASS

- [ ] **Step 5: Commit**

```bash
git add internal/teardown
git commit -m "Add best-effort teardown and break-glass

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 15: `internal/build` — responder-side kit builder and verifier

**Files:**
- Create: `internal/build/build.go`, `internal/build/build_test.go`

**Interfaces:**
- Consumes: `config`, `sign`, `manifest`, `teardown.CodeHash`.
- Produces:
  ```go
  type Options struct {
      CaseID, AuthKey, Hostname, ResponderNodeKey, ResponderIP, ServerURL string
      DNSResolvers      []string
      AllowRDP          bool
      DNSFallbackDHCP   bool
      TunnelTimeoutSec  int            // default 600
      HeartbeatGraceSec int            // default 300
      ContactName, ContactPhone, BreakglassCode string
      TTL               time.Duration  // incident.json validity; default 24h
      PayloadDir        string         // source payload/ (see payload/README.md)
      ExePath           string         // dist/dfirmedic.exe
      FieldCardPath     string         // FIELD-CARD.md
      OutDir            string         // USB mount point
      PrivKeyPath       string         // responder ed25519 private key
      Now               func() time.Time
  }
  type Result struct { IncidentPath string; Files []string }
  // Build writes OutDir/{dfirmedic.exe, incident.json, incident.json.sig, FIELD-CARD.txt, payload/**, payload/manifest.sha256}
  // then runs Verify on the result before returning.
  func Build(o Options) (*Result, error)
  // Verify is what `dfirmedic verify --kit` runs: signature, config validity, payload hashes.
  func Verify(kitDir string, pub ed25519.PublicKey, now time.Time) (*config.Incident, error)
  ```
- `Hostname` defaults to `ir-<CaseID>`. `incident.json` is written with `json.MarshalIndent` and signed over exactly those bytes.
- `manifest.sha256` is regenerated in `OutDir/payload` after copying, never copied from the source.

- [ ] **Step 1: Write the failing tests**

```go
package build

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/sign"
	"github.com/dfirtnt/DFIRMedic/internal/teardown"
)

func fixture(t *testing.T) (Options, []byte) {
	t.Helper()
	src := t.TempDir()
	payload := filepath.Join(src, "payload")
	os.MkdirAll(filepath.Join(payload, "tools"), 0o755)
	os.WriteFile(filepath.Join(payload, "velociraptor.exe"), []byte("v"), 0o755)
	os.WriteFile(filepath.Join(payload, "tools", "thor-lite.exe"), []byte("t"), 0o755)
	os.WriteFile(filepath.Join(src, "dfirmedic.exe"), []byte("exe"), 0o755)
	os.WriteFile(filepath.Join(src, "FIELD-CARD.md"), []byte("# card {{CASE_ID}} {{PHONE}}"), 0o644)
	pub, priv, _ := sign.GenerateKeypair()
	keyPath := filepath.Join(src, "responder.key")
	sign.WritePrivateKey(keyPath, priv)
	return Options{
		CaseID: "CASE-1", AuthKey: "tskey-auth-x", ResponderNodeKey: "nodekey:r", ResponderIP: "100.64.0.1",
		ServerURL: "https://100.64.0.1:8000/", DNSResolvers: []string{"1.1.1.1"},
		ContactName: "Alex", ContactPhone: "+1555", BreakglassCode: "hunter2",
		PayloadDir: payload, ExePath: filepath.Join(src, "dfirmedic.exe"), FieldCardPath: filepath.Join(src, "FIELD-CARD.md"),
		OutDir: filepath.Join(t.TempDir(), "usb"), PrivKeyPath: keyPath,
		Now: func() time.Time { return time.Date(2026, 9, 4, 22, 0, 0, 0, time.UTC) },
	}, pub
}

func TestBuildProducesVerifiableKit(t *testing.T) {
	o, pub := fixture(t)
	res, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"dfirmedic.exe", "incident.json", "incident.json.sig", "FIELD-CARD.txt", "payload/manifest.sha256", "payload/velociraptor.exe", "payload/tools/thor-lite.exe"} {
		if _, err := os.Stat(filepath.Join(o.OutDir, filepath.FromSlash(f))); err != nil {
			t.Fatalf("missing %s", f)
		}
	}
	inc, err := Verify(o.OutDir, pub, o.Now())
	if err != nil {
		t.Fatal(err)
	}
	if inc.Tailscale.Hostname != "ir-CASE-1" || inc.Watchdog.TunnelTimeoutSec != 600 || inc.Watchdog.HeartbeatGraceSec != 300 {
		t.Fatalf("defaults not applied: %+v", inc)
	}
	if inc.BreakglassCodeHash != teardown.CodeHash("hunter2") {
		t.Fatal("break-glass hash mismatch")
	}
	if !inc.ExpiresUTC.Equal(o.Now().Add(24 * time.Hour)) {
		t.Fatalf("default TTL 24h, got %v", inc.ExpiresUTC)
	}
	card, _ := os.ReadFile(filepath.Join(o.OutDir, "FIELD-CARD.txt"))
	if !strings.Contains(string(card), "CASE-1") || !strings.Contains(string(card), "+1555") {
		t.Fatalf("field card placeholders not filled: %s", card)
	}
	if res.IncidentPath != filepath.Join(o.OutDir, "incident.json") {
		t.Fatal(res.IncidentPath)
	}
}

func TestVerifyRejectsWrongKeyAndTamper(t *testing.T) {
	o, pub := fixture(t)
	if _, err := Build(o); err != nil {
		t.Fatal(err)
	}
	other, _, _ := sign.GenerateKeypair()
	if _, err := Verify(o.OutDir, other, o.Now()); err == nil {
		t.Fatal("wrong key accepted")
	}
	os.WriteFile(filepath.Join(o.OutDir, "payload", "velociraptor.exe"), []byte("evil"), 0o755)
	if _, err := Verify(o.OutDir, pub, o.Now()); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

func TestBuildRejectsMissingInputs(t *testing.T) {
	o, _ := fixture(t)
	o.AuthKey = ""
	if _, err := Build(o); err == nil {
		t.Fatal("empty authkey must fail validation")
	}
	o, _ = fixture(t)
	o.PayloadDir = filepath.Join(t.TempDir(), "nope")
	if _, err := Build(o); err == nil {
		t.Fatal("missing payload dir must fail")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	o, pub := fixture(t)
	Build(o)
	if _, err := Verify(o.OutDir, pub, o.Now().Add(48*time.Hour)); err == nil {
		t.Fatal("expired kit accepted")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/build/ -v`
Expected: FAIL — `undefined: Build`

- [ ] **Step 3: Implement `build.go`**

```go
// Package build assembles and signs a per-incident kit onto a USB stick, and
// verifies a kit the same way the orchestrator will in PREFLIGHT.
package build

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/manifest"
	"github.com/dfirtnt/DFIRMedic/internal/sign"
	"github.com/dfirtnt/DFIRMedic/internal/teardown"
)

type Options struct {
	CaseID, AuthKey, Hostname, ResponderNodeKey, ResponderIP, ServerURL string
	DNSResolvers                                                       []string
	AllowRDP, DNSFallbackDHCP                                          bool
	TunnelTimeoutSec, HeartbeatGraceSec                                int
	ContactName, ContactPhone, BreakglassCode                          string
	TTL                                                                time.Duration
	PayloadDir, ExePath, FieldCardPath, OutDir, PrivKeyPath            string
	Now                                                                func() time.Time
}

type Result struct {
	IncidentPath string
	Files        []string
}

func (o *Options) defaults() {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Hostname == "" {
		o.Hostname = "ir-" + o.CaseID
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

func (o Options) incident() *config.Incident {
	now := o.Now().UTC()
	return &config.Incident{
		Schema: 1, CaseID: o.CaseID, CreatedUTC: now, ExpiresUTC: now.Add(o.TTL),
		Tailscale: config.Tailscale{AuthKey: o.AuthKey, Hostname: o.Hostname, ResponderNodeKey: o.ResponderNodeKey, ResponderTailnetIP: o.ResponderIP},
		Velociraptor: config.Velo{ServerURL: o.ServerURL, ConfigFile: "payload/velociraptor.client.yaml"},
		Firewall: config.Firewall{DNSResolvers: o.DNSResolvers, AllowRDPFromResponder: o.AllowRDP, DNSFallbackToDHCP: o.DNSFallbackDHCP},
		Watchdog: config.Watchdog{TunnelTimeoutSec: o.TunnelTimeoutSec, HeartbeatGraceSec: o.HeartbeatGraceSec},
		Contact:  config.Contact{Name: o.ContactName, Phone: o.ContactPhone},
		BreakglassCodeHash: teardown.CodeHash(o.BreakglassCode),
	}
}

func Build(o Options) (*Result, error) {
	o.defaults()
	if o.BreakglassCode == "" {
		return nil, errors.New("break-glass code required")
	}
	inc := o.incident()
	if err := inc.Validate(o.Now()); err != nil {
		return nil, fmt.Errorf("incident config: %w", err)
	}
	if st, err := os.Stat(o.PayloadDir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("payload dir %s: not a directory", o.PayloadDir)
	}
	priv, err := sign.ReadPrivateKey(o.PrivKeyPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(o.OutDir, 0o755); err != nil {
		return nil, err
	}
	res := &Result{IncidentPath: filepath.Join(o.OutDir, "incident.json")}

	if err := copyTree(o.PayloadDir, filepath.Join(o.OutDir, "payload")); err != nil {
		return nil, fmt.Errorf("copy payload: %w", err)
	}
	if _, err := manifest.Write(filepath.Join(o.OutDir, "payload")); err != nil {
		return nil, err
	}
	if err := copyFile(o.ExePath, filepath.Join(o.OutDir, "dfirmedic.exe")); err != nil {
		return nil, fmt.Errorf("copy orchestrator: %w", err)
	}
	card, err := os.ReadFile(o.FieldCardPath)
	if err != nil {
		return nil, fmt.Errorf("field card: %w", err)
	}
	txt := strings.NewReplacer("{{CASE_ID}}", o.CaseID, "{{NAME}}", o.ContactName, "{{PHONE}}", o.ContactPhone).Replace(string(card))
	if err := os.WriteFile(filepath.Join(o.OutDir, "FIELD-CARD.txt"), []byte(txt), 0o644); err != nil {
		return nil, err
	}

	raw, err := json.MarshalIndent(inc, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(res.IncidentPath, raw, 0o600); err != nil {
		return nil, err
	}
	if err := sign.WriteSig(res.IncidentPath+".sig", sign.Sign(priv, raw)); err != nil {
		return nil, err
	}
	if _, err := Verify(o.OutDir, priv.Public().(ed25519.PublicKey), o.Now()); err != nil {
		return nil, fmt.Errorf("post-build verification failed: %w", err)
	}
	filepath.WalkDir(o.OutDir, func(p string, d fs.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			rel, _ := filepath.Rel(o.OutDir, p)
			res.Files = append(res.Files, filepath.ToSlash(rel))
		}
		return nil
	})
	return res, nil
}

func Verify(kitDir string, pub ed25519.PublicKey, now time.Time) (*config.Incident, error) {
	inc, raw, err := config.Load(filepath.Join(kitDir, "incident.json"))
	if err != nil {
		return nil, err
	}
	sig, err := sign.ReadSig(filepath.Join(kitDir, "incident.json.sig"))
	if err != nil {
		return nil, err
	}
	if !sign.Verify(pub, raw, sig) {
		return nil, errors.New("incident.json signature invalid")
	}
	if err := inc.Validate(now); err != nil {
		return nil, err
	}
	if _, err := manifest.Verify(filepath.Join(kitDir, "payload")); err != nil {
		return nil, err
	}
	return inc, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		if filepath.Base(p) == manifest.FileName {
			return nil // regenerated after copy
		}
		return copyFile(p, filepath.Join(dst, rel))
	})
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/build/ -v`
Expected: 4 PASS

- [ ] **Step 5: Commit**

```bash
git add internal/build
git commit -m "Add responder-side kit builder and verifier

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 16: `cmd/dfirmedic` wiring, field card, responder docs, integration runbook

**Files:**
- Modify: `cmd/dfirmedic/main.go`
- Create: `cmd/dfirmedic/cmds.go`, `cmd/dfirmedic/cmds_test.go`, `FIELD-CARD.md`, `docs/responder-setup.md`, `docs/integration-tests.md`
- Modify: `README.md` (add build + usage)

**Interfaces:**
- Consumes: every `internal` package.
- Produces the CLI:
  ```
  dfirmedic stage      [--kit DIR] [--workdir DIR] [--dry-run]
  dfirmedic connect    --workdir DIR [--dry-run]
  dfirmedic teardown   --workdir DIR [--purge] [--dry-run]
  dfirmedic breakglass --workdir DIR --code CODE
  dfirmedic keygen     [--out PATH]
  dfirmedic build      --case ID --authkey KEY --responder-node-key KEY --responder-ip IP --server-url URL
                       --phone P --name N --breakglass-code C [--dns 1.1.1.1,9.9.9.9] [--rdp] [--dns-dhcp-fallback]
                       [--ttl 24h] [--payload DIR] [--exe PATH] [--card PATH] --out USB_DIR [--key PATH]
  dfirmedic verify     --kit DIR
  ```
- `--kit` defaults to the directory containing the running executable. `--workdir` defaults to `C:\ProgramData\DFIRMedic\<case_id>` on Windows. `--key` defaults to `~/.dfirmedic/responder.key`.
- `stage` runs `stage.Run` and, on success, continues directly into `connect.Run` in the same process (spec §8.5 → §9). On any error it shows the beacon ERROR state and **holds the screen** until Ctrl-C so the person can read it.
- `keygen` prints the public key hex and the exact `make build-windows LDFLAGS=...` line to embed it.

- [ ] **Step 1: Write the failing test for argument parsing and defaults**

`cmd/dfirmedic/cmds_test.go`:
```go
package main

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseStageDefaultsKitToExeDir(t *testing.T) {
	o, err := parseStage([]string{}, `C:\usb\dfirmedic.exe`)
	if err != nil {
		t.Fatal(err)
	}
	if o.Kit != `C:\usb` {
		t.Fatal(o.Kit)
	}
	if o.DryRun {
		t.Fatal("dry-run must default off")
	}
}

func TestParseStageFlags(t *testing.T) {
	o, err := parseStage([]string{"--kit", "/k", "--workdir", "/w", "--dry-run"}, "/x/dfirmedic")
	if err != nil || o.Kit != "/k" || o.WorkDir != "/w" || !o.DryRun {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestDefaultWorkDir(t *testing.T) {
	got := defaultWorkDir("CASE-1")
	if runtime.GOOS == "windows" {
		if got != `C:\ProgramData\DFIRMedic\CASE-1` {
			t.Fatal(got)
		}
		return
	}
	if !strings.HasSuffix(got, filepath.Join("DFIRMedic", "CASE-1")) {
		t.Fatal(got)
	}
}

func TestParseBuildRequiresCore(t *testing.T) {
	if _, err := parseBuild([]string{"--case", "C"}); err == nil {
		t.Fatal("missing required flags must error")
	}
	o, err := parseBuild([]string{"--case", "C", "--authkey", "k", "--responder-node-key", "n", "--responder-ip", "100.64.0.1",
		"--server-url", "https://x/", "--phone", "+1", "--name", "A", "--breakglass-code", "z", "--out", "/usb", "--dns", "1.1.1.1,9.9.9.9", "--rdp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(o.DNSResolvers) != 2 || !o.AllowRDP || o.OutDir != "/usb" {
		t.Fatalf("%+v", o)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/dfirmedic/ -v`
Expected: FAIL — `undefined: parseStage`

- [ ] **Step 3: Implement `cmds.go`**

```go
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/build"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/connect"
	"github.com/dfirtnt/DFIRMedic/internal/manifest"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/sign"
	"github.com/dfirtnt/DFIRMedic/internal/stage"
	"github.com/dfirtnt/DFIRMedic/internal/tailscale"
	"github.com/dfirtnt/DFIRMedic/internal/teardown"
	"github.com/dfirtnt/DFIRMedic/internal/ui"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

// ---------- parsing ----------

type stageOpts struct {
	Kit, WorkDir string
	DryRun       bool
}

func parseStage(args []string, exePath string) (stageOpts, error) {
	var o stageOpts
	fs := flag.NewFlagSet("stage", flag.ContinueOnError)
	fs.StringVar(&o.Kit, "kit", filepath.Dir(exePath), "kit directory (default: directory of this executable)")
	fs.StringVar(&o.WorkDir, "workdir", "", "working directory (default: C:\\ProgramData\\DFIRMedic\\<case_id>)")
	fs.BoolVar(&o.DryRun, "dry-run", false, "log every command without executing")
	return o, fs.Parse(args)
}

func defaultWorkDir(caseID string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(`C:\ProgramData`, "DFIRMedic", caseID)
	}
	return filepath.Join(os.TempDir(), "DFIRMedic", caseID)
}

func parseBuild(args []string) (build.Options, error) {
	var o build.Options
	var dns, ttl string
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.StringVar(&o.CaseID, "case", "", "case id")
	fs.StringVar(&o.AuthKey, "authkey", "", "ephemeral tagged Tailscale auth key")
	fs.StringVar(&o.Hostname, "hostname", "", "tailnet hostname (default ir-<case>)")
	fs.StringVar(&o.ResponderNodeKey, "responder-node-key", "", "responder node public key (tailscale status --json --self)")
	fs.StringVar(&o.ResponderIP, "responder-ip", "", "responder tailnet IP")
	fs.StringVar(&o.ServerURL, "server-url", "", "Velociraptor server URL on the tailnet")
	fs.StringVar(&dns, "dns", "1.1.1.1,9.9.9.9", "comma-separated pinned DNS resolvers")
	fs.BoolVar(&o.AllowRDP, "rdp", false, "allow RDP from the responder")
	fs.BoolVar(&o.DNSFallbackDHCP, "dns-dhcp-fallback", false, "also allow the DHCP resolver")
	fs.IntVar(&o.TunnelTimeoutSec, "tunnel-timeout", 600, "seconds")
	fs.IntVar(&o.HeartbeatGraceSec, "heartbeat-grace", 300, "seconds")
	fs.StringVar(&o.ContactName, "name", "", "responder name shown on the beacon")
	fs.StringVar(&o.ContactPhone, "phone", "", "responder phone shown on the beacon")
	fs.StringVar(&o.BreakglassCode, "breakglass-code", "", "local rollback code")
	fs.StringVar(&ttl, "ttl", "24h", "incident.json validity")
	fs.StringVar(&o.PayloadDir, "payload", "payload", "payload source dir")
	fs.StringVar(&o.ExePath, "exe", filepath.Join("dist", "dfirmedic.exe"), "Windows orchestrator binary")
	fs.StringVar(&o.FieldCardPath, "card", "FIELD-CARD.md", "field card template")
	fs.StringVar(&o.OutDir, "out", "", "USB mount point")
	fs.StringVar(&o.PrivKeyPath, "key", defaultKeyPath(), "responder private key")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	var missing []string
	for name, v := range map[string]string{"case": o.CaseID, "authkey": o.AuthKey, "responder-node-key": o.ResponderNodeKey,
		"responder-ip": o.ResponderIP, "server-url": o.ServerURL, "phone": o.ContactPhone, "name": o.ContactName,
		"breakglass-code": o.BreakglassCode, "out": o.OutDir} {
		if v == "" {
			missing = append(missing, "--"+name)
		}
	}
	if len(missing) > 0 {
		return o, fmt.Errorf("missing required flags: %s", strings.Join(missing, " "))
	}
	for _, r := range strings.Split(dns, ",") {
		if r = strings.TrimSpace(r); r != "" {
			o.DNSResolvers = append(o.DNSResolvers, r)
		}
	}
	d, err := time.ParseDuration(ttl)
	if err != nil {
		return o, fmt.Errorf("--ttl: %w", err)
	}
	o.TTL = d
	return o, nil
}

func defaultKeyPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".dfirmedic", "responder.key")
}

// ---------- shared wiring ----------

type host struct {
	inc    *config.Incident
	raw    []byte
	sig    []byte
	pub    ed25519.PublicKey
	log    *audit.Log
	man    *audit.Manifest
	r      runner.Runner
	beacon *ui.Beacon
	fw     win.Firewall
	net    win.Net
	sys    win.Sys
	ts     tailscale.Client
	velo   velo.Client
}

// openHost loads config+sig from dir, opens the audit log in workDir, and wires the runner.
func openHost(dir, workDir string, dryRun bool) (*host, error) {
	inc, raw, err := config.Load(filepath.Join(dir, "incident.json"))
	if err != nil {
		return nil, err
	}
	sig, err := sign.ReadSig(filepath.Join(dir, "incident.json.sig"))
	if err != nil {
		return nil, err
	}
	pub, err := sign.EmbeddedPublicKey()
	if err != nil {
		return nil, err
	}
	if workDir == "" {
		workDir = defaultWorkDir(inc.CaseID)
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, err
	}
	log, err := audit.Open(filepath.Join(workDir, "audit.jsonl"), nil)
	if err != nil {
		return nil, err
	}
	man, err := audit.LoadManifest(filepath.Join(workDir, "manifest.json"))
	if err != nil {
		man = &audit.Manifest{CaseID: inc.CaseID, Phases: map[string]time.Time{}}
	}
	var r runner.Runner = runner.NewExec(log, man)
	if dryRun {
		r = runner.NewDryRun(log)
	}
	ui.EnableVT()
	payload := filepath.Join(workDir, "payload")
	return &host{
		inc: inc, raw: raw, sig: sig, pub: pub, log: log, man: man, r: r,
		beacon: ui.New(os.Stdout, inc.Contact),
		fw: win.Firewall{R: r}, net: win.Net{R: r}, sys: win.Sys{R: r},
		ts:   tailscale.Client{R: r, MSIPath: filepath.Join(payload, "tailscale-setup.msi")},
		velo: velo.Client{R: r, ExePath: filepath.Join(payload, "velociraptor.exe"), ConfigPath: filepath.Join(payload, "velociraptor.client.yaml")},
	}, nil
}

func hold() {
	fmt.Fprintln(os.Stderr, "\nPress Ctrl-C to close this window.")
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}

func ctx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// ---------- commands ----------

func cmdStage(args []string) int {
	exe, _ := os.Executable()
	o, err := parseStage(args, exe)
	if err != nil {
		return 2
	}
	h, err := openHost(o.Kit, o.WorkDir, o.DryRun)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	workDir := o.WorkDir
	if workDir == "" {
		workDir = defaultWorkDir(h.inc.CaseID)
	}
	exeHash, _ := manifest.HashFile(exe)
	c, cancel := ctx()
	defer cancel()
	d := stage.Deps{
		Inc: h.inc, RawConfig: h.raw, Sig: h.sig, PubKey: h.pub, KitDir: o.Kit, WorkDir: workDir, ExeSHA256: exeHash,
		R: h.r, Log: h.log, Man: h.man, Beacon: h.beacon, FW: h.fw, Net: h.net, Sys: h.sys, TS: h.ts, Velo: h.velo,
		Now: time.Now, Elevated: win.IsElevated,
	}
	if err := stage.Run(c, d); err != nil {
		h.beacon.Set(ui.Error, firstWord(err.Error())+" — staging failed")
		_ = h.log.Record("error", map[string]string{"error": err.Error()})
		hold()
		return 1
	}
	return runConnect(c, h, workDir)
}

func runConnect(c context.Context, h *host, workDir string) int {
	d := connect.Deps{
		Inc: h.inc, WorkDir: workDir, R: h.r, Log: h.log, Man: h.man, Beacon: h.beacon,
		Net: h.net, TS: h.ts, Velo: h.velo,
	}
	if err := connect.Run(c, d); err != nil {
		_ = h.log.Record("error", map[string]string{"error": err.Error()})
		hold()
		return 1
	}
	return 0
}

func cmdConnect(args []string) int {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	workDir := fs.String("workdir", "", "working directory")
	dry := fs.Bool("dry-run", false, "")
	if err := fs.Parse(args); err != nil || *workDir == "" {
		fmt.Fprintln(os.Stderr, "connect: --workdir required")
		return 2
	}
	h, err := openHost(*workDir, *workDir, *dry)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	c, cancel := ctx()
	defer cancel()
	return runConnect(c, h, *workDir)
}

func teardownDeps(h *host, workDir string) teardown.Deps {
	return teardown.Deps{Inc: h.inc, WorkDir: workDir, R: h.r, Log: h.log, Man: h.man,
		FW: h.fw, Sys: h.sys, TS: h.ts, Velo: h.velo, Now: time.Now}
}

func cmdTeardown(args []string) int {
	fs := flag.NewFlagSet("teardown", flag.ContinueOnError)
	workDir := fs.String("workdir", "", "working directory")
	purge := fs.Bool("purge", false, "delete the working directory afterwards")
	dry := fs.Bool("dry-run", false, "")
	if err := fs.Parse(args); err != nil || *workDir == "" {
		fmt.Fprintln(os.Stderr, "teardown: --workdir required")
		return 2
	}
	h, err := openHost(*workDir, *workDir, *dry)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	c, cancel := ctx()
	defer cancel()
	err = teardown.Run(c, teardownDeps(h, *workDir))
	if err != nil {
		fmt.Fprintln(os.Stderr, "teardown completed with errors:\n", err)
	}
	if *purge && !*dry {
		h.log.Close()
		if rmErr := os.RemoveAll(*workDir); rmErr != nil {
			fmt.Fprintln(os.Stderr, rmErr)
			return 1
		}
	}
	if err != nil {
		return 1
	}
	fmt.Println("teardown complete")
	return 0
}

func cmdBreakglass(args []string) int {
	fs := flag.NewFlagSet("breakglass", flag.ContinueOnError)
	workDir := fs.String("workdir", "", "working directory")
	code := fs.String("code", "", "break-glass code from the responder")
	if err := fs.Parse(args); err != nil || *workDir == "" || *code == "" {
		fmt.Fprintln(os.Stderr, "breakglass: --workdir and --code required")
		return 2
	}
	h, err := openHost(*workDir, *workDir, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	c, cancel := ctx()
	defer cancel()
	if err := teardown.Breakglass(c, teardownDeps(h, *workDir), *code); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("rollback complete")
	return 0
}

func cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", defaultKeyPath(), "private key path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if _, err := os.Stat(*out); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists; refusing to overwrite\n", *out)
		return 1
	}
	pub, priv, err := sign.GenerateKeypair()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := sign.WritePrivateKey(*out, priv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	hexPub := fmt.Sprintf("%x", []byte(pub))
	fmt.Printf("private key: %s\npublic key:  %s\n\nBuild the orchestrator with this key embedded:\n\n  make build-windows LDFLAGS=\"-X github.com/dfirtnt/DFIRMedic/internal/sign.embeddedPubKeyHex=%s\"\n", *out, hexPub, hexPub)
	return 0
}

func cmdBuild(args []string) int {
	o, err := parseBuild(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	res, err := build.Build(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("kit written to %s (%d files)\nincident config: %s\n", o.OutDir, len(res.Files), res.IncidentPath)
	return 0
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	kit := fs.String("kit", "", "kit directory")
	keyPath := fs.String("key", defaultKeyPath(), "responder private key (public key derived)")
	if err := fs.Parse(args); err != nil || *kit == "" {
		fmt.Fprintln(os.Stderr, "verify: --kit required")
		return 2
	}
	pub, err := sign.EmbeddedPublicKey()
	if err != nil {
		priv, kerr := sign.ReadPrivateKey(*keyPath)
		if kerr != nil {
			fmt.Fprintln(os.Stderr, errors.Join(err, kerr))
			return 1
		}
		pub = priv.Public().(ed25519.PublicKey)
	}
	inc, err := build.Verify(*kit, pub, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "INVALID:", err)
		return 1
	}
	fmt.Printf("OK: case %s, expires %s\n", inc.CaseID, inc.ExpiresUTC.Format(time.RFC3339))
	return 0
}

func firstWord(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i]
	}
	return s
}
```

- [ ] **Step 4: Wire `main.go`**

Replace the `switch` in `cmd/dfirmedic/main.go`:
```go
	switch os.Args[1] {
	case "stage":
		os.Exit(cmdStage(os.Args[2:]))
	case "connect":
		os.Exit(cmdConnect(os.Args[2:]))
	case "teardown":
		os.Exit(cmdTeardown(os.Args[2:]))
	case "breakglass":
		os.Exit(cmdBreakglass(os.Args[2:]))
	case "keygen":
		os.Exit(cmdKeygen(os.Args[2:]))
	case "build":
		os.Exit(cmdBuild(os.Args[2:]))
	case "verify":
		os.Exit(cmdVerify(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
```

- [ ] **Step 5: Run tests and both builds**

Run: `make check && make build-windows && make build-darwin && ./dist/dfirmedic keygen --out /tmp/dfm-test.key && rm /tmp/dfm-test.key`
Expected: tests PASS, both binaries build, keygen prints a public key and the LDFLAGS line.

- [ ] **Step 6: Write `FIELD-CARD.md`**

```markdown
DFIRMedic — Case {{CASE_ID}}
=============================

If anything on this card is unclear, STOP and call {{NAME}}: {{PHONE}}

BEFORE YOU START
  1. The computer must be DISCONNECTED from the network. Turn Wi-Fi OFF and unplug any network cable.
  2. Do not close any windows on the computer. Do not restart it.

STEPS
  1. Plug in the USB stick.
  2. Open the USB stick. Double-click  dfirmedic.exe
  3. If Windows asks "Do you want to allow this app to make changes?", click YES.
  4. A window with big yellow letters appears: STAGING.  Wait. Do not touch anything.
  5. When the letters turn green and say READY / RECONNECT NETWORK NOW:
       turn Wi-Fi back ON (or plug the network cable back in).
  6. Wait until the letters say CONNECTED.
  7. You are done. Leave the window open. Leave the computer on. Take the USB stick with you.

IF THE LETTERS TURN RED (ERROR)
  Call {{NAME}} at {{PHONE}} and read them the code on the screen (for example E14).
  Do not restart the computer. Do not close the window.
```

- [ ] **Step 7: Write `docs/responder-setup.md`**

```markdown
# Responder-side setup

One-time setup on your side. Everything the victim host does is in the spec (§5–§13).

## 1. Velociraptor server on an always-on tailnet node

Install Velociraptor on the always-on box, then in `server.config.yaml` bind
every listener to that node's tailnet IP — never `0.0.0.0`:

```yaml
Frontend:
  bind_address: 100.x.y.z
  bind_port: 8000
GUI:
  bind_address: 100.x.y.z
  bind_port: 8889
```

Generate the client config the kit ships:

```bash
velociraptor --config server.config.yaml config client > payload/velociraptor.client.yaml
```

Its `Client.server_urls` must be `https://100.x.y.z:8000/` (the tailnet IP).

## 2. Tailnet ACL

In the Tailscale admin console → Access controls:

```json
{
  "tagOwners": { "tag:ir-victim": ["autogroup:admin"] },
  "acls": [
    { "action": "accept", "src": ["tag:ir-victim"], "dst": ["100.x.y.z:8000"] },
    { "action": "accept", "src": ["<your workstation user or tag>"], "dst": ["tag:ir-victim:3389"] }
  ]
}
```

The first rule is the only reach a victim node has. The second exists only for the RDP opt-in.
Turn **device approval** on so a stolen key cannot silently join.

## 3. Exit node and domain allowlist

Advertise an exit node on your side and enforce the VirusTotal / Microsoft allowlist there
with DNS filtering. The victim never talks to those services directly; you submit hashes.

## 4. Responder identity for the kit

```bash
tailscale status --json --self | jq -r '.Self.PublicKey, .Self.TailscaleIPs[0]'
```

Use those as `--responder-node-key` and `--responder-ip`.

## 5. Signing key and embedded public key (once)

```bash
make build-darwin
./dist/dfirmedic keygen
```

Copy the printed `make build-windows LDFLAGS=...` line and run it. The public key is
now compiled into `dist/dfirmedic.exe`; every kit must be signed with the matching
private key at `~/.dfirmedic/responder.key`. Back that file up offline.

## 6. Per incident

1. Admin console → Settings → Keys → Generate auth key:
   **Reusable: off. Ephemeral: on. Pre-authorized: on. Tags: tag:ir-victim. Expiry: 1 hour.**
2. Format the USB **exFAT** (macOS: `diskutil eraseDisk ExFAT DFIRMEDIC /dev/diskN`).
3. Build the kit:

```bash
./dist/dfirmedic build \
  --case CASE-2026-0042 \
  --authkey tskey-auth-... \
  --responder-node-key nodekey:... --responder-ip 100.x.y.z \
  --server-url https://100.x.y.z:8000/ \
  --name "Your Name" --phone "+1..." \
  --breakglass-code "$(openssl rand -hex 4)" \
  --out /Volumes/DFIRMEDIC
```

4. `./dist/dfirmedic verify --kit /Volumes/DFIRMEDIC`
5. Print `FIELD-CARD.txt` from the stick and hand both to the on-site person.
6. Keep the break-glass code with you; read it over the phone only if rollback is needed.

## 7. After the engagement

From your workstation, over the tunnel: `dfirmedic.exe teardown --workdir C:\ProgramData\DFIRMedic\<case>`
(via a Velociraptor `Windows.System.CmdShell` collection), then delete the node in the admin console.
```

- [ ] **Step 8: Write `docs/integration-tests.md`**

```markdown
# Integration test runbook (Windows VM)

Unit tests cover logic with a fake runner. These runs prove the real commands on a
real Windows 10/11 Pro VM. Snapshot the VM **before** each row and restore afterwards.

Setup once: a test tailnet with your workstation as responder, a Velociraptor server on
it, a `tag:ir-victim` ACL, and a kit built with `--ttl 2h`. Copy the kit to the VM via an
exFAT USB image or shared folder that strips Mark-of-the-Web.

| # | Scenario | Steps | Expected |
|---|---|---|---|
| 1 | Happy path | VM NIC disconnected. Run `dfirmedic.exe stage`. Reconnect NIC at READY. | Beacon → CONNECTED. Velociraptor client appears in the server GUI. `audit.jsonl` chain verifies. `manifest.json` has phases PREFLIGHT…CONNECTED. |
| 2 | Network already up | Leave the NIC connected. Run `stage`. | Immediate ERROR E14. No firewall or install changes (`Get-NetFirewallRule -Group DFIRMedic-*` empty). |
| 3 | Watchdog timeout | Build the kit with `--tunnel-timeout 60`. Stop the responder workstation's tailscaled. Stage, reconnect. | After ~60 s: ERROR E50, all physical adapters Disabled, firewall still default-deny, Velociraptor service not running. |
| 4 | Heartbeat loss | Build with `--heartbeat-grace 60`. After CONNECTED, stop responder tailscaled. | After ~60 s: ERROR E51, adapters Disabled, Velociraptor stopped. |
| 5 | DERP fallback | On the VM host, block outbound UDP from the VM except 53. Stage, reconnect. | CONNECTED via relay (`tailscale status` shows `relay`). |
| 6 | Reboot mid-session | After CONNECTED, reboot the VM. | Startup task runs `connect`; Velociraptor stays stopped until the responder peer is verified, then starts. Beacon window reappears at CONNECTED. |
| 7 | Tampered payload | Edit one byte of `payload\thor-lite.exe` on the stick. | ERROR E13 in PREFLIGHT; nothing else changes. |
| 8 | Home edition + RDP | Build with `--rdp`; run on a Windows Home VM. | ERROR E15 in PREFLIGHT. |
| 9 | Break-glass | After CONNECTED, run `dfirmedic.exe breakglass --workdir … --code WRONG` then with the right code. | Wrong: E60, nothing changes, attempt logged. Right: full teardown. |
| 10 | Teardown golden | Before row 1: `netsh advfirewall export C:\before.wfw`. After teardown: export again. | Rule sets and profile settings identical (compare via `Get-NetFirewallRule` / `Get-NetFirewallProfile` JSON, since `.wfw` binaries contain timestamps). Tailscale and Velociraptor services absent; startup task absent. |
| 11 | Dry run | `dfirmedic.exe stage --dry-run` on any VM. | Beacon reaches READY; `audit.jsonl` lists every command as `dryrun`; no host changes. |
```

- [ ] **Step 9: Update `README.md`**

Append after the Design line:
```markdown

## Build

```bash
make build-darwin && ./dist/dfirmedic keygen      # once
make build-windows LDFLAGS="-X github.com/dfirtnt/DFIRMedic/internal/sign.embeddedPubKeyHex=<hex from keygen>"
```

## Use

See [docs/responder-setup.md](docs/responder-setup.md) for the responder side and
[docs/integration-tests.md](docs/integration-tests.md) for the VM test matrix.
```

- [ ] **Step 10: Final check and commit**

Run: `make check && make build-windows && make build-darwin`
Expected: all tests PASS, both binaries built.

```bash
git add -A
git commit -m "Wire CLI commands, field card, responder docs, integration runbook

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Self-review notes

Spec coverage — every section maps to a task: §5.1 (docs/responder-setup.md, Task 16), §6 (Tasks 1, 4, 15), §7 (Tasks 2, 15), §8.1–8.5 (Task 12), §9 (Task 13), §10 (Tasks 13, 14), §11 (Tasks 5, 6), §12 (Velociraptor artifacts are used as-is; the kit stages `tools/` in Task 12 and docs name the artifacts), §13 (Task 14), §14 (Tasks 1, 8, 11), §15 (unit tests in every task; VM matrix in Task 16), §16 risks are documented not coded, §17 resolutions appear as defaults in Tasks 2, 12, 15.

Two deliberate simplifications versus the spec text: (1) loopback is not given an explicit allow rule because Windows Filtering Platform does not filter loopback traffic; (2) `tailscale up --shields-up` is omitted per spec §8.3's own note.
