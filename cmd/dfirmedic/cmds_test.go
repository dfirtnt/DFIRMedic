package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/sign"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
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

func TestExeDir(t *testing.T) {
	cases := []struct{ in, want string }{
		{`C:\usb\dfirmedic.exe`, `C:\usb`}, // existing multi-segment case
		{`E:\dfirmedic.exe`, `E:\`},        // drive root
		{`/dfirmedic`, `/`},                // POSIX root
		{`/x/dfirmedic`, `/x`},             // POSIX multi-segment
		{`dfirmedic`, `.`},                 // no separator
	}
	for _, c := range cases {
		if got := exeDir(c.in); got != c.want {
			t.Errorf("exeDir(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseStageRejectsWorkDirWithSpace(t *testing.T) {
	if _, err := parseStage([]string{"--workdir", `C:\IR Cases\x`}, "/x/dfirmedic"); err == nil {
		t.Fatal("expected error for --workdir containing a space")
	}
}

func TestParseStageRejectsWorkDirWithQuote(t *testing.T) {
	if _, err := parseStage([]string{"--workdir", `C:\IR"Cases\x`}, "/x/dfirmedic"); err == nil {
		t.Fatal("expected error for --workdir containing a quote")
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
	o, err := parseBuild([]string{"--case", "C",
		"--server-url", "https://x/", "--phone", "+1", "--name", "A", "--breakglass-code", "z", "--out", "/usb", "--dns-dhcp-fallback"})
	if err != nil {
		t.Fatal(err)
	}
	if !o.DNSFallbackDHCP || o.OutDir != "/usb" {
		t.Fatalf("%+v", o)
	}
}

func TestParseBuildRejectsRemovedFlags(t *testing.T) {
	if _, err := parseBuild([]string{"--case", "C", "--authkey", "x"}); err == nil {
		t.Fatal("--authkey must no longer exist")
	}
}

// A double-click launches the exe with no arguments. The field card tells the
// on-site person to do exactly that, so a bare launch must mean `stage`.
func TestResolveCommandDefaultsToStageOnBareLaunch(t *testing.T) {
	name, rest := resolveCommand([]string{`E:\dfirmedic.exe`})
	if name != "stage" || len(rest) != 0 {
		t.Fatalf("bare launch → %q %v, want stage []", name, rest)
	}
	name, rest = resolveCommand([]string{"dfirmedic", "verify", "--kit", "x"})
	if name != "verify" || len(rest) != 2 || rest[1] != "x" {
		t.Fatalf("explicit command → %q %v", name, rest)
	}
}

// Early failures in stage (bad flags, kit not found) used to print to stderr
// and return, which closes the console before the operator can read it.
func TestStageHoldsWindowOnEarlyFailure(t *testing.T) {
	held := 0
	orig := hold
	hold = func() { held++ }
	defer func() { hold = orig }()
	if rc := cmdStage([]string{"--kit", filepath.Join(t.TempDir(), "missing")}); rc == 0 {
		t.Fatal("expected failure for a missing kit")
	}
	if held != 1 {
		t.Fatalf("hold called %d times, want 1", held)
	}
	held = 0
	if rc := cmdStage([]string{"--no-such-flag"}); rc == 0 {
		t.Fatal("expected failure for a bad flag")
	}
	if held != 1 {
		t.Fatalf("hold called %d times on bad flag, want 1", held)
	}
}

// testCAPEM is a real self-signed CA, so velo.CAFingerprint's certificate
// parse succeeds and the fingerprint comparison is the thing under test.
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

func clientYAML(caPEM string) string {
	var b strings.Builder
	b.WriteString("Client:\n  server_urls:\n  - https://203.0.113.10:443/\n  ca_certificate: |\n")
	for _, l := range strings.Split(strings.TrimRight(caPEM, "\n"), "\n") {
		b.WriteString("    " + l + "\n")
	}
	b.WriteString("  windows_installer:\n    service_name: Velociraptor\n    install_path: $ProgramFiles\\Velociraptor\\Velociraptor.exe\n")
	return b.String()
}

// TestReadClientCAReportsItsErrors: openHost used to swallow this in an IIFE
// (`caPEM, _ := func() ...`), so a missing or unparseable client config
// produced a nil CA and the probe failed ten minutes later as a bare E50.
func TestReadClientCAReportsItsErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := readClientCA(dir); err == nil {
		t.Fatal("a missing velociraptor.client.yaml must be an error")
	}
	if err := os.MkdirAll(filepath.Join(dir, "payload"), 0o700); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "payload", "velociraptor.client.yaml")
	if err := os.WriteFile(bad, []byte("Client:\n  nonce: abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readClientCA(dir); err == nil || !strings.Contains(err.Error(), "ca_certificate") {
		t.Fatalf("a client config with no CA must be an error naming ca_certificate, got %v", err)
	}
	if err := os.WriteFile(bad, []byte(clientYAML(testCAPEM)), 0o600); err != nil {
		t.Fatal(err)
	}
	pem, err := readClientCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(pem), "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("got %q", pem)
	}
}

func connectHost(t *testing.T, caPEM string) *host {
	t.Helper()
	fp, err := velo.CAFingerprint([]byte(testCAPEM))
	if err != nil {
		t.Fatal(err)
	}
	inc := &config.Incident{Server: config.Server{IP: "203.0.113.10", Port: 443, CASHA256: fp}}
	raw := []byte(`{"case_id":"C1"}`)
	pub, priv, err := sign.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return &host{inc: inc, raw: raw, sig: sign.Sign(priv, raw), pub: pub, caPEM: []byte(caPEM)}
}

// TestVerifyKitForConnect: the reboot-resume path (cmdConnect) never ran
// stage.Preflight, so nothing re-checked incident.json's signature or that
// the shipped client config belongs to the signed server before it started
// probing and started Velociraptor.
func TestVerifyKitForConnect(t *testing.T) {
	h := connectHost(t, testCAPEM)
	if err := verifyKitForConnect(h); err != nil {
		t.Fatalf("a well-formed kit must verify: %v", err)
	}

	bad := connectHost(t, testCAPEM)
	bad.sig[0] ^= 0xff
	if err := verifyKitForConnect(bad); err == nil || !strings.HasPrefix(err.Error(), "E11") {
		t.Fatalf("want E11 for a broken signature, got %v", err)
	}

	other := connectHost(t, otherCAPEM)
	if err := verifyKitForConnect(other); err == nil || !strings.HasPrefix(err.Error(), "E18") {
		t.Fatalf("want E18 for a client config from another server, got %v", err)
	}

	none := connectHost(t, "not a certificate")
	if err := verifyKitForConnect(none); err == nil || !strings.HasPrefix(err.Error(), "E18") {
		t.Fatalf("want E18 for an unreadable CA, got %v", err)
	}
}

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
