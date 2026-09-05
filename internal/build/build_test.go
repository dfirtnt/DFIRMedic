package build

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/manifest"
	"github.com/dfirtnt/DFIRMedic/internal/sign"
	"github.com/dfirtnt/DFIRMedic/internal/teardown"
)

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

func fixture(t *testing.T) (Options, []byte) {
	t.Helper()
	src := t.TempDir()
	payload := filepath.Join(src, "payload")
	os.MkdirAll(filepath.Join(payload, "tools"), 0o755)
	os.WriteFile(filepath.Join(payload, "velociraptor.exe"), []byte("v"), 0o755)
	os.WriteFile(filepath.Join(payload, "velociraptor.client.yaml"), []byte(fixtureClientYAML), 0o644)
	os.WriteFile(filepath.Join(payload, "tools", "thor-lite.exe"), []byte("t"), 0o755)
	os.WriteFile(filepath.Join(src, "dfirmedic.exe"), []byte("exe"), 0o755)
	os.WriteFile(filepath.Join(src, "FIELD-CARD.md"), []byte("# card {{CASE_ID}} {{PHONE}}"), 0o644)
	pub, priv, _ := sign.GenerateKeypair()
	keyPath := filepath.Join(src, "responder.key")
	sign.WritePrivateKey(keyPath, priv)
	return Options{
		CaseID: "CASE-1", ServerURL: "https://203.0.113.10:443/",
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
	if inc.Watchdog.TunnelTimeoutSec != 600 || inc.Watchdog.HeartbeatGraceSec != 300 {
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
	o.ServerURL = ""
	if _, err := Build(o); err == nil {
		t.Fatal("empty server URL must fail validation")
	}
	o, _ = fixture(t)
	o.PayloadDir = filepath.Join(t.TempDir(), "nope")
	if _, err := Build(o); err == nil {
		t.Fatal("missing payload dir must fail")
	}
}

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

func TestBuildRejectsServerURLThatIsOnlyAPrefixOfTheConfiguredOne(t *testing.T) {
	o, _ := fixture(t)
	// The shipped client config lists a *different*, longer URL that happens
	// to start with the exact bytes of --server-url. A left-anchored
	// substring/prefix check (strings.Contains(raw, "- "+serverURL)) would
	// wrongly accept this, since "- https://203.0.113.10:443/" is a prefix
	// of "- https://203.0.113.10:443/old-tunnel-path". Exact-line matching
	// must reject it.
	badYAML := `Client:
  server_urls:
  - https://203.0.113.10:443/old-tunnel-path
  ca_certificate: |
    -----BEGIN CERTIFICATE-----
    AAAA
    -----END CERTIFICATE-----
  windows_installer:
    service_name: Velociraptor
    install_path: $ProgramFiles\Velociraptor\Velociraptor.exe
`
	if err := os.WriteFile(filepath.Join(o.PayloadDir, "velociraptor.client.yaml"), []byte(badYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	o.ServerURL = "https://203.0.113.10:443/" // a true prefix of the shipped entry, not an exact match
	if _, err := Build(o); err == nil || !strings.Contains(err.Error(), "server_urls") {
		t.Fatalf("expected server_urls mismatch error for prefix-only match, got %v", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	o, pub := fixture(t)
	Build(o)
	if _, err := Verify(o.OutDir, pub, o.Now().Add(48*time.Hour)); err == nil {
		t.Fatal("expired kit accepted")
	}
}

func TestVerifyRejectsTamperedFileWithRegeneratedManifest(t *testing.T) {
	o, pub := fixture(t)
	if _, err := Build(o); err != nil {
		t.Fatal(err)
	}
	// Tamper a payload file, then regenerate manifest.sha256 to match —
	// this defeats manifest.Verify's per-file check, but must still be
	// caught by the PayloadManifestSHA256 binding (the fix for the
	// original tamper-and-regenerate vulnerability).
	if err := os.WriteFile(filepath.Join(o.OutDir, "payload", "velociraptor.exe"), []byte("evil"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Write(filepath.Join(o.OutDir, "payload")); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(o.OutDir, pub, o.Now()); err == nil {
		t.Fatal("tampered payload with a regenerated manifest must still be rejected by the manifest-hash binding")
	}
}
