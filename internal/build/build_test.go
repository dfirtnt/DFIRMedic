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
