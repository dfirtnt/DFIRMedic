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
  "breakglass_code_hash": "sha256:0000",
  "payload_manifest_sha256": "sha256:placeholder"
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

func TestValidateRejectsMissingPayloadManifestHash(t *testing.T) {
	inc, _, _ := Load(write(t, sample))
	inc.PayloadManifestSHA256 = ""
	if err := inc.Validate(inc.CreatedUTC); err == nil {
		t.Fatal("expected payload_manifest_sha256 required error")
	}
}

func TestValidateAcceptsSample(t *testing.T) {
	inc, _, _ := Load(write(t, sample))
	if err := inc.Validate(inc.CreatedUTC.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}
