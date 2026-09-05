package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
	if inc.CaseID != "CASE-2026-0042" || inc.Server.IP != "203.0.113.10" {
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
	inc.Server.IP = ""
	if err := inc.Validate(inc.CreatedUTC); err == nil {
		t.Fatal("expected missing server.ip error")
	}
	inc, _, _ = Load(write(t, sample))
	inc.Velociraptor.ConfigFile = ""
	if err := inc.Validate(inc.CreatedUTC); err == nil {
		t.Fatal("expected missing velociraptor.config_file error")
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

func TestValidateRejectsSchema1(t *testing.T) {
	inc, _, _ := Load(write(t, strings.Replace(sample, `"schema": 2`, `"schema": 1`, 1)))
	err := inc.Validate(time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "schema 1 unsupported") {
		t.Fatalf("want schema error, got %v", err)
	}
}

func TestValidateRejectsBadServer(t *testing.T) {
	cases := map[string]string{
		"hostname ip": strings.Replace(sample, `"ip":"203.0.113.10"`, `"ip":"velo.example.com"`, 1),
		"port zero":   strings.Replace(sample, `"port":443`, `"port":0`, 1),
		"bad ca hash": strings.Replace(sample, `"ca_sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"`, `"ca_sha256":"abc"`, 1),
		"no install":  strings.Replace(sample, `"install_path":"C:\\Program Files\\Velociraptor\\Velociraptor.exe"`, `"install_path":""`, 1),
		"no service":  strings.Replace(sample, `"service_name":"Velociraptor"`, `"service_name":""`, 1),
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

// TestValidateRejectsShallowInstallPath guards the teardown blast radius:
// teardown deletes the *parent directory* of install_path, so a path whose
// parent is a drive root (or which is not an absolute Windows path at all)
// must never make it out of the responder's build.
func TestValidateRejectsShallowInstallPath(t *testing.T) {
	for name, path := range map[string]string{
		"drive root file": `C:\\Velociraptor.exe`,
		"drive root":      `C:\\`,
		"bare file name":  `Velociraptor.exe`,
		"unix path":       `/usr/local/bin/velociraptor`,
	} {
		s := strings.Replace(sample, `"install_path":"C:\\Program Files\\Velociraptor\\Velociraptor.exe"`, `"install_path":"`+path+`"`, 1)
		inc, _, err := Load(write(t, s))
		if err != nil {
			t.Fatalf("%s: load: %v", name, err)
		}
		err = inc.Validate(time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC))
		if err == nil {
			t.Fatalf("%s: install_path %q accepted", name, path)
		}
		if !strings.Contains(err.Error(), "windows_installer.install_path") {
			t.Fatalf("%s: error must name windows_installer.install_path, got %v", name, err)
		}
	}
}
