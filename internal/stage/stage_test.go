package stage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	"github.com/dfirtnt/DFIRMedic/internal/ui"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

const incJSON = `{"schema":2,"case_id":"C1","created_utc":"2026-09-04T22:00:00Z","expires_utc":"2026-09-05T22:00:00Z",
"server":{"url":"https://203.0.113.10:443/","ip":"203.0.113.10","port":443,"ca_sha256":"__CA_HASH_PLACEHOLDER__"},
"velociraptor":{"config_file":"payload/velociraptor.client.yaml","install_path":"C:\\Program Files\\Velociraptor\\Velociraptor.exe","service_name":"Velociraptor"},
"firewall":{"dns_fallback_to_dhcp":false},
"watchdog":{"tunnel_timeout_sec":600,"heartbeat_grace_sec":300},
"contact":{"phone":"+1555","name":"Alex"},"breakglass_code_hash":"sha256:x",
"payload_manifest_sha256":"__MANIFEST_HASH_PLACEHOLDER__"}`

// fixtureClientYAML mirrors Task 6's build_test.go fixture: a minimal but
// well-formed velociraptor.client.yaml with a CA certificate and
// windows_installer block, exactly what velo.ExtractCA/ExtractInstallPath
// expect to find in a real client config.

// testCAPEM and otherCAPEM are real self-signed CA certificates: the
// fixtures used to carry a fake `AAAA` body, which velo.CAFingerprint now
// rejects because it parses the DER instead of hashing whatever it finds.
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

const fixtureClientYAML = `Client:
  server_urls:
  - https://203.0.113.10:443/
  ca_certificate: |
    -----BEGIN CERTIFICATE-----
    MIIBazCCARGgAwIBAgIBATAKBggqhkjOPQQDAjAcMRowGAYDVQQDExFERklSTWVk
    aWMgVGVzdCBDQTAgFw0yMDAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowHDEa
    MBgGA1UEAxMRREZJUk1lZGljIFRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMB
    BwNCAAQ0VadvyKRtY034nyXHgOvhAmYhcyP05/TRHMvnyND4eSspprUn4Bpcnnqo
    3zl3JZj1Rg2eIgU6CWzDlO2KNMxno0IwQDAOBgNVHQ8BAf8EBAMCAoQwDwYDVR0T
    AQH/BAUwAwEB/zAdBgNVHQ4EFgQUEx30H3MgsQ/gsIm4ZW8qV84sadAwCgYIKoZI
    zj0EAwIDSAAwRQIhAPYvQ+VMiWEcdW2P2EByp8HoxtAY5CTQPHfIp79XY8ybAiA4
    bYDmgS7eArLPZlqmoHGKLAvkIdcsXHITekEY+v+4Fw==
    -----END CERTIFICATE-----
  windows_installer:
    service_name: Velociraptor
    install_path: $ProgramFiles\Velociraptor\Velociraptor.exe
`

// otherClientYAML is the same config carrying a different (also real) CA.
var otherClientYAML = strings.Replace(fixtureClientYAML, indentPEM(testCAPEM), indentPEM(otherCAPEM), 1)

// indentPEM lines a PEM block up under `ca_certificate: |`.
func indentPEM(p string) string {
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimRight(p, "\n"), "\n") {
		b.WriteString("    " + l + "\n")
	}
	return b.String()
}

// disableScript is the prefix of the DisableOtherRules sweep for case C1.
const disableScript = "$r = @(Get-NetFirewallRule -Enabled True | Where-Object { $_.Group -ne 'DFIRMedic-C1'"

func calledPS(f *runner.Fake, script string) bool {
	return f.Called("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

func psKey(f *runner.Fake, script string) string {
	return f.Key("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

// happyFake returns a fake whose responses describe an offline, clean host.
func happyFake() *runner.Fake {
	f := runner.NewFake()
	f.Responses[psKey(f, "Get-NetAdapter")] = runner.Result{Stdout: `[{"Name":"Wi-Fi","InterfaceDescription":"Intel","Status":"Disconnected"}]`}
	f.Responses[psKey(f, "Get-NetFirewallProfile")] = runner.Result{Stdout: `[{"Name":"Domain","Enabled":1,"DefaultInboundAction":4,"DefaultOutboundAction":2}]`}
	f.Responses[psKey(f, "Get-NetFirewallRule")] = runner.Result{Stdout: `[{"Name":"r1"}]`}
	f.Responses[psKey(f, disableScript)] = runner.Result{Stdout: `["Core Networking - DHCP-Out","EvilPersist"]`}
	f.Responses[f.Key("reg.exe", "query")] = runner.Result{Stdout: "    EditionID    REG_SZ    Professional\r\n"}
	f.Responses[f.Key("sc.exe", "query", "Velociraptor")] = runner.Result{ExitCode: 1060}
	f.Responses[f.Key("sc.exe", "query", "type=")] = runner.Result{Stdout: "SERVICE_NAME: Spooler\r\n"}
	f.Responses[f.Key("sc.exe", "qc", "Velociraptor")] = runner.Result{Stdout: "        BINARY_PATH_NAME   : \"C:\\Program Files\\Velociraptor\\Velociraptor.exe\" --config \"C:\\Program Files\\Velociraptor\\client.config.yaml\" service run\r\n"}
	return f
}

func deps(t *testing.T, f *runner.Fake, incText string) Deps {
	t.Helper()
	kit := t.TempDir()
	work := filepath.Join(t.TempDir(), "work")
	os.MkdirAll(filepath.Join(kit, "payload", "tools"), 0o755)
	os.WriteFile(filepath.Join(kit, "payload", "velociraptor.exe"), []byte("velo"), 0o755)
	os.WriteFile(filepath.Join(kit, "payload", "velociraptor.client.yaml"), []byte(fixtureClientYAML), 0o644)
	os.WriteFile(filepath.Join(kit, "payload", "tools", "thor-lite.exe"), []byte("thor"), 0o755)
	os.WriteFile(filepath.Join(kit, "dfirmedic.exe"), []byte("exe"), 0o755)
	if _, err := manifest.Write(filepath.Join(kit, "payload")); err != nil {
		t.Fatal(err)
	}
	manifestHash, err := manifest.HashFile(filepath.Join(kit, "payload", manifest.FileName))
	if err != nil {
		t.Fatal(err)
	}
	incText = strings.Replace(incText, "__MANIFEST_HASH_PLACEHOLDER__", "sha256:"+manifestHash, 1)
	caPEM, err := velo.ExtractCA([]byte(fixtureClientYAML))
	if err != nil {
		t.Fatal(err)
	}
	caFP, err := velo.CAFingerprint(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	incText = strings.Replace(incText, "__CA_HASH_PLACEHOLDER__", caFP, 1)
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
		Velo:     velo.Client{R: f, ExePath: filepath.Join(work, "payload", "velociraptor.exe"), ConfigPath: filepath.Join(work, "payload", "velociraptor.client.yaml")},
		Now:      func() time.Time { return time.Date(2026, 9, 4, 23, 0, 0, 0, time.UTC) },
		Elevated: func() bool { return true },
	}
}

// resign mirrors the tail of deps: it recomputes the payload manifest hash
// (the caller has just rewritten a payload file and re-run manifest.Write),
// rewrites incident.json's payload_manifest_sha256 to match, re-signs with a
// fresh keypair, and returns Deps updated to match. Used by tests that
// tamper with kit contents after the kit has already been built by deps.
func resign(t *testing.T, d Deps) Deps {
	t.Helper()
	manifestHash, err := manifest.HashFile(filepath.Join(d.KitDir, "payload", manifest.FileName))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(d.KitDir, "incident.json"))
	if err != nil {
		t.Fatal(err)
	}
	newText := strings.Replace(string(raw), d.Inc.PayloadManifestSHA256, "sha256:"+manifestHash, 1)
	pub, priv, _ := sign.GenerateKeypair()
	if err := os.WriteFile(filepath.Join(d.KitDir, "incident.json"), []byte(newText), 0o600); err != nil {
		t.Fatal(err)
	}
	inc, rawNew, err := config.Load(filepath.Join(d.KitDir, "incident.json"))
	if err != nil {
		t.Fatal(err)
	}
	sig := sign.Sign(priv, rawNew)
	sign.WriteSig(filepath.Join(d.KitDir, "incident.json.sig"), sig)
	d.Inc, d.RawConfig, d.Sig, d.PubKey = inc, rawNew, sig, pub
	return d
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

func TestPreflightRefusesTamperedManifestHash(t *testing.T) {
	d := deps(t, happyFake(), incJSON)
	d.Inc.PayloadManifestSHA256 = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if err := Preflight(context.Background(), d); err == nil || !strings.Contains(err.Error(), "E17") {
		t.Fatalf("want E17, got %v", err)
	}
}

func TestPreflightRefusesExistingInstall(t *testing.T) {
	f := happyFake()
	f.Responses[f.Key("sc.exe", "query", "Velociraptor")] = runner.Result{Stdout: "SERVICE_NAME: Velociraptor"}
	if err := Preflight(context.Background(), deps(t, f, incJSON)); err == nil || !strings.Contains(err.Error(), "E16") {
		t.Fatalf("want E16, got %v", err)
	}
}

func TestPreflightNotElevated(t *testing.T) {
	d := deps(t, happyFake(), incJSON)
	d.Elevated = func() bool { return false }
	if err := Preflight(context.Background(), d); err == nil || !strings.Contains(err.Error(), "E10") {
		t.Fatalf("want E10, got %v", err)
	}
}

func TestPreflightRefusesExpiredConfig(t *testing.T) {
	f := happyFake()
	inc := strings.Replace(incJSON, `"expires_utc":"2026-09-05T22:00:00Z"`, `"expires_utc":"2020-01-01T00:00:00Z"`, 1)
	if err := Preflight(context.Background(), deps(t, f, inc)); err == nil || !strings.Contains(err.Error(), "E12") {
		t.Fatalf("want E12, got %v", err)
	}
}

// TestTakeBaselineCopiesRecoveryFilesBeforeInstall guards the fix for a real
// gap: breakglass/teardown load their config from --workdir only, with no
// kit fallback, so dfirmedic.exe/incident.json/incident.json.sig must exist
// there before the failure-prone payload copy in Install ever runs — not
// only after a fully successful Run().
func TestTakeBaselineCopiesRecoveryFilesBeforeInstall(t *testing.T) {
	f := happyFake()
	d := deps(t, f, incJSON)
	if _, err := TakeBaseline(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"dfirmedic.exe", "incident.json", "incident.json.sig"} {
		if _, err := os.Stat(filepath.Join(d.WorkDir, p)); err != nil {
			t.Fatalf("missing %s in workdir after TakeBaseline alone: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(d.WorkDir, "payload")); err == nil {
		t.Fatal("payload/ must not exist yet — it's Install's job, not TakeBaseline's; a test this loose would pass even if the recovery-file copy moved back into Install")
	}
}

func TestQuarantineRollsBackByImportingBaselinePolicy(t *testing.T) {
	f := happyFake()
	f.Responses[psKey(f, "New-NetFirewallRule -Group 'DFIRMedic-C1' -DisplayName 'DFIRMedic-C1: dhcp-out'")] = runner.Result{ExitCode: 1, Stderr: "nope"}
	d := deps(t, f, incJSON)
	base, err := TakeBaseline(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	err = Quarantine(context.Background(), d, base)
	if err == nil || !strings.Contains(err.Error(), "E30") {
		t.Fatalf("want E30, got %v", err)
	}
	if !f.Called("netsh.exe", "advfirewall", "import", filepath.Join(d.WorkDir, "firewall-original.wfw")) {
		t.Fatalf("rollback must import the exported baseline policy:\n%v", f.Calls)
	}
	if calledPS(f, "Remove-NetFirewallRule -Group 'DFIRMedic-C1' -ErrorAction SilentlyContinue") {
		t.Fatal("piecewise fallback must not run when the import succeeded")
	}
}

func TestQuarantineRollsBackWhenDisableSweepFails(t *testing.T) {
	f := happyFake()
	f.Errors[psKey(f, disableScript)] = errors.New("access denied")
	d := deps(t, f, incJSON)
	base, err := TakeBaseline(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	err = Quarantine(context.Background(), d, base)
	if err == nil || !strings.Contains(err.Error(), "E30") || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("want E30 wrapping the sweep error, got %v", err)
	}
	if calledPS(f, "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled 'True' -DefaultInboundAction 'Block' -DefaultOutboundAction 'Block'") {
		t.Fatal("defaults must not be flipped when the sweep failed")
	}
	if !f.Called("netsh.exe", "advfirewall", "import", filepath.Join(d.WorkDir, "firewall-original.wfw")) {
		t.Fatal("rollback must import the baseline policy")
	}
}

func TestQuarantineRollbackFallsBackWhenImportFails(t *testing.T) {
	f := happyFake()
	f.Responses[psKey(f, "Set-NetFirewallProfile -Profile Domain,Private,Public")] = runner.Result{ExitCode: 1, Stderr: "nope"}
	f.Errors[f.Key("netsh.exe", "advfirewall", "import")] = errors.New("import broke")
	d := deps(t, f, incJSON)
	base, err := TakeBaseline(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	err = Quarantine(context.Background(), d, base)
	if err == nil || !strings.Contains(err.Error(), "E30") || strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("fallback succeeded, so this must be a clean E30: %v", err)
	}
	for _, want := range []string{
		"Remove-NetFirewallRule -Group 'DFIRMedic-C1' -ErrorAction SilentlyContinue",
		"Set-NetFirewallProfile -Profile 'Domain' -Enabled 'True' -DefaultInboundAction 'Block' -DefaultOutboundAction 'Allow'",
		"Enable-NetFirewallRule -Name 'Core Networking - DHCP-Out','EvilPersist'",
	} {
		if !calledPS(f, want) {
			t.Fatalf("fallback missing %q in:\n%v", want, f.Calls)
		}
	}
}

func TestQuarantineReportsFailedRollback(t *testing.T) {
	f := happyFake()
	f.Responses[psKey(f, "New-NetFirewallRule -Group 'DFIRMedic-C1' -DisplayName 'DFIRMedic-C1: dhcp-out'")] = runner.Result{ExitCode: 1, Stderr: "nope"}
	f.Errors[f.Key("netsh.exe", "advfirewall", "import")] = errors.New("import broke")
	f.Errors[psKey(f, "Remove-NetFirewallRule -Group 'DFIRMedic-C1' -ErrorAction SilentlyContinue")] = errors.New("access denied")
	f.Errors[psKey(f, "Set-NetFirewallProfile -Profile 'Domain' -Enabled 'True' -DefaultInboundAction 'Block' -DefaultOutboundAction 'Allow'")] = errors.New("access denied")
	d := deps(t, f, incJSON)
	base, err := TakeBaseline(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	err = Quarantine(context.Background(), d, base)
	if err == nil || !strings.Contains(err.Error(), "rollback failed") || !strings.Contains(err.Error(), "import broke") {
		t.Fatalf("want rollback-failed error naming the import failure, got %v", err)
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
	iProf := strings.Index(all, "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled 'True' -DefaultInboundAction 'Block' -DefaultOutboundAction 'Block'")
	iVelo := strings.Index(all, "service install")
	iTask := strings.Index(all, "schtasks.exe /Create")
	if !(iRule < iProf && iProf < iVelo && iVelo < iTask) {
		t.Fatalf("bad order:\n%s", all)
	}
	if len(d.Man.Rules) != 9 { // dhcp x4, nd x2 (QuarantineRules) + 3 server egress rules (ServerRules)
		t.Fatalf("manifest rules (%d): %v", len(d.Man.Rules), d.Man.Rules)
	}
	// Pre-existing rules are disabled after the group exists (so the
	// disable sweep can skip it) and before the default-deny flip.
	iDisable := strings.Index(all, disableScript)
	iLastRule := strings.LastIndex(all, "New-NetFirewallRule")
	if iDisable < 0 || !(iLastRule < iDisable && iDisable < iProf) {
		t.Fatalf("disable-others must run between the last rule add and the profile flip:\n%s", all)
	}
	if len(d.Man.DisabledRules) != 2 || d.Man.DisabledRules[1] != "EvilPersist" {
		t.Fatalf("manifest must record which rules were disabled: %v", d.Man.DisabledRules)
	}
	// The victim reaches exactly one destination, by three named programs:
	// the installed Velociraptor service, the not-yet-run payload copy
	// `service install` uses once, and the orchestrator's TLS probe.
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
	// workdir populated, service points at workdir copies
	for _, p := range []string{"manifest.json", "baseline.json", "dfirmedic.exe", "incident.json", "incident.json.sig", filepath.Join("payload", "velociraptor.exe"), filepath.Join("payload", "tools", "thor-lite.exe")} {
		if _, err := os.Stat(filepath.Join(d.WorkDir, p)); err != nil {
			t.Fatalf("missing %s in workdir", p)
		}
	}
	if !f.Called("netsh.exe", "advfirewall", "export", filepath.Join(d.WorkDir, "firewall-original.wfw")) {
		t.Fatal("firewall export must be called with the workdir path")
	}
	if !strings.Contains(all, filepath.Join(d.WorkDir, "payload", "velociraptor.exe")+" --config") {
		t.Fatal("velociraptor must be installed from the workdir copy")
	}
	if strings.Contains(all, "fDenyTSConnections") {
		t.Fatal("RDP must not be enabled when the flag is false")
	}
}

func TestTakeBaselineCapturesVolatileState(t *testing.T) {
	f := happyFake()
	f.Responses[f.Key("netstat.exe", "-anob")] = runner.Result{Stdout: "TCP 0.0.0.0:445 LISTENING 4\r\n"}
	f.Responses[f.Key("ipconfig.exe", "/displaydns")] = runner.Result{Stdout: "evil.example\r\n"}
	d := deps(t, f, incJSON)
	b, err := TakeBaseline(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(d.WorkDir, "volatile")
	want := []string{"processes.json", "tasklist.csv", "netstat.txt", "dnscache.txt", "ipconfig.txt", "arp.txt", "routes.txt", "sessions.txt", "drivers.csv"}
	for _, name := range want {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("missing volatile/%s: %v", name, err)
		}
		if _, ok := b.Volatile[name]; !ok {
			t.Fatalf("baseline.volatile missing %s: %v", name, b.Volatile)
		}
	}
	got, _ := os.ReadFile(filepath.Join(dir, "netstat.txt"))
	if string(got) != "TCP 0.0.0.0:445 LISTENING 4\r\n" {
		t.Fatalf("netstat.txt = %q", got)
	}
	sum := sha256.Sum256(got)
	if b.Volatile["netstat.txt"].SHA256 != hex.EncodeToString(sum[:]) || b.Volatile["netstat.txt"].Error != "" {
		t.Fatalf("netstat.txt entry = %+v", b.Volatile["netstat.txt"])
	}
	// The hashes must reach the manifest so the files are bound to the signed evidence.
	if !strings.Contains(string(d.Man.Baseline), hex.EncodeToString(sum[:])) {
		t.Fatal("manifest baseline does not carry the volatile file hash")
	}
	for _, argv := range [][]string{
		{"tasklist.exe", "/v", "/fo", "csv"}, {"netstat.exe", "-anob"}, {"ipconfig.exe", "/displaydns"},
		{"ipconfig.exe", "/all"}, {"arp.exe", "-a"}, {"route.exe", "print"}, {"query.exe", "user"},
		{"driverquery.exe", "/v", "/fo", "csv"},
	} {
		if !f.Called(argv[0], argv[1:]...) {
			t.Fatalf("expected %v to be run", argv)
		}
	}
	all := ""
	for _, c := range f.Calls {
		all += strings.Join(c, " ") + "\n"
	}
	if !strings.Contains(all, "Win32_Process") {
		t.Fatalf("process tree must come from Win32_Process:\n%s", all)
	}
	// Volatile state is captured before the firewall export: it is the most
	// perishable thing in BASELINE and nothing should run ahead of it.
	if i, j := strings.Index(all, "netstat.exe"), strings.Index(all, "netsh.exe advfirewall export"); !(i >= 0 && j >= 0 && i < j) {
		t.Fatalf("volatile capture must precede the firewall export:\n%s", all)
	}
}

func TestVolatileCaptureFailureIsNonFatal(t *testing.T) {
	f := happyFake()
	f.Responses[f.Key("query.exe", "user")] = runner.Result{Stdout: "partial\r\n", ExitCode: 1}
	f.Errors[f.Key("query.exe", "user")] = errors.New("'query.exe' is not recognized")
	d := deps(t, f, incJSON)
	b, err := TakeBaseline(context.Background(), d)
	if err != nil {
		t.Fatalf("one failed volatile command must not abort staging: %v", err)
	}
	e := b.Volatile["sessions.txt"]
	if !strings.Contains(e.Error, "not recognized") {
		t.Fatalf("failure must be recorded next to the file: %+v", e)
	}
	got, _ := os.ReadFile(filepath.Join(d.WorkDir, "volatile", "sessions.txt"))
	if string(got) != "partial\r\n" {
		t.Fatalf("partial output must still be written, got %q", got)
	}
	if b.Volatile["netstat.txt"].Error != "" {
		t.Fatal("unrelated captures must be unaffected")
	}
}

// TestPreflightRefusesClientConfigFromAnotherServer guards E18: the shipped
// velociraptor.client.yaml's CA must match the fingerprint incident.json was
// signed with. Swapping the client config (e.g. an attacker repointing the
// kit at a rogue server, or a build mistake) must fail even though the
// payload manifest and incident.json signature are both freshly (and
// correctly) re-done to cover the swap.
func TestPreflightRefusesClientConfigFromAnotherServer(t *testing.T) {
	f := happyFake()
	d := deps(t, f, incJSON)
	os.WriteFile(filepath.Join(d.KitDir, "payload", "velociraptor.client.yaml"), []byte(otherClientYAML), 0o644)
	manifest.Write(filepath.Join(d.KitDir, "payload")) // keep E13/E17 out of the way
	// re-sign: incident.json's manifest hash changed
	d = resign(t, d)
	err := Preflight(context.Background(), d)
	if err == nil || !strings.HasPrefix(err.Error(), "E18") {
		t.Fatalf("want E18, got %v", err)
	}
}

// TestInstallRefusesUnexpectedServicePath guards E41: if `service install`
// registers the Velociraptor service from a path other than what
// incident.json's install_path (and therefore the firewall egress rule)
// names, the client can start but will be silently blocked by the
// firewall — staging must fail loudly instead.
func TestInstallRefusesUnexpectedServicePath(t *testing.T) {
	f := happyFake()
	f.Responses[f.Key("sc.exe", "qc", "Velociraptor")] = runner.Result{Stdout: "        BINARY_PATH_NAME   : \"C:\\Elsewhere\\Velociraptor.exe\" service run\r\n"}
	d := deps(t, f, incJSON)
	err := Install(context.Background(), d)
	if err == nil || !strings.HasPrefix(err.Error(), "E41") {
		t.Fatalf("want E41, got %v", err)
	}
}
