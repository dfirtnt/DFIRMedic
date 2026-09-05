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
		if r.LocalPort == "3389" {
			t.Fatalf("no RDP inbound rule without the flag: %+v", r)
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
	for _, want := range []string{"New-NetFirewallRule", "-Group 'DFIRMedic-C1'", "-Direction 'Outbound'", "-Action Allow", `-Program 'C:\Program Files\Tailscale\tailscaled.exe'`} {
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
	for _, want := range []string{"Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled 'True' -DefaultInboundAction 'Block' -DefaultOutboundAction 'Block'", "Remove-NetFirewallRule -Group 'DFIRMedic-C1'"} {
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

func TestRestoreProfilesQuotesValues(t *testing.T) {
	f := runner.NewFake()
	fw := Firewall{R: f}
	err := fw.RestoreProfiles(context.Background(), []ProfileState{
		{Name: "Domain'; Start-Process notepad.exe; '", Enabled: true, DefaultInboundAction: "Block", DefaultOutboundAction: "Allow"},
	})
	if err != nil {
		t.Fatal(err)
	}
	all := ""
	for _, c := range f.Calls {
		all += strings.Join(c, " ") + "\n"
	}
	if strings.Contains(all, "Start-Process") && !strings.Contains(all, "''; Start-Process notepad.exe; ''") {
		t.Fatalf("malicious profile name must be neutralized inside a quoted literal, got: %s", all)
	}
	if !strings.Contains(all, "-Profile 'Domain''; Start-Process notepad.exe; ''' -Enabled 'True'") {
		t.Fatalf("expected properly doubled-quote escaping, got: %s", all)
	}
}

func TestAddRuleQuotesRemoteAddress(t *testing.T) {
	f := runner.NewFake()
	fw := Firewall{R: f}
	txt, err := fw.AddRule(context.Background(), "G", Rule{
		Name: "x", Direction: "Outbound", RemoteAddress: "100.64.0.1'; Start-Process notepad.exe; '",
	})
	if err != nil {
		t.Fatal(err)
	}
	// The malicious value must be neutralized inside a quoted literal
	if strings.Contains(txt, "Start-Process") && !strings.Contains(txt, "Start-Process notepad.exe; '") {
		// Check that the single quotes are properly escaped (doubled)
		if !strings.Contains(txt, "'100.64.0.1''; Start-Process notepad.exe; '''") {
			t.Fatalf("malicious value must be neutralized via quote escaping, got: %s", txt)
		}
	}
	// Verify the -RemoteAddress parameter has proper quoting
	if !strings.Contains(txt, "-RemoteAddress '100.64.0.1''; Start-Process notepad.exe; '''") {
		t.Fatalf("expected properly doubled-quote escaping in -RemoteAddress, got: %s", txt)
	}
}

func TestAddRuleEmitsServiceAndIcmpType(t *testing.T) {
	f := runner.NewFake()
	fw := Firewall{R: f}
	txt, err := fw.AddRule(context.Background(), "G", Rule{
		Name: "dhcp-out", Direction: "Outbound", Program: SvchostPath, Service: "Dhcp", Protocol: "UDP", LocalPort: "68", RemotePort: "67",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`-Program '%SystemRoot%\System32\svchost.exe'`, "-Service 'Dhcp'", "-LocalPort '68'", "-RemotePort '67'"} {
		if !strings.Contains(txt, want) {
			t.Fatalf("missing %q in %s", want, txt)
		}
	}
	txt, err = fw.AddRule(context.Background(), "G", Rule{
		Name: "nd-out", Direction: "Outbound", Protocol: "ICMPv6", IcmpType: "133,135,136",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(txt, "-Protocol 'ICMPv6' -IcmpType 133,135,136") {
		t.Fatalf("icmp types must be emitted as a bare PowerShell list: %s", txt)
	}
}

func TestAddRuleRejectsNonNumericIcmpType(t *testing.T) {
	f := runner.NewFake()
	_, err := Firewall{R: f}.AddRule(context.Background(), "G", Rule{
		Name: "x", Direction: "Outbound", Protocol: "ICMPv6", IcmpType: "133; Start-Process notepad.exe",
	})
	if err == nil {
		t.Fatal("non-numeric IcmpType must be rejected before it reaches PowerShell")
	}
	if len(f.Calls) != 0 {
		t.Fatalf("nothing should run: %v", f.Calls)
	}
}

func TestQuarantineRulesScopeDNSToDnscache(t *testing.T) {
	rules := QuarantineRules([]string{"1.1.1.1"}, true, "")
	var seen int
	for _, r := range rules {
		if !strings.HasPrefix(r.Name, "dns-") {
			continue
		}
		seen++
		if r.Program != SvchostPath || r.Service != "Dnscache" {
			t.Fatalf("DNS rule must be scoped to the system resolver, not any process: %+v", r)
		}
	}
	if seen != 4 {
		t.Fatalf("expected pinned + dhcp-fallback udp/tcp rules, saw %d", seen)
	}
}

func TestQuarantineRulesIncludeDHCPClient(t *testing.T) {
	rules := QuarantineRules([]string{"1.1.1.1"}, false, "")
	want := map[string]Rule{
		"dhcp-out":   {Direction: "Outbound", Protocol: "UDP", LocalPort: "68", RemotePort: "67"},
		"dhcp-in":    {Direction: "Inbound", Protocol: "UDP", LocalPort: "68", RemotePort: "67"},
		"dhcpv6-out": {Direction: "Outbound", Protocol: "UDP", LocalPort: "546", RemotePort: "547"},
		"dhcpv6-in":  {Direction: "Inbound", Protocol: "UDP", LocalPort: "546", RemotePort: "547"},
	}
	for _, r := range rules {
		w, ok := want[r.Name]
		if !ok {
			continue
		}
		if r.Direction != w.Direction || r.Protocol != w.Protocol || r.LocalPort != w.LocalPort || r.RemotePort != w.RemotePort {
			t.Fatalf("%s: got %+v want %+v", r.Name, r, w)
		}
		if r.Program != SvchostPath || r.Service != "Dhcp" {
			t.Fatalf("%s must be scoped to the DHCP client service: %+v", r.Name, r)
		}
		delete(want, r.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing DHCP rules: %v (reconnect gets no address without them once pre-existing rules are disabled)", want)
	}
}

func TestQuarantineRulesIncludeIPv6NeighborDiscovery(t *testing.T) {
	rules := QuarantineRules([]string{"1.1.1.1"}, false, "")
	var out, in bool
	for _, r := range rules {
		if r.Protocol != "ICMPv6" {
			continue
		}
		if r.Program != "" || r.Service != "" {
			t.Fatalf("ND is kernel traffic, must not be program-scoped: %+v", r)
		}
		switch {
		case r.Direction == "Outbound" && r.IcmpType == "133,135,136":
			out = true
		case r.Direction == "Inbound" && r.IcmpType == "134,135,136":
			in = true
		default:
			t.Fatalf("unexpected ICMPv6 rule: %+v", r)
		}
	}
	if !out || !in {
		t.Fatalf("out=%v in=%v", out, in)
	}
}

func TestQuarantineRulesNoInboundBeyondDHCPAndNDWithoutRDP(t *testing.T) {
	for _, r := range QuarantineRules([]string{"1.1.1.1"}, false, "") {
		if r.Direction != "Inbound" {
			continue
		}
		if !strings.HasPrefix(r.Name, "dhcp") && r.Protocol != "ICMPv6" {
			t.Fatalf("unexpected inbound rule without RDP: %+v", r)
		}
	}
}

func TestDisableOtherRulesSkipsGroupAndReturnsNames(t *testing.T) {
	f := runner.NewFake()
	f.Responses["powershell.exe"] = runner.Result{Stdout: `["Core Networking - DHCP-Out","EvilPersist"]`}
	names, err := Firewall{R: f}.DisableOtherRules(context.Background(), "DFIRMedic-C1")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[1] != "EvilPersist" {
		t.Fatalf("names=%v", names)
	}
	script := f.Calls[0][len(f.Calls[0])-1]
	for _, want := range []string{"Get-NetFirewallRule -Enabled True", "$_.Group -ne 'DFIRMedic-C1'", "Disable-NetFirewallRule", "ConvertTo-Json -InputObject @($r.Name) -Compress"} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in %s", want, script)
		}
	}
}

func TestDisableOtherRulesHandlesNoneAndSingle(t *testing.T) {
	f := runner.NewFake()
	names, err := Firewall{R: f}.DisableOtherRules(context.Background(), "G")
	if err != nil || len(names) != 0 {
		t.Fatalf("empty stdout: names=%v err=%v", names, err)
	}
	f.Responses["powershell.exe"] = runner.Result{Stdout: `["only"]`}
	names, err = Firewall{R: f}.DisableOtherRules(context.Background(), "G")
	if err != nil || len(names) != 1 || names[0] != "only" {
		t.Fatalf("single: names=%v err=%v", names, err)
	}
}

func TestEnableRulesQuotesEachName(t *testing.T) {
	f := runner.NewFake()
	if err := (Firewall{R: f}).EnableRules(context.Background(), []string{"a'b", "c"}); err != nil {
		t.Fatal(err)
	}
	if len(f.Calls) != 1 {
		t.Fatalf("one PS call for all names, got %d", len(f.Calls))
	}
	script := f.Calls[0][len(f.Calls[0])-1]
	if !strings.Contains(script, "Enable-NetFirewallRule -Name 'a''b','c'") {
		t.Fatalf("got %s", script)
	}
	if err := (Firewall{R: runner.NewFake()}).EnableRules(context.Background(), nil); err != nil {
		t.Fatal("no names must be a no-op")
	}
}

// New-NetFirewallRule -RemoteAddress takes a string array. A single quoted
// string containing a comma is rejected by Windows as "The address is
// invalid" (seen on a real host, 2026-09-05), so multiple resolvers must be
// emitted as separate PowerShell string literals.
func TestAddRuleEmitsMultipleRemoteAddressesAsArray(t *testing.T) {
	f := runner.NewFake()
	fw := Firewall{R: f}
	txt, err := fw.AddRule(context.Background(), "G", Rule{Name: "dns-udp", Direction: "Outbound", RemoteAddress: "1.1.1.1,9.9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(txt, "-RemoteAddress '1.1.1.1','9.9.9.9' ") {
		t.Fatalf("multi-address must be a PowerShell array of quoted strings, got: %s", txt)
	}
	if strings.Contains(txt, "'1.1.1.1,9.9.9.9'") {
		t.Fatalf("comma-joined single string is rejected by Windows: %s", txt)
	}
	txt, _ = fw.AddRule(context.Background(), "G", Rule{Name: "one", Direction: "Outbound", RemoteAddress: "100.64.0.1"})
	if !strings.Contains(txt, "-RemoteAddress '100.64.0.1' ") {
		t.Fatalf("single address must stay a single literal: %s", txt)
	}
}

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
