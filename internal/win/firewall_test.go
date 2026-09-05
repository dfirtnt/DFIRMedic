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
