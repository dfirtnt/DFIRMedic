// Package win wraps the Windows tools the orchestrator drives. Every function
// builds a command and hands it to a runner.Runner; nothing here executes
// directly, so all of it is testable with runner.Fake on any OS.
package win

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/dfirtnt/DFIRMedic/internal/runner"
)

// SvchostPath is the host process for the Dnscache and Dhcp services. The
// built-in Core Networking rules use exactly this env-var form.
const SvchostPath = `%SystemRoot%\System32\svchost.exe`

var icmpTypeList = regexp.MustCompile(`^[0-9]+(,[0-9]+)*$`)

type Firewall struct{ R runner.Runner }

type ProfileState struct {
	Name                  string
	Enabled               bool
	DefaultInboundAction  string
	DefaultOutboundAction string
}

func psq(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// psqList quotes a comma-separated value as a PowerShell string array
// ('a','b'). New-NetFirewallRule's -RemoteAddress is string[]; a single
// literal containing a comma is rejected as an invalid address.
func psqList(s string) string {
	parts := strings.Split(s, ",")
	for i, p := range parts {
		parts[i] = psq(strings.TrimSpace(p))
	}
	return strings.Join(parts, ",")
}

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
	_, err := runner.PS(ctx, f.R, fmt.Sprintf("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled %s -DefaultInboundAction %s -DefaultOutboundAction %s", psq(en), psq(inbound), psq(outbound)))
	return err
}

func (f Firewall) RestoreProfiles(ctx context.Context, states []ProfileState) error {
	for _, s := range states {
		en := "False"
		if s.Enabled {
			en = "True"
		}
		if _, err := runner.PS(ctx, f.R, fmt.Sprintf("Set-NetFirewallProfile -Profile %s -Enabled %s -DefaultInboundAction %s -DefaultOutboundAction %s", psq(s.Name), psq(en), psq(s.DefaultInboundAction), psq(s.DefaultOutboundAction))); err != nil {
			return err
		}
	}
	return nil
}

type Rule struct {
	Name          string
	Direction     string // Inbound | Outbound
	Program       string
	Service       string // Windows service short name; narrows Program to that service's svchost instance
	Protocol      string // TCP | UDP | ICMPv6 | ""
	IcmpType      string // comma-separated numeric ICMP types, ICMPv6 only
	RemotePort    string
	LocalPort     string
	RemoteAddress string
}

func (f Firewall) AddRule(ctx context.Context, group string, r Rule) (string, error) {
	if r.IcmpType != "" && !icmpTypeList.MatchString(r.IcmpType) {
		return "", fmt.Errorf("rule %s: IcmpType %q is not a numeric list", r.Name, r.IcmpType)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "New-NetFirewallRule -Group %s -DisplayName %s -Direction %s -Action Allow", psq(group), psq(group+": "+r.Name), psq(r.Direction))
	if r.Program != "" {
		fmt.Fprintf(&b, " -Program %s", psq(r.Program))
	}
	if r.Service != "" {
		fmt.Fprintf(&b, " -Service %s", psq(r.Service))
	}
	if r.Protocol != "" {
		fmt.Fprintf(&b, " -Protocol %s", psq(r.Protocol))
	}
	if r.IcmpType != "" {
		// Validated above as digits and commas only, so it is safe unquoted;
		// quoting it would hand PowerShell a single string instead of a list.
		fmt.Fprintf(&b, " -IcmpType %s", r.IcmpType)
	}
	if r.RemotePort != "" {
		fmt.Fprintf(&b, " -RemotePort %s", psq(r.RemotePort))
	}
	if r.LocalPort != "" {
		fmt.Fprintf(&b, " -LocalPort %s", psq(r.LocalPort))
	}
	if r.RemoteAddress != "" {
		fmt.Fprintf(&b, " -RemoteAddress %s", psqList(r.RemoteAddress))
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

// DisableOtherRules disables every enabled rule outside group and returns
// their names. Windows evaluates enabled allow rules regardless of the
// profile default action, so flipping the default to Block alone leaves
// every pre-existing allow rule (built-in, third-party, or attacker-planted)
// matching. Import of the exported policy re-enables them at teardown.
func (f Firewall) DisableOtherRules(ctx context.Context, group string) ([]string, error) {
	script := fmt.Sprintf("$r = @(Get-NetFirewallRule -Enabled True | Where-Object { $_.Group -ne %s }); $r | Disable-NetFirewallRule; ConvertTo-Json -InputObject @($r.Name) -Compress", psq(group))
	res, err := runner.PS(ctx, f.R, script)
	if err != nil {
		return nil, err
	}
	txt := strings.TrimSpace(res.Stdout)
	if txt == "" {
		return nil, nil
	}
	var names []string
	if err := json.Unmarshal([]byte(txt), &names); err != nil {
		return nil, fmt.Errorf("parse disabled rule names: %w", err)
	}
	return names, nil
}

// EnableRules is the counterpart to DisableOtherRules for the rollback path.
func (f Firewall) EnableRules(ctx context.Context, names []string) error {
	if len(names) == 0 {
		return nil
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		if n == "" {
			return errors.New("empty rule name")
		}
		quoted[i] = psq(n)
	}
	_, err := runner.PS(ctx, f.R, "Enable-NetFirewallRule -Name "+strings.Join(quoted, ","))
	return err
}

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
