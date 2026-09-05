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
