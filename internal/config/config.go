// Package config loads and validates the per-incident incident.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"
)

type Incident struct {
	Schema                int       `json:"schema"`
	CaseID                string    `json:"case_id"`
	CreatedUTC            time.Time `json:"created_utc"`
	ExpiresUTC            time.Time `json:"expires_utc"`
	Tailscale             Tailscale `json:"tailscale"`
	Velociraptor          Velo      `json:"velociraptor"`
	Firewall              Firewall  `json:"firewall"`
	Watchdog              Watchdog  `json:"watchdog"`
	Contact               Contact   `json:"contact"`
	BreakglassCodeHash    string    `json:"breakglass_code_hash"`
	PayloadManifestSHA256 string    `json:"payload_manifest_sha256"`
}

type Tailscale struct {
	AuthKey            string `json:"authkey"`
	Hostname           string `json:"hostname"`
	ResponderNodeKey   string `json:"responder_node_key"`
	ResponderTailnetIP string `json:"responder_tailnet_ip"`
}

type Velo struct {
	ServerURL  string `json:"server_url"`
	ConfigFile string `json:"config_file"`
}

type Firewall struct {
	DNSResolvers          []string `json:"dns_resolvers"`
	AllowRDPFromResponder bool     `json:"allow_rdp_from_responder"`
	DNSFallbackToDHCP     bool     `json:"dns_fallback_to_dhcp"`
}

type Watchdog struct {
	TunnelTimeoutSec  int `json:"tunnel_timeout_sec"`
	HeartbeatGraceSec int `json:"heartbeat_grace_sec"`
}

type Contact struct {
	Phone string `json:"phone"`
	Name  string `json:"name"`
}

var caseIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Load reads and parses path. The raw bytes are returned so the caller can
// verify the detached signature over exactly what was on disk.
func Load(path string) (*Incident, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var inc Incident
	if err := json.Unmarshal(raw, &inc); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &inc, raw, nil
}

func (i *Incident) Validate(now time.Time) error {
	var errs []error
	if i.Schema != 1 {
		errs = append(errs, fmt.Errorf("schema %d unsupported", i.Schema))
	}
	if !caseIDRe.MatchString(i.CaseID) {
		errs = append(errs, errors.New("case_id must be 1-64 chars of [A-Za-z0-9._-]"))
	}
	if i.ExpiresUTC.IsZero() || !now.Before(i.ExpiresUTC) {
		errs = append(errs, fmt.Errorf("incident config expired at %s", i.ExpiresUTC.Format(time.RFC3339)))
	}
	if i.Tailscale.AuthKey == "" {
		errs = append(errs, errors.New("tailscale.authkey required"))
	}
	if i.Tailscale.Hostname == "" {
		errs = append(errs, errors.New("tailscale.hostname required"))
	}
	if i.Tailscale.ResponderNodeKey == "" {
		errs = append(errs, errors.New("tailscale.responder_node_key required"))
	}
	if i.Tailscale.ResponderTailnetIP == "" {
		errs = append(errs, errors.New("tailscale.responder_tailnet_ip required"))
	}
	if i.Velociraptor.ServerURL == "" || i.Velociraptor.ConfigFile == "" {
		errs = append(errs, errors.New("velociraptor.server_url and config_file required"))
	}
	if len(i.Firewall.DNSResolvers) == 0 && !i.Firewall.DNSFallbackToDHCP {
		errs = append(errs, errors.New("firewall.dns_resolvers required unless dns_fallback_to_dhcp"))
	}
	if i.Watchdog.TunnelTimeoutSec <= 0 || i.Watchdog.HeartbeatGraceSec <= 0 {
		errs = append(errs, errors.New("watchdog timeouts must be > 0"))
	}
	if i.Contact.Phone == "" {
		errs = append(errs, errors.New("contact.phone required"))
	}
	if i.BreakglassCodeHash == "" {
		errs = append(errs, errors.New("breakglass_code_hash required"))
	}
	if i.PayloadManifestSHA256 == "" {
		errs = append(errs, errors.New("payload_manifest_sha256 required"))
	}
	return errors.Join(errs...)
}

func (i *Incident) RuleGroup() string { return "DFIRMedic-" + i.CaseID }
