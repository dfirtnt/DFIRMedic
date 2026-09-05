// Package config loads and validates the per-incident incident.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"time"
)

// Schema is the incident.json format this kit understands. Schema 1 carried a
// Tailscale block; schema 2 (spec 2026-09-05) talks to a fixed server IP.
const Schema = 2

type Incident struct {
	Schema                int       `json:"schema"`
	CaseID                string    `json:"case_id"`
	CreatedUTC            time.Time `json:"created_utc"`
	ExpiresUTC            time.Time `json:"expires_utc"`
	Server                Server    `json:"server"`
	Velociraptor          Velo      `json:"velociraptor"`
	Firewall              Firewall  `json:"firewall"`
	Watchdog              Watchdog  `json:"watchdog"`
	Contact               Contact   `json:"contact"`
	BreakglassCodeHash    string    `json:"breakglass_code_hash"`
	PayloadManifestSHA256 string    `json:"payload_manifest_sha256"`
}

// Server is the one destination the victim may reach.
type Server struct {
	URL      string `json:"url"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	CASHA256 string `json:"ca_sha256"` // fingerprint of Client.ca_certificate in the shipped client config
}

type Velo struct {
	ConfigFile  string `json:"config_file"`
	InstallPath string `json:"install_path"` // where `service install` puts the binary; the egress rule names it
	ServiceName string `json:"service_name"`
}

type Firewall struct {
	DNSFallbackToDHCP bool `json:"dns_fallback_to_dhcp"`
}

type Watchdog struct {
	TunnelTimeoutSec  int `json:"tunnel_timeout_sec"`
	HeartbeatGraceSec int `json:"heartbeat_grace_sec"`
}

type Contact struct {
	Phone string `json:"phone"`
	Name  string `json:"name"`
}

var (
	caseIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	sha256Re = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// installPathRe requires at least <drive>:\<dir>\<file>. install_path is
	// signed, but signing only proves the responder built it - it does not
	// make a dangerous shape safe. Teardown deletes the *parent directory* of
	// this path with `rmdir /s /q`, so a drive-root path such as
	// `C:\Velociraptor.exe` would target the whole of C:. Rejecting the shape
	// here fails the kit at build/preflight time instead of at teardown time.
	// internal/teardown.installDir applies the same pattern one level deeper
	// (to the directory it is about to delete) as defence in depth.
	installPathRe = regexp.MustCompile(`^[A-Za-z]:\\[^\\]+\\[^\\]+`)
)

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
	if i.Schema != Schema {
		errs = append(errs, fmt.Errorf("schema %d unsupported (this kit requires schema %d)", i.Schema, Schema))
	}
	if !caseIDRe.MatchString(i.CaseID) {
		errs = append(errs, errors.New("case_id must be 1-64 chars of [A-Za-z0-9._-]"))
	}
	if i.ExpiresUTC.IsZero() || !now.Before(i.ExpiresUTC) {
		errs = append(errs, fmt.Errorf("incident config expired at %s", i.ExpiresUTC.Format(time.RFC3339)))
	}
	if i.Server.URL == "" {
		errs = append(errs, errors.New("server.url required"))
	}
	if net.ParseIP(i.Server.IP) == nil {
		errs = append(errs, fmt.Errorf("server.ip must be an IP literal, got %q", i.Server.IP))
	}
	if i.Server.Port < 1 || i.Server.Port > 65535 {
		errs = append(errs, fmt.Errorf("server.port out of range: %d", i.Server.Port))
	}
	if !sha256Re.MatchString(i.Server.CASHA256) {
		errs = append(errs, errors.New("server.ca_sha256 must be sha256:<64 hex>"))
	}
	if i.Velociraptor.ConfigFile == "" {
		errs = append(errs, errors.New("velociraptor.config_file required"))
	}
	if !installPathRe.MatchString(i.Velociraptor.InstallPath) {
		errs = append(errs, fmt.Errorf("velociraptor.install_path must be an absolute Windows path of at least "+
			`<drive>:\<dir>\<file> (set windows_installer.install_path in the Velociraptor client config), got %q`,
			i.Velociraptor.InstallPath))
	}
	if i.Velociraptor.ServiceName == "" {
		errs = append(errs, errors.New("velociraptor.service_name required"))
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
