// Package stage runs the offline staging phases from spec §8. Each phase
// records itself in the audit log and manifest; the first error aborts.
package stage

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/audit"
	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/manifest"
	"github.com/dfirtnt/DFIRMedic/internal/runner"
	"github.com/dfirtnt/DFIRMedic/internal/sign"
	"github.com/dfirtnt/DFIRMedic/internal/tailscale"
	"github.com/dfirtnt/DFIRMedic/internal/ui"
	"github.com/dfirtnt/DFIRMedic/internal/velo"
	"github.com/dfirtnt/DFIRMedic/internal/win"
)

const TaskNamePrefix = "DFIRMedic-"

type Deps struct {
	Inc       *config.Incident
	RawConfig []byte
	Sig       []byte
	PubKey    ed25519.PublicKey
	KitDir    string
	WorkDir   string
	ExeSHA256 string
	R         runner.Runner
	Log       *audit.Log
	Man       *audit.Manifest
	Beacon    *ui.Beacon
	FW        win.Firewall
	Net       win.Net
	Sys       win.Sys
	TS        tailscale.Client
	Velo      velo.Client
	Now       func() time.Time
	Elevated  func() bool
}

type Baseline struct {
	Hostname  string             `json:"hostname"`
	EditionID string             `json:"edition_id"`
	Timezone  string             `json:"timezone"`
	TimeUTC   time.Time          `json:"time_utc"`
	Profiles  []win.ProfileState `json:"profiles"`
	Rules     json.RawMessage    `json:"rules"`
	Adapters  []win.Adapter      `json:"adapters"`
	Services  string             `json:"services"`
}

func code(c, msg string, err error) error {
	if err != nil {
		return fmt.Errorf("%s %s: %w", c, msg, err)
	}
	return fmt.Errorf("%s %s", c, msg)
}

func (d Deps) phase(name string) error {
	if d.Man.Phases == nil {
		d.Man.Phases = map[string]time.Time{}
	}
	d.Man.Phases[name] = d.Now().UTC()
	return d.Log.Phase(name)
}

func (d Deps) saveManifest() error {
	return d.Man.Save(filepath.Join(d.WorkDir, "manifest.json"))
}

func Run(ctx context.Context, d Deps) error {
	if d.Man.Phases == nil {
		d.Man.Phases = map[string]time.Time{}
	}
	d.Man.CaseID = d.Inc.CaseID
	d.Man.OrchestratorSHA256 = d.ExeSHA256
	d.Beacon.Set(ui.Staging, "Checking")
	if err := Preflight(ctx, d); err != nil {
		return err
	}
	d.Beacon.Set(ui.Staging, "Recording baseline")
	base, err := TakeBaseline(ctx, d)
	if err != nil {
		return err
	}
	d.Beacon.Set(ui.Staging, "Locking network")
	if err := Quarantine(ctx, d, base); err != nil {
		return err
	}
	d.Beacon.Set(ui.Staging, "Installing")
	if err := Install(ctx, d); err != nil {
		return err
	}
	if err := d.phase("READY"); err != nil {
		return err
	}
	if err := d.saveManifest(); err != nil {
		return err
	}
	d.Beacon.Set(ui.Ready, "")
	return nil
}

func Preflight(ctx context.Context, d Deps) error {
	if err := d.phase("PREFLIGHT"); err != nil {
		return err
	}
	if !d.Elevated() {
		return code("E10", "not running as Administrator", nil)
	}
	if !sign.Verify(d.PubKey, d.RawConfig, d.Sig) {
		return code("E11", "incident.json signature invalid", nil)
	}
	if err := d.Inc.Validate(d.Now()); err != nil {
		return code("E12", "incident.json invalid", err)
	}
	manifestHash, err := manifest.HashFile(filepath.Join(d.KitDir, "payload", manifest.FileName))
	if err != nil {
		return code("E17", "cannot hash payload manifest", err)
	}
	if "sha256:"+manifestHash != d.Inc.PayloadManifestSHA256 {
		return code("E17", "payload manifest hash does not match signed incident.json — kit may have been tampered with", nil)
	}
	hashes, err := manifest.Verify(filepath.Join(d.KitDir, "payload"))
	if err != nil {
		return code("E13", "payload verification failed", err)
	}
	d.Man.Payload = hashes
	up, ads, err := d.Net.AnyPhysicalUp(ctx)
	if err != nil {
		return code("E14", "cannot read adapter state", err)
	}
	if up {
		return code("E14", fmt.Sprintf("network is connected (%s); disconnect before staging", ads[0].Name), nil)
	}
	if d.Inc.Firewall.AllowRDPFromResponder {
		ed, err := d.Sys.EditionID(ctx)
		if err != nil {
			return code("E15", "cannot read Windows edition", err)
		}
		if win.IsHomeEdition(ed) {
			return code("E15", "RDP requested but this is a Home edition ("+ed+")", nil)
		}
	}
	for _, svc := range []string{"Tailscale", velo.ServiceName} {
		exists, err := d.Sys.ServiceExists(ctx, svc)
		if err != nil {
			return code("E16", "cannot query service "+svc, err)
		}
		if exists {
			return code("E16", svc+" service already installed on this host", nil)
		}
	}
	return nil
}

func TakeBaseline(ctx context.Context, d Deps) (*Baseline, error) {
	if err := d.phase("BASELINE"); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(d.WorkDir, 0o700); err != nil {
		return nil, code("E20", "create workdir", err)
	}
	if err := d.FW.Export(ctx, filepath.Join(d.WorkDir, "firewall-original.wfw")); err != nil {
		return nil, code("E20", "firewall export", err)
	}
	b := &Baseline{TimeUTC: d.Now().UTC()}
	b.Hostname, _ = os.Hostname()
	b.Timezone, _ = d.Now().Zone()
	var err error
	if b.EditionID, err = d.Sys.EditionID(ctx); err != nil {
		return nil, code("E20", "edition", err)
	}
	if b.Profiles, err = d.FW.Profiles(ctx); err != nil {
		return nil, code("E20", "firewall profiles", err)
	}
	if b.Rules, err = d.FW.RulesJSON(ctx); err != nil {
		return nil, code("E20", "firewall rules", err)
	}
	if b.Adapters, err = d.Net.PhysicalAdapters(ctx); err != nil {
		return nil, code("E20", "adapters", err)
	}
	res, err := d.R.Run(ctx, "sc.exe", "query", "type=", "service", "state=", "all")
	if err != nil {
		return nil, code("E20", "services", err)
	}
	b.Services = res.Stdout
	raw, _ := json.MarshalIndent(b, "", "  ")
	if err := os.WriteFile(filepath.Join(d.WorkDir, "baseline.json"), raw, 0o600); err != nil {
		return nil, code("E20", "write baseline", err)
	}
	d.Man.Baseline = raw
	return b, nil
}

// Quarantine adds the allow-list first (harmless while defaults are still
// Allow), then flips the profile defaults to Block. Any failure removes the
// group and restores the baseline profile settings.
func Quarantine(ctx context.Context, d Deps, base *Baseline) error {
	if err := d.phase("QUARANTINE"); err != nil {
		return err
	}
	group := d.Inc.RuleGroup()
	rdpFrom := ""
	if d.Inc.Firewall.AllowRDPFromResponder {
		rdpFrom = d.Inc.Tailscale.ResponderTailnetIP
	}
	rollback := func(cause error) error {
		_ = d.Log.Record("quarantine_rollback", map[string]string{"cause": cause.Error()})
		removeErr := d.FW.RemoveGroup(ctx, group)
		restoreErr := d.FW.RestoreProfiles(ctx, base.Profiles)
		rollbackErr := errors.Join(removeErr, restoreErr)
		_ = d.Log.Record("quarantine_rollback_result", map[string]string{
			"ok":    fmt.Sprintf("%v", rollbackErr == nil),
			"error": fmt.Sprintf("%v", rollbackErr),
		})
		if rollbackErr != nil {
			return code("E30", "quarantine failed AND rollback failed — host may still be locked down, run breakglass", errors.Join(cause, rollbackErr))
		}
		return code("E30", "quarantine failed and was rolled back", cause)
	}
	for _, r := range win.QuarantineRules(d.Inc.Firewall.DNSResolvers, d.Inc.Firewall.DNSFallbackToDHCP, rdpFrom) {
		txt, err := d.FW.AddRule(ctx, group, r)
		if err != nil {
			return rollback(fmt.Errorf("rule %s: %w", r.Name, err))
		}
		d.Man.Rules = append(d.Man.Rules, txt)
	}
	if err := d.FW.SetAllProfiles(ctx, true, "Block", "Block"); err != nil {
		return rollback(err)
	}
	return nil
}

func Install(ctx context.Context, d Deps) error {
	if err := d.phase("INSTALL"); err != nil {
		return err
	}
	// Everything the services depend on must survive USB removal.
	if err := copyDir(filepath.Join(d.KitDir, "payload"), filepath.Join(d.WorkDir, "payload")); err != nil {
		return code("E40", "copy payload", err)
	}
	for _, f := range []string{"dfirmedic.exe", "incident.json", "incident.json.sig"} {
		if err := copyFile(filepath.Join(d.KitDir, f), filepath.Join(d.WorkDir, f)); err != nil {
			return code("E40", "copy "+f, err)
		}
	}
	_ = d.Log.Record("copy", map[string]string{"from": d.KitDir, "to": d.WorkDir})

	if err := d.TS.InstallMSI(ctx); err != nil {
		return code("E40", "install Tailscale", err)
	}
	if err := d.TS.Up(ctx, d.Inc.Tailscale.AuthKey, d.Inc.Tailscale.Hostname); err != nil {
		return code("E40", "tailscale up", err)
	}
	if err := d.Velo.InstallService(ctx); err != nil {
		return code("E40", "install Velociraptor", err)
	}
	if d.Inc.Firewall.AllowRDPFromResponder {
		if err := d.Sys.EnableRDP(ctx); err != nil {
			return code("E40", "enable RDP", err)
		}
	}
	exe := filepath.Join(d.WorkDir, "dfirmedic.exe")
	if err := d.Sys.CreateStartupTask(ctx, TaskNamePrefix+d.Inc.CaseID, exe, "connect --workdir "+d.WorkDir); err != nil {
		return code("E40", "startup task", err)
	}
	return nil
}
