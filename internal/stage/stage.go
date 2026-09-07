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
	"strings"
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
	// Volatile maps each file under <workdir>\volatile\ to its hash and, if
	// the command failed, the error. See volatile.go.
	Volatile map[string]VolatileCapture `json:"volatile"`
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
	rawCfg, err := os.ReadFile(filepath.Join(d.KitDir, filepath.FromSlash(d.Inc.Velociraptor.ConfigFile)))
	if err != nil {
		return code("E18", "read client config", err)
	}
	caPEM, err := velo.ExtractCA(rawCfg)
	if err != nil {
		return code("E18", "client config", err)
	}
	caFP, err := velo.CAFingerprint(caPEM)
	if err != nil {
		return code("E18", "client config", err)
	}
	if caFP != d.Inc.Server.CASHA256 {
		return code("E18", "client config CA does not match signed incident.json — kit was assembled from a different server", nil)
	}
	up, ads, err := d.Net.AnyPhysicalUp(ctx)
	if err != nil {
		return code("E14", "cannot read adapter state", err)
	}
	if up {
		return code("E14", fmt.Sprintf("network is connected (%s); disconnect before staging", ads[0].Name), nil)
	}
	for _, svc := range []string{velo.ServiceName} {
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
	// Copy the small files breakglass/teardown need BEFORE anything can go
	// wrong later: both open their config from --workdir only, with no kit
	// fallback, so if the big payload copy in INSTALL dies halfway the
	// recovery path the E30/E40 messages point at must still work.
	for _, f := range []string{"dfirmedic.exe", "incident.json", "incident.json.sig"} {
		if err := copyFile(filepath.Join(d.KitDir, f), filepath.Join(d.WorkDir, f)); err != nil {
			return nil, code("E20", "copy "+f, err)
		}
	}
	_ = d.Log.Record("copy", map[string]string{"from": d.KitDir, "to": d.WorkDir, "files": "dfirmedic.exe incident.json incident.json.sig"})
	// Volatile state first: it is the most perishable evidence in BASELINE and
	// everything after this point either reads persistent state or changes the host.
	d.Beacon.Set(ui.Staging, "Capturing volatile state")
	volatile, err := CaptureVolatile(ctx, d.R, filepath.Join(d.WorkDir, "volatile"))
	if err != nil {
		return nil, code("E20", "volatile capture", err)
	}
	// A rerun against an existing workdir (E30/E40 aborted a prior attempt
	// without deleting it) must not re-export now: if that prior run reached
	// QUARANTINE before failing, the host is already locked down, and
	// exporting now would capture the locked-down policy as "original" -
	// teardown would then "restore" the quarantine instead of undoing it.
	// The already-captured original is the one that must survive.
	wfwPath := filepath.Join(d.WorkDir, "firewall-original.wfw")
	if _, err := os.Stat(wfwPath); err == nil {
		_ = d.Log.Record("baseline_export_preserved", map[string]string{"path": wfwPath})
	} else if err := d.FW.Export(ctx, wfwPath); err != nil {
		return nil, code("E20", "firewall export", err)
	}
	b := &Baseline{TimeUTC: d.Now().UTC(), Volatile: volatile}
	b.Hostname, _ = os.Hostname()
	b.Timezone, _ = d.Now().Zone()
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
// Allow), disables every pre-existing rule so nothing outside the group can
// match, then flips the profile defaults to Block. Any failure imports the
// policy exported in BASELINE; if that import fails it falls back to
// undoing each step by hand.
func Quarantine(ctx context.Context, d Deps, base *Baseline) error {
	if err := d.phase("QUARANTINE"); err != nil {
		return err
	}
	group := d.Inc.RuleGroup()
	rollback := func(cause error) error {
		_ = d.Log.Record("quarantine_rollback", map[string]string{"cause": cause.Error()})
		importErr := d.FW.Import(ctx, filepath.Join(d.WorkDir, "firewall-original.wfw"))
		var rollbackErr error
		if importErr != nil {
			rollbackErr = errors.Join(
				d.FW.RemoveGroup(ctx, group),
				d.FW.RestoreProfiles(ctx, base.Profiles),
				d.FW.EnableRules(ctx, d.Man.DisabledRules),
			)
			if rollbackErr != nil {
				rollbackErr = errors.Join(importErr, rollbackErr)
			}
		}
		_ = d.Log.Record("quarantine_rollback_result", map[string]string{
			"ok":           fmt.Sprintf("%v", rollbackErr == nil),
			"import_error": fmt.Sprintf("%v", importErr),
			"error":        fmt.Sprintf("%v", rollbackErr),
		})
		if rollbackErr != nil {
			return code("E30", "quarantine failed AND rollback failed — host may still be locked down, run breakglass", errors.Join(cause, rollbackErr))
		}
		return code("E30", "quarantine failed and was rolled back", cause)
	}
	// Windows Firewall matches a program path when a process launches, not at
	// rule creation, so the not-yet-existing paths below (INSTALL copies the
	// payload and the orchestrator has already been copied in BASELINE) are fine.
	rules := append(
		win.QuarantineRules(d.Inc.Firewall.DNSFallbackToDHCP),
		win.ServerRules(
			d.Inc.Velociraptor.InstallPath,
			filepath.Join(d.WorkDir, "payload", "velociraptor.exe"),
			filepath.Join(d.WorkDir, "dfirmedic.exe"),
			d.Inc.Server.IP, d.Inc.Server.Port,
		)...,
	)
	for _, r := range rules {
		txt, err := d.FW.AddRule(ctx, group, r)
		if err != nil {
			return rollback(fmt.Errorf("rule %s: %w", r.Name, err))
		}
		d.Man.Rules = append(d.Man.Rules, txt)
	}
	// Enabled allow rules match regardless of the profile default, so every
	// rule that was on the host before us (built-in, third-party, or planted
	// by the intruder) must be off before the default-deny flip means anything.
	disabled, err := d.FW.DisableOtherRules(ctx, group)
	if err != nil {
		return rollback(fmt.Errorf("disable pre-existing rules: %w", err))
	}
	d.Man.DisabledRules = disabled
	_ = d.Log.Record("rules_disabled", map[string]any{"count": len(disabled), "names": disabled})
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
	// dfirmedic.exe/incident.json/incident.json.sig were copied in BASELINE.
	if err := copyDir(filepath.Join(d.KitDir, "payload"), filepath.Join(d.WorkDir, "payload")); err != nil {
		return code("E40", "copy payload", err)
	}
	_ = d.Log.Record("copy", map[string]string{"from": filepath.Join(d.KitDir, "payload"), "to": filepath.Join(d.WorkDir, "payload")})

	if err := d.Velo.InstallService(ctx); err != nil {
		return code("E40", "install Velociraptor", err)
	}
	got, err := d.Velo.InstalledBinaryPath(ctx)
	if err != nil {
		return code("E41", "read Velociraptor service path", err)
	}
	if !strings.EqualFold(got, d.Inc.Velociraptor.InstallPath) {
		return code("E41", fmt.Sprintf("Velociraptor service runs from %q but the firewall allows %q", got, d.Inc.Velociraptor.InstallPath), nil)
	}
	_ = d.Log.Record("velociraptor_path_verified", map[string]string{"path": got})
	exe := filepath.Join(d.WorkDir, "dfirmedic.exe")
	if err := d.Sys.CreateStartupTask(ctx, TaskNamePrefix+d.Inc.CaseID, exe, "connect --workdir "+d.WorkDir); err != nil {
		return code("E40", "startup task", err)
	}
	return nil
}
