// Package build assembles and signs a per-incident kit onto a USB stick, and
// verifies a kit the same way the orchestrator will in PREFLIGHT.
package build

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dfirtnt/DFIRMedic/internal/config"
	"github.com/dfirtnt/DFIRMedic/internal/manifest"
	"github.com/dfirtnt/DFIRMedic/internal/sign"
	"github.com/dfirtnt/DFIRMedic/internal/teardown"
)

type Options struct {
	CaseID, AuthKey, Hostname, ResponderNodeKey, ResponderIP, ServerURL string
	DNSResolvers                                                        []string
	AllowRDP, DNSFallbackDHCP                                           bool
	TunnelTimeoutSec, HeartbeatGraceSec                                 int
	ContactName, ContactPhone, BreakglassCode                           string
	TTL                                                                 time.Duration
	PayloadDir, ExePath, FieldCardPath, OutDir, PrivKeyPath             string
	Now                                                                 func() time.Time
}

type Result struct {
	IncidentPath string
	Files        []string
}

func (o *Options) defaults() {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Hostname == "" {
		o.Hostname = "ir-" + o.CaseID
	}
	if o.TunnelTimeoutSec == 0 {
		o.TunnelTimeoutSec = 600
	}
	if o.HeartbeatGraceSec == 0 {
		o.HeartbeatGraceSec = 300
	}
	if o.TTL == 0 {
		o.TTL = 24 * time.Hour
	}
}

// incident builds the signed config. payloadManifestSHA256 must be
// manifest.HashFile of the OutDir's already-written payload/manifest.sha256 —
// this is what binds the (otherwise unsigned) payload manifest to the
// signature, so a tampered payload file plus a regenerated manifest.sha256
// cannot pass internal/stage's Preflight (its E17 check compares against
// this same field). See internal/stage's E13/E17 checks.
func (o Options) incident(payloadManifestSHA256 string) *config.Incident {
	now := o.Now().UTC()
	return &config.Incident{
		Schema: 1, CaseID: o.CaseID, CreatedUTC: now, ExpiresUTC: now.Add(o.TTL),
		Tailscale:             config.Tailscale{AuthKey: o.AuthKey, Hostname: o.Hostname, ResponderNodeKey: o.ResponderNodeKey, ResponderTailnetIP: o.ResponderIP},
		Velociraptor:          config.Velo{ServerURL: o.ServerURL, ConfigFile: "payload/velociraptor.client.yaml"},
		Firewall:              config.Firewall{DNSResolvers: o.DNSResolvers, AllowRDPFromResponder: o.AllowRDP, DNSFallbackToDHCP: o.DNSFallbackDHCP},
		Watchdog:              config.Watchdog{TunnelTimeoutSec: o.TunnelTimeoutSec, HeartbeatGraceSec: o.HeartbeatGraceSec},
		Contact:               config.Contact{Name: o.ContactName, Phone: o.ContactPhone},
		BreakglassCodeHash:    teardown.CodeHash(o.BreakglassCode),
		PayloadManifestSHA256: "sha256:" + payloadManifestSHA256,
	}
}

func Build(o Options) (*Result, error) {
	o.defaults()
	if o.BreakglassCode == "" {
		return nil, errors.New("break-glass code required")
	}
	if st, err := os.Stat(o.PayloadDir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("payload dir %s: not a directory", o.PayloadDir)
	}
	priv, err := sign.ReadPrivateKey(o.PrivKeyPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(o.OutDir, 0o755); err != nil {
		return nil, err
	}
	res := &Result{IncidentPath: filepath.Join(o.OutDir, "incident.json")}

	if err := copyTree(o.PayloadDir, filepath.Join(o.OutDir, "payload")); err != nil {
		return nil, fmt.Errorf("copy payload: %w", err)
	}
	if _, err := manifest.Write(filepath.Join(o.OutDir, "payload")); err != nil {
		return nil, err
	}
	// The manifest must exist on disk before we can bind its hash into the
	// signed incident.json, so incident() is called only from here on.
	manifestHash, err := manifest.HashFile(filepath.Join(o.OutDir, "payload", manifest.FileName))
	if err != nil {
		return nil, fmt.Errorf("hash payload manifest: %w", err)
	}
	inc := o.incident(manifestHash)
	if err := inc.Validate(o.Now()); err != nil {
		return nil, fmt.Errorf("incident config: %w", err)
	}
	if err := copyFile(o.ExePath, filepath.Join(o.OutDir, "dfirmedic.exe")); err != nil {
		return nil, fmt.Errorf("copy orchestrator: %w", err)
	}
	card, err := os.ReadFile(o.FieldCardPath)
	if err != nil {
		return nil, fmt.Errorf("field card: %w", err)
	}
	txt := strings.NewReplacer("{{CASE_ID}}", o.CaseID, "{{NAME}}", o.ContactName, "{{PHONE}}", o.ContactPhone).Replace(string(card))
	if err := os.WriteFile(filepath.Join(o.OutDir, "FIELD-CARD.txt"), []byte(txt), 0o644); err != nil {
		return nil, err
	}

	raw, err := json.MarshalIndent(inc, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(res.IncidentPath, raw, 0o600); err != nil {
		return nil, err
	}
	if err := sign.WriteSig(res.IncidentPath+".sig", sign.Sign(priv, raw)); err != nil {
		return nil, err
	}
	if _, err := Verify(o.OutDir, priv.Public().(ed25519.PublicKey), o.Now()); err != nil {
		return nil, fmt.Errorf("post-build verification failed: %w", err)
	}
	filepath.WalkDir(o.OutDir, func(p string, d fs.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			rel, _ := filepath.Rel(o.OutDir, p)
			res.Files = append(res.Files, filepath.ToSlash(rel))
		}
		return nil
	})
	return res, nil
}

func Verify(kitDir string, pub ed25519.PublicKey, now time.Time) (*config.Incident, error) {
	inc, raw, err := config.Load(filepath.Join(kitDir, "incident.json"))
	if err != nil {
		return nil, err
	}
	sig, err := sign.ReadSig(filepath.Join(kitDir, "incident.json.sig"))
	if err != nil {
		return nil, err
	}
	if !sign.Verify(pub, raw, sig) {
		return nil, errors.New("incident.json signature invalid")
	}
	if err := inc.Validate(now); err != nil {
		return nil, err
	}
	manifestHash, err := manifest.HashFile(filepath.Join(kitDir, "payload", manifest.FileName))
	if err != nil {
		return nil, fmt.Errorf("hash payload manifest: %w", err)
	}
	if "sha256:"+manifestHash != inc.PayloadManifestSHA256 {
		return nil, errors.New("payload manifest hash does not match signed incident.json — kit may have been tampered with")
	}
	if _, err := manifest.Verify(filepath.Join(kitDir, "payload")); err != nil {
		return nil, err
	}
	return inc, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		if filepath.Base(p) == manifest.FileName {
			return nil // regenerated after copy
		}
		return copyFile(p, filepath.Join(dst, rel))
	})
}
