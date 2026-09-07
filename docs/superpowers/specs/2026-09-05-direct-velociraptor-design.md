# DFIRMedic — direct Velociraptor transport (drop Tailscale from the victim)

**Date:** 2026-09-05
**Status:** proposed; supersedes the parts of `2026-09-04-dfirmedic-design.md` named in §9
**Author:** starlord, with Claude

## 1. Summary

The victim host stops running Tailscale. It runs only the Velociraptor client, which
connects outbound to a fixed public IP on one TCP port. The quarantine firewall allows
exactly that connection, plus DHCP and IPv6 neighbor discovery, and nothing else — no
DNS at all. Tailscale remains on the responder side only, as the way the responder's Mac
reaches the Velociraptor server's GUI.

Everything else in the original design stands: offline staging, default-deny quarantine,
baseline and volatile capture, the audit chain, the beacon, the watchdog, teardown, and
break-glass.

## 2. Why

The 2026-09-05 real-host test (`DESKTOP-TVHKA02`) showed that Tailscale on the victim is
a reachability convenience that costs more than it returns:

- **Two egress holes in the quarantine that only exist because of Tailscale.** The
  pinned-resolver DNS rules let any process exfiltrate through the system resolver
  (`<data>.attacker.example` → 1.1.1.1 is a working covert channel). The `tailscaled`
  allow rule has no destination restriction because the daemon must reach the control
  plane and relays; a SYSTEM implant injecting into it inherits that allow.
- **An inbound path into the victim.** With correct tagging it is limited to the opt-in
  RDP rule. In the test the key was minted untagged and the node joined as a member
  device: every device on the tailnet could reach it and it could reach every device.
  One unticked checkbox turned the quarantine into a bridge.
- **Operational weight.** A second third-party install, an installer that launches a GUI,
  a per-incident credential on the stick with five settings to get right, a DNS bootstrap
  the kit never actually configured, and a tailnet identity that the kit, the ACL, and
  the server config all have to agree on. Roughly a third of the post-test defect list.

What Tailscale bought was "zero hosting": a laptop behind NAT could be the server. The
responder has already decided an always-on node is required for real incidents, so that
benefit is gone regardless.

## 3. Decisions (locked)

| Decision | Choice | Rejected |
|---|---|---|
| Victim transport | Velociraptor client → public IPv4, TCP 443, Velociraptor's own TLS with pinned internal CA | Tailscale on victim; WireGuard on victim; Cloudflare Tunnel (another agent) |
| Server hosting | New small Linux VPS with a static public IPv4, nothing else on it | Reuse a lab AWS host (shared workloads); Mac + port-forward (ties incidents to home IP and laptop uptime) |
| Public port | 443 | 8000 (blocked by more site firewalls; 443 to a raw IP still fails some corporate proxies — see §8) |
| Responder → server | Tailscale, VPS is a normal tailnet node; GUI bound to the VPS's tailnet IP only | Public GUI with auth; SSH tunnel (works, but Tailscale is already there) |
| Victim DNS | None. No DNS rules, no resolver configuration. `server_urls` is an IP literal | Pinned resolvers (covert channel); DHCP resolver fallback |
| Server identity check on the victim | TLS connect to `server_ip:443`, verify the presented certificate chains to the CA embedded in the shipped client config | `tailscale status` peer check (gone); plain TCP connect (does not prove it is *our* server) |
| RDP to victim | Removed | Kept via a second tunnel — nobody asked for it, and it was the only inbound rule |
| Velociraptor service path | Keep Velociraptor's default `install_path` (`%ProgramFiles%\Velociraptor\Velociraptor.exe`); `build` records it in `incident.json` so the firewall rule and teardown use the same string | Rewrite `install_path` to the workdir (copy-onto-self risk in `service install`); parse YAML at stage time (a YAML parser on the victim for one value) |
| Exit node / domain allowlist on responder side | Removed | The victim never resolves or reaches anything but the server; the responder submits hashes from their own machine, as before |

## 4. Architecture

### 4.1 Responder side

- **Velociraptor server on a VPS.** Static public IPv4. Linux. Velociraptor runs as a
  service under an unprivileged user. Listeners:
  - `Frontend`: `0.0.0.0:443`. The only port open to the internet.
  - `GUI`: the VPS's tailnet IP, `:8889`. Reachable from the responder's Mac only.
  - `API`: `127.0.0.1`. `Monitoring`: `127.0.0.1`.
  - Host firewall (`ufw`/nftables): inbound `443/tcp` from anywhere, `41641/udp` for
    Tailscale, everything else dropped. SSH only over the tailnet.
  - Datastore on an encrypted volume; the VPS holds evidence.
- **Tailnet.** The VPS joins as a normal node (or `tag:ir-server`). The policy no longer
  needs `tag:ir-victim`, the victim grant, or the RDP grant. The default
  `autogroup:member → autogroup:member` grant is enough.
- **`dfirmedic build`** takes `--server-url https://<ip>:443/` and derives `server_ip`
  and `server_port` from it. It reads `Client.windows_installer.install_path` and the
  `ca_certificate` from `payload/velociraptor.client.yaml`, expands `$ProgramFiles` to
  the literal `C:\Program Files`, and writes both into `incident.json` so the victim never
  parses YAML. No auth key. No responder node key or IP.

### 4.2 Victim side

Unchanged in shape: USB → working directory → `dfirmedic.exe` orchestrates. What changes
is what it installs and what it allows.

## 5. `incident.json` (schema 2)

```json
{
  "schema": 2,
  "case_id": "CASE-2026-0042",
  "created_utc": "...", "expires_utc": "...",
  "server": {
    "url": "https://203.0.113.10:443/",
    "ip": "203.0.113.10",
    "port": 443,
    "ca_sha256": "sha256:<fingerprint of the CA cert in the client config>"
  },
  "velociraptor": {
    "config_file": "payload/velociraptor.client.yaml",
    "install_path": "C:\\Program Files\\Velociraptor\\Velociraptor.exe",
    "service_name": "Velociraptor"
  },
  "firewall": { "dns_fallback_to_dhcp": false },
  "watchdog": { "tunnel_timeout_sec": 600, "heartbeat_grace_sec": 300 },
  "contact": { "name": "...", "phone": "..." },
  "breakglass_code_hash": "sha256:...",
  "payload_manifest_sha256": "sha256:..."
}
```

Removed: the entire `tailscale` block, `firewall.dns_resolvers`,
`firewall.allow_rdp_from_responder`. `firewall.dns_fallback_to_dhcp` stays only as an
escape hatch for a site whose DHCP-assigned resolver must be reachable for some reason
we have not met yet; default off, and when off there are **no** port-53 rules.
`Validate` rejects schema 1.

`ca_sha256` is the SHA-256 of the DER form of the CA certificate in the client config. It
lets preflight confirm the shipped client config and the signed `incident.json` describe
the same server, closing the "swap the yaml on the stick" case that the payload manifest
already covers but that is worth stating.

## 6. Staging changes

Phases and error codes keep their numbers. Only the contents change.

### 6.1 PREFLIGHT

- Drop the `Tailscale` service-exists check. Keep the `Velociraptor` one.
- Drop the Home-edition check (it existed only for RDP).
- Add: parse the CA certificate out of `payload/velociraptor.client.yaml`
  (`Client.ca_certificate` is a PEM block; extracting it needs a line scanner, not a
  YAML parser), hash it, compare to `server.ca_sha256`. Mismatch → **E18**
  "client config does not match signed incident.json".

### 6.2 BASELINE

Unchanged. (Existing-workdir reuse from the open task list still applies.)

### 6.3 QUARANTINE

Rule group `DFIRMedic-<case_id>`:

| Rule | Direction | Scope |
|---|---|---|
| `velociraptor-egress` | Out | Program `<install_path>`, TCP, remote `<server_ip>:<port>` |
| `velociraptor-egress-payload` | Out | Program `<workdir>\payload\velociraptor.exe`, TCP, remote `<server_ip>:<port>` — `service install` runs the payload copy once |
| `orchestrator-probe` | Out | Program `<workdir>\dfirmedic.exe`, TCP, remote `<server_ip>:<port>` — the reachability probe in §7 |
| `dhcp-out`, `dhcp-in`, `dhcpv6-out`, `dhcpv6-in` | as today | unchanged |
| `nd-out`, `nd-in` | as today | unchanged |
| `dns-dhcp-udp`, `dns-dhcp-tcp` | Out | only when `dns_fallback_to_dhcp` is true; unchanged scope |

Gone: `tailscaled`, `dns-udp`, `dns-tcp`, `rdp-from-responder`. Ten rules become nine, and every remaining outbound program rule has a single fixed destination.
Rollback, the disable-others sweep, and the default-deny flip are unchanged.

### 6.4 INSTALL

1. Copy payload to `<workdir>` (unchanged).
2. `velociraptor.exe --config payload\velociraptor.client.yaml service install`, stop it,
   set Manual start (unchanged).
3. Verify the service's binary path equals `velociraptor.install_path` from
   `incident.json` (`sc.exe qc Velociraptor`, parse `BINARY_PATH_NAME`). Mismatch →
   **E41** "Velociraptor installed to an unexpected path"; the egress rule would not
   match and the client would be silently blocked, which is exactly the failure seen on
   2026-09-05.
4. Register the startup task (unchanged).

Gone: `msiexec /i tailscale-setup.msi`, `tailscale up`.

### 6.5 READY

Unchanged.

## 7. Reconnect sequence

1. On-site person reconnects. Link-up detected; watchdog starts (`tunnel_timeout_sec`).
2. Orchestrator probes the server every `poll` seconds: open a TLS connection to
   `server_ip:port`. Go's default verifier insists on a hostname or IP SAN match, which
   Velociraptor's internal CA does not provide, so the dial sets `InsecureSkipVerify=true`
   **and** supplies `VerifyPeerCertificate`, which runs `x509.Certificate.Verify` against
   a root pool containing only the CA from the client config, with no name check. Success
   = handshake completes and the leaf chains to the pinned CA. Connection is then closed;
   no HTTP is sent. (`InsecureSkipVerify` here disables only the name check; the chain
   check is mandatory and a failure aborts the handshake.)
3. On first success: audit `server_verified` with the leaf certificate fingerprint. Start
   the Velociraptor service. Beacon → `CONNECTED`.
4. Heartbeat: repeat the probe every `poll`. If it fails for longer than
   `heartbeat_grace_sec` → **E51** fail-closed (unchanged). Probe timeout → **E50**
   (unchanged).

The probe lives in `internal/probe` and is the only network code in the orchestrator.
It is a `crypto/tls` dial with a custom `VerifyPeerCertificate`; it does not speak
Velociraptor's protocol and cannot be confused by a captive portal, because a portal
cannot present a certificate signed by our CA.

Why a probe rather than reading the client's own state: the client has no local status
interface the kit can query without the API port, and the probe works before the service
is started, which is the case that matters (the gate).

Reboot path: the startup task runs `connect`, which is steps 2–4. Velociraptor stays
Manual-start until the probe passes. Unchanged behavior.

## 8. Failure handling

| Condition | Response |
|---|---|
| Server not verified within `tunnel_timeout_sec` | E50, fail closed (unchanged) |
| Probe fails longer than `heartbeat_grace_sec` | E51, fail closed (unchanged) |
| Velociraptor fails to start | E52 (unchanged) |
| Site blocks outbound 443 to arbitrary IPs (proxy-only egress) | E50. **Known limit**, replaces the old DERP-fallback story. Documented on the field card as "call the responder"; the responder decides whether to move the machine to another network. |
| VPS IP changes | Every existing kit is dead. Static IP is a hard hosting requirement; `verify` on the responder side should re-probe the URL before a kit ships. |
| Attacker replays the client config | They can enroll a bogus client on the server. Noise, not access; the server labels clients by enrollment and the responder ignores unexpected ones. |

Break-glass and teardown: remove the "tailscale logout" and "uninstall Tailscale" steps;
add "delete `<install_path>`'s directory" after `service remove` so the Program Files
copy does not outlive the engagement. Adapter re-enable no longer means "every physical
adapter": `FailClosed` records the names it actually disabled (`manifest.json`
`disabled_adapters`), and teardown/break-glass re-enable only those — falling back to the
baseline's Up adapters for a manifest predating that field. A name from either list can be
stale by the time teardown runs (a USB NIC unplugged, a virtual adapter torn down);
`EnableAll` skips that specific phantom-adapter error rather than aborting the batch on it.
The rest of the open task list unchanged.

## 9. What this supersedes in the 2026-09-04 spec

| Section | Disposition |
|---|---|
| §4 Decisions: tunnel, key handling, key minting rows | Replaced by §3 here |
| §5.1 Responder side | Replaced by §4.1 |
| §7 `incident.json` | Replaced by §5 |
| §8.1, §8.3, §8.4 | Amended per §6 |
| §9 Reconnect sequence | Replaced by §7 |
| §10 table, rows "Tunnel not verified", "Reboot" | Amended per §8 |
| §10.1 Break-glass | Tailscale steps removed |
| §12 "Process explorer" RDP clause | Removed |
| §14 Stack: "`tailscale.exe`" in the delegated-binaries list | Removed; add `internal/probe` as the one piece of in-process network code and why (§7) |
| §15 Testing: DERP row | Replaced by "proxy-only egress → E50" |
| §16 Risks: Tailscale licensing, "Not literally only my computer" | Removed; add the three rows in §10 below |
| §17 items 1, 5, 6, 7 | Superseded |

## 10. Risks

- **Public Velociraptor frontend.** One port on one box faces the internet. Velociraptor's
  frontend is designed for hostile clients and this is the upstream project's normal
  deployment shape. Mitigations: nothing else on the VPS, unprivileged service user,
  automatic Velociraptor upgrades, GUI and SSH reachable only over the tailnet.
- **VPS holds evidence.** Compromise of the VPS is compromise of every collection.
  Mitigations: encrypted datastore volume; the responder pulls collections to their own
  machine and can wipe the VPS between engagements.
- **Egress-filtered sites.** A victim on a network that only permits web traffic through
  an authenticating proxy cannot reach a raw IP on 443. The old design had the same limit
  behind DERP; it was just less visible. The field card already says "call the responder"
  for any ERROR.
- **Unchanged from before:** Defender heuristics on an unknown binary that flips the
  firewall; live SYSTEM-level operator can undo everything; kernel implant invalidates
  live response; THOR Lite license scope.

## 11. Testing

- **Unit:** `internal/probe` against an in-process TLS listener: pinned CA passes; a
  cert from a different CA fails; a plain TCP listener fails; a timeout is reported as
  such. `config.Validate` rejects schema 1 and missing `server`/`install_path`. Quarantine
  rule set is exactly the nine rules in §6.3 (plus two with DHCP fallback).
  INSTALL's path check parses `sc qc` output and raises E41 on mismatch. Teardown
  removes the install directory.
- **Integration (`docs/integration-tests.md`):** rows 1, 1b, 1c, 2, 3, 4, 6, 7, 9, 10
  stay with Tailscale wording removed. Row 5 (DERP) becomes "block outbound 443 from the
  VM; expect E50 within `tunnel_timeout_sec`." Row 8 (Home + RDP) is deleted. New row:
  swap `velociraptor.client.yaml` on the stick for one from a different server; expect
  E13 (manifest) — and if the manifest is regenerated too, E17; and if `incident.json` is
  also forged, E11. New row: server reachable but presenting a certificate from another
  CA (stand up a second Velociraptor with a fresh CA on the same IP); expect E50, never
  CONNECTED.
- **Real host:** the second real-host test in the task list runs against this design,
  not the old one.

## 12. Deletions and replacements (implementation checklist)

Delete:
- `internal/tailscale/` (package and tests)
- `payload/tailscale-setup.msi` and its README line
- `build` flags `--authkey`, `--hostname`, `--responder-node-key`, `--responder-ip`,
  `--rdp`, `--dns`
- `config.Tailscale`, `config.Firewall.DNSResolvers`, `config.Firewall.AllowRDPFromResponder`
- `win.QuarantineRules` entries `tailscaled`, `dns-udp`, `dns-tcp`, `rdp-from-responder`
- `win.IsHomeEdition` and the edition preflight
- `stage.Install` MSI and `tailscale up` steps; `teardown` logout and uninstall steps
- Responder doc §2 (tailnet ACL for victims), §3 (exit node), §4 (responder identity);
  §6 auth-key step
- Integration rows 5 and 8 as written

Add:
- `internal/probe`: `Verify(ctx, ip, port, caPEM) (leafFingerprint string, err error)`
- `config.Server{URL, IP, Port, CASHA256}`, `config.Velo.InstallPath`, schema 2
- `build`: derive `server.ip`/`port` from `--server-url`; read `install_path` and CA from
  the client yaml; write both; refuse a `server_urls` entry that is a hostname
- Preflight E18; Install E41
- Quarantine rules `velociraptor-egress` (install path), `velociraptor-egress-payload`,
  `orchestrator-probe`
- Teardown: delete install directory
- Responder doc: VPS setup (§4.1 here, as commands), tailnet note reduced to "join the
  VPS", `build` example without key or node identity
- Field card: unchanged text; the "reconnect" step still applies

Todoist tasks affected (project DFIRMedic): "Set pinned DNS resolvers…" and "Install
Tailscale silently…" and "`build` rejects auth keys…" are superseded by this spec;
"Velociraptor egress rule must allow the service's real install path" is subsumed by §6.3/§6.4;
"Decide where the Velociraptor server lives" is resolved (VPS).

## 13. Out of scope

- Multi-server or failover. One VPS, one IP.
- Client-side proxy support for egress-filtered sites.
- Any change to the responder-side analyst follow-on.
- Automating VPS provisioning. The responder doc gets the manual steps.
