# DFIRMedic — Design Spec

**Date:** 2026-09-04
**Status:** Draft for review
**Author:** starlord, with Claude

## 1. Summary

DFIRMedic is a sneakernet-deployed rescue kit for a compromised Windows host that has been taken offline. A non-technical person on site copies the kit from a USB stick and runs it. The kit stages everything it needs while the machine is still offline — including a default-deny outbound firewall — then tells the person to reconnect Wi-Fi. Within seconds of the NIC coming up, a Tailscale tunnel is established to the responder's workstation and only that workstation, a Velociraptor client calls home over it, and the responder drives triage interactively from their own machine.

The kit's job is to make the window between "NIC up" and "tunnel verified" both short and safe, and to leave an evidentiary record of everything it touched.

## 2. Goals

- Establish a secure tunnel between the victim host and the responder's workstation, reachable by no other tailnet node.
- Minimize the time the host is online before that tunnel is verified, and make that window safe by pre-staging a default-deny outbound firewall.
- Support interactive remote triage: event log interrogation, process inspection, autoruns, YARA/IOC scanning, and arbitrary artifact collection.
- Require nothing of the on-site person beyond "run this, wait for green, reconnect Wi-Fi, leave."
- Record every change to the host in a tamper-evident manifest, and fully reverse those changes at teardown.
- Cost nothing beyond what the responder already has. No code-signing certificate.

## 3. Non-goals

- Not a general EDR or fleet tool. One host, one incident, one responder.
- Not a replacement for offline imaging. If the host has a kernel-level implant, nothing this kit produces is trustworthy; that's the point where the responder stops and images the disk.
- Not proof of containment. Firewall lockdown is a speed bump against commodity malware, not a guarantee against a live operator with SYSTEM.
- Does not solve initial access. A person must be physically at the machine.
- No AI on the victim host, and no AI in the trust path. The staging state machine, containment decisions, and chain of custody are deterministic and auditable. AI assistance is a separate responder-side component (see §17, Follow-on).

## 4. Decisions (locked)

| Decision | Choice | Rejected alternatives and why |
|---|---|---|
| Tunnel | Tailscale | Static WireGuard (needs a hosted endpoint, no relay fallback); Headscale (too much ops for a few uses a year) |
| Egress policy | Layered: local Windows Firewall default-deny with a minimal allowlist; real domain whitelist enforced at the responder's exit node | Local-only IP allowlist (CDN ranges shift, brittle); tunnel-only with no local fallback (goes dark if tunnel drops) |
| Collection model | Tunnel-first, all interactive | Offline-first collection (optimizes total online time, which is not the goal — the goal is the pre-tunnel gap) |
| Local UI | Status beacon only, for a non-technical operator | Runbook or console UIs expose tooling and findings to whoever is at the keyboard |
| Key handling | Per-incident `incident.json` on the USB, ed25519-signed, carrying an ephemeral tagged Tailscale auth key with ~1h TTL | Compile-per-incident (needs toolchain at incident time); key typed at runtime (long string in front of a non-technical person) |
| Footprint | Installed, documented, reversible: Tailscale MSI and Velociraptor service persist across reboot | Userspace networking or strictly portable (reboot or crash strands the host offline with nobody on site) |
| Orchestrator | Thin Go binary, unsigned, `CGO_ENABLED=0`, console TUI | `tsnet` in-process (custom networking code); PowerShell (most-scrutinized thing on Windows) |
| Code signing | None. USB formatted exFAT strips Mark-of-the-Web, so SmartScreen does not prompt | Paid cert (rejected on cost); SignPath (requires public OSS); Azure Trusted Signing ($9.99/mo, unnecessary) |
| Scope | Internal use on systems the responder's own organization owns | Service-provider / client engagements (would change the THOR Lite license position and the Tailscale plan) |
| Server hosting | Always-on tailnet node running the Velociraptor server | Mac with sleep disabled (lid-close drops the session); VPS (evidence on a third party's disk) |
| GUI access | VQL-only by default; RDP over the tailnet as an opt-in flag | MeshCentral (another server and another agent); RDP by default (pollutes logon events, absent on Windows Home) |
| Scanner | THOR Lite | LOKI-RS (beta). THOR Lite permits commercial use but not service-provider use; acceptable under the internal-use scope |
| Key minting | Responder mints the ephemeral key in the Tailscale admin console and pastes it into `dfirmedic build` | OAuth client or API key in Keychain (a long-lived key-minting credential on the workstation, for a task done a few times a year) |

## 5. Architecture

### 5.1 Responder side

- **Velociraptor server** on an always-on tailnet node (home server, NUC, or similar), bound to its tailnet IP only, never `0.0.0.0`. It must be reachable for the whole time the victim is online; the responder's Mac is the analyst console only and may sleep freely.
- **Tailnet ACL:** `tag:ir-victim` may reach exactly one host (the Velociraptor server) on exactly one port. No other tailnet nodes are reachable from a victim node. Device auto-approval off.
- **Exit node** on the responder side enforces the real domain allowlist (VirusTotal, Microsoft, etc.) with DNS-based filtering. The victim host never talks to those services directly; the responder submits hashes from their own side.
- **`dfirmedic build` CLI:** assembles the per-incident config. The responder mints an ephemeral, pre-authorized, `tag:ir-victim` auth key with a short TTL in the Tailscale admin console and pastes it in; the CLI writes and signs `incident.json`, verifies payload hashes, and copies the kit to the USB. No Tailscale API integration.

### 5.2 Victim side

Everything runs from the USB, is copied to a working directory on the host, and is orchestrated by `dfirmedic.exe`.

## 6. USB layout

```
dfirmedic.exe                   Go orchestrator, unsigned
incident.json                   per-incident config (see 7)
incident.json.sig               ed25519 signature
FIELD-CARD.txt                  printed instructions for the on-site person
payload/
  tailscale-setup.msi           vendor-signed, unmodified
  velociraptor.exe              vendor-signed, stock — never repacked
  velociraptor.client.yaml      external client config (preserves Authenticode)
  tools/
    autorunsc64.exe             Microsoft-signed
    procexp64.exe               Microsoft-signed
    pslist64.exe                Microsoft-signed
    thor-lite.exe               THOR Lite (Nextron)
    thor-lite.lic               THOR Lite license file
    signatures/                 THOR Lite signature set
  manifest.sha256               hashes of every file in payload/
```

The USB is formatted **exFAT**. Mark-of-the-Web lives in an NTFS alternate data stream; exFAT and FAT32 have none, so files copied through the stick carry no MOTW and SmartScreen's unknown-publisher prompt does not fire.

Velociraptor's offline-collector repacking embeds config into the PE and invalidates its Authenticode signature. The kit never repacks; it ships the stock signed binary and passes config via `--config`.

## 7. `incident.json`

```json
{
  "schema": 1,
  "case_id": "CASE-2026-0042",
  "created_utc": "2026-09-04T22:15:00Z",
  "expires_utc": "2026-09-05T22:15:00Z",
  "tailscale": {
    "authkey": "tskey-auth-…",
    "hostname": "ir-CASE-2026-0042",
    "responder_node_key": "nodekey:…",
    "responder_tailnet_ip": "100.x.y.z"
  },
  "velociraptor": {
    "server_url": "https://100.x.y.z:8000/",
    "config_file": "payload/velociraptor.client.yaml"
  },
  "firewall": {
    "dns_resolvers": ["1.1.1.1", "9.9.9.9"],
    "allow_rdp_from_responder": false,
    "dns_fallback_to_dhcp": false
  },
  "watchdog": {
    "tunnel_timeout_sec": 600,
    "heartbeat_grace_sec": 300
  },
  "contact": {
    "phone": "+1 …",
    "name": "…"
  },
  "breakglass_code_hash": "sha256:…",
  "payload_manifest_sha256": "sha256:…"
}
```

The signature is verified against an ed25519 public key compiled into `dfirmedic.exe`. An unsigned or expired config is fatal in preflight. The auth key is the only secret on the stick; it is ephemeral, single-use, tagged, and expires on its own.

`payload_manifest_sha256` is the sha256 of `payload/manifest.sha256` itself (§6's per-file hash listing), carried inside the signed config. Without this field, the per-file manifest would be just another file on the USB — an attacker with physical access could swap a payload binary and regenerate `manifest.sha256` to match, and preflight's payload check (§8.1) would accept it. Binding the manifest's own hash into the signed `incident.json` means a tampered manifest can't be regenerated without the responder's private key. `dfirmedic build` computes this after writing the payload manifest and before signing; `dfirmedic verify` and preflight both check it before trusting the per-file manifest.

## 8. Staging state machine

`dfirmedic.exe stage` runs the following phases. Each phase gates the next; any failure halts and shows `ERROR`. All phase transitions are timestamped in the audit log.

### 8.1 PREFLIGHT

- Confirm elevation. The binary's embedded manifest requests `requireAdministrator` so UAC prompts up front rather than failing mid-staging.
- Verify `incident.json.sig`. Reject if invalid or `expires_utc` has passed.
- Verify SHA-256 of `payload/manifest.sha256` itself against the signed `payload_manifest_sha256`. This is what stops a regenerated manifest from covering a swapped payload file.
- Verify SHA-256 of every file under `payload/` against `manifest.sha256`.
- **Refuse to proceed if any non-loopback adapter has connectivity.** This is the check that protects the core requirement. Applies to `stage` only, not to service auto-start after reboot.
- Check Windows version, disk space, and that Tailscale and Velociraptor are not already installed.
- If `allow_rdp_from_responder` is true, confirm the edition ships a Remote Desktop server (Pro/Enterprise/Server). Home editions fail preflight with a clear error rather than failing later.

### 8.2 BASELINE

Capture evidence before touching anything.

- **Volatile state first**, to `<workdir>\volatile\`, from Windows built-ins only: process tree with command lines (`Win32_Process`), `tasklist /v`, `netstat -anob`, `ipconfig /displaydns`, `ipconfig /all`, `arp -a`, `route print`, `query user`, `driverquery /v`. This is the state INSTALL and QUARANTINE destroy or pollute (the kit's own services, task, and connections land on top of it). Each command has a 60 s timeout; a failed command is recorded in `baseline.json` next to the file's hash and does not halt staging (`query user` is absent on Home editions). Persistent artifacts — autoruns, prefetch, scheduled tasks — are deliberately not collected here: they survive staging, and every second offline is the gap this design minimizes. They are collected over the tunnel (§12).
- `netsh advfirewall export <workdir>\firewall-original.wfw`
- Dump all existing firewall rules, running services, and network adapter state to JSON.
- Record hostname, domain, OS build, system time, timezone, and clock skew against the responder's time if known.
- Open the audit log (see 11).

Attacker-installed firewall rules are evidence. This snapshot is what teardown restores.

### 8.3 QUARANTINE

Applied while offline so it is already in force when the NIC comes up.

- Enable Windows Firewall on Domain, Private, and Public profiles.
- Set `DefaultOutboundAction Block` and `DefaultInboundAction Block` on all three profiles.
- Disable every rule that was enabled before staging and is not in the `DFIRMedic-<case_id>` group. Windows evaluates enabled allow rules regardless of the profile default, so without this sweep the built-in Core Networking rules, third-party app rules, and any allow rule the intruder persisted would still match. The disabled names are recorded in the manifest as `disabled_rules`; `firewall-original.wfw` restores them at teardown.
- Create rule group `DFIRMedic-<case_id>` containing **allow rules only**. Because the sweep removes the built-ins, everything the host needs to get an address must be here too:
  - Outbound: `tailscaled.exe`, any protocol, any port (covers direct UDP and DERP fallback over TCP/443).
  - Outbound and inbound: DHCPv4 (UDP 68/67) and DHCPv6 (UDP 546/547), scoped to `svchost.exe` service `Dhcp`. Without these the host never gets an address on reconnect and the watchdog fails closed.
  - Outbound ICMPv6 133/135/136 and inbound 134/135/136 (IPv6 neighbor discovery). IPv4 ARP is below the firewall and needs nothing.
  - Outbound: UDP/TCP 53 to the pinned resolvers in `incident.json`, scoped to `svchost.exe` service `Dnscache`. Tailscale cannot bootstrap without DNS; this is easy to forget. If `dns_fallback_to_dhcp` is true, port 53 to any host is also allowed with the same service scope, for sites that block outbound DNS to the internet. The service scope is what keeps that fallback from being a DNS-tunneling exfil channel for arbitrary processes.
  - Outbound: the workdir's `velociraptor.exe`, any port, to `responder_tailnet_ip` specifically. Velociraptor is a separate process from `tailscaled` and needs its own explicit rule to reach the responder over the tunnel — this assumes the Velociraptor server and the tailnet node named by `responder_tailnet_ip`/`responder_node_key` are the same host; see the responder setup guide.
  - Inbound: TCP 3389 from `responder_tailnet_ip` only, if `allow_rdp_from_responder` is true. Remote Desktop itself is enabled in INSTALL in that case, and the change is logged.
  - Loopback.

Because explicit block rules override allow rules in Windows Firewall, the group contains no block rules at all. Everything not allowed is denied by the profile default.

Order matters: the group is added first (harmless while defaults are still Allow), then the sweep disables everything outside it, then the defaults flip. A failure at any point imports `firewall-original.wfw`; if the import itself fails, the group is removed, the profiles restored from `baseline.json`, and the swept rules re-enabled by name.

**Known limit:** on a domain-joined host whose Group Policy sets "Apply local firewall rules" to No, the whole group is ignored and the host fails closed on reconnect. Group Policy can also re-enable swept rules on refresh. The baseline export shows the policy source; check it before staging a domain machine.

**Note on Tailscale `--shields-up`:** the chat design proposed it. It is *not* used, because it blocks all inbound tailnet connections including the responder's RDP session. The tailnet ACL plus the inbound 3389 rule above achieve the same restriction more precisely.

### 8.4 INSTALL

- Install `tailscale-setup.msi` silently. This registers the `tailscaled` service and wintun driver.
- `tailscale up --authkey=<key> --hostname=<hostname> --accept-routes=false --accept-dns=false`
  The daemon will attempt to connect and fail (no network). That is expected; it retries on its own once the NIC is up.
- Install Velociraptor as a service using `velociraptor.exe --config payload\velociraptor.client.yaml service install`, then set the service to **Manual** start. It must not start until the tunnel is verified.
- If `allow_rdp_from_responder` is true, enable Remote Desktop (`fDenyTSConnections = 0`) and log the change.
- Copy `dfirmedic.exe` and `incident.json` to `<workdir>` so teardown and break-glass work without the USB.

### 8.5 READY

Beacon shows:

```
  READY
  RECONNECT NETWORK NOW
```

The orchestrator waits for link-up on any adapter.

## 9. Reconnect sequence

1. On-site person reconnects Wi-Fi.
2. Link-up detected. Watchdog starts (`tunnel_timeout_sec`).
3. Orchestrator polls `tailscale status --json` until:
   - `BackendState == "Running"`, **and**
   - a peer with `PublicKey == responder_node_key` is present and online.
   Connected is not sufficient; the kit verifies it is talking to *the responder*.
4. Start the Velociraptor service. It connects to `server_url` over the tailnet.
5. Beacon shows `CONNECTED`. Watchdog transitions to heartbeat mode.
6. On-site person leaves.

The pre-staged default-deny covers the gap between step 1 and step 3. The window exists; nothing can traverse it except `tailscaled`, the system resolver's DNS, and the DHCP and neighbor-discovery traffic in §8.3. Pre-existing allow rules are disabled, so an intruder's persisted rule does not survive the gap.

## 10. Failure handling

| Condition | Response |
|---|---|
| Tunnel not verified within `tunnel_timeout_sec` | Disable all non-loopback adapters. Keep firewall locked. Beacon: `ERROR — CALL <name> <phone>`. |
| Tunnel drops for more than `heartbeat_grace_sec` after establishment | Same as above. |
| Preflight, baseline, quarantine, or install phase fails | Halt. Beacon shows `ERROR` with a short code and the phone number. No partial quarantine is left in place — quarantine is applied last-thing-first so a failure mid-phase can be unwound. |
| Reboot | Services persist and auto-start. `tailscaled` reconnects. Velociraptor is Manual-start, so it does not come up until the orchestrator (registered as a startup task) re-verifies the responder peer and starts it. |
| Defender quarantines a payload | Staging halts at hash verification. `thor-lite.exe` is the likeliest target; it is staged but not executed until the responder invokes it. |

### 10.1 Break-glass

`dfirmedic.exe breakglass` restores the machine to its baseline: stops and removes the Velociraptor service, logs out and uninstalls Tailscale, deletes the `DFIRMedic-<case_id>` rule group, imports `firewall-original.wfw`, and re-enables every physical network adapter (undoing a fail-closed watchdog trip, if one occurred — nothing else does). It requires a code whose SHA-256 matches `breakglass_code_hash`; the responder reads the code over the phone. This is accident prevention and audit trail, not security — an attacker with admin can undo any of this manually.

## 11. Chain of custody

### 11.1 Manifest

`<workdir>\manifest.json` records:

- `case_id` and `dfirmedic.exe`'s own SHA-256.
- UTC timestamp of every phase transition.
- SHA-256 of every payload file.
- Every firewall rule created, with full rule text.
- Every command executed, with arguments, exit code, and duration.
- The baseline snapshot (8.2) in full.

### 11.2 Audit log

`<workdir>\audit.jsonl` is append-only. Each line is `{seq, ts_utc, event, data, prev_hash, hash}` where `hash = sha256(seq || ts || event || data || prev_hash)`. Tampering with any entry breaks the chain from that point forward.

### 11.3 Shipping

Manifest and audit log are shipped to the responder over the tunnel at first connect (via a Velociraptor artifact that collects `<workdir>`) and again at teardown. Collected forensic artifacts ride in Velociraptor's own collection containers, which already hash and encrypt.

## 12. Triage capability mapping

| Original requirement | Delivered by |
|---|---|
| Interactive event log interrogation | Velociraptor `Windows.EventLogs.*` artifacts and ad hoc VQL with `parse_evtx()`. `Windows.System.PowerShell` for PowerShell when wanted. |
| Process explorer | Velociraptor `Windows.System.Pslist` (hashes and signature status), `pstree`, `Windows.System.DLLs`, `Windows.System.Handles`, and `netstat()`, rendered in the Velociraptor GUI. Kill, suspend, and dump are VQL. RDP over the tailnet to run `procexp64.exe` only if `allow_rdp_from_responder` is set. |
| Autoruns | `Windows.Sysinternals.Autoruns` artifact wrapping `autorunsc64.exe`. |
| LOKI scanner | `thor-lite.exe` invoked through a custom artifact; output parsed back. Full-disk scans run for hours. |
| Remote command execution | Velociraptor `Windows.System.CmdShell` and `Windows.System.PowerShell`. |
| Filesystem and persistence artifacts (MFT, USN, prefetch, autoruns, hives, event logs) | Velociraptor `Windows.KapeFiles.Targets` (`_KapeTriage`), `Windows.NTFS.MFT`, `Windows.Forensics.Usn`, `Windows.Forensics.Prefetch`, `Windows.Sysinternals.Autoruns`. Run as the standard first-connect collection (responder-setup §7); nothing here is collected offline because none of it is destroyed by staging. |
| Pre-staging volatile state | Captured offline in BASELINE (§8.2) to `<workdir>\volatile\`; ships with the workdir at first connect. |

## 13. Teardown

`dfirmedic.exe teardown` (invoked by the responder over the tunnel, or locally). The responder ships the final manifest and audit log via a Velociraptor collection of `<workdir>` before invoking it, since teardown removes the very access that collection needs. Teardown itself, best-effort — every step runs even if an earlier one fails, and all failures join into one returned error:

1. Stop and remove the Velociraptor service.
2. Delete the startup task.
3. `tailscale logout`; uninstall the MSI.
4. Delete the `DFIRMedic-<case_id>` rule group.
5. Import `firewall-original.wfw`.
6. Re-enable every physical network adapter (undoes a fail-closed watchdog trip, if one occurred).
7. Restore profile default actions to their baseline values.

`<workdir>` itself is left in place — including the audit log and manifest — unless the responder passes `--purge`, which removes it after teardown completes.

On the responder side, the tailnet node is deleted explicitly even though the ephemeral key would expire it anyway.

## 14. Stack

- **Language:** Go. `CGO_ENABLED=0 GOOS=windows GOARCH=amd64`, cross-compiled from macOS.
- **UI:** full-screen console TUI. Large block-letter status, high contrast, one screen. No GUI toolkit — avoids CGO, keeps the binary behaviorally boring.
- **Privilege:** embedded manifest with `requireAdministrator`.
- **Crypto:** ed25519 for config signing; SHA-256 for hashing. Standard library only.
- **Every dangerous action is delegated** to a Microsoft-signed or vendor-signed binary: `netsh.exe`, `NetSecurity` cmdlets, `msiexec.exe`, `tailscale.exe`, `velociraptor.exe`. The orchestrator sequences, renders, and logs. It does not inject, pack, obfuscate, or make direct syscalls.

## 15. Testing

- **Unit:** signature verification (valid, invalid, expired), payload hash verification, audit-log chain integrity, state machine transitions including every failure branch.
- **Dry-run:** `dfirmedic.exe stage --dry-run` is intended to log every action it would take, with the exact command line, without executing — for review and for CI. **Currently broken:** the dry-run runner returns a blank success for every command including `sc.exe query`, which `Preflight`'s already-installed check reads as "service present," so `stage --dry-run` fails immediately with E16 rather than reaching READY. Needs either per-command canned responses or a redesign where dry-run executes read-only queries for real and only skips state-changing commands. Not yet fixed; tracked as a known limitation, not a documented capability.
- **Integration:** a Windows VM restored from snapshot before every run. Test matrix:
  - Happy path: stage → reconnect → tunnel verified → Velociraptor connects.
  - Watchdog: reconnect with the responder offline; adapters must go down at the timeout.
  - Heartbeat: kill the responder mid-session; adapters must go down after the grace period.
  - DERP fallback: block outbound UDP on the VM's host; tunnel must still establish over TCP/443.
  - Reboot mid-session: tunnel re-establishes; Velociraptor does not start until the peer is re-verified.
  - Defender quarantine: remove a payload file; staging must halt at hash verification.
  - Teardown golden test: `netsh advfirewall export` before staging and after teardown must be identical.

## 16. Risks

- **Defender behavioral detection.** An unknown binary that flips the firewall to default-deny and installs a VPN is a strong malware heuristic. Mitigated by delegating every such action to signed binaries. Not eliminated.
- **Tailscale licensing.** The free Personal plan is scoped to personal use. Organizational use likely belongs on a paid plan; the responder decides.
- **Not literally "only my computer."** Tailscale bootstrap contacts Tailscale's coordination plane, and traffic may relay via DERP. Traffic is end-to-end encrypted throughout, and the ACL restricts reachability, but the guarantee is policy, not topology. Accepted in exchange for zero hosting and relay resilience.
- **Live operator with SYSTEM** can disable the firewall and undo everything. The audit log will show it happened.
- **Kernel implant** invalidates all live-response output. Escalate to imaging.
- **THOR Lite license scope.** Commercial use is permitted; service-provider use is not. This kit is scoped to the responder's own organization. If it is ever used for a third party, swap in LOKI-RS (GPL-3).

## 17. Resolved questions

Settled 2026-09-04 and folded into §4:

1. Server hosting — always-on tailnet node.
2. GUI access — VQL-only by default; RDP as an opt-in flag with a preflight edition check.
3. Scanner — THOR Lite, under the internal-use scope.
4. Watchdog defaults — 600 s tunnel timeout, 300 s heartbeat grace; both configurable in `incident.json`.
5. DNS — pinned public resolvers, with `dns_fallback_to_dhcp` for sites that block outbound 53.
6. Key minting — manual paste from the Tailscale admin console; no API integration.
7. Tailscale plan — the responder's call; see §16.

### Follow-on: responder-side analyst

Out of scope for this spec; gets its own once the kit exists. An advisory component on the responder's workstation that reads the Velociraptor datastore and never touches the host directly. Planned modes, in priority order:

1. Triage copilot over collected results (event log timelining, autoruns and process-tree anomalies, YARA hit contextualization) and a VQL assistant — one component, two modes.
2. Sigma over collected `.evtx` (Hayabusa/Chainsaw or Velociraptor's own support), then AI triage of the matches rather than the raw logs.
3. Incident report drafting from manifest, audit log, and findings.

Hard rules: anything that executes on the host is gated on responder approval; no autonomous remediation; the audit log is never written by the model. Evidence leaves the responder's environment for whatever model is used, so the analyst needs a cloud/local model switch for engagements where that is contractually unacceptable.
