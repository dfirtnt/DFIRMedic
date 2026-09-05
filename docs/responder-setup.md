# Responder-side setup

One-time setup on your side. Everything the victim host does is in the spec (§5–§13).

## 1. Velociraptor server on an always-on tailnet node

Install Velociraptor on the always-on box, then in `server.config.yaml` bind
every listener to that node's tailnet IP — never `0.0.0.0`:

```yaml
Frontend:
  bind_address: 100.x.y.z
  bind_port: 8000
GUI:
  bind_address: 100.x.y.z
  bind_port: 8889
```

Generate the client config the kit ships:

```bash
velociraptor --config server.config.yaml config client > payload/velociraptor.client.yaml
```

Its `Client.server_urls` must be `https://100.x.y.z:8000/` (the tailnet IP).

## 2. Tailnet ACL

In the Tailscale admin console → Access controls:

```json
{
  "tagOwners": { "tag:ir-victim": ["autogroup:admin"] },
  "acls": [
    { "action": "accept", "src": ["tag:ir-victim"], "dst": ["100.x.y.z:8000"] },
    { "action": "accept", "src": ["<your workstation user or tag>"], "dst": ["tag:ir-victim:3389"] }
  ]
}
```

The first rule is the only reach a victim node has. The second exists only for the RDP opt-in.
Turn **device approval** on so a stolen key cannot silently join.

## 3. Exit node and domain allowlist

Advertise an exit node on your side and enforce the VirusTotal / Microsoft allowlist there
with DNS filtering. The victim never talks to those services directly; you submit hashes.

## 4. Responder identity for the kit

```bash
tailscale status --json --self | jq -r '.Self.PublicKey, .Self.TailscaleIPs[0]'
```

Use those as `--responder-node-key` and `--responder-ip`.

## 5. Signing key and embedded public key (once)

```bash
make build-darwin
./dist/dfirmedic keygen
```

Copy the printed `make build-windows LDFLAGS=...` line and run it. The public key is
now compiled into `dist/dfirmedic.exe`; every kit must be signed with the matching
private key at `~/.dfirmedic/responder.key`. Back that file up offline.

## 6. Per incident

1. Admin console → Settings → Keys → Generate auth key:
   **Reusable: off. Ephemeral: on. Pre-authorized: on. Tags: tag:ir-victim. Expiry: 1 hour.**
2. Format the USB **exFAT** (macOS: `diskutil eraseDisk ExFAT DFIRMEDIC /dev/diskN`).
3. Build the kit:

```bash
./dist/dfirmedic build \
  --case CASE-2026-0042 \
  --authkey tskey-auth-... \
  --responder-node-key nodekey:... --responder-ip 100.x.y.z \
  --server-url https://100.x.y.z:8000/ \
  --name "Your Name" --phone "+1..." \
  --breakglass-code "$(openssl rand -hex 4)" \
  --out /Volumes/DFIRMEDIC
```

4. `./dist/dfirmedic verify --kit /Volumes/DFIRMEDIC`
5. Print `FIELD-CARD.txt` from the stick and hand both to the on-site person.
6. Keep the break-glass code with you; read it over the phone only if rollback is needed.

## 7. After the engagement

From your workstation, over the tunnel: `dfirmedic.exe teardown --workdir C:\ProgramData\DFIRMedic\<case>`
(via a Velociraptor `Windows.System.CmdShell` collection), then delete the node in the admin console.
