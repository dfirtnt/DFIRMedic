# Responder-side setup

One-time setup on your side. Everything the victim host does is in the spec (§5–§13).

**One node wears three hats.** `--responder-node-key`/`--responder-ip` (§4) name a single
tailnet node that the victim host trusts in three separate ways: it's the node
`ResponderOnline` polls for before starting Velociraptor, it's the only source the RDP-inbound
rule allows (if `--rdp` is set), and — since §8.3 — it's the only destination the victim's
Velociraptor client is allowed to reach at the firewall level. Nothing enforces that this is
also where your Velociraptor **server** actually listens (`--server-url`, §1) — if you run the
server on a different node than the one you name here, the firewall rule that's supposed to let
Velociraptor phone home won't cover the connection. The setup below runs all of it on one
always-on box for exactly this reason; split them only if you also adjust §8.3's egress rule
to match.

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

## 7. First-connect collection

The kit collects nothing over the wire itself; it captures pre-staging volatile state
offline (spec §8.2) and leaves everything persistent to you, because persistent
artifacts survive staging and every second offline is the gap the design minimizes.
When the client appears in the GUI, run these before anything interactive, in this order:

1. **`Windows.Search.FileFinder`** on `C:\ProgramData\DFIRMedic\<case>\**` with upload — gets you
   `manifest.json`, `audit.jsonl`, `baseline.json`, and `volatile\` (process tree with command
   lines, `netstat -anob`, DNS cache, ARP, routes, sessions, drivers, all as of before the kit
   touched the host). Verify the audit chain and the `volatile` hashes in `baseline.json` first.
2. **`Windows.KapeFiles.Targets`** with `_KapeTriage` — raw `$MFT`, `$LogFile`, `$UsnJrnl:$J`, hives,
   event logs, prefetch, Amcache, LNK/jumplists. This is the classic triage image; expect
   1–3 GB over the tunnel.
3. **`Windows.Sysinternals.Autoruns`** — the kit's own entries are the `Tailscale` and
   `Velociraptor` services and the `DFIRMedic-<case>` task; everything else is the host's.
4. **`Windows.Forensics.Prefetch`**, **`Windows.NTFS.MFT`**, **`Windows.Forensics.Usn`** as parsed
   views when you want to query rather than download.

Tool-backed artifacts (Autoruns, WinPmem for `Windows.Memory.Acquisition`) fetch their binary from
**your server's** tool cache over the tunnel, not from the internet — the victim cannot reach
GitHub. Populate the cache once, now, while the Mac has internet: Server Artifacts → Tools, or
launch each artifact once against any client. Otherwise the first real incident stalls on a
download the victim cannot make.

Make step 1 automatic if you like: a client event rule or a hunt scoped to label `ir-victim`
fires it the moment a victim checks in.

## 8. After the engagement

From your workstation, over the tunnel: `dfirmedic.exe teardown --workdir C:\ProgramData\DFIRMedic\<case>`
(via a Velociraptor `Windows.System.CmdShell` collection), then delete the node in the admin console.

> **Launch teardown detached.** Teardown's first step stops the Velociraptor
> service — the very channel you are watching the collection through — so a
> collection that waits for its own command to finish will never report a
> result, and you lose visibility partway through with the firewall only
> partially restored. Run it so it outlives the transport: wrap it in a
> scheduled task (`schtasks /Create /SC ONCE /ST <t+1min> /RU SYSTEM /Z /TR "..."`,
> or `/Run` it immediately), or `start /b` it from the CmdShell collection, and
> accept that the collection itself will not show a result. `/Z` deletes the
> ad-hoc task once it's run — teardown itself only removes its own
> `DFIRMedic-<case>` startup task, not one you create for this. Confirm the
> outcome afterwards from the host's `audit.jsonl` / `manifest.json`, or
> on-site — not from the collection output. If the tunnel is already gone,
> fall back to the local break-glass path (§10.1).
