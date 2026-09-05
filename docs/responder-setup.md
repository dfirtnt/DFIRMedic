# Responder-side setup

One-time setup on your side. Everything the victim host does is in the specs
(`docs/superpowers/specs/`). The victim reaches exactly one thing: your Velociraptor
frontend at a fixed public IP. It never runs Tailscale and never resolves a name.

## 1. Velociraptor server on a VPS

A small Linux VPS with a **static public IPv4**, nothing else on it. On it:

```bash
# as root
useradd --system --home /opt/velociraptor --shell /usr/sbin/nologin velociraptor
mkdir -p /opt/velociraptor /var/lib/velociraptor && chown velociraptor: /opt/velociraptor /var/lib/velociraptor
# install the same release as payload/velociraptor.exe (currently 0.77.2)
curl -fsSL -o /opt/velociraptor/velociraptor https://github.com/Velocidex/velociraptor/releases/download/v0.77.2/velociraptor-v0.77.2-linux-amd64
chmod 0755 /opt/velociraptor/velociraptor
# join the tailnet so you can reach the GUI; the victim never uses this
curl -fsSL https://tailscale.com/install.sh | sh && tailscale up
TAILNET_IP=$(tailscale ip -4)
PUBLIC_IP=$(curl -fsS https://api.ipify.org)
/opt/velociraptor/velociraptor config generate --merge "{
  \"Frontend\": {\"hostname\": \"$PUBLIC_IP\", \"bind_address\": \"0.0.0.0\", \"bind_port\": 443},
  \"GUI\": {\"bind_address\": \"$TAILNET_IP\", \"bind_port\": 8889, \"public_url\": \"https://$TAILNET_IP:8889/app/index.html\"},
  \"API\": {\"bind_address\": \"127.0.0.1\"}, \"Monitoring\": {\"bind_address\": \"127.0.0.1\"},
  \"Datastore\": {\"location\": \"/var/lib/velociraptor\", \"filestore_directory\": \"/var/lib/velociraptor\"},
  \"Client\": {\"server_urls\": [\"https://$PUBLIC_IP:443/\"]}
}" > /opt/velociraptor/server.config.yaml
chown velociraptor: /opt/velociraptor/server.config.yaml && chmod 0600 /opt/velociraptor/server.config.yaml
/opt/velociraptor/velociraptor --config /opt/velociraptor/server.config.yaml user add admin --role administrator
/opt/velociraptor/velociraptor --config /opt/velociraptor/server.config.yaml service install   # systemd unit
# host firewall: only 443 public; SSH and GUI over the tailnet
ufw default deny incoming && ufw allow 443/tcp && ufw allow in on tailscale0 && ufw enable
```

Binding to port 443 as a non-root user needs `setcap cap_net_bind_service=+ep /opt/velociraptor/velociraptor`
or `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the unit.

Confirm `Client.server_urls` in the generated config is `https://<public-ip>:443/` — an IP,
never a hostname — then export the client config the kit ships:

```bash
/opt/velociraptor/velociraptor --config /opt/velociraptor/server.config.yaml config client > velociraptor.client.yaml
```

Copy that file to `payload/velociraptor.client.yaml` on your Mac. `dfirmedic build` reads the
CA and `install_path` out of it and refuses a client config whose `server_urls` does not
list your `--server-url`. **If the VPS IP ever changes, every kit built against it is dead.**

Put the datastore on an encrypted volume; the VPS holds evidence.

## 2. Tailnet

Only you and the VPS. No victim tags, no victim grants, no RDP. The default
`autogroup:member → autogroup:member` grant is enough. Keep device approval on.

## 3. Tool cache

Artifacts with a tool dependency (Autoruns) fetch the binary from **your server**, never
the internet. Seed it once: GUI → View Artifacts → `Windows.Sysinternals.Autoruns` → Tools →
Upload `payload/tools/autorunsc64.exe`, or from the VPS
`velociraptor --config server.config.yaml tools upload --name Autorun_amd64 autorunsc64.exe`
followed by a service restart. Memory acquisition needs nothing: WinPmem is built into the client.

## 4. Sanity check from the responder side

```bash
openssl s_client -connect <public-ip>:443 </dev/null 2>/dev/null | openssl x509 -noout -issuer
```

The issuer must be your Velociraptor CA. The kit does the same check on the victim
(spec 2026-09-05 §7); if this fails here it will fail there.

## 5. Signing key and embedded public key (once)

```bash
make build-darwin
./dist/dfirmedic keygen
```

Copy the printed `make build-windows LDFLAGS=...` line and run it. The public key is
now compiled into `dist/dfirmedic.exe`; every kit must be signed with the matching
private key at `~/.dfirmedic/responder.key`. Back that file up offline.

## 6. Per incident

1. Format the USB **exFAT** (macOS: `diskutil eraseDisk ExFAT DFIRMEDIC /dev/diskN`).
2. Build the kit:

```bash
./dist/dfirmedic build \
  --case CASE-2026-0042 \
  --server-url https://<public-ip>:443/ \
  --name "Your Name" --phone "+1..." \
  --breakglass-code "$(openssl rand -hex 4)" \
  --out /Volumes/DFIRMEDIC
```

3. `./dist/dfirmedic verify --kit /Volumes/DFIRMEDIC`
4. Print `FIELD-CARD.txt` from the stick and hand both to the on-site person.
5. Keep the break-glass code with you; read it over the phone only if rollback is needed.

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
3. **`Windows.Sysinternals.Autoruns`** — the kit's own entries are the `Velociraptor`
   service and the `DFIRMedic-<case>` task; everything else is the host's.
4. **`Windows.Forensics.Prefetch`**, **`Windows.NTFS.MFT`**, **`Windows.Forensics.Usn`** as parsed
   views when you want to query rather than download.

Tool-backed artifacts fetch their binary from your server's tool cache, not the internet — see §3.

Make step 1 automatic if you like: a client event rule or a hunt scoped to label `ir-victim`
fires it the moment a victim checks in.

## 8. After the engagement

From your workstation, over the tunnel: `dfirmedic.exe teardown --workdir C:\ProgramData\DFIRMedic\<case>`
(via a Velociraptor `Windows.System.CmdShell` collection).

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
