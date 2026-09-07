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

`API.bind_address` above is loopback-only and needs no firewall rule or kit change, so its
port is free to move. On a responder Mac running Docker Desktop, `config generate`'s default
API port (8001) collides with Docker's own `*:8001` listener — check first with
`lsof -nP -iTCP:8001 -sTCP:LISTEN` and add `"API": {"bind_address": "127.0.0.1", "bind_port": 8501}`
(or any free port) to the merge above if it's taken.

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

`build` also parses the CA as an X.509 certificate — a PEM block that is not really a
certificate fails here rather than as an E50 on the victim ten minutes in — and requires
`Client.windows_installer.install_path` to be at least `<drive>:\<dir>\<file>`, so a
drive-root path such as `C:\Velociraptor.exe` will not build.

Keep that path at least two directories deep; the Velociraptor default
`$ProgramFiles\Velociraptor\Velociraptor.exe` is what you want. Teardown deletes the
*parent directory* of `install_path` with `rmdir /s /q`, and it refuses to do that when the
parent is a drive root or a single top-level directory — `$ProgramFiles\Velociraptor.exe`
would make that parent all of `C:\Program Files`. Such a kit still stages and runs, but
teardown logs a refusal for that one step (everything else still reverses) and the
Velociraptor files have to be removed by hand.

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
2. **`Custom.Windows.KapeTriage`** — raw `$MFT`, `$LogFile`, `$UsnJrnl:$J`, hives, event logs,
   prefetch, Amcache, LNK/jumplists via `Windows.Collectors.File`'s NTFS accessor. This server's
   Velociraptor version has no `Windows.KapeFiles.Targets`/`_KapeTriage` (removed/renamed
   upstream) — see `docs/triage-playbook.md` and `server/artifacts/`. Expect 1–3 GB over the
   tunnel.
3. **`Custom.DFIRMedic.BaselineTriage`** — bundles Autoruns, services, scheduled tasks, WMI
   persistence, Prefetch/Shimcache/Amcache/UserAssist/BAM/RunMRU execution evidence, recent
   LNK/RecycleBin, RDP logons, live process/network state, and a YARA sweep into one flow. See
   `docs/triage-playbook.md` for the full source list and how it's loaded onto a server.
4. **`Windows.Forensics.Prefetch`**, **`Windows.NTFS.MFT`**, **`Windows.Forensics.Usn`** as parsed
   views when you want to query rather than download (also covered raw by step 2).

Tool-backed artifacts fetch their binary from your server's tool cache, not the internet — see §3.

Make step 1 automatic if you like: a client event rule or a hunt scoped to label `ir-victim`
fires it the moment a victim checks in.

## 8. After the engagement

From your workstation, over the tunnel: `C:\ProgramData\DFIRMedic\<case>\dfirmedic.exe teardown`
(via a Velociraptor `Windows.System.CmdShell` collection) — `--workdir` defaults to the
directory of that exe, so the full path above is all `CmdShell` needs.

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

## 9. Error codes you are most likely to be phoned about

The on-site person reads the code off the beacon; you decide what happens next.
Every code is also in `audit.jsonl` in the working directory, with the underlying error.

**E18 — the shipped client config does not belong to the signed server.** The CA in
`payload/velociraptor.client.yaml` does not match `server.ca_sha256` in `incident.json`
(or the file is missing/unreadable). Nothing has been changed on the host: staging stops
in preflight, and the reboot-resume path (`connect`) stops before it probes. It means the
kit was assembled wrong — a client config from a different or rebuilt server — not that
the host is compromised in a new way. Rebuild the kit from the *current* server's
`config client` output and re-run; do not try to patch the stick in the field.

**E41 — Velociraptor installed itself somewhere the firewall does not allow.** `service
install` registered the service from a path other than `install_path`, so the client would
start and then be silently blocked by the default-deny egress rule. This one leaves the
host **quarantined, with the service installed and no startup task**, so it will not come
back by itself after a reboot. Recovery is the local break-glass path: read the
break-glass code to the on-site person and have them run

```
dfirmedic.exe breakglass --code <code>
```

run from `C:\ProgramData\DFIRMedic\<case>` — `--workdir` defaults to the directory of
whichever `dfirmedic.exe` copy is running it, so no path needs to be read over the phone.
Pass `--workdir` explicitly only when invoking a copy from somewhere else (e.g. the USB).

which reverses staging (service, install directory, firewall, adapters) and puts the host
back the way it was. Then fix the kit — the usual cause is an `install_path` in the client
config that does not match where that Velociraptor build actually installs — and start over.

**E50 / E51 — the server could not be verified, or stopped being verifiable.** The host
fails closed: Velociraptor is stopped and every adapter is disabled, firewall still locked.
The beacon and `audit.jsonl` now carry the last probe error, and `probe_failed` records name
the server and the reason. "certificate not signed by the pinned CA" means something else is
answering on that IP (captive portal, proxy, wrong host); a dial timeout means the network
never came up. If you cannot fix it from your side, break-glass as above.
