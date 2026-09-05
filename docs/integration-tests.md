# Integration test runbook (Windows VM)

Unit tests cover logic with a fake runner. These runs prove the real commands on a
real Windows 10/11 Pro VM. Snapshot the VM **before** each row and restore afterwards.

Setup once: a test tailnet with your workstation as responder, a Velociraptor server on
it, a `tag:ir-victim` ACL, and a kit built with `--ttl 2h`. Copy the kit to the VM via an
exFAT USB image or shared folder that strips Mark-of-the-Web.

| # | Scenario | Steps | Expected |
|---|---|---|---|
| 1 | Happy path | VM NIC disconnected. Run `dfirmedic.exe stage`. Reconnect NIC at READY. | Beacon → CONNECTED. Velociraptor client appears in the server GUI. `audit.jsonl` chain verifies. `manifest.json` has phases PREFLIGHT…CONNECTED. |
| 2 | Network already up | Leave the NIC connected. Run `stage`. | Immediate ERROR E14. No firewall or install changes (`Get-NetFirewallRule -Group DFIRMedic-*` empty). |
| 3 | Watchdog timeout | Build the kit with `--tunnel-timeout 60`. Stop the responder workstation's tailscaled. Stage, reconnect. | After ~60 s: ERROR E50, all physical adapters Disabled, firewall still default-deny, Velociraptor service not running. |
| 4 | Heartbeat loss | Build with `--heartbeat-grace 60`. After CONNECTED, stop responder tailscaled. | After ~60 s: ERROR E51, adapters Disabled, Velociraptor stopped. |
| 5 | DERP fallback | On the VM host, block outbound UDP from the VM except 53. Stage, reconnect. | CONNECTED via relay (`tailscale status` shows `relay`). |
| 6 | Reboot mid-session | After CONNECTED, reboot the VM. | Startup task runs `connect` and the watchdog/connect logic runs correctly in the background; Velociraptor stays stopped until the responder peer is verified, then starts. **No beacon is visible to anyone on-site after a reboot** — the task is registered `schtasks /SC ONSTART /RU SYSTEM`, so it runs in Session 0 with no interactive desktop. Known limitation, not a bug: verify state from the server GUI and `audit.jsonl` / `manifest.json` instead. |
| 7 | Tampered payload | Edit one byte of `payload\thor-lite.exe` on the stick. | ERROR E13 in PREFLIGHT; nothing else changes. |
| 8 | Home edition + RDP | Build with `--rdp`; run on a Windows Home VM. | ERROR E15 in PREFLIGHT. |
| 9 | Break-glass | After CONNECTED, run `dfirmedic.exe breakglass --workdir … --code WRONG` then with the right code. | Wrong: E60, nothing changes, attempt logged. Right: full teardown. |
| 10 | Teardown golden | Before row 1: `netsh advfirewall export C:\before.wfw`. After teardown: export again. | Rule sets and profile settings identical (compare via `Get-NetFirewallRule` / `Get-NetFirewallProfile` JSON, since `.wfw` binaries contain timestamps). Tailscale and Velociraptor services absent; startup task absent. |
| 11 | Dry run | `dfirmedic.exe stage --dry-run` on any VM. | Beacon reaches READY; `audit.jsonl` lists every command as `dryrun`; no host changes. |
