# Integration test runbook (Windows VM)

Unit tests cover logic with a fake runner. These runs prove the real commands on a
real Windows 10/11 Pro VM. Snapshot the VM **before** each row and restore afterwards.

Setup once: a test tailnet with your workstation as responder, a Velociraptor server on
it, a `tag:ir-victim` ACL, and a kit built with `--ttl 2h`. Copy the kit to the VM via an
exFAT USB image or shared folder that strips Mark-of-the-Web.

| # | Scenario | Steps | Expected |
|---|---|---|---|
| 1 | Happy path | VM NIC disconnected. Run `dfirmedic.exe stage`. Reconnect NIC at READY. | Beacon → CONNECTED. Velociraptor client appears in the server GUI. `audit.jsonl` chain verifies. `manifest.json` has phases PREFLIGHT…CONNECTED. `<workdir>\volatile\` holds the nine pre-staging captures (`processes.json`, `tasklist.csv`, `netstat.txt`, `dnscache.txt`, `ipconfig.txt`, `arp.txt`, `routes.txt`, `sessions.txt`, `drivers.csv`); `baseline.json` `volatile` lists each with a SHA-256 that matches the file, and no `error` fields on a Pro edition. `netstat.txt` shows PIDs and binaries (`-b` needs the elevation preflight guarantees). |
| 1b | DHCP after quarantine | Before row 1, add a throwaway outbound allow rule for `notepad.exe` and enable the built-in `Remote Desktop` group. Stage, reconnect. | Host gets a DHCP lease and the tunnel comes up. `Get-NetFirewallRule -Enabled True` lists only the `DFIRMedic-*` group plus rules Tailscale's installer added. The `notepad.exe` rule and `Remote Desktop` group are Disabled and named in `manifest.json` `disabled_rules`. Try IPv6 too if the lab has it; ND and DHCPv6 are covered by the group but have only been checked against the fake. |
| 1c | Volatile capture tolerates a missing tool | On the VM, rename `C:\Windows\System32\query.exe` (or use a Home edition without `--rdp`). Stage. | Staging still reaches READY. `baseline.json` `volatile["sessions.txt"].error` is set; `sessions.txt` exists (empty); all other captures are intact. |
| 2 | Network already up | Leave the NIC connected. Run `stage`. | Immediate ERROR E14. No firewall or install changes (`Get-NetFirewallRule -Group DFIRMedic-*` empty). |
| 3 | Watchdog timeout | Build the kit with `--tunnel-timeout 60`. Stop the responder workstation's tailscaled. Stage, reconnect. | After ~60 s: ERROR E50, all physical adapters Disabled, firewall still default-deny, Velociraptor service not running. |
| 4 | Heartbeat loss | Build with `--heartbeat-grace 60`. After CONNECTED, stop responder tailscaled. | After ~60 s: ERROR E51, adapters Disabled, Velociraptor stopped. |
| 5 | DERP fallback | On the VM host, block outbound UDP from the VM except 53. Stage, reconnect. | CONNECTED via relay (`tailscale status` shows `relay`). |
| 6 | Reboot mid-session | After CONNECTED, reboot the VM. | Startup task runs `connect` and the watchdog/connect logic runs correctly in the background; Velociraptor stays stopped until the responder peer is verified, then starts. **No beacon is visible to anyone on-site after a reboot** — the task is registered `schtasks /SC ONSTART /RU SYSTEM`, so it runs in Session 0 with no interactive desktop. Known limitation, not a bug: verify state from the server GUI and `audit.jsonl` / `manifest.json` instead. |
| 7 | Tampered payload | Edit one byte of `payload\thor-lite.exe` on the stick. | ERROR E13 in PREFLIGHT; nothing else changes. |
| 8 | Home edition + RDP | Build with `--rdp`; run on a Windows Home VM. | ERROR E15 in PREFLIGHT. |
| 9 | Break-glass | After CONNECTED, run `dfirmedic.exe breakglass --workdir … --code WRONG` then with the right code. | Wrong: E60, nothing changes, attempt logged. Right: full teardown. |
| 10 | Teardown golden | Before row 1: `netsh advfirewall export C:\before.wfw`. Trigger row 3 or 4 (a watchdog fail-closed) first, then run `dfirmedic.exe teardown --workdir ...`. Export again after. | Rule sets and profile settings identical (compare via `Get-NetFirewallRule` / `Get-NetFirewallProfile` JSON, since `.wfw` binaries contain timestamps). Tailscale and Velociraptor services absent; startup task absent. **Adapters disabled by the fail-closed watchdog are re-enabled** — this is the specific property that used to be missing (breakglass/teardown didn't restore connectivity after a watchdog trip). `<workdir>` itself is untouched unless `--purge` was passed. |
| 11 | Dry run | `dfirmedic.exe stage --dry-run` on any VM. | **Currently fails, not a test bug:** dry-run's `sc.exe query` handling reads as "service already installed," so `stage --dry-run` halts at E16 immediately rather than reaching READY. This is a known, open defect (see spec §15) — do not treat this row's failure as a regression to chase; it will start passing once dry-run is fixed. |
