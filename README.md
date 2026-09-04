# DFIRMedic

Sneakernet-deployed rescue kit for a compromised Windows host that has been taken offline.

An on-site person runs the kit from a USB stick. It stages a default-deny firewall, Tailscale, and a Velociraptor client while the machine is still offline, then signals when it is safe to reconnect Wi-Fi. Seconds later, a tunnel is up to the responder's workstation — and only that workstation — and triage is driven remotely.

Design: [docs/superpowers/specs/2026-09-04-dfirmedic-design.md](docs/superpowers/specs/2026-09-04-dfirmedic-design.md)
