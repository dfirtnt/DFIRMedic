# Triage playbook

Two custom Velociraptor artifacts, checked into `server/artifacts/` and loaded onto
a server with:

```bash
velociraptor --config <server.config.yaml> query \
  "SELECT artifact_set(prefix='Custom.', definition=read_file(filename='server/artifacts/<file>.yaml')) FROM scope()"
```

(the Hetzner Terraform in `infra/hetzner/` does this automatically at first boot for
both artifacts below). Restart the Velociraptor service after loading on an
already-running server so the GUI picks up the new artifact immediately, rather than
waiting for its own periodic reload.

Every artifact name referenced below was checked against a live server's
`artifact_definitions()` on 2026-09-06 (Velociraptor 0.77.2) — names drift between
releases (see `docs/responder-setup.md` §7's original `Windows.KapeFiles.Targets`
reference, which no longer exists). Re-verify names before reusing this against a
different Velociraptor version.

## Custom.Windows.KapeTriage

Raw-disk file grab via `Windows.Collectors.File`'s NTFS accessor: `$MFT`, `$LogFile`,
`$UsnJrnl:$J`, registry hives, event logs, prefetch, Amcache, LNK/jumplists. This is
what `responder-setup.md` §7.2 originally meant by "KAPE triage target list" — no
external KAPE binary involved, Velociraptor's own raw NTFS reader does the same job.

Run this first (per §7's ordering) since it captures the file-level evidence a later,
noisier collection could disturb.

## Custom.DFIRMedic.BaselineTriage

One collection, no parameters, for "where do I even start" on a host with no specific
lead yet. Bundles 16 built-in artifacts as named sources in a single flow:

| Source | Artifact | Answers |
|---|---|---|
| Autoruns | `Windows.Sysinternals.Autoruns` | What auto-starts |
| Services | `Windows.System.Services` | What's installed as a service |
| ScheduledTasks | `Windows.System.TaskScheduler` | What's scheduled |
| WMIPersistence | `Windows.Persistence.PermanentWMIEvents` | WMI event subscriptions |
| Prefetch | `Windows.Forensics.Prefetch` | What ran, when |
| Shimcache | `Windows.Registry.AppCompatCache` | Execution evidence (no timestamp reliability) |
| Amcache | `Windows.Forensics.Amcache` | Execution evidence with first-run time |
| UserAssist | `Windows.Registry.UserAssist` | GUI-launched programs per user |
| BAM | `Windows.Forensics.Bam` | Per-user last-run times |
| RunMRU | `Windows.Timeline.Registry.RunMRU` | Run-dialog history |
| RecentLnk | `Windows.Forensics.Lnk` | Recently opened files |
| RecycleBin | `Windows.Forensics.RecycleBin` | Deleted files, anti-forensics |
| RDPLogons | `Windows.EventLogs.RDPAuth` | Lateral movement via RDP |
| LiveNetstat | `Windows.Network.Netstat` | Current connections |
| LiveProcesses | `Windows.System.Pslist` | Current processes |
| YaraProcessSweep | `Windows.Detection.Yara.Process` | Bundled default rule only matches one Cobalt Strike variant — swap in case-specific rules for real hunting |

This is breadth, not depth. It was built and loaded (`artifact_set`) on the lab
server on 2026-09-06 and confirmed to parse and launch (flow `F.DAEVEKQB9EB9S`
against client `C.29a19f07ac314755`), but **not yet confirmed end-to-end** — the
test VM went offline mid-run, so the flow is queued rather than completed. Verify a
full run lands cleanly before relying on this during a real incident.

For a specific IOC (hash, IP, known-bad path) rather than a lead-less baseline, use
`Windows.EventLogs.EvtxHunter` with an `IocRegex` directly instead — this bundle
doesn't include it since it needs input to be useful.

## Order for a first connect

1. `Custom.Windows.KapeTriage` — raw file evidence, before anything else touches the host.
2. `Custom.DFIRMedic.BaselineTriage` — the "what's here" sweep.
3. Anything IOC-specific once the above two give you a lead.
