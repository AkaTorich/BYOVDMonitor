# BYOVD Monitor

A lightweight detector for known-vulnerable drivers on Windows. Watches
configured folders, hashes new and changed PE files, and matches them
against a local copy of the [loldrivers.io](https://www.loldrivers.io/)
database. On a match, you get a real-time alert.

Two editions share the same detection engine:

- **[Desktop edition (GUI)](BYOVDMonitor/README.md)** — a plain WPF
  application with a status lamp, sound alerts and a live detection
  log. For workstations and admin-driven monitoring.
- **[Server edition (service)](BYOVDMonitor.Service/README.md)** —
  a headless Windows service that runs as `LocalSystem`, writes alerts
  to the Windows event log and (optionally) POSTs them to a webhook for
  SIEM ingest. For servers.

No kernel driver, no code-signing certificate required — both editions
run entirely in user mode.

## Why it works

BYOVD attacks rely on the driver's **existing valid signature**. The
attacker ships the binary unchanged, because any byte tweak breaks the
signature and the driver won't load on systems that enforce signing.
That makes hash-based detection on disk a good fit: the attacker has
no incentive to modify the file.

For the corner cases — minor recompiles or in-place patching that
preserves the signature — the engine also matches by **Imphash** (the
import-table fingerprint) and **Authentihash** (the signed body of the
PE excluding the certificate blob). A match on any of the three is an
alert.

## What gets detected

- Appearance of a known-vulnerable driver in a monitored folder
  (downloads, temp directories, `System32\drivers`, web roots, etc.).
- Pre-existing or modified files that happen to match a known
  vulnerable driver by SHA-256, Imphash, or Authentihash.
- **The driver install itself**, wherever the file lands. The engine
  watches the Windows event log (`Service Control Manager` 7045 in the
  *System* log, plus `4697` in *Security* when audit is enabled) for a
  new kernel-mode driver service, resolves its image path and hashes
  that file against loldrivers — so a driver dropped in a random temp
  path, outside every monitored folder, is still caught. User-mode:
  reading the event log needs no kernel driver.
- **Suspicious driver signatures**: an installed driver whose
  Authenticode signature is revoked, explicitly distrusted, from an
  untrusted root, tampered, or missing. Checked with `WinVerifyTrust`
  (revocation only against the local CRL cache, never the network), as
  a low-confidence heuristic for drivers not yet in loldrivers.
- Optional second layer: per-file lookup of new files in
  [Team Cymru MHR](https://team-cymru.com/community-services/mhr/)
  by SHA-1 over DNS (no API key required, off by default).

Every detection carries a **confidence** level — `High` for an exact
content match (SHA-256 / Authentihash) or a known-bad driver install,
`Medium` for a Team Cymru MHR verdict, `Low` for an Imphash-only match
(the import fingerprint is often shared between unrelated drivers) or a
signature heuristic. It is shown in the GUI column, the event-log
alert and the webhook payload.

## Detection time and resource use

Detection is faster than the driver-load sequence on the same machine,
so the engine flags files **before** they can be loaded into the kernel
on a normal install path. Resource use is minimal: a cheap PE
pre-filter discards non-PE files for almost free, and a per-folder
baseline skips rehashing of unchanged files between scans. A periodic
deep rescan (default once per day) recomputes everything from scratch
to close a narrow tamper window.

## Build

Build with the .NET SDK (the engine targets .NET Framework 4.8):

    dotnet build BYOVDMonitor\BYOVDMonitor.csproj         -c Release
    dotnet build BYOVDMonitor.Service\Service.csproj      -c Release

Outputs (all build artifacts land in one solution-level `bin\`, set by
`Directory.Build.props`):

- `bin\BYOVDMonitor.exe`
- `bin\BYOVDMonitorService.exe`

See each edition's README for installation, configuration, and
operational details:

- **[BYOVDMonitor/README.md](BYOVDMonitor/README.md)** — desktop edition
- **[BYOVDMonitor.Service/README.md](BYOVDMonitor.Service/README.md)** — server edition

## Limitations

- Detects **known** vulnerable drivers only — coverage is bounded by
  the freshness of the loldrivers list (refreshed automatically once
  per hour).
- Detects appearance on disk and the driver-service **install** event,
  not the in-kernel load instruction itself. Blocking the load outright
  would need a signed kernel driver, which is intentionally out of
  scope here. The event-log layer narrows the gap: the install is seen
  regardless of where the file sits.
- Both editions run in user mode. An attacker who already has admin
  on the host can stop the process or service. Pair with a hardened
  baseline (e.g. WDAC / HVCI driver block list) for defense in depth.

## License

No third-party packages. The detection engine is plain C# against
.NET Framework 4.8.
