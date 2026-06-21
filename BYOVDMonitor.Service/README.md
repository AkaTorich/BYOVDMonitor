# BYOVD Monitor Service (server edition)

A headless Windows service that does what the GUI version
([BYOVDMonitor](../BYOVDMonitor/README.md)) does — but without a
window, lamp or sound: watches the configured folders, matches files
against the local loldrivers hash list (SHA-256 + Imphash +
Authentihash) and, optionally, Team Cymru MHR, then reports detections
to the **Windows event log** and/or to a **webhook** for SIEM ingest.

The detection engine is shared one-for-one with the GUI project.

## Build

    dotnet build BYOVDMonitor.Service\Service.csproj -c Release

Output: `BYOVDMonitor.Service\bin\Release\net48\BYOVDMonitorService.exe`.

## Install (on the target server, from an elevated prompt)

    BYOVDMonitorService.exe install

What `install` does:

- Creates `C:\ProgramData\BYOVDMonitor\` and **hardens the ACL** —
  only `SYSTEM` and `Administrators` have write access
  (`icacls /inheritance:r /grant:r ...`). This blocks tampering with
  the per-folder baseline from a non-privileged user account.
- Registers the `BYOVDMonitor` source in the Windows `Application`
  event log.
- Writes a default `config.json` (if one isn't already there).
- Registers the `BYOVDMonitor` service via `sc.exe`, start type
  `auto`, identity `LocalSystem`. Failure action: restart after
  60 seconds, three times.
- Starts the service.

After install, edit `C:\ProgramData\BYOVDMonitor\config.json` (see
below) and restart:

    BYOVDMonitorService.exe stop
    BYOVDMonitorService.exe start

## Commands

| Command     | Action                                                      |
|-------------|-------------------------------------------------------------|
| `install`   | Register and start the Windows service (requires elevation) |
| `uninstall` | Stop and unregister the service (requires elevation)        |
| `start`     | Start the service                                           |
| `stop`      | Stop the service                                            |
| `status`    | Show service status (`sc query`)                            |
| `console`   | Run the service core in the current console (for debugging) |
| `config`    | Print the path to `config.json`                             |

## config.json

```json
{
  "Folders": [
    { "Path": "C:\\Windows\\System32\\drivers", "IncludeSubdirectories": false },
    { "Path": "C:\\inetpub",                    "IncludeSubdirectories": true  }
  ],
  "HashListUrl": "https://www.loldrivers.io/api/drivers.json",
  "MaxFileSizeMb": 64,
  "IncludeAllExtensions": true,
  "RescanIntervalMinutes": 15,
  "MhrEnabled": false,
  "WebhookUrl": "https://siem.example.com/byovd"
}
```

- `Folders` — list of folders to watch. On a server, typically
  `System32\drivers` plus any directories where normal applications
  can drop files (downloads, web roots, profile temp paths).
- `MhrEnabled` — extra per-file lookup of new files in Team Cymru MHR
  (DNS, no API key). Sends the file's SHA-1 to an external DNS server.
  Off by default.
- `WebhookUrl` — destination for alert POSTs (`application/json`).
  Empty disables the webhook. Payload format:

```json
{
  "event": "byovd_detection",
  "time": "2026-06-21T12:37:05.9Z",
  "host": "WEBSRV01",
  "file": "C:\\inetpub\\evil.sys",
  "sha256": "77D89944...",
  "match": "Driver name from loldrivers",
  "source": "loldrivers/sha256"
}
```

`source` values:

- `loldrivers/sha256` — exact file match
- `loldrivers/imphash` — same imports as a known vulnerable driver
  (file bytes may differ)
- `loldrivers/authentihash` — same signed body as a known vulnerable
  driver
- `MHR` — file's SHA-1 is known to Team Cymru MHR

## Windows event log

Source: `BYOVDMonitor`, log: `Application`.

| EventID | Meaning                                              |
|---------|------------------------------------------------------|
| 1000    | Information (start/stop/hash list update)            |
| 2000    | **Alert: vulnerable driver detected**                |
| 3000    | Warning (scan failure, update check failure)         |
| 4000    | Error (service startup failure)                      |

Recent alerts:

    Get-WinEvent -FilterHashtable @{ LogName="Application"; ProviderName="BYOVDMonitor"; Id=2000 } -MaxEvents 20

## Data directory

`C:\ProgramData\BYOVDMonitor\`:

- `config.json`     — service configuration.
- `hashes.json`     — local loldrivers cache (SHA-256 + Imphash +
  Authentihash, ~5000 entries). Refreshed once per hour via
  conditional GET (ETag).
- `baseline\*.json` — per-root-folder cache of clean files (so
  unchanged files aren't rehashed on every rescan).

`uninstall` does **not** wipe the data directory (to make repair
re-installs easier). To remove it manually:

    Remove-Item -Recurse -Force "C:\ProgramData\BYOVDMonitor"

## Debugging

If the service fails to start, the easiest way to see the exception is
to run the same core logic in the foreground:

    BYOVDMonitorService.exe console

(does not require elevation, provided the data directory already
exists and is writable by the current user).
