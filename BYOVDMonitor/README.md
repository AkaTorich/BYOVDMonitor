# BYOVD Monitor

A lightweight user-mode detector for known-vulnerable drivers (BYOVD).
No kernel driver, no code-signing certificate — a plain WPF application
(.NET Framework 4.8).

The administrator configures a list of folders. In real time and on
periodic rescans, the app hashes every PE file in those folders and
compares the hash against a local copy of the loldrivers.io database.
On a match, a red lamp lights up, an alert sound plays, and the entry
appears in the detection log with one-click access to the file's folder.

## What it detects

Appearance of a known-vulnerable driver **file** in a monitored folder
(downloads, temp directories, `System32\drivers`, artifact-collection
paths, etc.). This is file-on-disk detection by hash, not interception
of the kernel load itself — for that you'd need a signed kernel driver,
which is intentionally not used here.

Because BYOVD attacks rely on the driver's existing valid signature,
attackers ship the binary unchanged. SHA-256 matching catches that.
For minor binary tweaks (resources, debug info, sections shuffled)
that change SHA-256 but not the import table, **Imphash** still matches.
For tweaks anywhere inside the signed body, **Authentihash** still
matches. Any of the three matches raises the alert.

## Features

- Configurable list of monitored folders (with "include subfolders" option).
- Real-time `FileSystemWatcher` plus startup and periodic full rescans.
- Hash list from loldrivers.io is stored **locally** (`hashes.json`).
  On first run the app offers to download it; once per hour it checks
  for updates (conditional GET via ETag) and offers to refresh. Only
  the update fetch goes over the network.
- Per-folder baseline (local cache): SHA-256 of already-checked clean
  files is remembered, so unchanged files (same size + mtime) are
  skipped without rehashing on repeated scans and across restarts.
  Vulnerable files are never cached and are flagged every time.
- Cheap PE pre-filter: a new/changed file is first checked for an
  "MZ…PE" header (68 bytes read); only if it's a PE image
  (`.sys`/`.exe`/`.dll`/`.ocx`/`.efi`, etc.) is the full SHA-256
  computed. Text, images and archives are skipped at near-zero cost.
- **Triple matching**: SHA-256 + Imphash + Authentihash. Imphash (MD5
  of imported function names, pefile format) is stable against
  cosmetic byte tweaks; it only changes when the driver is recompiled
  with different dependencies. Authentihash is the SHA-256 of the PE
  body with the CheckSum field and the signature blob excluded:
  catches tampering inside the signed image. A match on any of the
  three raises an alert; the log row's `Source` column tells you which
  one fired (`loldrivers/sha256`, `loldrivers/imphash`,
  `loldrivers/authentihash`).
- Optional second layer — **Team Cymru MHR**: new files (from the
  watcher) that don't match loldrivers are looked up by SHA-1 over DNS
  (`<sha1>.malware.hash.cymru.com`), no API key. Throttled to one
  request per 250 ms; off by default.
- Manual file check (the **Check file…** button) — runs loldrivers
  and MHR against an arbitrary file you pick.
- Lamp indicator: grey (no list / idle), green (clean), red blinking
  (detection).
- Sound notification on detection (toggleable).
- Detection log: source of the match, "Open folder" (Explorer with the
  file selected) and "Copy SHA-256".

## Build

    dotnet build BYOVDMonitor.csproj -c Release

Output: `bin\Release\net48\BYOVDMonitor.exe`. You can also open the
`.csproj` in Visual Studio and build the usual way.

## Where the data lives

`%APPDATA%\BYOVDMonitor\`:

- `config.json` — settings and the list of folders.
- `hashes.json` — local copy of the loldrivers hash list (with the
  ETag for efficient update checks).
- `baseline\*.json` — per-root-folder cache of clean files (hashes of
  files already verified, so they aren't rehashed next time).

## Sources

- **Primary** (offline list pull):
  `https://www.loldrivers.io/api/drivers.json` (~30 MB; ~5000+ entries
  with SHA-256, ~37% of them also carry Imphash and Authentihash).
  URL is configurable in `config.json` (`HashListUrl`). loldrivers
  aggregates several sources, including Microsoft's recommended
  driver block list.
- **Optional, per-file lookup**: Team Cymru MHR over DNS
  (`<sha1>.malware.hash.cymru.com`), no API key. Toggle in the window.

## Limitations

- File hashing capped at 64 MB per file (configurable, `MaxFileSizeMb`);
  real drivers are tiny.
- The "skip unchanged" optimisation uses size + mtime. If an attacker
  modifies a file and restores those attributes, the file will be
  treated as unchanged until the next real change. To force a fresh
  check: "Scan now" or "Check file…".
- MHR sends the file's SHA-1 to an external DNS server (third party);
  off by default for that reason.
- The first scan of large recursive trees can take time; subsequent
  scans are fast thanks to the per-folder baseline.
