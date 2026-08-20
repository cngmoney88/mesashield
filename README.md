# MesaShield Security

A real, working antivirus and firewall manager for Windows, built in C# / .NET 8.

**v0.2** adds AMSI script scanning, a ransomware behavior guard, cloud reputation lookups,
a system-tray presence with notifications, scheduled scans/updates, run-at-startup, and an
auto-updater. See `CHANGELOG.md`. Everything below reflects v0.2.

## What it does

**Antivirus**
- On-demand scanning (quick scan, full scan, or any folder) with three detection layers:
  1. **Signature hashes** — SHA-256 matching against MalwareBazaar (abuse.ch), a free community
     threat-intelligence feed of ~1M confirmed malware samples, with one-click updates.
  2. **Pattern rules** — a YARA-style rule engine (JSON format, extendable in `Rules/*.msrules.json`),
     with the EICAR test rule built in so you can verify detection works.
  3. **Heuristics** — double extensions (`invoice.pdf.exe`), executables disguised as images/documents,
     packed/high-entropy executables, suspicious PowerShell/script content, ransomware-style destructive
     commands, Office documents with macros. Scans inside zip archives too.
- **Real-time protection** — watches Downloads, Desktop, Temp, and any USB drive the moment it's
  plugged in; malicious files are quarantined automatically.
- **Process monitoring** — scans the executable behind every newly launched program; kills and
  quarantines anything that matches a known threat.
- **Quarantine** — detected files are AES-encrypted (can never execute) with byte-exact restore
  for false positives.

**Firewall**
- Live view of every TCP connection and which app owns it (same API netstat uses).
- One-click block/allow per application — writes real Windows Firewall rules, grouped under
  "MesaShield" so they're easy to find and remove.

**App**
- Dark-themed dashboard: protection status, signature count, threat counters, activity log.

## Building it (on your Windows machine)

1. Install the .NET 8 SDK: https://dotnet.microsoft.com/download/dotnet/8.0 (SDK, not just runtime)
2. Open a terminal in this folder and run:
   ```
   dotnet build -c Release
   dotnet test                # 11 engine tests, incl. EICAR detection — should all pass
   ```
3. Run the app:
   ```
   dotnet run --project MesaShield.App -c Release
   ```
   Or publish a standalone exe you can pin to the taskbar:
   ```
   dotnet publish MesaShield.App -c Release -r win-x64 --self-contained -o publish
   ```
   → `publish\MesaShield.App.exe`

**Run as administrator** for the full experience: firewall rule changes, event-driven process
monitoring, and scanning other users' folders all need elevation. Everything else works as a
standard user.

## First run

1. Go to **Updates** → **Download full database** (~50 MB, ~1M signatures from MalwareBazaar).
2. Real-time protection starts automatically.
3. Verify it works: create a text file containing the EICAR test string (search "EICAR test file" —
   it's a harmless industry standard) in your Downloads folder. MesaShield should quarantine it
   within seconds. Note: Windows Defender will probably grab it first — that's both AVs working.

## Living alongside Windows Defender

MesaShield is not registered with Windows Security Center (that requires Microsoft's vetted
partner program), so Defender stays active alongside it. That's fine — they don't conflict, and
during development it's actually what you want. You may want to add MesaShield's data folder
(`%LocalAppData%\MesaShield`) to Defender's exclusions so quarantined (encrypted) files and
signature downloads don't get flagged.

## Project layout

| Project | What's in it |
|---|---|
| `MesaShield.Core` | Scan engine, signature DB, pattern rules, heuristics, quarantine, updater, event log. Cross-platform, fully unit-tested. |
| `MesaShield.Windows` | Real-time watcher, USB detection, process watcher, firewall manager, connection monitor. |
| `MesaShield.App` | WPF dashboard. |
| `MesaShield.Tests` | Engine test suite (xUnit). |

## Adding your own detection rules

Drop a file like this into `%LocalAppData%\MesaShield\Rules\myrules.msrules.json`:

```json
[
  {
    "name": "My.CustomRule",
    "severity": "Malicious",
    "strings": ["some-string-that-only-appears-in-the-malware"],
    "condition": "any",
    "description": "Why this rule exists"
  }
]
```

## Roadmap (the honest version)

- v0.1 (this): full user-mode AV + firewall manager ✅
- Next: system tray + Windows notifications, scheduled scans, settings persistence,
  self-contained installer (MSIX/Inno Setup), scan-result caching by hash
- Later: browser download hooks (AMSI), central dashboard for multiple shop machines
- Commercial-scale (requires a company + Microsoft partnership): kernel minifilter driver,
  ELAM, Windows Security Center registration via the Microsoft Virus Initiative
