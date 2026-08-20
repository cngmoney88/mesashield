# MesaShield privacy

MesaShield is built to be the most privacy-respecting security tool you can run: it protects
the machine without turning the machine into a data source. This document states plainly what
it does and does not do, and how to verify it.

## What MesaShield collects about you

Nothing. There is no MesaShield company server, no account, no analytics, and no telemetry in
the app. Scanning, the learning models, quarantine, and logs all live on the machine and never
leave it.

## The only outbound traffic that exists

Three things, all optional or data-free, all visible in the app's **Privacy** page and recorded
in its audit log:

| Destination | Why | What is sent |
|---|---|---|
| `bazaar.abuse.ch` | Download public malware-hash lists (definitions) | Nothing about you — a plain file download |
| `api.github.com` | Check your own repo for app updates | Nothing about you |
| `virustotal.com` | **Optional**, only if you set a key | A file's SHA-256 fingerprint — never the file itself, never file contents |

Requests use a generic `User-Agent: MesaShield` with no machine name, user name, or version.

## Privacy modes

Set in **Privacy → Network policy**:

- **Standard** — definition and app updates run; cloud reputation runs only if you added a
  VirusTotal key.
- **Strict** — cloud reputation is hard-blocked at the network layer, so no file fingerprint
  can leave the machine even by accident. Definition/app updates (which send nothing about you)
  still work.
- **Offline** — MesaShield makes zero internet connections. Definitions come only from a local
  mirror folder you point it at (e.g. a share on your server). Full air-gap compatible.

The mode is enforced by a single network chokepoint every request must pass through — it isn't
just a UI preference.

## Verify it yourself

- **Privacy page → Recent outbound connections:** a live audit of every connection the app
  attempted, its purpose, and whether it was allowed or blocked.
- **The audit file:** `%LocalAppData%\MesaShield\Logs\network-audit.jsonl` — plain JSON lines.
- **The source:** it's all open in this repo. The network chokepoint is
  `MesaShield.Core/Privacy/PrivacyGuard.cs`; grep the codebase for `HttpClient` — there is
  exactly one, and it is wrapped by the privacy handler.
- **A packet capture** (Wireshark / your firewall) in Offline mode will show no MesaShield
  traffic at all.

## Your data controls

- **Log auto-purge:** delete activity logs older than N days (Privacy page).
- **Erase all learned data:** one click wipes every model, learned baseline, and log on the
  machine. MesaShield re-learns from scratch afterward.
- **Local storage only:** quarantined files are AES-encrypted; nothing is uploaded.

## Running fully air-gapped

Set mode to **Offline**, and set **Local update mirror** to a folder (e.g. a share on your
SERVER) where an admin drops the `*.hashes` definition files. Machines pull definitions from
there on their schedule and never touch the internet. App updates in this mode are done by
running a new installer, not over the network.
