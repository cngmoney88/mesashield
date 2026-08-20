# MesaShield changelog

## v0.17.0 — hands-off updates + live traffic
- **Fully automatic updates.** The GitHub update source is pre-configured, and updates now
  download, verify, and install on their own on a schedule — no clicking, and no SmartScreen
  prompt (the internet mark is stripped only after the SHA-256 check passes). Downgrade-guarded.
- **Live Traffic view.** The Traffic page now shows every outbound connection as it happens —
  program, destination, and the decision — so you can watch exactly where data goes. Reminder:
  Observe mode only watches; switch to Enforce to actually block data leaving.
- **.NET baked in:** the GitHub self-contained installer needs no prerequisites on any PC.

## v0.16.0 — Fleet Command + downgrade fix
- **Downgrade guard (fixes the "reverts to v0.8.0" regression).** MesaShield now refuses to
  install any build older than what is already installed — both the installer and the in-app
  updater check the version first. A stale GitHub release can no longer drag a machine backward.
- **Fleet Command center.** The Fleet tab can now push actions to any machine or the whole
  fleet — Quick/Full scan, Update signatures, Check for app update, and set Egress mode — over
  the same shared folder, no server software. Machines apply pushed commands within a minute and
  report richer status (deep monitoring, elevation, egress mode, blocks/24h).

## v0.15.0 — tamper-proofing / self-defense
- **Self-healing.** A watchdog checks every minute that each protection module is running and
  restarts any that were stopped, logging it as a possible tamper attempt and notifying you.
- **Hard to kill.** The elevated autostart is now a resilient scheduled task that relaunches
  MesaShield within minutes if it is killed (paired with single-instance, kill = it comes back),
  auto-restarts on failure, and is re-registered automatically if someone deletes it.

## v0.14.0 — one app, one window
- **Single instance.** MesaShield can no longer open a second window. Launching it again (or
  clicking any copy of the exe) simply brings the one running window to the front. Ends the
  "which app am I looking at" confusion.

## v0.13.0 — one-tap deep monitoring
- **Deep monitoring now elevates itself.** Click "Enable deep monitoring" on the dashboard,
  approve one Windows prompt, and MesaShield registers a scheduled task that launches it with
  administrator rights at every logon — silently, no more prompts. ETW deep monitoring and
  active firewall/egress blocking then run automatically from then on.

## v0.12.0 — data-loss prevention (egress control)
- **New Traffic page.** See every outbound connection live — which program, where it's going
  (with resolved hostname), and MesaShield's decision and reasoning for each.
- **Learns essential vs non-essential.** The network learner builds a per-machine profile of the
  destinations each program normally uses; core OS plumbing (Windows Update, DNS, NTP, certs) is
  recognized as essential and never blocked.
- **Stops data leaving.** Three modes: Off, Observe (alert only), and Enforce — which blocks
  connections to destinations a program has never used, and treats a large upload to a brand-new
  external host as exfiltration. Blocking is done via the Windows Firewall (needs admin).
- **You stay in control:** approve or block any destination from the Traffic view; your choices
  persist and override the automatic decisions.

## v0.11.0 — update reliability
- **Fixed the "reverts to the old version" bug.** The installer now stops any running installed
  copy (which auto-starts to the tray and locked its own file) before replacing it, with retries.
  This is why re-running the installer kept bouncing back to the previous version.
- **Reliable in-app "Update now."** Instead of an in-place exe swap that Windows blocks, the app
  now hands off to the downloaded self-installer after it exits, and clearly tells you to expect
  (and approve) the SmartScreen prompt — with a fallback that opens the installer's folder if the
  handoff can't start. No more silent no-ops.
- Fixed the "vv0.10.0" version label (now shows "v0.10.0").

## v0.10.0 — privacy hardening
- **Provable no-phone-home.** Every outbound request now passes through a single network
  chokepoint that enforces policy and records the decision. There is no MesaShield server and
  no telemetry anywhere — this makes that verifiable, not just a claim.
- **Three privacy modes:** Standard (updates on, cloud lookup only with a key), Strict (no file
  fingerprint ever leaves the machine — cloud lookups hard-blocked), and Offline (zero internet
  connections; definitions come from a local mirror folder on your server).
- **Privacy page** in the app: pick the mode, see every address the app could contact and why,
  read the live outbound-connection audit log, set log auto-purge, and one-click erase all
  learned data and logs.
- **Local signature mirror** so offline fleets update definitions from a LAN share, never the
  internet. Generic User-Agent — no machine/user/version fingerprint in requests.

## v0.9.0 — learned classifier
- **One-class "known-good" model.** MesaShield can now learn the statistical profile of
  legitimate software and flag files that don't fit — real, data-trained ML that needs no
  malware samples and runs entirely offline. Conservative by design (flags "suspicious," never
  auto-quarantines).
- **One-click training in the app.** Settings → "Build known-good model from this PC" learns
  from the software already installed on the machine (Program Files, System32). Nothing is
  uploaded. A Python trainer (`ml-training/train_benign_model.py`) is included for building a
  shared model to distribute to the fleet.
- Honest note: a full malware/clean-corpus classifier (EMBER-style) remains a separate offline
  project; this one-class approach is the safe, genuinely-trained path shipping now.

## v0.8.0 — deep monitoring
- **ETW deep monitoring.** Real-time, system-wide telemetry via Event Tracing for Windows:
  every process start (with true parent-process info) and outbound TCP connection feeds the
  on-device learners. Enables detections like "a document reader just connected to an internet
  address this machine has never contacted" — the shape of data exfiltration and C2 beacons.
  Needs administrator; degrades gracefully to the existing layers when not elevated.
- **Network anomaly learning.** Learns which external endpoints each program normally talks to
  and flags novel connections. Fully on-device.

## v0.7.0 — fleet rollout
- **Silent install** (`--silent`) — push MesaShield to many machines with no clicks.
- **Deploy config** — ship a `MesaShield.deploy.json` next to the installer and each machine
  comes up already pointed at your shared fleet folder and update source.
- **Deployment tooling** — `deploy/Deploy-MesaShield.ps1` (push to one or many machines),
  a deploy-config example, and `DEPLOYMENT.md` covering USB, script push, GPO/Intune, and signing.
- **Code signing** wired into the release pipeline (add a cert as two repo secrets to remove
  the SmartScreen warning; unsigned still works).

## v0.6.0 — the shop dashboard
- **Fleet dashboard.** A new Fleet tab shows every Mesa Fab machine at a glance — health,
  version, protection state, signature count, 24h alerts, quarantine, and what each has
  learned. Each machine writes a small status file to a shared folder on your server
  (e.g. \\SERVER\MesaShield\status); any machine's Fleet tab reads them all. Stays entirely
  on your LAN — no cloud, no server software to run.
- Quieted benign "access denied" log noise from the process monitor.

## v0.5.0 — it learns
- **On-device adaptive learning.** MesaShield now learns what's normal for each machine —
  which programs run, from where, signed or not, at what hours — using online anomaly
  detection (running statistics + decayed novelty models). After a warm-up it flags genuine
  outliers with plain-English reasons ("first time this program has run; unsigned; from Temp;
  at 3am"). Fully local: the model is a few KB of counts, nothing leaves the device, and it
  keeps adapting as the machine's normal drifts.
- **Offline ML malware classifier.** A logistic model scores unknown PE files locally from
  static features (entropy, section stats, imports, header shape). Ships with a conservative
  baseline model so it works immediately; a model trained on a real corpus (see
  `ml-training/train_classifier.py`, works with the open EMBER dataset) drops in and updates
  like a signature file. No file contents are ever uploaded.
- Both are on by default and toggle in Settings. Privacy by construction — all learning and
  inference happen on the machine.

## v0.4.0 — one-click deploy
- **Self-installing.** The single .exe is now its own installer: run it once from anywhere
  (USB, Downloads, a share) and it copies itself into %LocalAppData%\Programs\MesaShield,
  creates Start Menu + Desktop shortcuts, sets run-at-startup, and relaunches. One click per
  company machine; auto-starts on every boot after. No admin rights needed.
- Shipped **self-contained** — no .NET or anything else required on the target machine.

## v0.3.1
- Skips online-only OneDrive/cloud files instead of forcing them to download during scans.
- Sidebar now shows the real app version (was a hardcoded "0.1.0" label).

## v0.3.0 — the "seamless" release
- **One-click self-update.** "Update now" no longer asks you to do anything: MesaShield
  downloads the new version, swaps itself out, and relaunches automatically.
- **Zero-click first run.** On first launch it downloads the full signature database in the
  background and notifies you when protection is fully active — no manual "download database" step.
- **GitHub auto-update pipeline.** A ready-to-use GitHub Actions workflow builds, tests, and
  publishes each release; point the app at your repo and every machine self-updates forever.
  See `SETUP-GITHUB-AUTOUPDATE.md`.
- Ships as a single ~730 KB .exe — double-click to run (uses the .NET 8 already on the machine).

## v0.2.0 — the "runs hands-off, and much more advanced" release

New protection layers:
- **AMSI script scanning** — MesaShield now scans scripts (PowerShell, VBScript, JS, batch,
  HTA) through the Windows Antimalware Scan Interface. This catches obfuscated and
  runtime-decoded scripts — the fileless-attack technique plain file scanning misses —
  and pulls in the verdict of every AMSI provider on the machine (including Defender).
- **Ransomware behavior guard** — watches your Documents, Pictures, and Desktop for the
  *behavior* of ransomware rather than any specific file:
  - Hidden **canary/decoy files** are seeded in each folder; any write to one is a
    near-certain ransomware signal and triggers an immediate block.
  - **Mass-encryption detection** — a burst of file rewrites with high-entropy
    (encrypted) content, or files suddenly gaining extensions like `.locked`/`.encrypted`,
    trips the alarm and the offending process is terminated.
- **Cloud reputation (VirusTotal)** — optional second opinion from 70+ engines. Add a free
  API key in Settings; lookups run only on already-suspicious files to respect the free
  rate limit, and verdicts are cached on disk.

Runs hands-off:
- **System-tray icon** with a right-click menu (open, quick scan, pause/resume protection,
  quit) and **Windows notifications** for every block. Closing the window now minimizes to
  the tray; quit from the tray menu to fully exit.
- **Scheduled scans and signature updates** — set a daily/weekly/hourly cadence in Settings.
  Missed windows (machine asleep) run on next wake.
- **Run at startup** — launches minimized to the tray when you sign in.

Keeps itself current:
- **Auto-updater for the app itself** — point it at a GitHub `owner/repo` or a release
  manifest URL. It checks on a schedule, shows an in-app banner when a new version is out,
  and downloads it (verifying the published SHA-256 before accepting the file).

Plus: a full **Settings** page for every toggle, schedule, and key; persisted configuration.

Test suite: 33 tests, all passing (engine, quarantine, scheduling, semver, settings,
behavior engine, reputation client, update checker).

## v0.1.0 — first working build
- On-demand scanner: signature hashes (MalwareBazaar), pattern rules (YARA-style + EICAR),
  heuristics, zip inspection.
- Real-time protection, USB auto-scan, process monitoring.
- AES-encrypted quarantine with byte-exact restore.
- Firewall manager: live connection viewer + per-app block/allow.
- Dark-themed WPF dashboard.
