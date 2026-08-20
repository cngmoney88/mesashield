# Deploying MesaShield across the shop

Three ways, smallest to biggest. All of them end with each machine protected, self-updating,
and reporting to your Fleet dashboard.

## The one-time prep (do this once)

1. **Turn on self-update + fleet reporting for the whole shop** by creating a deploy config.
   Copy `deploy/MesaShield.deploy.example.json` to `MesaShield.deploy.json`, and set:
   - `FleetSharedFolder` → a folder on your server every machine can reach,
     e.g. `\\SERVER\MesaShield\status`. Create that folder and give the machines write access.
   - `UpdateChannel` → your GitHub `owner/repo` once the pipeline is set up (see
     `SETUP-GITHUB-AUTOUPDATE.md`).
   Keep this file next to `MesaShield-Setup.exe` — the installer applies it automatically, so
   machines come up already configured with zero clicking.

2. **(Recommended) Sign the app** so nobody sees a SmartScreen warning — see "Code signing" below.

## Option A — walk up to each machine (simplest)

Put `MesaShield-Setup.exe` (and `MesaShield.deploy.json` beside it) on a USB stick or a shared
folder. On each machine, double-click `MesaShield-Setup.exe`. It installs itself, starts
protecting, sets itself to run at startup, and picks up your deploy config. Done — one
double-click per machine.

## Option B — push from one place with a script

From an admin machine that can reach the others via PowerShell remoting:

```powershell
# One machine:
.\deploy\Deploy-MesaShield.ps1 -Setup .\MesaShield-Setup.exe

# Several machines at once:
.\deploy\Deploy-MesaShield.ps1 -Setup .\MesaShield-Setup.exe -Computers PC-1,PC-2,SHOP-3
```

It copies the installer (and deploy config) to each machine and runs it silently (`--silent` —
installs and starts with no window). Nothing to click on the far end.

## Option C — Group Policy / Intune (for a managed domain)

- **GPO:** put `MesaShield-Setup.exe --silent` in a per-user logon script (User Configuration →
  Policies → Windows Settings → Scripts → Logon). Because the install is per-user and needs no
  admin, this "just works" at next sign-in. Drop `MesaShield.deploy.json` next to the exe on the
  share the script runs from.
- **Intune:** package `MesaShield-Setup.exe` as a Win32 app with install command
  `MesaShield-Setup.exe --silent` and a detection rule checking for
  `%LocalAppData%\Programs\MesaShield\MesaShield.App.exe`.

## Code signing (removes the SmartScreen warning)

The app runs fine unsigned, but Windows shows a blue "unknown publisher" box the first time.
To remove it:

1. Buy an **Authenticode** code-signing certificate (a standard OV cert is ~$200-400/yr; an
   **EV** cert costs more but earns SmartScreen trust immediately). Vendors: DigiCert, Sectigo,
   SSL.com, and others.
2. Export it as a `.pfx`, then add two secrets to your GitHub repo (Settings → Secrets and
   variables → Actions):
   - `CODE_SIGN_PFX_BASE64` — the .pfx file base64-encoded
     (`[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pfx"))`).
   - `CODE_SIGN_PASSWORD` — the .pfx password.
3. That's it — the release pipeline signs every build automatically. No secrets = unsigned build,
   no error.

This is the only "constraint" between you and a shop-grade installer, and it's just a purchase +
two secrets. (The deeper constraint — a kernel driver / official-AV registration — is a separate,
company-level path and isn't needed for everything MesaShield does.)

## After deployment

Open the **Fleet** tab on any machine (pointed at the same shared folder) to see every machine's
health, version, alerts, quarantine, and learning progress in one place. Updates flow
automatically from your GitHub releases; signatures update on their own schedule.
