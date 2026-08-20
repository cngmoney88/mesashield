# Turning on automatic self-update (one-time, ~15 minutes)

This makes every copy of MesaShield update itself from GitHub — no rebuilds, no dropping
files, nothing for you to do after this. You do it once.

## What you'll end up with

- A private GitHub repo holding the MesaShield code.
- A build robot (GitHub Actions) that, every time a new version is tagged, builds the app,
  runs the tests, and publishes the new `.exe` as a downloadable Release.
- MesaShield on each machine set to watch that repo. It checks daily, and when a new
  version appears it downloads and installs it on its own, then relaunches.

## Step 1 — Make a GitHub account and repo

1. If you don't have one, create a free account at https://github.com (I can't create
   accounts for you, but it's quick).
2. Click the **+** at top-right → **New repository**. Name it `mesashield`. Set it to
   **Private**. Don't add a readme. Click **Create repository**.

## Step 2 — Upload the code

Easiest way, no command line:

1. On the new repo's page, click **uploading an existing file**.
2. Unzip the MesaShield source I gave you, then drag **all** of its files and folders into
   the upload box (including the hidden `.github` folder — if your file explorer hides it,
   turn on "show hidden files" first, or use the git steps below).
3. Click **Commit changes**.

If you're comfortable with git instead:

```
cd path\to\MesaShield
git init
git add .
git commit -m "MesaShield v0.3"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/mesashield.git
git push -u origin main
```

## Step 3 — Publish the first release

A "release" is what MesaShield updates to. Tag a version and the build robot does the rest.

Command line:

```
git tag v0.3.0
git push origin v0.3.0
```

Or on the website: **Releases** (right sidebar) → **Draft a new release** → in "Choose a
tag" type `v0.4.0` and pick "Create new tag" → **Publish release**. The Actions robot
starts building; in a couple of minutes the release will have `MesaShield-Setup.exe` attached
(a self-contained installer — no .NET or anything else needed on the machines you run it on).

You can watch it under the repo's **Actions** tab.

## Step 4 — Point MesaShield at the repo

On each machine, open MesaShield → **Settings** → **Update source**, and enter:

```
YOUR-USERNAME/mesashield
```

(just the `owner/repo`, e.g. `creede/mesashield`). Tick **Automatically check for new
versions**, then **Save settings**. Done.

Because the repo is private, MesaShield needs to be able to read it. For a private repo,
either make just the *releases* accessible, or keep it simple and mark the repo **Public**
(the code isn't secret — it's your own security tool). If you'd rather keep it private,
tell me and I'll add token-based auth to the updater.

## From now on

To ship an update, you (or I, in a session) bump the version and push a new tag
(`v0.3.1`, `v0.4.0`, …). Every machine picks it up automatically within a day — or
immediately if someone clicks **Check now** in Settings. That's the whole loop.

## Deploying to the shop machines (one click each)

Once a release is published, each company machine gets MesaShield the same easy way:

1. Download `MesaShield-Setup.exe` from the repo's **Releases** page (or put it on a USB
   stick / shared folder and carry it around).
2. Double-click it once. It installs itself, makes a Desktop + Start Menu shortcut, starts
   protecting, and sets itself to launch on every boot. No admin prompt, no .NET to install,
   nothing else to click.
3. First launch, open **Settings**, set **Update source** to `YOUR-USERNAME/mesashield`,
   tick auto-update, **Save**. From then on that machine self-updates forever.

That's the whole rollout: one download, one double-click per machine.

When we build the central dashboard later, this same pipeline is how updates and policy
push out fleet-wide — and how each machine reports its status back to you.
