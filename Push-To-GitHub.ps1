<#
  Push-To-GitHub.ps1 — puts MesaShield on GitHub and publishes the first release,
  which is what turns on automatic updates + hosts the installer for the shop machines.

  RUN THIS FROM INSIDE the extracted MesaShield source folder (the one that contains
  MesaShield.sln and the .github folder).

  Before running: create an EMPTY repo on github.com named "mesashield"
  (no README, no .gitignore). Then run:

      powershell -ExecutionPolicy Bypass -File .\Push-To-GitHub.ps1 -Owner YOURNAME

  On the first push a browser window opens to sign you into GitHub — that's normal,
  it's how Git logs in without you typing a password.
#>
param(
    [Parameter(Mandatory = $true)][string]$Owner,   # your GitHub username
    [string]$Repo = "mesashield",
    [string]$Tag  = "v0.8.0"
)

$ErrorActionPreference = "Stop"

# 1. Git installed?
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "Git isn't installed. Get it from https://git-scm.com/download/win, then re-run this." -ForegroundColor Red
    return
}

# 2. Make sure we're in the repo root.
if (-not (Test-Path ".\MesaShield.sln")) {
    Write-Host "Run this from the MesaShield source folder (the one with MesaShield.sln)." -ForegroundColor Red
    return
}

# 3. Identity (only sets locally if you haven't set it globally).
if (-not (git config user.email)) { git config user.email "creede@mesafab.com" }
if (-not (git config user.name))  { git config user.name  "$Owner" }

# 4. A .gitignore so build junk doesn't get committed.
@"
bin/
obj/
*.user
"@ | Out-File -Encoding ascii .gitignore

# 5. Init, commit, push.
if (-not (Test-Path ".git")) { git init | Out-Null }
git add -A
git commit -m "MesaShield $Tag" | Out-Null
git branch -M main
git remote remove origin 2>$null
git remote add origin "https://github.com/$Owner/$Repo.git"
Write-Host "Pushing code to https://github.com/$Owner/$Repo ..." -ForegroundColor Cyan
git push -u origin main

# 6. Tag → triggers the build robot to publish the release with the installer.
git tag $Tag 2>$null
git push origin $Tag
Write-Host ""
Write-Host "Done. Watch the build at https://github.com/$Owner/$Repo/actions" -ForegroundColor Green
Write-Host "In a few minutes the Releases page will have MesaShield-Setup.exe." -ForegroundColor Green
Write-Host "Then in MesaShield -> Settings -> Update source, enter:  $Owner/$Repo" -ForegroundColor Yellow
