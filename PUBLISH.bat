@echo off
setlocal enabledelayedexpansion
rem ============================================================
rem  MesaShield — one-click publish to GitHub
rem  Double-click this file. It extracts the newest source,
rem  commits it, tags the version, and pushes to GitHub so the
rem  Actions build produces a release your PCs auto-update from.
rem ============================================================
cd /d "%~dp0"
title MesaShield Publisher

echo.
echo   MesaShield Publisher
echo   ====================
echo   Folder: %CD%
echo.

rem --- 0. Sanity: is this a git repo? ---
if not exist ".git" (
  echo   [X] This folder is not a git repository ^(no .git folder^).
  echo       Put PUBLISH.bat inside your MesaShield repo folder and try again.
  echo.
  pause & exit /b 1
)

rem --- 1. Apply the new source payload if one is sitting here ---
if exist "%~dp0update-payload.zip" (
  echo   [*] Applying new source from update-payload.zip ...
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "try { Expand-Archive -LiteralPath '%~dp0update-payload.zip' -DestinationPath '%~dp0' -Force; Write-Host '       done.' } catch { Write-Host ('       ERROR: ' + $_.Exception.Message); exit 1 }"
  if errorlevel 1 ( echo   [X] Could not extract the payload. & pause & exit /b 1 )
) else (
  echo   [i] No update-payload.zip here — publishing whatever is already in the folder.
)

rem --- 2. Make sure git knows who you are (prevents the "Author identity unknown" failure) ---
for /f "delims=" %%n in ('git config user.name 2^>nul') do set GN=%%n
if "!GN!"=="" (
  echo   [*] Setting git identity ...
  git config user.name  "Creede"
  git config user.email "creede@mesafab.com"
)

rem --- 3. Read the version straight from the project file ---
set VER=
for /f "tokens=3 delims=<>" %%v in ('findstr /c:"<Version>" MesaShield.App\MesaShield.App.csproj') do set VER=%%v
if "!VER!"=="" (
  echo   [X] Could not read ^<Version^> from MesaShield.App\MesaShield.App.csproj
  pause & exit /b 1
)
echo   [i] Version to publish: v!VER!
echo.

rem --- 4. Stage + commit everything (skip cleanly if nothing changed) ---
git add -A
git diff --cached --quiet
if errorlevel 1 (
  git commit -m "Release v!VER!" 1>nul
  echo   [*] Committed release v!VER!.
) else (
  echo   [i] No file changes to commit — will still ensure the tag + push.
)

rem --- 5. Tag the version (force-move if it already exists locally) ---
git tag -f "v!VER!" 1>nul
echo   [*] Tagged v!VER!.

rem --- 6. Push branch, then the tag (force the tag so re-publishes work) ---
echo.
echo   [*] Pushing to GitHub ...
for /f "delims=" %%b in ('git rev-parse --abbrev-ref HEAD') do set BR=%%b
git push origin "!BR!"
if errorlevel 1 (
  echo   [X] Push of the code failed ^(see the message above^). Nothing was tagged on GitHub.
  echo       Most common cause: you need to sign in to GitHub once in this window.
  pause & exit /b 1
)
git push -f origin "v!VER!"
if errorlevel 1 (
  echo   [X] Push of the tag failed ^(see above^).
  pause & exit /b 1
)

echo.
echo   ============================================================
echo   [OK] Published v!VER! to GitHub.
echo.
echo   The build now runs automatically. Watch it here:
echo     https://github.com/cngmoney88/mesashield/actions
echo.
echo   When it finishes ^(a few minutes^), the release appears here:
echo     https://github.com/cngmoney88/mesashield/releases
echo   and your PCs will auto-update to v!VER! on their next check.
echo   ============================================================
echo.
pause
endlocal
