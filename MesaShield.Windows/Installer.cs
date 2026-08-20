using System.Diagnostics;

namespace MesaShield.Windows;

/// <summary>
/// Makes the single .exe act as its own installer. The first time it's run from anywhere
/// that isn't the install location (a USB stick, Downloads, a network share), it copies
/// itself into a per-user Programs folder, creates Start Menu and Desktop shortcuts, and
/// relaunches from there. No admin rights, no separate setup wizard — one double-click on
/// each company machine installs and starts it, and it auto-starts on every boot after.
/// </summary>
public static class Installer
{
    public static string InstallDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Programs", "MesaShield");

    public static string InstalledExePath => Path.Combine(InstallDirectory, "MesaShield.App.exe");

    /// <summary>
    /// Ensure the app is installed. Returns true if it installed and launched the installed
    /// copy (the caller should then exit immediately). Returns false when already running from
    /// the install location, so normal startup should proceed.
    /// </summary>
    public static bool EnsureInstalled(string[] args, out string message)
    {
        message = "";
        if (!OperatingSystem.IsWindows()) return false;

        var currentExe = Environment.ProcessPath;
        if (currentExe is null) return false;

        // Already running from the install location → run normally.
        if (PathsEqual(currentExe, InstalledExePath)) return false;

        // Explicit "portable"/"no-install" escape hatch.
        if (args.Contains("--no-install")) return false;

        var silent = args.Contains("--silent");

        try
        {
            Directory.CreateDirectory(InstallDirectory);

            // DOWNGRADE GUARD: never let an older installer overwrite a newer installed build.
            // (This is what caused "it reverts to v0.8.0" — an old installer from a stale GitHub
            // release was replacing a newer install. Now the old one refuses and launches the newer.)
            if (File.Exists(InstalledExePath) && IsOlderThanInstalled(currentExe))
            {
                Process.Start(new ProcessStartInfo { FileName = InstalledExePath, Arguments = "--installed", UseShellExecute = true });
                message = "A newer MesaShield is already installed — kept it and launched it (downgrade blocked).";
                return true;
            }

            // The installed copy is likely already running (it auto-starts to the tray), which
            // would lock its .exe and make the copy below fail — the old cause of "it reverts to
            // the old version." Stop any running installed instance first, then copy with retries.
            StopInstalledInstances();
            var copied = TryCopy(currentExe, InstalledExePath);

            // Carry a deployment config (if the admin shipped one beside the installer) into the
            // install folder so the installed app picks up fleet folder / update source on first run.
            var srcConfig = Path.Combine(Path.GetDirectoryName(currentExe)!, MesaShield.Core.DeployConfig.FileName);
            if (File.Exists(srcConfig))
                try { File.Copy(srcConfig, Path.Combine(InstallDirectory, MesaShield.Core.DeployConfig.FileName), overwrite: true); } catch { }

            if (!silent) CreateShortcuts();

            Process.Start(new ProcessStartInfo
            {
                FileName = InstalledExePath,
                Arguments = silent ? "--installed --minimized" : "--installed",
                UseShellExecute = true,
            });

            message = copied
                ? $"Installed to {InstallDirectory} and launched."
                : "MesaShield was already installed; launched the installed copy.";
            return true;
        }
        catch (Exception ex)
        {
            // If install fails for any reason, fall back to running in place rather than not at all.
            message = $"Install step skipped ({ex.Message}); running in place.";
            return false;
        }
    }

    /// <summary>True if the running installer's version is older than the currently-installed exe.</summary>
    private static bool IsOlderThanInstalled(string currentExe)
    {
        try
        {
            static Version Read(string path)
            {
                var v = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
                return new Version(v.FileMajorPart, v.FileMinorPart, v.FileBuildPart, v.FilePrivatePart);
            }
            return Read(currentExe) < Read(InstalledExePath);
        }
        catch { return false; }   // if we can't tell, don't block the install
    }

    /// <summary>Terminate any MesaShield already running from the install location so its file can be replaced.</summary>
    private static void StopInstalledInstances()
    {
        foreach (var p in Process.GetProcessesByName("MesaShield.App"))
        {
            if (p.Id == Environment.ProcessId) continue;
            try
            {
                string? path = null;
                try { path = p.MainModule?.FileName; } catch { /* access denied — fall through and stop it anyway */ }
                if (path is null || PathsEqual(path, InstalledExePath))
                {
                    p.Kill(entireProcessTree: true);
                    p.WaitForExit(5000);
                }
            }
            catch { /* already gone / protected */ }
        }
    }

    private static bool TryCopy(string source, string dest)
    {
        // Retry a few times — the previous instance may take a moment to release the file.
        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                File.Copy(source, dest, overwrite: true);
                return true;
            }
            catch (IOException) when (attempt < 4)
            {
                Thread.Sleep(700);
            }
            catch (IOException)
            {
                return false;
            }
            catch (UnauthorizedAccessException) when (attempt < 4)
            {
                Thread.Sleep(700);
            }
        }
        return false;
    }


    private static void CreateShortcuts()
    {
        var startMenu = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "MesaShield.lnk");
        var desktop = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "MesaShield.lnk");

        CreateShortcut(startMenu);
        CreateShortcut(desktop);
    }

    /// <summary>Create a .lnk via Windows Script Host (through PowerShell, so we need no COM reference).</summary>
    private static void CreateShortcut(string lnkPath)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(lnkPath)!);
            var ps =
                $"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{lnkPath}');" +
                $"$s.TargetPath='{InstalledExePath}';" +
                $"$s.WorkingDirectory='{InstallDirectory}';" +
                $"$s.Description='MesaShield Security';" +
                $"$s.Save()";
            var startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -WindowStyle Hidden -Command \"{ps}\"",
                CreateNoWindow = true,
                UseShellExecute = false,
            };
            Process.Start(startInfo)?.WaitForExit(5000);
        }
        catch
        {
            // A missing shortcut isn't fatal — the app still installs and runs.
        }
    }

    private static bool PathsEqual(string a, string b)
    {
        try { return string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase); }
        catch { return false; }
    }
}
