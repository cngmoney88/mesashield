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

            // Copy ourselves in. If the target is locked (already running), just launch it.
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

    private static bool TryCopy(string source, string dest)
    {
        try
        {
            File.Copy(source, dest, overwrite: true);
            return true;
        }
        catch (IOException)
        {
            return false; // target locked (installed copy already running)
        }
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
