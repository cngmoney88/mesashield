using System.Diagnostics;
using System.IO.Compression;

namespace MesaShield.Windows;

/// <summary>
/// Applies a downloaded app update to the currently-running install with no user steps:
/// it writes a short helper batch that waits for this process to exit, swaps the new
/// executable over the old one, relaunches MesaShield, and deletes itself. The result
/// is a one-click "Update now" that fully completes on its own.
/// </summary>
public static class SelfUpdater
{
    /// <summary>
    /// Begin applying <paramref name="downloadedPath"/> (an .exe or a .zip containing the exe).
    /// On success this launches the helper and returns true; the caller should then shut the app down.
    /// </summary>
    public static bool ApplyAndRestart(string downloadedPath, out string message)
    {
        message = "";
        if (!OperatingSystem.IsWindows()) { message = "Self-update is only supported on Windows."; return false; }

        string currentExe;
        try
        {
            currentExe = Process.GetCurrentProcess().MainModule?.FileName
                         ?? throw new InvalidOperationException("Can't determine the running executable path.");
        }
        catch (Exception ex) { message = ex.Message; return false; }

        // Resolve the new executable (extract if we were handed a zip).
        string newExe;
        try
        {
            newExe = ResolveNewExecutable(downloadedPath, Path.GetFileName(currentExe));
        }
        catch (Exception ex) { message = $"Couldn't read the update package: {ex.Message}"; return false; }

        var pid = Environment.ProcessId;
        var backup = currentExe + ".old";
        var batPath = Path.Combine(Path.GetTempPath(), $"mesashield-update-{Guid.NewGuid():N}.bat");

        // The helper: wait for us to exit, back up the old exe, copy the new one in, relaunch, self-delete.
        var script = $"""
            @echo off
            echo Updating MesaShield...
            :waitloop
            tasklist /fi "PID eq {pid}" 2>nul | find "{pid}" >nul
            if not errorlevel 1 (
                timeout /t 1 /nobreak >nul
                goto waitloop
            )
            if exist "{backup}" del /q "{backup}"
            move /y "{currentExe}" "{backup}" >nul
            copy /y "{newExe}" "{currentExe}" >nul
            if errorlevel 1 (
                move /y "{backup}" "{currentExe}" >nul
            ) else (
                del /q "{backup}" >nul 2>&1
            )
            start "" "{currentExe}"
            del /q "%~f0"
            """;

        try
        {
            File.WriteAllText(batPath, script);
            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c \"{batPath}\"",
                CreateNoWindow = true,
                UseShellExecute = false,
            });
            return true;
        }
        catch (Exception ex)
        {
            message = $"Couldn't launch the updater: {ex.Message}";
            return false;
        }
    }

    private static string ResolveNewExecutable(string downloadedPath, string exeName)
    {
        if (downloadedPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            return downloadedPath;

        if (downloadedPath.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        {
            var extractDir = Path.Combine(Path.GetDirectoryName(downloadedPath)!,
                "extracted-" + Path.GetFileNameWithoutExtension(downloadedPath));
            if (Directory.Exists(extractDir)) Directory.Delete(extractDir, recursive: true);
            ZipFile.ExtractToDirectory(downloadedPath, extractDir);

            var found = Directory.EnumerateFiles(extractDir, exeName, SearchOption.AllDirectories).FirstOrDefault()
                        ?? Directory.EnumerateFiles(extractDir, "MesaShield.App.exe", SearchOption.AllDirectories).FirstOrDefault();
            if (found is null) throw new FileNotFoundException($"'{exeName}' not found inside the update package.");
            return found;
        }

        throw new NotSupportedException("Update package must be an .exe or .zip.");
    }
}
