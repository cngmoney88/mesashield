using System.Diagnostics;

namespace MesaShield.Windows;

/// <summary>
/// Registers, queries, and controls the MesaShield always-on Windows Service via <c>sc.exe</c>.
/// Install/uninstall/start/stop require Administrator. Query operations are safe for any user, so
/// the desktop app can cheaply ask "is the service protecting this PC?" and become a viewer if so.
/// </summary>
public static class ServiceControl
{
    public const string ServiceName = "MesaShield";
    private const string DisplayName = "MesaShield Security";
    private const string Description =
        "MesaShield always-on protection: real-time antivirus, ransomware behavior guard, " +
        "data-loss-prevention firewall, and adaptive learning. Runs before login and restarts if stopped.";

    /// <summary>True if the service is registered on this machine (installed), regardless of run state.</summary>
    public static bool IsInstalled()
    {
        var (code, output) = Run($"query \"{ServiceName}\"");
        // sc query returns 1060 ("service does not exist") when not installed.
        return code == 0 && output.Contains("SERVICE_NAME", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True if the service is currently RUNNING (protection is active headlessly).</summary>
    public static bool IsRunning()
    {
        var (code, output) = Run($"query \"{ServiceName}\"");
        return code == 0 && output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Register the service to auto-start at boot, with automatic restart-on-failure, then start it.
    /// Requires Administrator. Returns true on success.</summary>
    public static bool Install(string serviceExePath)
    {
        // Quoting matters: binPath must be a single quoted token for sc.exe.
        var binPath = $"\\\"{serviceExePath}\\\"";
        if (IsInstalled()) Uninstall();   // clean re-register (e.g. exe moved)

        var (code, _) = Run($"create \"{ServiceName}\" binPath= \"{binPath}\" start= auto DisplayName= \"{DisplayName}\"");
        if (code != 0) return false;

        Run($"description \"{ServiceName}\" \"{Description}\"");
        // Restart 5s after each of the first three failures; reset the failure counter daily.
        Run($"failure \"{ServiceName}\" reset= 86400 actions= restart/5000/restart/5000/restart/5000");
        // Also restart on non-crash stops (e.g. a tamper attempt that stops the service cleanly).
        Run($"failureflag \"{ServiceName}\" 1");

        var (startCode, _) = Run($"start \"{ServiceName}\"");
        return startCode == 0 || startCode == 1056;   // 1056 = already running
    }

    /// <summary>Stop and remove the service. Requires Administrator.</summary>
    public static bool Uninstall()
    {
        Run($"stop \"{ServiceName}\"");
        var (code, _) = Run($"delete \"{ServiceName}\"");
        return code == 0;
    }

    public static bool Start()
    {
        var (code, _) = Run($"start \"{ServiceName}\"");
        return code == 0 || code == 1056;
    }

    public static bool Stop()
    {
        var (code, _) = Run($"stop \"{ServiceName}\"");
        return code == 0 || code == 1062;   // 1062 = not started
    }

    private static (int code, string output) Run(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return (-1, "");
            var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(15000);
            return (p.HasExited ? p.ExitCode : -1, output);
        }
        catch (Exception ex)
        {
            return (-1, ex.Message);
        }
    }
}
