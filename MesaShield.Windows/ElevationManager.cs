using System.Diagnostics;
using System.Security.Principal;

namespace MesaShield.Windows;

/// <summary>
/// Handles running MesaShield with administrator rights — needed for deep (ETW) monitoring and
/// active firewall/egress blocking. The good experience: ask for elevation ONCE, then register a
/// scheduled task that launches MesaShield elevated at every logon with no further prompts (the
/// standard mechanism security tools use). After that, deep monitoring is simply always on.
/// </summary>
public static class ElevationManager
{
    private const string TaskName = "MesaShieldElevated";

    public static bool IsElevated
    {
        get
        {
            if (!OperatingSystem.IsWindows()) return false;
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }

    /// <summary>Relaunch this app elevated (one UAC prompt). Returns true if the elevated process started.</summary>
    public static bool RelaunchAsAdmin(params string[] args)
    {
        if (!OperatingSystem.IsWindows()) return false;
        var exe = Environment.ProcessPath;
        if (exe is null) return false;
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = string.Join(' ', args),
                UseShellExecute = true,
                Verb = "runas",          // triggers the UAC elevation prompt
            });
            return true;
        }
        catch (Exception)
        {
            // User declined the UAC prompt, or elevation failed.
            return false;
        }
    }

    /// <summary>
    /// Create/refresh a scheduled task that runs MesaShield elevated at logon with no prompt.
    /// Must be called from an elevated process. Also removes the plain (non-elevated) Run-key
    /// autostart so the app isn't launched twice.
    /// </summary>
    public static bool InstallElevatedAutostart(string exePath)
    {
        if (!OperatingSystem.IsWindows() || !IsElevated) return false;
        try
        {
            var user = WindowsIdentity.GetCurrent().Name;   // DOMAIN\user
            // Register from an XML definition so we get real resilience: run elevated at logon AND
            // at boot, re-launch every few minutes (single-instance makes that a no-op if already
            // running, but re-starts it within minutes if it was killed), and auto-restart on
            // failure. This is the tamper/watchdog behavior — killing MesaShield just brings it back.
            var xml = BuildTaskXml(exePath, user);
            var xmlPath = Path.Combine(Path.GetTempPath(), "mesashield-task.xml");
            File.WriteAllText(xmlPath, xml, new System.Text.UnicodeEncoding(false, true)); // UTF-16 w/ BOM
            var ok = RunSchtasks($"/create /f /tn \"{TaskName}\" /xml \"{xmlPath}\"");
            try { File.Delete(xmlPath); } catch { }
            if (ok) StartupManager.SetEnabled(false, exePath); // drop the duplicate Run-key entry
            return ok;
        }
        catch (Exception) { return false; }
    }

    private static string BuildTaskXml(string exePath, string user)
    {
        // Repeats every 5 minutes indefinitely; MultipleInstancesPolicy=IgnoreNew + our own
        // single-instance guard means the repeats are harmless while running and restore it if killed.
        return $"""
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <RegistrationInfo>
            <Description>MesaShield Security — keeps protection running elevated.</Description>
          </RegistrationInfo>
          <Triggers>
            <LogonTrigger>
              <Enabled>true</Enabled>
              <Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
            </LogonTrigger>
            <BootTrigger>
              <Enabled>true</Enabled>
              <Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
            </BootTrigger>
          </Triggers>
          <Principals>
            <Principal id="Author">
              <UserId>{System.Security.SecurityElement.Escape(user)}</UserId>
              <LogonType>InteractiveToken</LogonType>
              <RunLevel>HighestAvailable</RunLevel>
            </Principal>
          </Principals>
          <Settings>
            <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
            <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
            <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
            <AllowHardTerminate>false</AllowHardTerminate>
            <StartWhenAvailable>true</StartWhenAvailable>
            <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
            <AllowStartOnDemand>true</AllowStartOnDemand>
            <Enabled>true</Enabled>
            <Hidden>false</Hidden>
            <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
            <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
          </Settings>
          <Actions Context="Author">
            <Exec>
              <Command>{System.Security.SecurityElement.Escape(exePath)}</Command>
              <Arguments>--minimized</Arguments>
            </Exec>
          </Actions>
        </Task>
        """;
    }

    public static bool ElevatedAutostartExists()
    {
        if (!OperatingSystem.IsWindows()) return false;
        return RunSchtasks($"/query /tn \"{TaskName}\"", silent: true);
    }

    public static void RemoveElevatedAutostart()
    {
        if (!OperatingSystem.IsWindows()) return;
        RunSchtasks($"/delete /f /tn \"{TaskName}\"", silent: true);
    }

    private static bool RunSchtasks(string arguments, bool silent = false)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = arguments,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = silent,
                RedirectStandardError = silent,
            });
            if (p is null) return false;
            p.WaitForExit(8000);
            return p.ExitCode == 0;
        }
        catch { return false; }
    }
}
