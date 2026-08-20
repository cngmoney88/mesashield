using System.Diagnostics;
using System.Management;
using MesaShield.Core;
using MesaShield.Core.Ml;

namespace MesaShield.Windows;

/// <summary>
/// Watches for new process launches and scans the executable behind each one.
/// Uses WMI Win32_ProcessStartTrace when running elevated (instant, event-driven)
/// and falls back to fast polling otherwise. If the executable is detected as
/// malicious the process is killed and the file quarantined.
/// </summary>
public sealed class ProcessWatcher : IDisposable
{
    private readonly ScanEngine _engine;
    private readonly QuarantineManager _quarantine;
    private readonly ShieldEventLog _log;
    private readonly ScanOptions _options = new() { ScanArchives = false };
    private readonly HashSet<string> _recentlyScanned = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private ManagementEventWatcher? _wmiWatcher;
    private CancellationTokenSource? _pollCts;

    /// <summary>Raised when a process was blocked (killed + exe quarantined).</summary>
    public event Action<string /*exePath*/, ThreatFinding>? ProcessBlocked;

    /// <summary>Raised for every new process, so the on-device anomaly learner can observe it.</summary>
    public event Action<ProcessObservation>? ProcessObserved;

    public bool IsRunning { get; private set; }
    public string Mode { get; private set; } = "stopped";

    public ProcessWatcher(ScanEngine engine, QuarantineManager quarantine, ShieldEventLog log)
    {
        _engine = engine;
        _quarantine = quarantine;
        _log = log;
    }

    public void Start()
    {
        if (IsRunning || !OperatingSystem.IsWindows()) return;
        try
        {
            var query = new WqlEventQuery("SELECT ProcessID, ProcessName FROM Win32_ProcessStartTrace");
            _wmiWatcher = new ManagementEventWatcher(query);
            _wmiWatcher.EventArrived += OnProcessStarted;
            _wmiWatcher.Start();
            Mode = "event-driven (elevated)";
        }
        catch (ManagementException)
        {
            // Win32_ProcessStartTrace needs admin rights; fall back to polling.
            _pollCts = new CancellationTokenSource();
            _ = Task.Run(() => PollAsync(_pollCts.Token));
            Mode = "polling (standard user)";
        }
        IsRunning = true;
        _ = _log.LogAsync("realtime", $"Process monitoring started: {Mode}");
    }

    private void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var pid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);
            _ = InspectProcessAsync(pid);
        }
        catch (Exception ex)
        {
            _ = _log.LogAsync("error", $"Process watcher error: {ex.Message}");
        }
    }

    private async Task PollAsync(CancellationToken ct)
    {
        var known = new HashSet<int>(Process.GetProcesses().Select(p => p.Id));
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(2000, ct).ConfigureAwait(false);
                var current = Process.GetProcesses().Select(p => p.Id).ToHashSet();
                foreach (var pid in current.Where(id => !known.Contains(id)))
                    await InspectProcessAsync(pid).ConfigureAwait(false);
                known = current;
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            {
                // Benign: some processes (protected/system apps) can't be inspected by a standard
                // user. Not an error worth surfacing.
            }
            catch (Exception ex)
            {
                await _log.LogAsync("error", $"Process poll error: {ex.Message}").ConfigureAwait(false);
            }
        }
    }

    private async Task InspectProcessAsync(int pid)
    {
        string? exePath = null;
        try
        {
            using var process = Process.GetProcessById(pid);
            exePath = process.MainModule?.FileName;
        }
        catch (Exception)
        {
            // Access denied (system/protected process) or already exited — both fine to skip.
            return;
        }
        if (exePath is null) return;

        // Feed the on-device anomaly learner (every process, including system ones, so it
        // learns a complete picture of what's normal for this machine).
        if (ProcessObserved is not null)
        {
            ProcessObserved.Invoke(new ProcessObservation
            {
                ExecutablePath = exePath,
                HourOfDay = DateTime.Now.Hour,
            });
        }

        // Skip Windows' own binaries and things we just scanned.
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (exePath.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase)) return;
        lock (_gate)
        {
            if (!_recentlyScanned.Add(exePath)) return;
            if (_recentlyScanned.Count > 4096) _recentlyScanned.Clear();
        }

        var result = await _engine.ScanFileAsync(exePath, _options).ConfigureAwait(false);
        var malicious = result.Findings.FirstOrDefault(f => f.Severity == ThreatSeverity.Malicious);
        if (malicious is null) return;

        // Kill first, then quarantine the binary.
        try
        {
            using var process = Process.GetProcessById(pid);
            process.Kill(entireProcessTree: true);
        }
        catch (Exception) { /* already gone */ }

        await _quarantine.QuarantineAsync(malicious).ConfigureAwait(false);
        await _log.LogAsync("blocked",
            $"Blocked process and quarantined executable: {malicious.ThreatName}",
            exePath, malicious.ThreatName).ConfigureAwait(false);
        ProcessBlocked?.Invoke(exePath, malicious);
    }

    public void Dispose()
    {
        if (_wmiWatcher is not null)
        {
            _wmiWatcher.EventArrived -= OnProcessStarted;
            try { _wmiWatcher.Stop(); } catch (ManagementException) { }
            _wmiWatcher.Dispose();
        }
        _pollCts?.Cancel();
        IsRunning = false;
        Mode = "stopped";
    }
}
